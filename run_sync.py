#!/usr/bin/env python3
import os
import datetime
import sys
import json
import pickle
import hashlib
import time
import configparser
import traceback
import argparse
from peewee import SqliteDatabase,CharField,Model,TextField,DateTimeField

if "__file__" in locals():
    sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

#from libsync import AdConnect,SambaInfo,write_log_json_data,take_stats,logger,logging,generate_password
from libsync import AdConnect,SambaInfo,write_log_json_data,take_stats,logger,logging,generate_password,PermissionsMissing

class FatalSyncError(RuntimeError):
    """Needs operator action; retrying cannot help."""

parser = argparse.ArgumentParser(description='Azure ad sync')
parser.add_argument('--conf', dest='azureconf', default='/etc/azureconf/azure.conf',help='path to conf file')
parser.add_argument('--service-mode', action=argparse.BooleanOptionalAction,dest='servicemode',help='Run the script in service mode',default=False)
parser.add_argument('--force', action=argparse.BooleanOptionalAction,dest='force',help='Force synchronization of all objects',default=False)
parser.add_argument('--dryrun', action=argparse.BooleanOptionalAction,dest='dryrun',help='simulate a send but does not actually perform the actions',default=None)

args = parser.parse_args()

azureconf=args.azureconf
config = configparser.ConfigParser()
config.read(azureconf)

if config.has_option('common', 'folder_callback_python') and config.get('common', 'folder_callback_python'):
    sys.path.append(config.get('common', 'folder_callback_python'))
    from callbackaadsync import callback_calculated_user,callback_calculated_hashnt,callback_calculated_group,callback_calculated_device,callback_after_send_obj,callback_after_send_hashnt,callback_end_synchro
else:
    callback_after_send_obj = None
    callback_after_send_hashnt = None
    callback_end_synchro = None

db = SqliteDatabase(config.get('common', 'dbpath'))

if args.dryrun != None:
    dry_run=args.dryrun
else:
    dry_run = config.getboolean('common', 'dry_run')
    
logfile = '/var/log/azure_ad_sync'

synchronization_interval_service=60

if config.has_option('common', 'synchronization_interval_service'):
    synchronization_interval_service = config.getint('common', 'synchronization_interval_service')

if config.has_option('common', 'logfile'):
    logfile = config.get('common', 'logfile')

calculate_deletions_based_on_last_sync = False
if config.has_option('common', 'calculate_deletions_based_on_last_sync'):
    calculate_deletions_based_on_last_sync = config.getboolean('common', 'calculate_deletions_based_on_last_sync')

if dry_run:
    handler = logging.StreamHandler(sys.stdout)
elif logfile:
    handler = logging.FileHandler(logfile)
else:
    handler = logging.StreamHandler(sys.stderr)
logging.basicConfig(level=logging.WARNING, format='%(message)s', handlers=[handler], force=True)

class AzureObject(Model):
    sourceanchor = CharField(primary_key=True, index=True)
    object_type = CharField(null=True)
    last_data_send = TextField(null=True)
    last_data_send_date = DateTimeField(null=True)
    last_sha256_hashnt_send = TextField(null=True)
    last_send_hashnt_date = DateTimeField(null=True)

    class Meta:
        database = db

def hash_for_data(data):
    return hashlib.sha1(pickle.dumps(data)).hexdigest()

#tenant_sync_confirmed = False

def ensure_tenant_sync(azure, hash_synchronization):
    """Switch DirSync and password hash sync on in the tenant when they are off.
    The tenant is asked once per process: a service does not repeat this call every
    cycle (each call is one more chance for Entra to answer "not yet"); a restart
    asks again. A failure leaves the check open, so the next cycle repeats it."""
    # global tenant_sync_confirmed
    # if tenant_sync_confirmed:
    #     return
    sync_conf = azure.get_sync_configuration()
    if str(sync_conf['IsDirSyncing']).lower() != 'true':
        if not dry_run and not sys.stdin.isatty():
            raise FatalSyncError('DirSync is not enabled for this tenant; run the script once interactively to enable it.')
        # enable ad sync
        azure.enable_ad_sync()
        write_log_json_data('enable_ad_sync',{"EnableDirSync":True})

    # enable password hash sync
    if hash_synchronization and not (int(sync_conf['DirSyncFeatures']) & 1): # 1 = PasswordHashSync
        azure.enable_password_hash_sync()
        write_log_json_data('enable_password_hash_sync',{"PasswordHashSync":True})
    #tenant_sync_confirmed = True


def build_azure():
    azure = AdConnect(entra_aba_dir=config.get("common", "entra_aba_dir", fallback="/root/entra_aba"))
    azure.dry_run = dry_run
    azure.confirmations = 1 if args.servicemode else 2   # new Entra application: passes needed in a row
    azure.retry_delay = config.getint('common', 'permission_retry_delay', fallback=15)   # first wait after a refused call, doubles each time
    azure.retry_count = config.getint('common', 'permission_retry_count', fallback=6)    # tries before giving up
    azure.sync_device = config.getboolean('common', 'sync_device')
    if config.get('common', 'proxy'):
        azure.proxiesconf = {'http':config.get('common', 'proxy'),'https':config.get('common','proxy')}
    else:
        azure.proxiesconf = {}

    if config.has_option('common', 'verify'):
        if config.get('common', 'verify').lower() in ('true', '1'):
            azure.verify = True
        elif config.get('common', 'verify').lower() in ('false', '0'):
            azure.verify = False
        else:
            azure.verify = config.get('common', 'verify')
    else:
        azure.verify = True

    if config.has_option('common', 'tenant_id'):
        azure.tenant_id = config.get('common', 'tenant_id')

    if config.has_option('common', 'azureadname'):
        azure.domain = config.get('common', 'azureadname')

    return azure

def startup_checks():
    """Run once at the start of an initial run and of the service: local identity ready,
    DirSync / password hash sync on. The wait for a new Entra application stays lazy
    (first AdConnect.connect() of the process, see _wait_for_new_identity). Every call to
    Entra is retried on refusal (AdConnect._call). Any failure is fatal."""
    azure = build_azure()
    if not azure.identity_ready():
        # A dry run also creates the certificate (and later the db): without them nothing works.
        # It still needs a terminal for the administrator login.
        #if dry_run or not sys.stdin.isatty():
        if not sys.stdin.isatty():
            raise FatalSyncError(
                f'Entra application identity in {azure.entra_aba_dir} is not initialised (or belongs to another tenant). '
                #'Run once interactively without --dryrun, or: '
                'Run once interactively (with or without --dryrun), or: '
                'python3 AADInternals_python/_aad_certificate_manager.py bootstrap '
                f'--tenant-id <GUID> --state-dir {azure.entra_aba_dir} --apply'
            )
    try:
        azure.connect()
        #azure._wait_for_new_identity()     # stays lazy in AdConnect.connect()
        ensure_tenant_sync(azure, config.getboolean('common', 'hash_synchronization'))
    except FatalSyncError:
        raise
    except PermissionsMissing as exc:
        raise FatalSyncError(str(exc)) from exc
    except Exception as exc:
        raise FatalSyncError('Startup failed: %s' % exc) from exc
    return azure

#def run_sync(force=False,from_db=False, azure=False):
def run_sync(force=False,from_db=False,azure=None):

    global config
    global db

    global dry_run

    hash_synchronization = config.getboolean('common', 'hash_synchronization')

    sync_device = config.getboolean('common', 'sync_device')

    if dry_run:
        print('DRY RUN ON: the script will not perform any actions')

    # azure = AdConnect(entra_aba_dir=config.get("common", "entra_aba_dir", fallback="/root/entra_aba"))
    # azure.dry_run = dry_run
    # azure.confirmations = 1 if args.servicemode else 2   # new Entra application: passes needed in a row
    # azure.sync_device = sync_device
    # if config.get('common', 'proxy'):
    #     azure.proxiesconf = {'http':config.get('common', 'proxy'),'https':config.get('common','proxy')}
    # else:
    #     azure.proxiesconf = {}

    # if config.has_option('common', 'verify'):
    #     if config.get('common', 'verify').lower() in ('true', '1'):
    #         azure.verify = True
    #     elif config.get('common', 'verify').lower() in ('false', '0'):
    #         azure.verify = False
    #     else:
    #         azure.verify = config.get('common', 'verify')
    # else:
    #     azure.verify = True

    # if config.has_option('common', 'tenant_id'):
    #     azure.tenant_id = config.get('common', 'tenant_id')

    # if config.has_option('common', 'azureadname'):
    #    azure.domain = config.get('common', 'azureadname')
    #azure = build_azure()
    if azure is None:            # first cycle: reuse the client checked by startup_checks()
        azure = build_azure()
    # # check if identity is ready
    # if not azure.identity_ready():
    #     if dry_run or not sys.stdin.isatty():
    #         raise FatalSyncError(
    #             f'Entra application identity in {azure.entra_aba_dir} is not initialised (or belongs to another tenant). '
    #             'Run once interactively without --dryrun, or: '
    #             'python3 AADInternals_python/_aad_certificate_manager.py bootstrap '
    #             f'--tenant-id <GUID> --state-dir {azure.entra_aba_dir} --apply'
    #         )

    if config.has_option('common', 'enable_single_sign_on'):
        enable_single_sign_on = config.getboolean('common', 'enable_single_sign_on')
    else:
        enable_single_sign_on = False

    basedn = None
    if config.has_option('common', 'basedn'):
        basedn = config.get('common', 'basedn')

    basedn_user = basedn
    if config.has_option('common', 'basedn_user'):
        basedn_user = config.get('common', 'basedn_user')

    basedn_group = basedn
    if config.has_option('common', 'basedn_group'):
        basedn_group = config.get('common', 'basedn_group')

    basedn_computer = basedn
    if config.has_option('common', 'basedn_computer'):
        basedn_computer = config.get('common', 'basedn_computer')

    custom_filter_user = None
    if config.has_option('common', 'custom_filter_user'):
        custom_filter_user = config.get('common', 'custom_filter_user')

    custom_filter_group = None
    if config.has_option('common', 'custom_filter_group'):
        custom_filter_group = config.get('common', 'custom_filter_group')

    custom_filter_computer = None
    if config.has_option('common', 'custom_filter_computer'):
        custom_filter_computer = config.get('common', 'custom_filter_computer')

    url = '/var/lib/samba/private/sam.ldb'
    if config.has_option('common', 'url'):
        url = config.get('common', 'url')

    user = None
    if config.has_option('common', 'user_ad'):
        user = config.get('common', 'user_ad')

    password = None
    if config.has_option('common', 'password_ad'):
        password = config.get('common', 'password_ad')

    pathsmbconf = "/etc/samba/smb.conf"
    if config.has_option('common', 'pathsmbconf'):
        pathsmbconf = config.get('common', 'pathsmbconf')

    #https://learn.microsoft.com/en-us/azure/active-directory/hybrid/connect/plan-connect-userprincipalname#alternate-login-id

    use_get_syncobjects = True
    if config.has_option('common', 'use_get_syncobjects'):
        use_get_syncobjects = config.getboolean('common', 'use_get_syncobjects')

    azure.use_get_syncobjects = use_get_syncobjects

    alternate_login_id_attr = "userPrincipalName"
    if config.has_option('common', 'alternate_login_id_attr'):
            alternate_login_id_attr = config.get('common', 'alternate_login_id_attr')


    smb = SambaInfo(smbconf=pathsmbconf,
            url=url,
            SourceAnchorAttr=config.get('common', 'SourceAnchorAttr'),
            basedn=basedn,
            custom_filter_user=custom_filter_user,
            custom_filter_group=custom_filter_group,
            custom_filter_computer=custom_filter_computer,
            alternate_login_id_attr=alternate_login_id_attr,
            basedn_user=basedn_user,
            basedn_group=basedn_group,
            basedn_computer=basedn_computer,
            user=user,
            password=password
        )
    if config.has_option('common', 'folder_callback_python') and config.get('common', 'folder_callback_python'):
        smb.callback_calculated_user   = callback_calculated_user
        smb.callback_calculated_hashnt = callback_calculated_hashnt
        smb.callback_calculated_group  = callback_calculated_group
        smb.callback_calculated_device = callback_calculated_device

    smb.write_msDSConsistencyGuid_if_empty = config.getboolean('common', 'write_msDSConsistencyGuid_if_empty')
    smb.use_msDSConsistencyGuid_if_exist = config.getboolean('common', 'use_msDSConsistencyGuid_if_exist')
    smb.dry_run = dry_run
    smb.add_device = sync_device

    if config.has_option('common', 'warning_duplicate_mail_value'):
        smb.warning_duplicate_mail_value = config.getboolean('common', 'warning_duplicate_mail_value')

    if not AzureObject.table_exists():
        db.create_tables([AzureObject])
    #ensure_tenant_sync(azure, hash_synchronization)

    if enable_single_sign_on:

        azure_ad_sso_user_exist = smb.azure_ad_sso_user_exist()
        azure_ad_sso_expire = False
        if azure_ad_sso_user_exist :
            azure_ad_sso_expire = smb.azure_ad_sso_user_expire()

        if (not azure_ad_sso_user_exist) or azure_ad_sso_expire:
            if dry_run:
                write_log_json_data(
                    'sso',
                    {
                        'create_account': not azure_ad_sso_user_exist,
                        'enable_sso_flag': not azure_ad_sso_user_exist,
                        'rotate_password': True,
                        'domain_name': smb.domaine
                    }
                )
            elif sys.stdin.isatty():
                random_password = generate_password()

                if not azure_ad_sso_user_exist:
                    azure.set_desktop_sso_enabled()
                    write_log_json_data('enable_sso', {"enable_sso": True})

                azure.set_desktop_sso(
                    domain_name=smb.domaine,
                    password=random_password
                )
                write_log_json_data('set_password_sso', {"domain_name": smb.domaine})

                if not azure_ad_sso_user_exist:
                    smb.create_azureadssoacc()

                smb.set_password_azureadssoacc(password=random_password)

            else:
                write_log_json_data('error', {'message': "The AZUREADSSOACC account password needs to be renewed. Please run the script interactively to perform this operation."})

    smb.generate_all_dict()

    if config.getboolean('common', 'do_delete'):
        
        if from_db:
            for u in AzureObject.select(AzureObject.sourceanchor,AzureObject.last_data_send).where(AzureObject.object_type=='user'):
                azure.dict_az_user[u.sourceanchor] = json.loads(u.last_data_send)
        else:
            azure.generate_all_dict()

        # Delete user in azure and not found in samba
        for user in azure.dict_az_user:
            if not user in smb.dict_all_users_samba:
                try:
                    azure.delete_user(user)
                    write_log_json_data('delete',azure.dict_az_user[user])
                except PermissionsMissing:      # permissions not there (yet): abort the run
                    raise
                except:
                    write_log_json_data('error',{'sourceanchor':user,'action':'delete_user','traceback':traceback.format_exc(),'data_delete':azure.dict_az_user[user]})
                    continue
                if not dry_run:
                    AzureObject.delete().where(AzureObject.sourceanchor==user,AzureObject.object_type=='user').execute()


        # Delete group in azure and not found in samba
        if (not use_get_syncobjects) or from_db:
            for g in AzureObject.select(AzureObject.sourceanchor,AzureObject.last_data_send).where(AzureObject.object_type=='group'):
                azure.dict_az_group[g.sourceanchor] = json.loads(g.last_data_send)

        for group in azure.dict_az_group:
            if not group in smb.dict_all_group_samba:
                try:
                    azure.delete_group(group)
                    write_log_json_data('delete',azure.dict_az_group[group])
                except PermissionsMissing:      # permissions not there (yet): abort the run
                    raise
                except:
                    write_log_json_data('error',{'sourceanchor':group,'action':'delete_group','traceback':traceback.format_exc(),'data_delete':azure.dict_az_group[group]})
                    continue
                if not dry_run:
                    AzureObject.delete().where(AzureObject.sourceanchor==group,AzureObject.object_type=='group').execute()

        # Delete device in azure and not found in samba
        if sync_device:

            if (not use_get_syncobjects) or from_db:
                for d in AzureObject.select(AzureObject.sourceanchor,AzureObject.last_data_send).where(AzureObject.object_type=='device'):
                    azure.dict_az_devices[d.sourceanchor] = json.loads(d.last_data_send)

            for device in azure.dict_az_devices:
                if not device in smb.dict_all_device_samba:
                    try:
                        azure.delete_device(device)
                        write_log_json_data('delete',azure.dict_az_devices[device])
                    except PermissionsMissing:      # permissions not there (yet): abort the run
                        raise
                    except:
                        write_log_json_data('error',{'sourceanchor':device,'action':'delete_device','traceback':traceback.format_exc(),'data_delete':azure.dict_az_devices[device]})
                        continue
                    if not dry_run:
                        AzureObject.delete().where(AzureObject.sourceanchor==device,AzureObject.object_type=='device').execute()

    dict_error={}

    send_user = False
    #create all user found samba
    for entry in smb.dict_all_users_samba:
        last_data =  AzureObject.select(AzureObject.last_data_send).where(AzureObject.sourceanchor==entry,AzureObject.object_type=='user').first()
        if force or (not last_data) or json.loads(last_data.last_data_send) != smb.dict_all_users_samba[entry] :
            try:
                azure.send_obj_to_az(smb.dict_all_users_samba[entry])
                write_log_json_data('send',smb.dict_all_users_samba[entry])
                send_user = True
            except PermissionsMissing:      # permissions not there (yet): abort the run
                raise
            except:
                dict_error[entry]=None
                write_log_json_data('error',{'sourceanchor':entry,'action':'send_user','traceback':traceback.format_exc(),'data_send':smb.dict_all_users_samba[entry]})
                continue 
            if callback_after_send_obj != None :
                callback_after_send_obj(sambaobj=smb.samdb_loc,az=azure.az,entry=entry,dry_run=dry_run,last_send=last_data.last_data_send if last_data else {})
            if not dry_run:
                if not last_data:
                    AzureObject.insert(sourceanchor=entry,object_type='user',last_data_send =json.dumps(smb.dict_all_users_samba[entry]),last_data_send_date = datetime.datetime.now()).execute()
                else:
                    AzureObject.update(last_data_send =json.dumps(smb.dict_all_users_samba[entry]),last_data_send_date = datetime.datetime.now()).where(AzureObject.sourceanchor==entry).execute()

    if sync_device:
        if config.getboolean('common', 'create_service_connection_point'):
            if not smb.check_service_connection_point_existe():
                azure.connect()
                write_log_json_data('write_service_connection_point',{"write_service_connection_point":True})
                if not dry_run:
                    smb.write_service_connection_point(azure.tenant_id,config.get('common', 'azureadname'))
            
        #create all device found samba (experimental)
        for entry in smb.dict_all_device_samba:
            last_data =  AzureObject.select(AzureObject.last_data_send).where(AzureObject.sourceanchor==entry,AzureObject.object_type=='device').first()
            if force or (not last_data) or json.loads(last_data.last_data_send) != smb.dict_all_device_samba[entry] :
                try:
                    azure.send_obj_to_az(smb.dict_all_device_samba[entry])
                    write_log_json_data('send',smb.dict_all_device_samba[entry])
                except PermissionsMissing:      # permissions not there (yet): abort the run
                    raise
                except:
                    dict_error[entry]=None
                    write_log_json_data('error',{'sourceanchor':entry,'action':'send_device','traceback':traceback.format_exc(),'data_send':smb.dict_all_device_samba[entry]})
                    continue
                if callback_after_send_obj != None :
                    callback_after_send_obj(sambaobj=smb.samdb_loc,az=azure.az,entry=entry,dry_run=dry_run,last_send=last_data.last_data_send if last_data else {})
                if not dry_run:
                    if not last_data:
                        AzureObject.insert(sourceanchor=entry,object_type='device',last_data_send =json.dumps(smb.dict_all_device_samba[entry]),last_data_send_date = datetime.datetime.now()).execute()
                    else:
                        AzureObject.update(last_data_send =json.dumps(smb.dict_all_device_samba[entry]),last_data_send_date = datetime.datetime.now()).where(AzureObject.sourceanchor==entry).execute()        

    #create all group found samba
    list_nested_group = {}
    list_group_create = {}

    for entry in smb.dict_all_group_samba:
        if not AzureObject.select(AzureObject.sourceanchor).where(AzureObject.sourceanchor==entry,AzureObject.object_type=='group').first():
            list_group_create[entry] = None

    for entry in smb.dict_all_group_samba:
        last_data =  AzureObject.select(AzureObject.last_data_send).where(AzureObject.sourceanchor==entry,AzureObject.object_type=='group').first()
        if force or (not last_data) or json.loads(last_data.last_data_send) != smb.dict_all_group_samba[entry] :
            try:
                azure.send_obj_to_az(smb.dict_all_group_samba[entry])
                write_log_json_data('send',smb.dict_all_group_samba[entry])
            except PermissionsMissing:      # permissions not there (yet): abort the run
                raise
            except:
                dict_error[entry]=None
                write_log_json_data('error',{'sourceanchor':entry,'action':'send_group','traceback':traceback.format_exc(),'data_send':smb.dict_all_group_samba[entry]})
                continue

            if callback_after_send_obj != None :
                callback_after_send_obj(sambaobj=smb.samdb_loc,az=azure.az,entry=entry,dry_run=dry_run,last_send=last_data.last_data_send if last_data else {})
            if [g for g in smb.dict_all_group_samba[entry]['groupMembers'] if g in dict_error]:
                continue

            if dry_run:
                continue

            for g in smb.dict_all_group_samba[entry]["groupMembers"]:
                if g in list_group_create:
                    list_nested_group[entry] = None

            if entry in list_nested_group:
                continue

            if not dry_run:
                if not last_data:
                    AzureObject.insert(sourceanchor=entry,object_type='group',last_data_send =json.dumps(smb.dict_all_group_samba[entry]),last_data_send_date = datetime.datetime.now()).execute()
                else:
                    AzureObject.update(last_data_send =json.dumps(smb.dict_all_group_samba[entry]),last_data_send_date = datetime.datetime.now()).where(AzureObject.sourceanchor==entry).execute()

    already_wait = False
    if list_nested_group:
        print('New group with nested detected wait 30s for send again')
        time.sleep(30)
        already_wait = True
        for entry in list_nested_group:
            try:
                azure.send_obj_to_az(smb.dict_all_group_samba[entry])
                write_log_json_data('send',smb.dict_all_group_samba[entry])
                last_data =  AzureObject.select(AzureObject.last_data_send).where(AzureObject.sourceanchor==entry,AzureObject.object_type=='group').first()
                if not last_data:
                    AzureObject.insert(sourceanchor=entry,object_type='group',last_data_send =json.dumps(smb.dict_all_group_samba[entry]),last_data_send_date = datetime.datetime.now()).execute()
                else:
                    AzureObject.update(last_data_send =json.dumps(smb.dict_all_group_samba[entry]),last_data_send_date = datetime.datetime.now()).where(AzureObject.sourceanchor==entry).execute()
            except PermissionsMissing:      # permissions not there (yet): abort the run
                raise
            except:
                write_log_json_data('error',{'sourceanchor':entry,'action':'send_group','traceback':traceback.format_exc(),'data_send':smb.dict_all_group_samba[entry]})
                continue


    if not send_user:
        already_wait = True

    #send all_password
    if hash_synchronization:
        for entry in smb.dict_id_hash :
            sha2password= hash_for_data(smb.dict_id_hash[entry])
            last_data =  AzureObject.select(AzureObject.last_sha256_hashnt_send).where(AzureObject.sourceanchor==entry,AzureObject.object_type=='user').first()
            if entry in dict_error and not last_data:
                continue
            if force or (not last_data) or last_data.last_sha256_hashnt_send != sha2password :
                # Microsoft is very slow between sending the account and sending the password
                try:
                    azure.send_hashnt(smb.dict_id_hash[entry],entry)
                    write_log_json_data('send_nthash',{'SourceAnchor':entry,'onPremisesSamAccountName':smb.dict_all_users_samba[entry]['onPremisesSamAccountName'],'nthash':'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'})
                except PermissionsMissing:      # permissions not there (yet): abort the run
                    raise
                except Exception as e:
                    if "Result" in str(e):
                        if not already_wait:
                            print('Fail, we may be a little too fast for microsoft, we will wait and try again ...' )
                            time.sleep(30)
                            already_wait = True
                        try:
                            azure.send_hashnt(smb.dict_id_hash[entry],entry)
                            write_log_json_data('send_nthash',{'SourceAnchor':entry,'onPremisesSamAccountName':smb.dict_all_users_samba[entry]['onPremisesSamAccountName'],'nthash':'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'})
                        except PermissionsMissing:      # permissions not there (yet): abort the run
                            raise
                        except Exception as e:
                            write_log_json_data('error',{'sourceanchor':entry,'action':'send_hashnt','traceback':traceback.format_exc(),'data_send_hashnt':{'SourceAnchor':entry,'onPremisesSamAccountName':smb.dict_all_users_samba[entry]['onPremisesSamAccountName'],'nthash':'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'}})
                            if "Result" in str(e):
                                print('\n\nMaybe the user was manually deleted online? Run a force sync again to resend them... (use --force)\n\n')
                            continue

                    else:
                        write_log_json_data('error',{'sourceanchor':entry,'action':'send_hashnt','traceback':traceback.format_exc(),'data_send_hashnt':{'SourceAnchor':entry,'onPremisesSamAccountName':smb.dict_all_users_samba[entry]['onPremisesSamAccountName'],'nthash':'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'}})
                        continue

                if callback_after_send_hashnt != None:
                    callback_after_send_hashnt(sambaobj=smb.samdb_loc,az=azure.az,SourceAnchor=entry,hashnt=smb.dict_id_hash[entry],dry_run=dry_run)
                if not dry_run:
                    AzureObject.update(last_sha256_hashnt_send = sha2password,last_send_hashnt_date = datetime.datetime.now()).where(AzureObject.sourceanchor==entry).execute()

    if callback_end_synchro != None:
        callback_end_synchro(sambaobj=smb.samdb_loc,az=azure.az,dry_run=dry_run)

def report_run(announce):
    """One line on the console / in the journal when a run is over. Real log entries go
    to the logfile only, so without this a finished run looks like a run that did nothing.
    In service mode, quiet cycles (nothing sent, nothing failed) stay quiet, except
    the first one and the first one after a failure (announce)."""
    counts = take_stats()
    if args.servicemode and not announce and not counts:
        return
    text = ", ".join("%s=%d" % (name, counts[name]) for name in sorted(counts)) or "nothing to send"
    if counts.get('error'):
        text += " - see %s" % logfile
    print("Sync run finished%s: %s" % (" (dry run)" if dry_run else "", text), flush=True)

if __name__ == '__main__':
    retry_delay = synchronization_interval_service
    announce = True      # say something after the start and after a failure, even if nothing was sent
    try:
        try:
            #startup_checks()          # permission checks: once per initial run / once per service start
            checked_azure = startup_checks()          # permission checks: once per initial run / once per service start
        except FatalSyncError as exc:
            write_log_json_data("fatal", traceback.format_exc())
            print("Fatal: %s" % exc, file=sys.stderr, flush=True)
            sys.exit(2)

        while True:
            try:
                #run_sync(force=args.force,from_db=calculate_deletions_based_on_last_sync)
                                #run_sync(force=args.force,from_db=calculate_deletions_based_on_last_sync)
                run_sync(force=args.force,from_db=calculate_deletions_based_on_last_sync,azure=checked_azure)

                retry_delay = synchronization_interval_service
                report_run(announce)
                announce = False
            except (FatalSyncError, PermissionsMissing) as exc:
                write_log_json_data(
                    "fatal",
                    traceback.format_exc()
                )
                print("Fatal: %s" % exc, file=sys.stderr, flush=True)
                sys.exit(2)
            except Exception as exc:
                write_log_json_data("error",traceback.format_exc())
                if not args.servicemode :
                    raise
                retry_delay = min(retry_delay * 2, 3600)
                print("Sync run failed: %s: %s (details in %s), next try in %d seconds"
                      % (type(exc).__name__, exc, logfile, retry_delay), file=sys.stderr, flush=True)
                take_stats()
                announce = True
            checked_azure = None
            if not args.servicemode :
                break
            calculate_deletions_based_on_last_sync = True
            time.sleep(retry_delay)
    finally:
        db.close()