#!/usr/bin/env python
import os
import sys
import json
import ldb
import base64
import datetime
import logging
import random
import string

from samba.auth import system_session
from samba.credentials import Credentials
from samba.samdb import SamDB
from samba import param
from AADInternals_python.AADInternals import AADInternals

from samba.dsdb import UF_ACCOUNTDISABLE
from AdAccountReader import AdAccountReader

import optparse
import samba.getopt as options

logging.getLogger("adal-python").setLevel(logging.WARN)

logger = logging.getLogger()

def write_log_json_data(action,data):
    logger.info(json.dumps({'type':action,'timestamp': str(datetime.datetime.utcnow()),'data':data}))

def generate_password(length=127):
    special_chars = "!#$%()*+,-./:;=?@[\\]^_{|}~"
    password = [random.choice(string.ascii_lowercase), random.choice(string.ascii_uppercase), random.choice(string.digits), random.choice(special_chars)]
    password += random.choices(string.ascii_letters + string.digits + special_chars, k=length - 4)
    random.shuffle(password)
    return ''.join(password)

class AdConnect():

    def __init__(self):


        self.proxiesconf = None

        self.domain= None
        self.tenant_id= None
        self.save_to_cache=True
        self.use_cache = True
        self.cache_file = os.path.join(os.path.dirname(os.path.realpath(__file__)),'last_token.json')

        self.dry_run=True
        self.sync_device=False
        use_get_syncobjects = True

        self.az = None
        self.dict_az_user={}
        self.dict_az_group={}
        self.dict_az_devices={}
        self.verify=True

    def connect(self):
        if not self.az:
            self.az = AADInternals(proxies=self.proxiesconf,
                                   use_cache=self.use_cache,
                                   save_to_cache=self.save_to_cache,
                                   tenant_id=self.tenant_id,
                                   cache_file=self.cache_file,
                                   domain=self.domain,
                                   verify=self.verify)
            self.az.get_token(scopes=["https://graph.windows.net/.default"])
            self.tenant_id = self.az.tenant_id


    def enable_ad_sync(self):
        self.connect()
        self.az.set_adsyncenabled(enabledirsync=True)

    def set_desktop_sso_enabled(self):
        self.connect()
        if not self.dry_run:
            self.az.set_desktop_sso_enabled(enable=True)

    def set_desktop_sso(self, domain_name: str, password: str, computer_name: str = "AZUREADSSOACC", enable: bool = True):
        self.connect()
        if not self.dry_run:
            self.az.set_desktop_sso( domain_name, password, computer_name, enable)

    def enable_password_hash_sync(self):
        self.connect()
        self.az.set_sync_features(enable_features=['PasswordHashSync'])

    def send_obj_to_az(self,entry):
        self.connect()
        if not self.dry_run:
            self.az.set_azureadobject(**entry)

    def delete_user(self,entry):
        self.connect()
        if not self.dry_run:
            self.az.remove_azureadoject(sourceanchor=entry,objecttype='User')

    def delete_group(self,entry):
        self.connect()
        if not self.dry_run:
            self.az.remove_azureadoject(sourceanchor=entry,objecttype='Group')

    def delete_device(self,entry):
        self.connect()
        if not self.dry_run:
            self.az.remove_azureadoject(sourceanchor=entry,objecttype='Device')            

    def generate_all_dict(self):
        self.connect()
        self.dict_az_user = {}
        self.dict_az_group = {}
        self.dict_az_devices = {}

        for user in self.az.list_users(select="onPremisesImmutableId,userPrincipalName,onPremisesSyncEnabled"):
            if not user.get('onPremisesImmutableId'):
                continue
            if not user.get('onPremisesSyncEnabled'):
                continue
            self.dict_az_user[user["onPremisesImmutableId"]] = user

        if not self.use_get_syncobjects:
            return

        try:
            list_groups = self.az.list_groups(include_immutable_id=True, select="id")
        except Exception as e:
            if 'Identity synchronization is not yet activated for this company' in str(e):
                list_groups = []
            else:
                raise

        for group in list_groups:
            if not group.get('onPremisesImmutableId'):
                continue
            self.dict_az_group[group["onPremisesImmutableId"]] = group

        return None
        try:
            list_devices = self.az.list_devices(select="onPremisesImmutableId,id")
        except Exception as e:
            if 'Identity synchronization is not yet activated for this company' in str(e):
                list_devices = []
            else:
                raise

        if self.sync_device:
            for device in list_devices:
                if not device.get('onPremisesImmutableId'):
                    continue
                self.dict_az_devices[user["onPremisesImmutableId"]] = device

    def send_hashnt(self,hashnt,sourceanchor):
        self.connect()
        if not self.dry_run:
            self.az.set_userpassword(hashnt=hashnt,sourceanchor=sourceanchor)


class SambaInfo():

    def __init__(self, smbconf="/etc/samba/smb.conf",url='/var/lib/samba/private/sam.ldb',SourceAnchorAttr="objectSid",basedn=None,alternate_login_id_attr=None,basedn_user=None,basedn_group=None,basedn_computer=None,custom_filter_user='',custom_filter_group='',custom_filter_computer='',user=None,password=None):

        self.callback_calculated_user   = None
        self.callback_calculated_hashnt = None
        self.callback_calculated_group  = None
        self.callback_calculated_device = None
        self.warning_duplicate_mail_value = True

        # SAMDB
        lp = param.LoadParm()
        lp.load(smbconf)
        self.domaine = lp.get('realm').lower()

        self.alternate_login_id_attr = alternate_login_id_attr

        creds = Credentials()
        creds.guess(lp)
        
        self.user = None
        if user or password:
            creds.set_username(user)
            self.user = user
            creds.set_password(password)

        self.samdb_loc = SamDB(url=url,session_info=system_session(),credentials=creds, lp=lp)
        if user : 
            self.account_reader = AdAccountReader(url.split('//')[1].split(':')[0], lp, creds,samdb=self.samdb_loc)

        self.default_basedn = self.samdb_loc.get_default_basedn()
        self.basedn = [str(self.default_basedn)]

        if basedn:
            if type(basedn) == list :
                self.basedn = basedn 
            else:
                self.basedn = [bdn.strip() for bdn in basedn.split('|')]

        self.basedn_user = self.basedn
        if basedn_user:
            if type(basedn_user) == list :
                self.basedn_user = basedn_user
            else:
                self.basedn_user = [bdn.strip() for bdn in basedn_user.split('|')]

        self.basedn_group = self.basedn
        if basedn_group:
            if type(basedn_group) == list :
                self.basedn_group = basedn_group
            else:
                self.basedn_group = [bdn.strip() for bdn in basedn_group.split('|')]

        self.basedn_computer = self.basedn
        if basedn_computer:
            if type(basedn_computer) == list :
                self.basedn_computer = basedn_computer
            else:
                self.basedn_computer = [bdn.strip() for bdn in basedn_computer.split('|')]

        self.custom_filter_computer = ''
        if custom_filter_computer:
            self.custom_filter_computer = custom_filter_computer

        self.custom_filter_user = ''
        if custom_filter_user:
            self.custom_filter_user = custom_filter_user

        self.custom_filter_group = ''
        if custom_filter_group:
            self.custom_filter_group = custom_filter_group


        self.dict_all_users_samba={}
        self.dict_all_device_samba={}
        self.all_dn={}
        self.dict_id_hash = {}
        self.SourceAnchorAttr = SourceAnchorAttr

        self.dry_run=True
        self.write_msDSConsistencyGuid_if_empty = None
        self.use_msDSConsistencyGuid_if_exist = None
        self.add_device= False

    def check_service_connection_point_existe(self):
        configurationdn =  str(self.samdb_loc.get_config_basedn())
        return  bool(self.samdb_loc.search(base=configurationdn,expression='(&(cn=62a0ff2e-97b9-4513-943f-0d221bd30080)(objectClass=serviceConnectionPoint))'))

    def azure_ad_sso_user_expire(self):
        for u in self.samdb_loc.search(base=self.samdb_loc.get_default_basedn(),expression='(servicePrincipalName=HOST/autologon.microsoftazuread-sso.com)'):
            pwd_last_set_timestamp = int(u['pwdLastSet'][0])
            if pwd_last_set_timestamp == 0:
                return True
            pwd_last_set_date = datetime.datetime(1601, 1, 1) + datetime.timedelta(seconds=pwd_last_set_timestamp // 10**7)
            return pwd_last_set_date < datetime.datetime.utcnow() - datetime.timedelta(days=30)

    def azure_ad_sso_user_exist(self):
        return bool(self.samdb_loc.search(base=self.samdb_loc.get_default_basedn(),expression='(servicePrincipalName=HOST/autologon.microsoftazuread-sso.com)'))

    def create_azureadssoacc(self,computername='azureadssoacc'):
        self.samdb_loc.newcomputer(computername,service_principal_name_list=["HOST/aadg.windows.net.nsatc.net","HOST/autologon.microsoftazuread-sso.com"])

    def set_password_azureadssoacc(self,password=None,computername='azureadssoacc'):
        self.samdb_loc.setpassword(search_filter='(samAccountName=%s$)' % computername,password=password,force_change_at_next_login=False)

    def write_service_connection_point(self,tenant_id,azureadname):

        configurationdn =  str(self.samdb_loc.get_config_basedn())

        ldif_data = """dn: CN=Device Registration Configuration,CN=Services,%s
changetype: add
objectClass: container""" % configurationdn
        self.samdb_loc.modify_ldif(ldif_data)

        ldif_data = """dn: CN=62a0ff2e-97b9-4513-943f-0d221bd30080,CN=Device Registration Configuration,CN=Services,%s
changetype: add
objectClass: serviceConnectionPoint
keywords: azureADName:%s
keywords: azureADId:%s""" % (configurationdn,azureadname,tenant_id)

        self.samdb_loc.modify_ldif(ldif_data)

    def return_source_anchor(self,entry):

        sid = self.samdb_loc.schema_format_value("objectSID", entry["objectSID"][0]).decode('utf-8')

        if sid.startswith('S-1-5-32-'):
            return ""
        if int(sid.rsplit('-',)[-1]) < 1000:
            return ""

        if self.SourceAnchorAttr.lower() == "objectSID_str".lower():
            SourceAnchor = sid
        else:
            SourceAnchor = entry[self.SourceAnchorAttr][0]

        if type(SourceAnchor) == str:
            SourceAnchor = SourceAnchor.encode('utf-8')

        msDSConsistencyGuid = entry.get("ms-DS-ConsistencyGuid",[b''])[0]

        if self.use_msDSConsistencyGuid_if_exist:
            if msDSConsistencyGuid :
                SourceAnchor = msDSConsistencyGuid

        try:
            decode_SourceAnchor = SourceAnchor.decode('utf-8')
        except:
            decode_SourceAnchor= base64.b64encode(SourceAnchor).decode('utf-8')

        if self.write_msDSConsistencyGuid_if_empty:
            if not msDSConsistencyGuid :
                ldif_data = """dn: %s
changetype: modify
replace: ms-DS-ConsistencyGuid
ms-DS-ConsistencyGuid:: %s
""" % (entry['distinguishedName'][0].decode('utf-8'), base64.b64encode(SourceAnchor).decode('utf-8'))
                write_log_json_data('set_ms-DS-ConsistencyGuid',{'ms-DS-ConsistencyGuid':decode_SourceAnchor,'dn':entry['distinguishedName'][0].decode('utf-8')})
                if not self.dry_run:
                    self.samdb_loc.modify_ldif(ldif_data)

        return decode_SourceAnchor



    def generate_all_dict(self):
        self.dict_all_users_samba={}
        self.all_dn={}
        self.dict_id_hash = {}
        # Search all users

        result_user = []
        for bdn_user in self.basedn_user:
                result_user.extend(self.samdb_loc.search(base=bdn_user, expression=r"(&(objectClass=user)(!(objectClass=computer))%s)" % self.custom_filter_user))

        dict_mail_dn={}
        for user in result_user:

            # Update if password different in dict mail pwdlastset
            if self.user :
                account_attributes = self.account_reader.get_account_attributes(user['distinguishedName'][0].decode('utf-8'), decrypted=True)
                hashnt = self.account_reader.get_unicodePwd(account_attributes)
                if not hashnt :
                    hashnt = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
                else:
                    hashnt = hashnt.hex().upper()
            else:
                passwordattr = 'unicodePwd'
                password = self.samdb_loc.search(self.samdb_loc.get_default_basedn(),expression="(sAMAccountName=%s)" % str(user["sAMAccountName"]) ,scope=ldb.SCOPE_SUBTREE,attrs=[passwordattr])[0]
                if not passwordattr in password:
                    continue
                hashnt = password[passwordattr][0].hex().upper()

            SourceAnchor = self.return_source_anchor(user)
            dn = user['distinguishedName'][0].decode('utf-8')

            if int(user["userAccountControl"][0]) & UF_ACCOUNTDISABLE:
                enabled = False
            else:
                enabled = True

            if enabled :
                accountexpire = int(user['accountExpires'][0].decode('utf-8'))
                if not accountexpire in (0,9223372036854775807):
                    epoch_start = datetime.datetime(1601, 1, 1)
                    expiration_date = epoch_start + datetime.timedelta(microseconds=accountexpire // 10)
                    if expiration_date < datetime.datetime.utcnow():
                        enabled = False

            data = {
                       "SourceAnchor"               : SourceAnchor,
                       "accountEnabled"             : enabled,
                       "userPrincipalName"          : user.get(self.alternate_login_id_attr,[b''])[0].decode('utf-8'),
                       "onPremisesSamAccountName"   : user.get("sAMAccountName",[b''])[0].decode('utf-8'),
                       "onPremisesDistinguishedName": str(user["dn"]),
                       "dnsDomainName"              : self.domaine,
                       "manager"                    : self.return_source_anchor(self.samdb_loc.search(self.samdb_loc.get_default_basedn(),expression="(distinguishedName=%s)" % user.get("manager")[0].decode('utf-8'),attrs=[self.SourceAnchorAttr,'objectSID','distinguishedName','ms-DS-ConsistencyGuid'])[0]) if user.get("manager") else ''  ,
                       "displayName"                : user.get("displayName",[b''])[0].decode('utf-8'),
                       "onPremiseSecurityIdentifier": base64.b64encode(user["objectSid"][0]).decode('utf-8'),
                       "userCertificate"            : [base64.b64encode(c).decode('utf-8') for c in user.get("userCertificate",[])],
                       "givenName"                  : user.get("givenName",[b''])[0].decode('utf-8'),
                       "surname"                    : user.get("sn",[b''])[0].decode('utf-8'),
                       "commonName"                 : user.get("cn",[b''])[0].decode('utf-8'),
                       "physicalDeliveryOfficeName" : user.get("physicalDeliveryOfficeName",[b''])[0].decode('utf-8'),
                       "department"                 : user.get("department",[b''])[0].decode('utf-8'),
                       "employeeId"                 : user.get("employeeId",[b''])[0].decode('utf-8'),
                       "streetAddress"              : user.get("streetAddress",[b''])[0].decode('utf-8'),
                       "city"                       : user.get("city",[b''])[0].decode('utf-8'),
                       "state"                      : user.get("state",[b''])[0].decode('utf-8'),
                       "telephoneNumber"            : user.get("telephoneNumber",[b''])[0].decode('utf-8'),
                       "company"                    : user.get("company",[b''])[0].decode('utf-8'),
                       "employeeType"               : user.get("employeeType",[b''])[0].decode('utf-8'),
                       "facsimileTelephoneNumber"   : user.get("facsimileTelephoneNumber",[b''])[0].decode('utf-8'),
                       "mail"                       : user.get("mail",[b''])[0].decode('utf-8'),
                       "mobile"                     : user.get("mobile",[b''])[0].decode('utf-8'),
                       "title"                      : user.get("title",[b''])[0].decode('utf-8'),
                       "proxyAddresses"             : [p.decode('utf-8') for p in user.get("proxyAddresses",[])],
                       "usertype"                   : "User"
                   }

            if self.warning_duplicate_mail_value:
                for testmail in [self.alternate_login_id_attr,'mail','proxyAddresses']:
                    if not testmail in user:
                        continue
                    for v in user[testmail]:
                        m = v.decode('utf-8').lower().split(':')[-1].strip()
                        if not m :
                            continue
                        if not m in dict_mail_dn:
                            dict_mail_dn[m] = {dn:[]}
                        if not dn in dict_mail_dn[m]:
                            dict_mail_dn[m][dn] = []
                        dict_mail_dn[m][dn].append(testmail)
     
            if self.callback_calculated_user != None:
                data = self.callback_calculated_user(sambaobj=self.samdb_loc,entry=user,result=data)
                SourceAnchor = data['SourceAnchor']

            if not SourceAnchor:
                continue

            if not data:
                continue

            if self.callback_calculated_hashnt != None:
                hashnt = self.callback_calculated_hashnt(sambaobj=self.samdb_loc,entry=user,result=data,hashnt=hashnt)

            self.dict_id_hash[SourceAnchor]=hashnt

            self.all_dn[str(user["dn"])]=SourceAnchor
            self.dict_all_users_samba[SourceAnchor] = data

        for t in dict_mail_dn:
            if len(dict_mail_dn[t]) > 1:
                write_log_json_data('warning_duplicate_mail_value',{'mail':t,'list_conflicting_objects':dict_mail_dn[t]})

        if self.add_device:
            self.dict_all_device_samba={}

            result_computer = []
            for bdn_computer in self.basedn_computer:
                    result_computer.extend(self.samdb_loc.search(base=bdn_computer,  expression=r"(&(objectClass=computer)%s)" % self.custom_filter_computer))

            for device in result_computer:

                SourceAnchor = self.return_source_anchor(device)

                data = {
                            "SourceAnchor"               : SourceAnchor,
                            "onPremisesSamAccountName"   : device.get("sAMAccountName",[b''])[0].decode('utf-8'),
                            "onPremisesDistinguishedName": str(device["dn"]),
                            "dnsDomainName"              : self.domaine,
                            "displayName"                : device.get("sAMAccountName",[b''])[0].decode('utf-8').strip('$'),
                            "onPremiseSecurityIdentifier": base64.b64encode(device["objectSid"][0]).decode('utf-8'),
                            "userCertificate"            : [base64.b64encode(c).decode('utf-8') for c in device.get("userCertificate",[])],
                            "deviceTrustType"            : "ServerAd",
                            "deviceId"                   : base64.b64encode(device["objectGUID"][0]).decode('utf-8'),
                            "deviceOSType"               : device.get("operatingSystem",[b''])[0].decode('utf-8'),
                            "deviceOSVersion"            : device.get("operatingSystemVersion",[b''])[0].decode('utf-8'),
                            "usertype"                   : "Device"
                        }

                if self.callback_calculated_device != None:
                    data = self.callback_calculated_device(sambaobj=self.samdb_loc,entry=device,result=data)
                    SourceAnchor = data['SourceAnchor']

                if not data:
                    continue

                if not SourceAnchor:
                    continue

                self.all_dn[str(device["dn"])]=SourceAnchor
                self.dict_all_device_samba[SourceAnchor] = data            


        self.dict_all_group_samba = {}


        result_group = []
        for bdn_group in self.basedn_group:
                result_group.extend(self.samdb_loc.search(base=bdn_group, expression=r"(&(objectClass=group)%s)" % self.custom_filter_group))

        for group in result_group:

            SourceAnchor = self.return_source_anchor(group)

            data = {
                           "SourceAnchor"               : SourceAnchor,
                           "onPremisesSamAccountName"   : group.get("sAMAccountName",[b''])[0].decode('utf-8'),
                           "onPremisesDistinguishedName": str(group["dn"]),
                           "dnsDomainName"              : self.domaine,
                           "displayName"                : group.get("sAMAccountName",[b''])[0].decode('utf-8'),
                           "groupMembers"               : [str(m) for m in group.get('member',[])],
                           "SecurityEnabled"            : group.get("grouptype",[b''])[0].decode('utf-8') in ['-2147483644','-2147483640','-2147483646'],
                           "usertype"                   : "Group",
                           "mail"                       : group.get("mail",[b''])[0].decode('utf-8'),
                           "proxyAddresses"             : [p.decode('utf-8') for p in group.get("proxyAddresses",[])],
                           "Description"                : group.get("description",[b''])[0].decode('utf-8'),
                       }

            if self.callback_calculated_group != None:
                data = self.callback_calculated_group(sambaobj=self.samdb_loc,entry=group,result=data)
                SourceAnchor = data['SourceAnchor']

            if not data:
                continue

            if not SourceAnchor:
                continue

            self.all_dn[str(group["dn"])]=SourceAnchor
            self.dict_all_group_samba[SourceAnchor] = data

        for group in self.dict_all_group_samba:
            self.dict_all_group_samba[group]['groupMembers']=[self.all_dn[m] for m in self.dict_all_group_samba[group]['groupMembers'] if m in self.all_dn]
