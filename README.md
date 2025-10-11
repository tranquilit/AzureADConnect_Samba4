# Notes

If you use this script and it works correctly - please do not be lazy to put a star. This motivates me very much to develop my product. If you lack some functions, write about it. I will try to add them if they fit into the product concept.

# Install notes

```
apt-get install git
git clone --recurse-submodules https://github.com/tranquilit/AzureADConnect_Samba4.git /opt/sync-azure
mkdir /etc/azureconf/
cp -f /opt/sync-azure/azure.conf.exemple /etc/azureconf/azure.conf
apt-get install python3-peewee python3-passlib python3-xmltodict python3-requests python3-msal -y
```


If you are not under debian or if you do not have the packages available :

```
apt-get install python3-pip
pip3 install -r /opt/sync-azure/requirements.txt
pip3 install -r /opt/sync-azure/AADInternals_python/requirements.txt
```

 - Configure /etc/azureconf/azure.conf

You can try like this:

```
python3 /opt/sync-azure/run_sync.py
```

The script sends all users and groups a first time and then only sends what has been modified since the last send during the next launch. (delta)

To force a send from all again, use --force (force sync) :

```
python3 /opt/sync-azure/run_sync.py --force
```

&#x1F4A1; Once your first full sync has taken place, it's worth changing this setting to True to make the script run much faster. 
This makes it possible to calculate deletions based on the last send and therefore no longer query Microsoft servers at each launch.

```
calculate_deletions_based_on_last_sync=True
```

# Warning

* Please note that this project uses Microsoft APIs not officially documented. Microsoft may break compatibility at any time

* userPrincipalName is used for the email address (add alternate_login_id_attr=mail in azure.conf to use the mail attribute instead of the userPrincipalName attribute ) [1]

* "password writeback" not supported

* User and group management only (device optional)

[1] https://learn.microsoft.com/en-us/azure/active-directory/hybrid/connect/plan-connect-userprincipalname#alternate-login-id

# sourceanchor

The default sourceanchor in azure.conf.exemple is the objectGUID with msDSConsistencyGuid! read : https://learn.microsoft.com/en-us/azure/active-directory/hybrid/plan-connect-design-concepts#using-ms-ds-consistencyguid-as-sourceanchor

You can run the script on a previous installation but you have to pay attention to the previous configuration of your azure ad connect (sourceanchor)

> **&#x26A0;&#xFE0F;Warning**
> If "sourceanchor" changes, it will initiate object deletions and then object recreations. You must therefore choose your sourceanchor well and not change it

A dry_run mode allows you to run the script without making any changes

# advanced configuration

## using specific basedn

You can specify a specific basedn for search in samba:

```
basedn = OU=TEST,DC=MYDOMAIN,DC=LAN
```

OR a base dn for each type of object:

```
basedn_user     = OU=USER,DC=MYDOMAIN,DC=LAN
basedn_group    = OU=GROUP,DC=MYDOMAIN,DC=LAN
basedn_computer = OU=COMPUTER,DC=MYDOMAIN,DC=LAN
```

For precisely several bases dn, separate them with | 

```
basedn_user     = OU=USER,DC=MYDOMAIN,DC=LAN|OU=USER2,DC=MYDOMAIN,DC=LAN
```

## custom filter for search

You can specify a specific custom ldap filter for search in samba:

```
custom_filter_user     = (memberof:1.2.840.113556.1.4.1941:=CN=group_users,OU=Groupe,DC=mydomain,DC=lan)
custom_filter_group    = (memberof:1.2.840.113556.1.4.1941:=CN=group_groups,OU=Groupe,DC=mydomain,DC=lan)
custom_filter_computer = (memberof:1.2.840.113556.1.4.1941:=CN=group_computers,OU=Groupe,DC=mydomain,DC=lan)
```

## Do not use userPrincipalName as login

You can specify which attribute should be used as login. Please note this must be an email address. Use alternate_login_id_attr


```
alternate_login_id_attr = mail
```

Mode not recommended, it will cause problems with sso mode because the email is not a login in the kerberos sense.

## other settings

* credential_cache_file :


specifies where the last connection token will be stored and read:

```
credential_cache_file = /root/last_token.json
```

* dbpath :


specifies where the db that stores the state of the last scan will be stored:

```
dbpath = /root/last_send_azuread.db
```

* calculate_deletions_based_on_last_sync :

calculate deletions based on local last sync, does not list the users, groups and devices of the Azure AD to calculate the necessary deletion and will make the comparison with the last send of the script. Much faster mode 

```
calculate_deletions_based_on_last_sync=True
```

## Samba configuration

You can add pathsmbconf and url parameters in the configuration file. 
If you are using a samba version of the distribution this should not be necessary.

```
url         = /usr/local/samba/private/sam.ldb
pathsmbconf = /usr/local/samba/lib/smb.conf
```

## Use Python callback to modify the calculated result of the script

Copy callback_template:

```
cp -r /opt/sync-azure/callback_template /root/callbackaad
```

add option in config file : 

```
folder_callback_python = /root/callbackaad
```

Now edit /root/callbackaad/callbackaadsync.py (do not change the file name)

Exemple: 

```
def callback_calculated_user(sambaobj=None,entry=None,result=None):
    result['company'] = "MY ENTERPRISE"
    return result
```

In this example we force the company entry "MY ENTERPRISE" on all user entries

- sambaobj is the already instantiated samdb object, it can be used to do searches

- Entry is user entry returned by samdb

- result is resultcalculated by the script so you can modify it

The function returns the result modify, if the function returns None, the user will be skipped from the sync

## Use Python callback to run code after sending

In certain cases we want to execute code in addition to sending it to Azure AD

Exemple: Send an email, Enter something into a database, Perform additional actions in Azure AD.

In this case you can use: callback_after_send_obj and callback_after_send_hashnt

A final callback is called at the end of the sync with callback_end_synchro

## Run the project on a member machine (non-domain controller)

The machine must have samba installed. (Many samba libraries are required)

Add in azure.conf add :

```
url=ldap://srvads.ad.lan:389
user_ad=administrator
password_ad=password
```
The specified account must have permission to replicate passwords.

This operating mode also works with a Microsoft active directory.


# compatibility


The first version of this project used the "objectsid" string as "sourceanchor", this mode now corresponds to an "objectSID_str" as sourceanchor in the ini file, this mode does not exist with azure ad microsoft, so it should no longer be used.

# Frequent problems and questions

## Access to Azure Active Directory has been denied

If the script crashes with this message:

```
  File "/opt/sync-azure/AADInternals_python/AADInternals.py", line 596, in xml_to_result
    raise Exception(dataxml["s:Envelope"]["s:Body"]['s:Fault']['s:Reason']['s:Text']['#text'])
Exception: Access to Azure Active Directory has been denied. Contact Technical Support.

```

It appears that the user you authenticated with does not have the rights to perform the requested actions.

You can change user by deleting the /root/last_token_azuread.json file and running the script again.

## Log parsing

The logs are stored in JSON format and, by default, they are stored here: /var/log/azure_ad_sync.

You can, for example, parse them with jq:

```
cat /var/log/azure_ad_sync | jq 'select(.type == "send_nthash") |  .timestamp, .data.onPremisesSamAccountName '
```

```
cat /var/log/azure_ad_sync | jq 'select(.data.onPremisesSamAccountName == "luke.skywalker") '
```

```
cat /var/log/azure_ad_sync | jq 'select(.data.onPremisesSamAccountName == "luke.skywalker") |  .timestamp, .type '
```


## SSLError (SSLCertVerificationError)

If the script crashes with this message:

```
SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:992)')
```

Certainly you have a firewall that performs SSL inspection.

Add in azure.conf : 

```
verify=/root/ca.crt
```

/root/ca.crt is the firewall certificate


## Duplicate Attribute resiliency 

You can sometimes with this kind of message:

```
INFO:root:{"type": "warning_duplicate_mail_value", "timestamp": "2024-11-11 14:31:04.764566", "data": {"mail": "chewbacca@testoutlook.mail.onmicrosoft.com", "list_conflicting_objects": {"CN=chewie,CN=Users,DC=mydomain,DC=lan": ["proxyAddresses"], "CN=chewbacca,CN=Users,DC=mydomain,DC=lan": ["userPrincipalName"]}}}
```

or 

```
This object has been updated in your Azure Active Directory, but with some modified properties, because the following attributes are associated with another object [ProxyAddresses <pii>SMTP:chewie@testoutlook.mail.onmicrosoft.com</pii>;]. Please refer to https://aka.ms/duplicateattributeresiliency for steps on how to resolve this issue.
```

This means that two different accounts have the same email address.

In Active directory : Either by the userPrincipalName attribute, by email or by the proxyAddresses attribute

Sometimes the duplicate is in your active directory and you can identify duplicate objects with "warning_duplicate_mail_value" in logs.

If the duplicate is not in your active directory this means that the duplicate is present in "entra id" with an account not synchronized with the active directory.

When you have resolved the conflicts it may sometimes be necessary to force a synchronization with:

```
python3 /opt/sync-azure/run_sync.py --force
```

## When you have an existing tenant

The explanation here applies to this project :

https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-install-existing-tenant

### Case Azure Administrator Sync

Synchronization does not work with an "entra id" administrator account :

see: https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-install-existing-tenant#admin-role-considerations

* Remove administrator rights from the account in Azure.
* Start synchronization
* The account should now go to “local sync enabled”
* You can now restore the rights previously removed
* The account is now recognized as a synchronized local account, synchronization works again.

