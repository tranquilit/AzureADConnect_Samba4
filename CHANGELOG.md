# Changelog

## [2026-10-22]
- Switch Azure AD Sync (WCF Binary) to the Microsoft Entra AD Synchronization Service (`6bf85cfa-ac8a-4be5-b5de-425a0d0dc016`) using PFX-based application authentication, the `6bf85cfa-ac8a-4be5-b5de-425a0d0dc016/.default` scope, and `ADSynchronization.ReadWrite.All`; use Microsoft Graph application permissions for user/group reads.
- Add configurable `entra_aba_dir` (default: `/root/entra_aba`) for the PFX identity; support certificate rotation.
- Keep administrator tokens for DirSync and Seamless SSO in memory only; require interactive execution for SSO password renewal and log an error during unattended runs.

## [2025-08-31]
- Fix : Only log after successful action, add "data" in error log.

## [2025-03-23]
- Fix : https://github.com/sfonteneau/AADInternals_python/issues/12
- Fix maybe : https://github.com/sfonteneau/AADInternals_python/issues/11

## [2025-03-08]
- Add "Microsoft Entra seamless single sign-on" (https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sso-quick-start)
  For enable : add "enable_single_sign_on" params in conf file. Do not delete the machine account "azureadssoacc"
  Not properly tested yet, feedback appreciated

## [2025-01-06]
-  manager attribute support

## [2024-12-10]
- Expired user accounts are now automatically marked as disabled.
  This does not synchronize the attribute value but when the expiration date is reached the user will be disabled when starting the synchronization.

## [2024-11-15]
- [FIX] Not delete user if onPremisesImmutableId but no onPremisesSyncEnabled

## [2024-11-11]
- Added an email duplication detection feature in the userprincipalname and proxyaddresses mail fields.

## [2024-11-09]
- Add params verify, Useful when you have a firewall that performs SSL inspection, you can mention the firewall certificate in configuration file.

## [2024-11-02]
- When do_delete is active, the calls graph.windows.net (deprecated) have been replaced by graph.microsoft.com

## [2024-10-31]
- Remove password and mail for login, lib : switch to adal to msal
- Replace DIY cache, by official cache in msal

## [2024-08-29]
- Add attribut "mail" , "proxyaddress" and "description" sync for group 

## [2024-05-29]
- tenant_id is no strictly necessary in the configuration file because an API point allows it to be retrieved. (for facilitate initial setup)

## [2024-05-19]
- pathsamdb parameter was renamed to url
- The script can now run on a member machine (non-domain controller) see: https://github.com/sfonteneau/AzureADConnect_Samba4/blob/main/README.md#run-the-project-on-a-member-machine-non-domain-controller

## [2024-05-15]
- FIX "expireOn" delta calculation, this would generate an expired token error. "expireOn" is not in UTC...

## [2024-04-12]
- Improving code  : repair a broken import in samba 4.20

## [2024-02-26]
- The refresh token was never renewed, The problem should occur every 90 days. Also, now the refresh token is only used if the "expiresOn" date is reached.

## [2023-12-28]
- renaming callbacks, add callback_after_send_obj ,callback_after_send_hashnt and callback_end_synchro

## [2023-12-23]
- Python callback support, see https://github.com/sfonteneau/AzureADConnect_Samba4/blob/7115dfa9a1f7fea052e7a2d0f223536a6f93229b/README.md#use-python-callback-to-modify-the-calculated-result-of-the-script

## [2023-12-15]
- pathsmbconf and pathsamdb add in config file to be more flexible in the configuration

## [2023-12-08]
- Support multiple basedn, use "|" separator in conf file to define multiple basedn
- Add "custom_filter_user" , "custom_filter_group" , "custom_filter_computer" options. usage exemple :  custom_filter_user=(memberof:1.2.840.113556.1.4.1941:=CN=ccc,OU=Groupe,DC=mydomain,DC=lan)

## [2023-10-27]
- Fix aadinternals_python, replace aadsync_client_build "1.5.29.0" with "2.2.8.0", now "1.5.29.0" no longer works.

## [2023-10-05]
- Config "basedn_user", "basedn_group", "basedn_computer" add in azure.conf, if not defined the value equal to basedn. Allows you to finely define the organizational unit for each type of object.
- Improvement of "--service-mode" to avoid querying the Microsoft APIs too often, we now base ourselves on the local db after the first launch. Default interval now = 60s

## [2023-07-15]
- Improved logs, The output is now in json and out in /var/log/azure_ad_sync. customizable with "logfile" in config file. 
- Errors are now non-blocking but logged
- You can now run the script in service mode with "--service-mode" arg (for use with systemd). In this mode the synchronization interval is 600 seconds. You can change this value with "synchronization_interval_service" in the conf file.

## [2023-07-06]
- Multi-factor authentication support. 
  Use the old token to regenerate a new token. The tenant id is now required in conf file
  For the first run an external authentication and a copy paste will be necessary
- New available option in conf file : tenant_id, save_to_cache, use_cache , credential_cache_file

## [2023-06-18]
- add use_get_syncobjects in azure.conf by default = True (allows not to use the history of shipments given by microsoft but rather to rely on the local database to find the sourceanchoor. less reliable but useful if get_syncobjects fails. It would be so much easier if Microsoft gave the source anchor for groups and devices and not just users...)

## [2023-06-14]
- basedn option Add in azure.conf (for search in specific basedn in samba)
- alternate_login_id_attr option Add  in azure.conf (to set alternate attribute for login id (https://learn.microsoft.com/en-us/azure/active-directory/hybrid/connect/plan-connect-userprincipalname#alternate-login-id) for mapping on mail 

## [2023-05-13]
- Support for writing "CN=62a0ff2e-97b9-4513-943f-0d221bd30080,CN=Device Registration Configuration" in samba4
- Add azureadname config in azure.conf (use for write CN=Device Registration Configuration) 

## [2023-05-10]
- Add Device synchronization in sync (configuration in conf file)
- Force usertype in dict (restart a forced sync for users)
- Add onPremiseSecurityIdentifier and usercertificate for the user

## [2023-05-09]
- Add "do_delete" in the configuration file, if True, delete accounts with a "sourceanchor" online and not found in samba

## [2023-05-03]
- Switch from saving the last sendings of a json file to a sqlite database (restart of a forced synchronization)

## [2023-04-29]
- added backward compatibility of samba 4.13

## [2023-04-28]
- Added "hash_synchronization" option in the configuration file 

## [2023-04-27 - 2023-04-26]
switch to "microsoft azure ad connect" operating mode:
- Choice of sourceanchor in the configuration file
- objectGUID and ObjectSid are not decoded (byte) (convert to base64 when sending to azuread)
- possibility to use ms-ds-consistencyguid
- Added the possibility of a sourceanchor objectSID_str for backward compatibility with old version of the project.

## [2023-04-24]
- Added a pause when sending the password hash, otherwise too fast between account creation and password sending.
- Sending the group twice for nested groups, otherwise too fast between the creation of groups.

## [2023-04-21 - 2023-04-20]
- added "adsync" and "PasswordHashSync" enable (allows to run the script on an instance that has never seen "microsoft azure ad connect")

## [2023-02-02]
- Send only if data change, write last data send in json file
- Add attributes in the sync

## [2023-02-01]
- first working version, use obectsid decoded for sourceanchor
