# EnginFrame + EntraID + SSO

# General Flow

Suppose that your auth domain will be domain.com/auth and the sso php files will be in domain.com/sso

1. The user will enter in the domain.com/auth to start the authentication
2. The user will be redirected to Microsoft Entra ID login
3. The Entra ID will redirect the user to domain.com/sso/callback.php with the authorization code
4. The callback.php file will exchange the authorization code to the access token (flow ref: https://youtu.be/2RE6IhXfmHY?si=zvFZFAfNaa7fFlJh&t=123 )
5. With the accessToken, secure_page.php will be called to start EnginFrame login procedure
6. The EnginFrame will receive the login and password sent by secure_page.php. The login will be the credentials that you configured. By default is the ID of Entra ID user. The password will be the Entra ID Access Token.
7. Using the ef.auth file from EnginFrame pam plugin, EnginFrame will validate the login (when _result =0) and map the user according ef.user.mapping script. This validation can happen in two ways: Just accepting the mapped user ("custom" auth type) or doing one more Entra ID call to validate the Access Token ("entraidtoken" auth type). The "entraidtoken" option is the default one and we recommend that option.
8. If the credentials are validated and if ef.user.mapping can map the user, EnginFrame will open the dashboard home.

# To setup EnginFrame with Entra ID

## Requirements

- Apache 2.4.37+
- Apache2 modules: php, mod_auth_openidc, mod_ssl, mod_json and mod_proxy_html
- PHP 7.2+ or 8.0+
- SSL Certificates

Notes:
- It is recommended to use some Linux distro that is not close to End of Life date
- It is recommended to use PHP 8.0+ version; 7.2+ will work, but there is no official security updates anymore

## (1) Replace the ##*## strings

This step was created to make easier to configure all files editing just one file and executing one script. You can also replace everything manually.

In the file replacements.txt you will find all strings that you need to replace for real values. Copy this file as replacements_custom.txt and replace all data. The string to be replaced and the real value is separated by a space, one per line. For example: ##STRINGTOBECHANGED## MYNEWSTRING or ##MYURL## mydomain.com

The script replace_strings.sh will read replacements_custom.txt and execute it in all files that need customization. Execute the script when replacements_custom.txt is done.

If you did something wrong in replacements_custom.txt, please  reset the git to the last commit:

```bash
git reset --hard HEAD^
```

Fix what was wrong in the replacements_custom.txt and execute the script again to replace all strings. The git reset will not remove your replacements_custom.txt.

Here are the strings descriptions that you have to replace:
- ##ADMINEMAIL## : The apache2 sysadmin email
- ##HOSTNAME## : The domain that will be used to setup this integration. Example: subdomain.domain.com (without http/https syntax; https is mandatory and will be automatically added)
- ##YOURTENANTID## : Tenant ID to access your Entra ID Directory
- ##YOURAPPID## : The App Client ID (created in Microsoft Entra ID center)
- ##YOURAPPSECRET## : The App Secret (created in Microsoft Entra ID center)
- ##YOURAPPCLIENTVALUE## : The App Value (not Secret ID)
- ##SSOLOGIN## : If you want the users doing the login in subdomain.domain.com/auth, replace with "auth", without the double quotes. Example: auth
- ##PHPCALLBACKPATH## : The path of the php files. Example: if is "sso", then the callback.php file will be in subdomain.domain.com/sso/callback.php. Examples: sso or sso/api or api. Do not add the "/" in the end. If you add, the script will remove.
- ##EFENDPOINT## : the EnginFrame endpoint. Examples: subdomain.domain.com:8443, subdomain.domain.com etc; Do not add http/https, https is mandatory and will be automatically added
- ##AUTHTYPE## : Options: entraidtoken or custom. "entraidtoken" means that the EnginFrame password will be the Entra ID Token, which will be validated (again) by EnginFrame. "custom" means that both user and password will be checked in the same way (PAM, LDAP etc).

Notes:
- The ##SSOLOGIN## (used for entra id auth) needs to be different of ##PHPCALLBACKPATH##, so make sure of that to avoid problems
- The replacements.txt file already come with one example per string
- Make sure that ##EFENDPOINT## has a valid certificate, or you will have problems with EnginFrame login; If you intend to use self signed certificate, use the Apache subdomain configured to do ProxyPass to your EnginFrame (check your apache conf file)

## (2) Apache setup

Currently just Apache is supported. The Apache needs to have installed:
- libphp (7.4+)
- mod_auth_openidc (RedHat Linux distro based) or libapache2-mod-auth-openid (Debian Linux distro based)

1. Install and start the Apache service with PHP 7.4+ (required)
2. Copy the files config_files/entraid-ssl.conf to /etc/httpd/conf.d/ Apache directory.
3. Edit the copied entraid-ssl.conf file and check if ProxyPass and ProxyPassReverse are correctly pointing to EnginFrame endpoint
4. Set chmod 640 for entraid-ssl.conf
5. Restart the Apache service

Notes:
- Double check the right SSL config for SSLCertificateFile and SSLCertificateKeyFile
- Check if entraid-ssl.conf can source options-ssl-apache.conf

## (3) Setup the PHP files

There are some php files that you need to setup.

1. Enter in the directory that you want to setup the php files. Suppose that will be /var/www/html/sso/.
2. Copy the files scripts/php/* to the same directory.

## (4) Configure EnginFrame settings

1. Edit the server.conf file (/opt/DIR/enginframe/DIR/enginframe/conf/server.conf) to set this config:
```bash
ef.filter.csrf.tokenCheck=false
ef.filter.csrf.allowAccessWithNoOrigin=true
ef.filter.csrf.targetOrigins=https://subdomain.domain.com:8443, https://subdomain.domain.com
```

2. Edit the ef.auth.conf (/opt/*/enginframe/*/enginframe/plugins/pam/conf/ef.auth.conf) to set this config:
```bash
EFAUTH_USERMAPPING="true"
```

## (5) Replace the EnginFrame ef.auth file

Copy the file config_file/ef.auth to replace your working ef.auth file.

The ef.auth path will be something like this: /opt/nisp/enginframe/2024.0-r1705/enginframe/plugins/pam/bin/ef.auth

1. Do the backup:
```bash
cp /opt/nisp/enginframe/2024.0-r1705/enginframe/plugins/pam/bin/ef.auth /opt/nisp/enginframe/2024.0-r1705/enginframe/plugins/pam/bin/ef.auth-original
```
2. Replace:
```bash
cp -f config_file/ef.auth /opt/nisp/enginframe/2024.0-r1705/enginframe/plugins/pam/bin/ef.auth
chmod 640 /opt/nisp/enginframe/2024.0-r1705/enginframe/plugins/pam/bin/ef.auth
```

## (6) Create the Microsoft Entra ID App

1. Enter in the Microsoft Entra ID center dashboard
2. Click in Applications
3. Click in App registrations
4. Click in New registration
5. Fill the name
6. Select the account type; If you do not know, select the "Accounts in this organizational directory only (Default Directory only - Single tenant)"
7. Fill the Redirect UI with Web dropdown option and write your URI (example: https://subdomain.domain.com/sso/callback.php)
8. Click in Register
9. Now click in API permissions and click in "Grant admin consent for Default Directory"
10. Now click in App roles and then in Create App Role
11. Fill with a Name, select Applications, as Value set "User.Read" without double quotes and write some description. Click in Apply.
12. Finally, click in "Certificates & secrets" and then "New client secret".
13. Fill the form and click in add.
14. Save the "Value", this is your Secret Value and will appear just one time in the Microsoft Entra ID dashboard. The secret copy can be viewed anytime. 

Now you have an APP and the credentials to access Entra ID Directory, so you are able to fill all replacements_custom.txt string.

## (7) Mapping the users

You need to create a file called ef.user.mapping that usually is stored in a path like this: /opt/nisp/enginframe/2024.0-r1705/enginframe/plugins/pam/bin/ef.user.mapping

Here is one example of user mapping
:
```bash
#!/bin/bash

case "$1" in
    "francisco@mydomain.com")
        echo "francisco"
        ;;
    "fran@mydomain.com')
        echo "fran"
        ;;
    *)
        echo "efadmin"
esac
```

If you want map every user for a specific user, just build your bash logic in this file. If you want to map everyone to one user, you can just do:

```bash
echo "efadmin"
```

Important: Make sure the file has root:root with execution permissions.

## (8) Edit secure_page.php to send the right User info

In the step 8 you did a script that will map the Entra ID information to a Linux user. In the secure_page.php you need to set which Entra ID information do you want to sent to EnginFrame. Please open the file and check the ef_user variable. By default, we send the userInfo['id'] from Entra ID, but you can change that in the code.

If you want to list all user info, edit the secure_page.php file and uncomment the below lines.

```bash
//echo "<pre>";
//print_r($userInfo);
//die();;
```
and then do the auth again to see all info that you can use to send to EnginFrame as login. You can do the same thing for User Claims (check userClaims variable). The logic will be the same.

# Issues and resolutions

### Token not found
The secure_page.php can not get the CSRF Token from EnginFrame interface. Open the secure_page.php file and check if the EnginFrame endpoint URLs are correct. You nee to replace all URLs with correct EnginFrame URL.

### callback.php 500 error

- 500 internal server error means some resource being denied. Can be apache module, php library, php curl failing to call Entra ID service or wrong file permissions
- Please check if you have all apache modules: php, php-curl, php-json, openidc, proxy and ssl.
- Add the code below after php tag to debug:
```bash
error_reporting(E_ALL);
ini_set('display_errors', 1);
```

And set
```bash
die();
```

where you want to stop in the code.

### EnginFrame wrong credentials

You need to check in secure_page.php if you are sending the right user (check ef_user variable) to EnfinFrame user mapping script. You can uncomment the debug line in ef.auth script and check in the /tmp what is coming to EnginFrame as user.

### Apache DNS lookup failure

You have more than one apache config file listening the /auth. Please make sure that you have just one.

### callback.php is being redirected to index.php file

This happens when callback did not receive any Authorization Code from Microsoft Entra ID. You need to add User.Read permissions into App roles in the Microsoft Entra ID dashboard.

### Some users can login into EnginFrame, but some of them, not

- You need to review your ef.user.mapping script to check if all users are being mapped as expected
- If you are seeing some permission denied to request the Authorization Code, maybe your user is not allowed to use the App that you created in the Microsoft Entra ID
