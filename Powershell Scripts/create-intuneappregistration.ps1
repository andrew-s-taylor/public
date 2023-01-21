<#PSScriptInfo
.VERSION 2.0.0
.GUID 43e38b3f-984a-456c-aff0-129d869514a3
.AUTHOR AndrewTaylor
.DESCRIPTION Creates an app registration for Graph, AzureAD and Conditional Access and outputs details to CSV
.COMPANYNAME 
.COPYRIGHT GPL
.TAGS intune endpoint MEM environment
.LICENSEURI https://github.com/andrew-s-taylor/public/blob/main/LICENSE
.PROJECTURI https://github.com/andrew-s-taylor/public
.ICONURI 
.EXTERNALMODULEDEPENDENCIES azuread
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
#>
<#
.SYNOPSIS
  Builds an App Registration for Intune
.DESCRIPTION
.DESCRIPTION Creates an app registration for Graph, AzureAD and Conditional Access and outputs details to CSV

.INPUTS
None required
.OUTPUTS
Within Azure
.NOTES
  Version:        2.0.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  05/06/2022
  Modified Date:  31/10/2022
  Purpose/Change: Initial script development
  Added logic to check Powershell version and warn if not at least 6.1
  Change:         Switched from AAD module to Microsoft Graph module
  
.EXAMPLE
N/A
#>

##Check Powershell version
$PSVersion = $PSVersionTable.PSVersion

#If version is less than 6.1, throw an error and stop execution of the script
if ($PSVersion -lt 6.1) {
    Throw "You need to be running Powershell 6.1 or above for this to complete, please upgrade"
}

Write-Host "Installing Microsoft Graph modules if required (current user scope)"

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph) {
    Write-Host "Microsoft Graph Already Installed"
} 
else {
    try {
        Install-Module -Name Microsoft.Graph -Scope CurrentUser -Repository PSGallery -Force 
    }
    catch [Exception] {
        $_.message 
        exit
    }
}


# Load the Graph module
Import-Module microsoft.graph

#Connect to Graph
Select-MgProfile -Name Beta
Connect-MgGraph -Scopes  	RoleAssignmentSchedule.ReadWrite.Directory, Domain.Read.All, Domain.ReadWrite.All, Directory.Read.All, Policy.ReadWrite.ConditionalAccess, DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, openid, profile, email, offline_access




Function Get-ScriptVersion(){
    
    <#
    .SYNOPSIS
    This function is used to check if the running script is the latest version
    .DESCRIPTION
    This function checks GitHub and compares the 'live' version with the one running
    .EXAMPLE
    Get-ScriptVersion
    Returns a warning and URL if outdated
    .NOTES
    NAME: Get-ScriptVersion
    #>
    
    [cmdletbinding()]
    
    param
    (
        $liveuri
    )
$contentheaderraw = (Invoke-WebRequest -Uri $liveuri -Method Get)
$contentheader = $contentheaderraw.Content.Split([Environment]::NewLine)
$liveversion = (($contentheader | Select-String 'Version:') -replace '[^0-9.]','') | Select-Object -First 1
$currentversion = ((Get-Content -Path $PSCommandPath | Select-String -Pattern "Version: *") -replace '[^0-9.]','') | Select-Object -First 1
if ($liveversion -ne $currentversion) {
write-warning "Script has been updated, please download the latest version from $liveuri"
}
}
Get-ScriptVersion -liveuri "https://raw.githubusercontent.com/andrew-s-taylor/public/main/Powershell%20Scripts/create-intuneappregistration.ps1"


function New-RandomPassword {
  param(
      [Parameter()]
      [int]$MinimumPasswordLength = 5,
      [Parameter()]
      [int]$MaximumPasswordLength = 10,
      [Parameter()]
      [int]$NumberOfAlphaNumericCharacters = 5,
      [Parameter()]
      [switch]$ConvertToSecureString
  )
  
  Add-Type -AssemblyName 'System.Web'
  $length = Get-Random -Minimum $MinimumPasswordLength -Maximum $MaximumPasswordLength
  $password = [System.Web.Security.Membership]::GeneratePassword($length,$NumberOfAlphaNumericCharacters)
  if ($ConvertToSecureString.IsPresent) {
      ConvertTo-SecureString -String $password -AsPlainText -Force
  } else {
      $password
  }
}



write-host "Getting Azure Tenant Details"
##Get Tenant Details
##Grab Tenant ID
##Get Tenant Details
##Grab Tenant ID
$domain = get-mgdomain | where-object IsDefault -eq $true

$suffix = $domain.Id
$uri = "https://graph.microsoft.com/beta/organization"
$tenantdetails = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
$tenantid = $tenantdetails.id
write-host "Tenant Domain: $suffix"
$tenantid = $tenantdetails.ObjectID
write-host "Tenant ID: $tenantid"

#Create Application
write-host "Creating Application"
$AppDisplayName = "Intune App Registration"
$aadApplication = New-MgApplication -DisplayName $AppDisplayName
write-host "Application Created"
##MS Graph Permissions
	
#Get Service Principal of Microsoft Graph Resource API 
$graphSP =  Get-MgServicePrincipal -All $true | Where-Object {$_.DisplayName -eq "Microsoft Graph"}
 
#Initialize RequiredResourceAccess for Microsoft Graph Resource API 
$requiredGraphAccess = New-Object Microsoft.Open.AzureAD.Model.RequiredResourceAccess
$requiredGraphAccess.ResourceAppId = $graphSP.AppId
$requiredGraphAccess.ResourceAccess = New-Object System.Collections.Generic.List[Microsoft.Open.AzureAD.Model.ResourceAccess]
 
#Set Application Permissions
#All Intune
#Conditional Access
#AzureAD Users and Groups
#PIM
$ApplicationPermissions = @('AppCatalog.ReadWrite.All','Application.ReadWrite.All','BitlockerKey.Read.All','DeviceManagementApps.ReadWrite.All','DeviceManagementConfiguration.ReadWrite.All','DeviceManagementManagedDevices.ReadWrite.All','DeviceManagementServiceConfig.ReadWrite.All','WindowsUpdates.ReadWrite.All','Policy.ReadWrite.ConditionalAccess','User.ReadWrite.All','Group.ReadWrite.All','GroupMember.ReadWrite.All','PrivilegedAccess.ReadWrite.AzureAD','PrivilegedAccess.ReadWrite.AzureADGroup','PrivilegedAccess.ReadWrite.AzureResources')
 
#Add app permissions
ForEach ($permission in $ApplicationPermissions) {
$reqPermission = $null
#Get required app permission
$reqPermission = $graphSP.AppRoles | Where-Object {$_.Value -eq $permission}
if($reqPermission)
{
$resourceAccess = New-Object Microsoft.Open.AzureAD.Model.ResourceAccess
$resourceAccess.Type = "Role"
$resourceAccess.Id = $reqPermission.Id    
#Add required app permission
$requiredGraphAccess.ResourceAccess.Add($resourceAccess)
}
else
{
Write-Host "App permission $permission not found in the Graph Resource API" -ForegroundColor Red
}
}
 
#Set Delegated Permissions
$DelegatedPermissions = @('User.Read.All', 'Directory.Read.All') #Leave it as empty array if not required
 
#Add delegated permissions
ForEach ($permission in $DelegatedPermissions) {
$reqPermission = $null
#Get required delegated permission
$reqPermission = $graphSP.Oauth2Permissions | Where-Object {$_.Value -eq $permission}
if($reqPermission)
{
$resourceAccess = New-Object Microsoft.Open.AzureAD.Model.ResourceAccess
$resourceAccess.Type = "Scope"
$resourceAccess.Id = $reqPermission.Id    
#Add required delegated permission
$requiredGraphAccess.ResourceAccess.Add($resourceAccess)
}
else
{
Write-Host "Delegated permission $permission not found in the Graph Resource API" -ForegroundColor Red
}
}
 
#Add required resource accesses
$requiredResourcesAccess = New-Object System.Collections.Generic.List[Microsoft.Open.AzureAD.Model.RequiredResourceAccess]
$requiredResourcesAccess.Add($requiredGraphAccess)
 
#Set permissions in existing Azure AD App
$appObjectId=$aadApplication.ObjectId
Update-MgApplication -ApplicationId $appObjectId -RequiredResourceAccess $requiredResourcesAccess

write-host "Application Permissions Set"

##Create the Secret
write-host "Creating Secret"
$appObjectId=$aadApplication.ObjectId
$passwordCred = @{
    displayName = 'AppAccessKey'
    endDateTime = (Get-Date).AddYears(2)
 }
 
$appPassword = Add-MgApplicationPassword -ApplicationId $appObjectId -PasswordCredential $passwordCred
$appsecret = $appPassword.Value #Display app secret key
write-host "Secret Created"

##Create Enterprise App
write-host "Creating Enterprise App"
$appId=$aadApplication.AppId
$servicePrincipal = New-MgServicePrincipal -AppId $appId -Tags @("WindowsAzureActiveDirectoryIntegratedApp")
write-host "Enterprise App Created"

##Grant App Permissions
write-host "Granting App Permissions"
ForEach ($resourceAppAccess in $requiredResourcesAccess)
{
$resourceApp = Get-MgServicePrincipal -All $true | Where-Object {$_.AppId -eq $resourceAppAccess.ResourceAppId}
ForEach ($permission in $resourceAppAccess.ResourceAccess)
{
if ($permission.Type -eq "Role")
{
    $servicePrincipalId = $servicePrincipal.ObjectId
    $resourceID = $resourceApp.ObjectId
    $approleid = $permission.Id
    $params = @{
        PrincipalId = $servicePrincipalId
        ResourceId = $resourceID
        AppRoleId = $approleid
    }
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $servicePrincipalId -BodyParameter $params
}
}
}
write-host "App Permissions Granted"


##Grant Delegated Permissions
write-host "Granting Delegated Permissions"
      
# Azure AD PowerShell client id. 
$ClientId = "1950a258-227b-4e31-a9cf-717495945fc2"
$RedirectUri = "urn:ietf:wg:oauth:2.0:oob"
$resourceURI = "https://graph.microsoft.com"
$authority = "https://login.microsoftonline.com/common"
$authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority     
 
# Get token by prompting login window.
$platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Always"
$authResult = $authContext.AcquireTokenAsync($resourceURI, $ClientID, $RedirectUri, $platformParameters)
$accessToken = $authResult.Result.AccessToken

$GrantConsnetForAllUsers=$true #Set $true to give consent for all users and set $false to give consent for individual user
if ($GrantConsnetForAllUsers) {
#Grant consent for all users
$consentType = "AllPrincipals"
$principalId = $null
} else {
#Grant consent for the required user alone
$consentType = "Principal"
#Get or provide object id for the required Azure AD user
$principalId = (Get-MgUser -SearchString "user@contoso.com").ObjectId
#$principalId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}
 
ForEach ($resourceAppAccess in $requiredResourcesAccess)
{
$delegatedPermissions = @()
#$resourceApp - get servicePrincipal of Resource API App(ex: Microsoft Graph, Office 365 SharePoint Online)
$resourceApp = Get-MgServicePrincipal -All $true | Where-Object {$_.AppId -eq $resourceAppAccess.ResourceAppId}
ForEach ($permission in $resourceAppAccess.ResourceAccess)
{
if ($permission.Type -eq "Scope")
{
$permissionObj = $resourceApp.OAuth2Permissions | Where-Object {$_.Id -contains $permission.Id}
$delegatedPermissions += $permissionObj.Value
}
}
 
if($delegatedPermissions)
{
#Get existing grant entry
$existingGrant = Get-MgOauth2PermissionGrant -All $true | Where-Object { $_.ClientId -eq $servicePrincipal.ObjectId -and $_.ResourceId -eq $resourceApp.ObjectId -and  $_.PrincipalId -eq $principalId}
 
if(!$existingGrant){
#Create new grant entry
$postContent = @{
clientId = $servicePrincipal.ObjectId
consentType = $consentType
principalId = $principalId
resourceId  = $resourceApp.ObjectId
scope       = $delegatedPermissions -Join " "
}
 
$requestBody = $postContent | ConvertTo-Json
Write-Host "Grant consent for $delegatedPermissions ($($resourceApp.DisplayName))" -ForegroundColor Green
$headers = @{Authorization = "Bearer $accessToken"}
$response = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" -Body $requestBody -Method POST -ContentType "application/json"
 
} else {
#Update existing grant entry
$delegatedPermissions+=$existingGrant.Scope -Split " "
$delegatedPermissions = $delegatedPermissions | Select -Unique
$patchContent = @{
scope       = $delegatedPermissions -Join " "
}
 
$requestBody = $patchContent | ConvertTo-Json
Write-Host "Update consent for $delegatedPermissions ($($resourceApp.DisplayName))" -ForegroundColor Green
$headers = @{Authorization = "Bearer $accessToken"}
$response = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/$($existingGrant.ObjectId)" -Body $requestBody -Method PATCH -ContentType "application/json"
 
}
}
}
write-host "Delegated Permissions Granted"

##Create Directory for Certificate and CSV
write-host "Creating Directory for Certificate and CSV"
$DirectoryToCreate = "c:\AppRegistrations"
if (-not (Test-Path -LiteralPath $DirectoryToCreate)) {
    
    try {
        New-Item -Path $DirectoryToCreate -ItemType Directory -ErrorAction Stop | Out-Null #-Force
    }
    catch {
        Write-Error -Message "Unable to create directory '$DirectoryToCreate'. Error was: $_" -ErrorAction Stop
    }
    write-host "Successfully created directory '$DirectoryToCreate'."

}
else {
    write-host "Directory already existed"
}

###Create Service Principal for Azure AD with Certificate


write-host "Creating Certificate for Azure AD"
##Create Certificate
$CertDisplayName = "AzureADServicePrincipal"
$Certpath = $DirectoryToCreate + "\" + $CertDisplayName + ".pfx"
$pwd1 = New-RandomPassword -MinimumPasswordLength 10 -MaximumPasswordLength 15 -NumberOfAlphaNumericCharacters 6
$now = [System.DateTime]::Now
$notAfter = $now.AddYears(2)
$thumb = (New-SelfSignedCertificate -DnsName $suffix -CertStoreLocation "cert:\LocalMachine\My"  -KeyExportPolicy Exportable -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" -NotAfter $notAfter).Thumbprint
$pwd = ConvertTo-SecureString -String $pwd1 -Force -AsPlainText
Export-PfxCertificate -cert "cert:\localmachine\my\$thumb" -FilePath $Certpath -Password $pwd
write-host "Successfully created certificate at $Certpath"

##Load the Certificate
write-host "Loading Certificate"
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate($Certpath, $pwd)
$keyValue = [System.Convert]::ToBase64String($cert.GetRawCertData())
write-host "Certificate Loaded"

##Create App
write-host "Creating Azure AD Application"
$AADDisplay = "AzureADApp"
$application = New-MgApplication -DisplayName $AADDisplay -IdentifierUris $suffix
$params = @{
	KeyCredential = @{
		Type = "AsymmetricX509Cert"
		Usage = "Verify"
		Key = $keyValue
	}
	PasswordCredential = $null
}
Add-MgApplicationKey -ApplicationId $applicationId -BodyParameter $params
#Add-MgApplicationKey -ApplicationId $application.ObjectId -CustomKeyIdentifier $AADDisplay -Type AsymmetricX509Cert -Usage Verify -Value $keyValue -StartDate $cert.Certificate.NotBefore -EndDate $cert.Certificate.NotAfter
write-host "Successfully created Azure AD Application"

##Create Service Principal
write-host "Creating Azure AD Service Principal"
$sp=New-MgServicePrincipal -AppId $application.AppId
write-host "Successfully created Azure AD Service Principal"

##Assign Roles
write-host "Assigning Roles"
write-host "Assigning User Administrator"
New-MgRoleManagementDirectoryRoleAssignment -DirectoryScopeId "/" -RoleDefinitionID (Get-MgRoleManagementDirectoryRoleDefinition | where-object {$_.DisplayName -eq "User Administrator"}).Id -PrincipalID $sp.ObjectId
write-host "Successfully assigned User Administrator"
write-host "Assigning Privileged Role Administrator"
New-MgRoleManagementDirectoryRoleAssignment -DirectoryScopeId "/" -RoleDefinitionID (Get-MgRoleManagementDirectoryRoleDefinition | where-object {$_.DisplayName -eq "Privileged role administrator"}).Id -PrincipalID $sp.ObjectId
write-host "Successfully assigned Privileged Role Administrator"
write-host "Assigning Conditional Access Administrator"
New-MgRoleManagementDirectoryRoleAssignment -DirectoryScopeId "/" -RoleDefinitionID (Get-MgRoleManagementDirectoryRoleDefinition | where-object {$_.DisplayName -eq "Conditional Access administrator"}).Id -PrincipalID $sp.ObjectId
write-host "Successfully assigned Conditional Access Administrator"
write-host "Roles assigned"




write-host "Successfully assigned Roles"

##Create CSV File with details
write-host "Creating CSV File with details"

$csvfile = "$directorytocreate\$($suffix)-$($appObjectId)-details.csv"
$enterpriseAppId = $servicePrincipal.ObjectId
$props=[ordered]@{
     TenantID=$tenantid
     AppID=$AppID
     EnterpriseAppID=$enterpriseappID
     AppSecret=$appsecret
     DisplayName=$appdisplayname
     TenantDomain=$suffix
     CertPassword=$pwd1
     AzureADAppID=$application.ObjectId
     AzureADAppName=$AADDisplay
     AzureADServicePrincipal=$sp.ObjectID
     AzureADClientID=$application.AppID
}
New-Object PsObject -Property $props | 
     Export-Csv $csvfile -NoTypeInformation
write-host "CSV File created - $csvfile"
invoke-item $DirectoryToCreate