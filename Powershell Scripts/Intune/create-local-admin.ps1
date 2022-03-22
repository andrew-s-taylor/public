<#PSScriptInfo
.VERSION 1.2
.GUID 1c0a3eff-2a30-4ed7-904f-15396802c874
.AUTHOR AndrewTaylor
.DESCRIPTION Builds an Intune landing zone using intunebackupandrestore
.Deploys Windows and Office update ring groups
.Configures an "Intune-Users" Group
.Deploys compliance policies for Android, iOS, Windows and MacOS
.Deploys base configuration profiles for Android, iOS, Windows and MacOS
.Deploys Security baselines for Windows
.Assigns everything as approproate
.Deploys Office 365 and Edge as required apps
.Deploys 7-Zip as available app
.Creates an Admins group with assignment on the Azure Joined Local Device Admins PIM role
.Creates a conditional access policy for compliant devices only
.COMPANYNAME 
.COPYRIGHT GPL
.TAGS intune endpoint MEM environment
.LICENSEURI https://github.com/andrew-s-taylor/public/blob/main/LICENSE
.PROJECTURI https://github.com/andrew-s-taylor/public
.ICONURI 
.EXTERNALMODULEDEPENDENCIES microsoft.graph.intune intunebackupandrestore
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
#>
<#
.SYNOPSIS
  Builds an Intune landing zone
.DESCRIPTION
.Deploys Windows and Office update ring groups
.Configures an "Intune-Users" Group
.Deploys compliance policies for Android, iOS, Windows and MacOS
.Deploys base configuration profiles for Android, iOS, Windows and MacOS
.Deploys Security baselines for Windows
.Assigns everything as approproate
.Deploys Office 365 and Edge as required apps
.Deploys 7-Zip as available app
.Creates an Admins group with assignment on the Azure Joined Local Device Admins PIM role
.Creates a conditional access policy for compliant devices only

.INPUTS
Runmode:
silent (hides popups)
.OUTPUTS
Within Azure
.NOTES
  Version:        1.2
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  21/03/2022
  Purpose/Change: Initial script development
  
.EXAMPLE
N/A
#>

$ErrorActionPreference = "Continue"
##Start Logging to %TEMP%\intune.log
$date = get-date -format ddMMyyyy
Start-Transcript -Path $env:TEMP\intune-$date.log
###############################################################################################################
######                                         Install Modules                                           ######
###############################################################################################################
Write-Host "Installing Intune modules if required (current user scope)"

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph.Intune) {
    Write-Host "Microsoft Graph Already Installed"
} 
else {
    try {
        Install-Module -Name Microsoft.Graph.Intune -Scope CurrentUser -Repository PSGallery -Force 
    }
    catch [Exception] {
        $_.message 
        exit
    }
}


Write-Host "Installing AzureAD Preview modules if required (current user scope)"

#Install AZ Module if not available
if (Get-Module -ListAvailable -Name AzureADPreview) {
    Write-Host "AZ Ad Preview Module Already Installed"
} 
else {
    try {
        Install-Module -Name AzureADPreview -Scope CurrentUser -Repository PSGallery -Force -AllowClobber 
    }
    catch [Exception] {
        $_.message 
        exit
    }
}

####################################################

function Get-AuthToken {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthToken
    Authenticates you with the Graph API interface
    .NOTES
    NAME: Get-AuthToken
    #>
    
    [cmdletbinding()]
    
    param
    (
        [Parameter(Mandatory=$true)]
        $User
    )
    
    $userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User
    
    $tenant = $userUpn.Host
    
    Write-Host "Checking for AzureAD module..."
    
        $AadModule = Get-Module -Name "AzureAD" -ListAvailable
    
        if ($AadModule -eq $null) {
    
            Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"
            $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable
    
        }
    
        if ($AadModule -eq $null) {
            write-host
            write-host "AzureAD Powershell module not installed..." -f Red
            write-host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
            write-host "Script can't continue..." -f Red
            write-host
            exit
        }
    
    # Getting path to ActiveDirectory Assemblies
    # If the module count is greater than 1 find the latest version
    
        if($AadModule.count -gt 1){
    
            $Latest_Version = ($AadModule | select version | Sort-Object)[-1]
    
            $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }
    
                # Checking if there are multiple versions of the same module found
    
                if($AadModule.count -gt 1){
    
                $aadModule = $AadModule | select -Unique
    
                }
    
            $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
            $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    
        }
    
        else {
    
            $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
            $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    
        }
    
    [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
    
    [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null
    
    $clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
    
    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
    
    $resourceAppIdURI = "https://graph.microsoft.com"
    
    $authority = "https://login.microsoftonline.com/$Tenant"
    
        try {
    
        $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
    
        # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
        # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession
    
        $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"
    
        $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")
    
        $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId).Result
    
            # If the accesstoken is valid then create the authentication header
    
            if($authResult.AccessToken){
    
            # Creating header for Authorization token
    
            $authHeader = @{
                'Content-Type'='application/json'
                'Authorization'="Bearer " + $authResult.AccessToken
                'ExpiresOn'=$authResult.ExpiresOn
                }
    
            return $authHeader
    
            }
    
            else {
    
            Write-Host
            Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
            Write-Host
            break
    
            }
    
        }
    
        catch {
    
        write-host $_.Exception.Message -f Red
        write-host $_.Exception.ItemName -f Red
        write-host
        break
    
        }
    
    }
    
    ####################################################



### Prompt for a Password
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

$PasswordPrompt                  = New-Object system.Windows.Forms.Form
$PasswordPrompt.ClientSize       = New-Object System.Drawing.Point(400,48)
$PasswordPrompt.text             = "Password Prompt"
$PasswordPrompt.TopMost          = $false

$Label1                          = New-Object system.Windows.Forms.Label
$Label1.text                     = "Enter Password"
$Label1.AutoSize                 = $true
$Label1.width                    = 25
$Label1.height                   = 10
$Label1.location                 = New-Object System.Drawing.Point(26,14)
$Label1.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Button1                         = New-Object system.Windows.Forms.Button
$Button1.text                    = "Submit"
$Button1.width                   = 60
$Button1.height                  = 30
$Button1.location                = New-Object System.Drawing.Point(269,4)
$Button1.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$passwordbox                     = New-Object system.Windows.Forms.MaskedTextBox
$passwordbox.multiline           = $false
$passwordbox.width               = 100
$passwordbox.height              = 20
$passwordbox.location            = New-Object System.Drawing.Point(145,8)
$passwordbox.Font                = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$PasswordPrompt.controls.AddRange(@($Label1,$Button1,$passwordbox))

[void]$PasswordPrompt.ShowDialog()

$Button1.Add_Click({ 
    $password = $passwordbox.Text
 


##Connect to AzureAD
Connect-AzureAD


##Get the tenant
$tenant = Get-AzureADTenantDetail | Select-Object VerifiedDomains

foreach ($domain in $tenant) {
    if ($domain._Default -eq $True) {
        $domainname = $domain.Name
    }
}


$Name = "Intune Admin"
$UPN1 = "intuneadmin@"
$UPN = $UPN1 + $domainname

### Create the User
$PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
$PasswordProfile.Password = $password
$usercreate = New-AzureADUser -DisplayName $Name -PasswordProfile $PasswordProfile -UserPrincipalName $UPN -AccountEnabled $true


#region Authentication

write-host

# Checking if authToken exists before running authentication
if($global:authToken){

    # Setting DateTime to Universal time to work in all timezones
    $DateTime = (Get-Date).ToUniversalTime()

    # If the authToken exists checking when it expires
    $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes

        if($TokenExpires -le 0){

        write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
        write-host

            # Defining User Principal Name if not present

            if($User -eq $null -or $User -eq ""){

            $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
            Write-Host

            }

        $global:authToken = Get-AuthToken -User $User

        }
}

# Authentication doesn't exist, calling Get-AuthToken function

else {

    if($User -eq $null -or $User -eq ""){

    $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
    Write-Host

    }

# Getting the authorization token
$global:authToken = Get-AuthToken -User $User

}

#endregion

####################################################

##Configure the JSON
$templateid = "0f2b5d70-d4e9-4156-8c16-1397eb6c54a5"
$templateuri = "https://graph.microsoft.com/beta/deviceManagement/intents?$filter=templateId eq '0f2b5d70-d4e9-4156-8c16-1397eb6c54a5'"

$localadmins = Invoke-RestMethod -Method Get -Uri $templateuri -Headers $authtoken
$localadmins.value



##Create the policy

$request = @{
    displayName = "IntuneLocalAdmins"
    description = "Create Local Admin"
    templateId = $localadmins.value.id
} | ConvertTo-Json
$instance = Invoke-RestMethod -Method Post -Uri "https://graph.microsoft.com/beta/deviceManagement/templates/$($localadmins.value.id)/createInstance" -Headers $authtoken -ContentType 'Application/Json' -body $request
$instance

$definitionbase = "deviceConfiguration--deviceManagementUserRightsSetting_localUsersOrGroups"


##All done, notify


})