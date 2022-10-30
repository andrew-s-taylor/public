$maximumfunctioncount = 32768
<#PSScriptInfo
.VERSION 2.0
.GUID 1c0a3eff-2a30-4ed7-904f-15396802c874
.AUTHOR AndrewTaylor
.DESCRIPTION Creates Local Admin
.COMPANYNAME 
.COPYRIGHT GPL
.TAGS intune endpoint MEM environment
.LICENSEURI https://github.com/andrew-s-taylor/public/blob/main/LICENSE
.PROJECTURI https://github.com/andrew-s-taylor/public
.ICONURI 
.EXTERNALMODULEDEPENDENCIES microsoft.graph.intune microsoft.graph
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
#>
<#
.SYNOPSIS
  Creates local admin from JSON
.DESCRIPTION
.Creates Local Admin from JSON

.INPUTS
Runmode:
silent (hides popups)
.OUTPUTS
Within Azure
.NOTES
  Version:        2.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  21/03/2022
  Modified:      29/10/2022
  Purpose/Change: Initial script development
  Change: Switched to Graph authentication
  
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
 


#Connect to Graph
Select-MgProfile -Name Beta
Connect-MgGraph -Scopes  	RoleAssignmentSchedule.ReadWrite.Directory, Domain.Read.All, Domain.ReadWrite.All, Directory.Read.All, Policy.ReadWrite.ConditionalAccess, DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, openid, profile, email, offline_access



##Get Tenant Details
##Grab Tenant ID
$domainname = get-mgdomain | where-object IsDefault -eq $true

$Name = "Intune Admin"
$UPN1 = "intuneadmin@"
$UPN = $UPN1 + $domainname

### Create the User
$PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
$PasswordProfile.Password = $password
$usercreate = New-MgUser -DisplayName $Name -PasswordProfile $PasswordProfile -UserPrincipalName $UPN -AccountEnabled



####################################################

##Configure the JSON
$initialjson="https://raw.githubusercontent.com/andrew-s-taylor/public/main/Powershell%20Scripts/Intune/localadminpolicy.json"
$jsonpath = $env:Temp+"\intuneadmin.json"

# Download config
Invoke-WebRequest -Uri $initialjson -OutFile $jsonpath -UseBasicParsing
((Get-Content -path $jsonpath -Raw) -replace '<REPLACEME>',$UPN) | Set-Content -Path $jsonpath

$ImportPath = $env:Temp+"\intuneadmin.json"

$JSON_Data = gc "$ImportPath"

$JSON_Convert = $JSON_Data | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id,createdDateTime,lastModifiedDateTime,version,supportsScopeTags

$JSON_Output =  $JSON_Convert | Select-Object * -ExcludeProperty id, createdDateTime, LastmodifieddateTime, version, creationSource | ConvertTo-Json -Depth 100


    $uri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"

$body = ([System.Text.Encoding]::UTF8.GetBytes($JSON_Output.tostring()))
Invoke-MgGraphRequest -Uri $uri -Method Post -Body $body  -ContentType "application/json; charset=utf-8"  





##Create the policy




##All done, notify


})