<#PSScriptInfo
.VERSION 1.0.4
.GUID 7b1c483b-b109-4d45-8abc-84760c84d9d9
.AUTHOR AndrewTaylor
.DESCRIPTION Lists all discovered apps with drill-down
.COMPANYNAME 
.COPYRIGHT GPL
.TAGS intune endpoint MEM environment
.LICENSEURI https://github.com/andrew-s-taylor/public/blob/main/LICENSE
.PROJECTURI https://github.com/andrew-s-taylor/public
.ICONURI 
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
#>
<#
.SYNOPSIS
  Lists all discovered apps with drill-down
.DESCRIPTION
Lists all discovered apps with drill-down

.INPUTS
None
.OUTPUTS
Creates a log file in %Temp%
.NOTES
  Version:        1.0.4
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  04/11/2022
  Updated: 07/02/2023
  Purpose/Change: Initial script development
  Change: Added Regex escape for special characters
 
.EXAMPLE
N/A
#>


$ErrorActionPreference = "Continue"
##Start Logging to %TEMP%\intune.log
$date = get-date -format yyyyMMddTHHmmssffff
Start-Transcript -Path $env:TEMP\intune-$date.log

#Install MS Graph if not available


Write-Host "Installing Microsoft Graph modules if required (current user scope)"

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph.authentication) {
    Write-Host "Microsoft Graph Already Installed"
} 
else {
    try {
        Install-Module -Name Microsoft.Graph.authentication -Scope CurrentUser -Repository PSGallery -Force 
    }
    catch [Exception] {
        $_.message 
        exit
    }
}


# Load the Graph module
Import-Module microsoft.graph.authentication

Function Connect-ToGraph {
  <#
.SYNOPSIS
Authenticates to the Graph API via the Microsoft.Graph.Authentication module.

.DESCRIPTION
The Connect-ToGraph cmdlet is a wrapper cmdlet that helps authenticate to the Intune Graph API using the Microsoft.Graph.Authentication module. It leverages an Azure AD app ID and app secret for authentication or user-based auth.

.PARAMETER Tenant
Specifies the tenant (e.g. contoso.onmicrosoft.com) to which to authenticate.

.PARAMETER AppId
Specifies the Azure AD app ID (GUID) for the application that will be used to authenticate.

.PARAMETER AppSecret
Specifies the Azure AD app secret corresponding to the app ID that will be used to authenticate.

.PARAMETER Scopes
Specifies the user scopes for interactive authentication.

.EXAMPLE
Connect-ToGraph -TenantId $tenantID -AppId $app -AppSecret $secret

-#>
  [cmdletbinding()]
  param
  (
      [Parameter(Mandatory = $false)] [string]$Tenant,
      [Parameter(Mandatory = $false)] [string]$AppId,
      [Parameter(Mandatory = $false)] [string]$AppSecret,
      [Parameter(Mandatory = $false)] [string]$scopes
  )

  Process {
      Import-Module Microsoft.Graph.Authentication
      $version = (get-module microsoft.graph.authentication | Select-Object -expandproperty Version).major

      if ($AppId -ne "") {
          $body = @{
              grant_type    = "client_credentials";
              client_id     = $AppId;
              client_secret = $AppSecret;
              scope         = "https://graph.microsoft.com/.default";
          }
   
          $response = Invoke-RestMethod -Method Post -Uri https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token -Body $body
          $accessToken = $response.access_token
   
          $accessToken
          if ($version -eq 2) {
              write-host "Version 2 module detected"
              $accesstokenfinal = ConvertTo-SecureString -String $accessToken -AsPlainText -Force
          }
          else {
              write-host "Version 1 Module Detected"
              Select-MgProfile -Name Beta
              $accesstokenfinal = $accessToken
          }
          $graph = Connect-MgGraph  -AccessToken $accesstokenfinal 
          Write-Host "Connected to Intune tenant $TenantId using app-based authentication (Azure AD authentication not supported)"
      }
      else {
          if ($version -eq 2) {
              write-host "Version 2 module detected"
          }
          else {
              write-host "Version 1 Module Detected"
              Select-MgProfile -Name Beta
          }
          $graph = Connect-MgGraph -scopes $scopes
          Write-Host "Connected to Intune tenant $($graph.TenantId)"
      }
  }
}    
##Connect to MS Graph

Connect-ToGraph -Scopes "DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, openid, profile, email, offline_access"



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
write-host "Script has been updated, please download the latest version from $liveuri" -ForegroundColor Red
}
}
Get-ScriptVersion -liveuri "https://raw.githubusercontent.com/andrew-s-taylor/public/main/Powershell%20Scripts/Intune/intune-inventory-discovered-apps.ps1"




##Grab all devices
$uri = "https://graph.microsoft.com/beta/deviceManagement/manageddevices"
$alldevices = (Invoke-MgGraphRequest -uri $uri -Method GET -OutputType PSObject).value

##Drop them into an array to save too many nested loops
$deviceids = @()

##Populate the array
foreach ($device in $alldevices) {
$deviceid = $device.id
$deviceids += $deviceid
}

##Create an array for the apps
$discoveredapps = @()

##Populate App array
foreach ($deviceapp in $deviceids) {

$uri = "https://graph.microsoft.com/beta/deviceManagement/manageddevices('$deviceapp')?`$expand=detectedApps"
$appsfound = (Invoke-MgGraphRequest -uri $uri -Method GET -OutputType PSObject).detectedApps
foreach ($app in $appsfound) {
$discoveredapps += $app.DisplayName
}
}

##Group the apps to get a count, sort and then display in GUI with drill-down
$appslist = $discoveredapps | group | select Count, Name | Sort-Object Count -Descending | Out-GridView -Title "Discovered Apps" -PassThru | ForEach-Object {
##App to search for
$appname = [regex]::Escape($_.Name)
$rawappname = $_.Name

##Create an array of devices with the app installed in case we want to export-csv or GUI popup with this data at a later date
$deviceswithappinstalled = @()

##Loop through machines looking for the app
foreach ($findtheapp in $deviceids) {
$uri = "https://graph.microsoft.com/beta/deviceManagement/manageddevices('$findtheapp')?`$expand=detectedApps"
$appsfound = (Invoke-MgGraphRequest -uri $uri -Method GET -OutputType PSObject).detectedApps
##App found, grab the devicename
if ($appsfound -match "$appname") {
$deviceuri = "https://graph.microsoft.com/beta/deviceManagement/manageddevices/$Aappsfound"
$devicename = (Invoke-MgGraphRequest -uri $uri -Method GET -OutputType PSObject).devicename
write-host "App $rawappname found on device $devicename ($findtheapp)"
$deviceswithappinstalled += $devicename
}
}
}


Stop-Transcript