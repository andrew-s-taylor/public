<#PSScriptInfo
.VERSION 3.4
.GUID 729ebf90-26fe-4795-92dc-ca8f570cdd22
.AUTHOR AndrewTaylor
.DESCRIPTION Synchronises All Intune managed devices
.COMPANYNAME 
.COPYRIGHT GPL
.TAGS intune endpoint MEM environment
.LICENSEURI https://github.com/andrew-s-taylor/public/blob/main/LICENSE
.PROJECTURI https://github.com/andrew-s-taylor/public
.ICONURI 
.EXTERNALMODULEDEPENDENCIES microsoft.graph.intune
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
#>
<#
.SYNOPSIS
  Synchronises All Intune managed devices
.DESCRIPTION
Synchronises All Intune managed devices

.INPUTS
None required
.OUTPUTS
Within Azure
.NOTES
  Version:        3.4
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  24/11/2021
  Modified Date:  24/02/2023
  Purpose/Change: Initial script development
  Change:   Switched to MSGraph Auth
  Change:   Added pagination support for larger estates
  Change: Bug fix
  Change: Removed MS Graph module and switched to MgGraph
  
.EXAMPLE
N/A
#>

####################################################
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

####################################################################### END INSTALL MODULES #######################################################################

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
Get-ScriptVersion -liveuri "https://raw.githubusercontent.com/andrew-s-taylor/public/main/Powershell%20Scripts/Intune/SyncAllIntuneDevices.ps1"

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
####################################################################### CREATE AAD OBJECTS #######################################################################
#Connect to Graph
Connect-ToGraph -Scopes CloudPC.ReadWrite.All, Domain.Read.All, Directory.Read.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, openid, profile, email, offline_access

####################################################
    
    function SyncDevice {
        param
(
    $DeviceID
)
        $Resource = "deviceManagement/managedDevices('$DeviceID')/syncDevice"
        $uri = "https://graph.microsoft.com/Beta/$($resource)"
        write-verbose $uri
        Write-Verbose "Sending sync command to $DeviceID"
        Invoke-MgGraphRequest -Uri $uri -Method Post -Body $null
    }
    ####################################################


    
    
#####################################################
#Sync All Devices
#####################################################

$graphApiVersion = "beta"
$Resource = "deviceManagement/managedDevices"
$uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"

$devices = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
$alldevices = @()
$alldevices += $devices.value
$policynextlink = $devices."@odata.nextlink"

while ($null -ne $policynextlink) {
$nextdevices = (Invoke-MgGraphRequest -Uri $policynextlink -Method Get -OutputType PSObject)
$policynextlink = $nextdevices."@odata.nextLink"
$alldevices += $nextdevices.value
}





foreach ($device in $alldevices) {
    SyncDevice -Deviceid $device.id
    $devicename = $device.deviceName
    write-host "Sync sent to $devicename"
}

##All done
Disconnect-MgGraph