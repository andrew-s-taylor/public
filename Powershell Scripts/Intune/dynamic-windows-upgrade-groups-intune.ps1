<#
.SYNOPSIS
  Creates semi-dynamic AAD groups for Win11 and Win10 devices
.DESCRIPTION
  Checks for Device Compliance with Windows 11
  Creates Win11 group for compliant device
  Creates Win10 group for non-compliant
.INPUTS
None
.OUTPUTS
None
.NOTES
  Version:        3.0.1
  Author:         Andrew Taylor
  WWW:            andrewstaylor.com
  Creation Date:  26/01/2023
  Purpose/Change: Initial script development
 
.EXAMPLE
N/A
#>

<#PSScriptInfo
.VERSION 3.0.1
.GUID 1bcfb95b-ab34-48c5-92de-ff191763c471
.AUTHOR AndrewTaylor
.COMPANYNAME 
.COPYRIGHT GPL
.TAGS intune endpoint MEM environment enrollment
.LICENSEURI https://github.com/andrew-s-taylor/public/blob/main/LICENSE
.PROJECTURI https://github.com/andrew-s-taylor/public
.ICONURI 
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
#>

###############################################################################################################
######                                              Set Variables                                        ######
###############################################################################################################

##Group Name for Windows 10 Devices
$w10groupname = "W11NonCompliantDevices"

##Group Name for Windows 11 Devices
$w11groupname = "W11CompliantDevices"




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
Get-ScriptVersion -liveuri "https://raw.githubusercontent.com/andrew-s-taylor/public/main/Powershell%20Scripts/Intune/dynamic-windows-upgrade-groups-intune.ps1"

function getallpagination () {
    <#
.SYNOPSIS
This function is used to grab all items from Graph API that are paginated
.DESCRIPTION
The function connects to the Graph API Interface and gets all items from the API that are paginated
.EXAMPLE
getallpagination -url "https://graph.microsoft.com/v1.0/groups"
 Returns all items
.NOTES
 NAME: getallpagination
#>
[cmdletbinding()]
    
param
(
    $url
)
    $response = (Invoke-MgGraphRequest -uri $url -Method Get -OutputType PSObject)
    $alloutput = $response.value
    
    $alloutputNextLink = $response."@odata.nextLink"
    
    while ($null -ne $alloutputNextLink) {
        $alloutputResponse = (Invoke-MGGraphRequest -Uri $alloutputNextLink -Method Get -outputType PSObject)
        $alloutputNextLink = $alloutputResponse."@odata.nextLink"
        $alloutput += $alloutputResponse.value
    }
    
    return $alloutput
    }

##Connect to Graph
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

Connect-ToGraph -Scopes "Device.Read.All, User.Read.All, Domain.Read.All, Directory.Read.All, DeviceManagementManagedDevices.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, Group.ReadWrite.All, GroupMember.ReadWrite.All, openid, profile, email, offline_access, Mail.Send"


##Get Devices compliant/not compliant with windows 11
write-host "Inspecting devices for Windows 11 compliance"
$reporturi = "https://graph.microsoft.com/beta/deviceManagement/userExperienceAnalyticsWorkFromAnywhereMetrics('allDevices')/metricDevices?`$select=id,deviceName,managedBy,manufacturer,model,osDescription,osVersion,upgradeEligibility,azureAdJoinType,upgradeEligibility,ramCheckFailed,storageCheckFailed,processorCoreCountCheckFailed,processorSpeedCheckFailed,tpmCheckFailed,secureBootCheckFailed,processorFamilyCheckFailed,processor64BitCheckFailed,osCheckFailed&dtFilter=all&`$orderBy=osVersion asc"

$reportdata = getallpagination -url $reporturi

$compliantdevices = @()
$noncompliantdevices = @()
write-host "Checking Machines for Compatibility"
$counter = 0

foreach ($machine in $reportdata) {
    $counter++
    $deviceid = $machine.id
    Write-Progress -Activity 'Processing Devices' -CurrentOperation $deviceid -PercentComplete (($counter / $reportdata.count) * 100)

    $w11compliance = $machine.upgradeEligibility
    if ($w11compliance -eq "Capable") {
        $compliantdevices += $machine.deviceName
    }
    else {
        $noncompliantdevices += $machine.deviceName
    }
}

$alldevices = getallpagination -url "https://graph.microsoft.com/beta/devices"


write-host "Creating AAD Groups"
##Create AAD Groups
write-host "Creating Windows 11 Group"
$win11groupexist = (get-mggroup -filter "displayName eq '$w11groupname'").id
write-host "Creating Windows 10 Group"
$win10groupexist = (get-mggroup -filter "displayName eq '$w10groupname'").id

##Windows 11
##Check if group exists
write-host "Checking if Windows 11 Group Exists"
if ($null -ne $win11groupexist) {
    $allmembers = get-mggroupmember -All -GroupId $win11groupexist
##It exists, add members
write-host "Windows 11 Group Exists, adding members"
foreach ($compliantdevice in $compliantdevices) {
    $compliantdeviceid = ($alldevices | Where-Object displayName -eq $compliantdevice).id
    ##Check if already in the group
    write-host "Checking if $compliantdevice is already in the group"
    $groupmember = ($allmembers) | where-object ID -eq $compliantdeviceid
    if ($null -eq $groupmember) {
    write-host "Adding $compliantdevice to the group"
   new-mggroupmember -GroupId $win11groupexist -DirectoryObjectId  $compliantdeviceid
    }
}
}
else {
##Does not, create it first
write-host "Windows 11 Group does not exist, creating it"
$win11group = new-mggroup -DisplayName $w11groupname -Description "Devices Compliant with Windows 11" -SecurityEnabled -mailEnabled:$false -MailNickname $w11groupname
$win11groupid = $win11group.id
$allmembers = get-mggroupmember -All -GroupId $win11groupid
foreach ($compliantdevice in $compliantdevices) {
    $compliantdeviceid = ($alldevices | Where-Object displayName -eq $compliantdevice).id

    ##Check if already in the group
    write-host "Checking if $compliantdevice is already in the group"
    $groupmember = ($allmembers) | where-object ID -eq $compliantdeviceid
    if ($null -eq $groupmember) {
        write-host "Adding $compliantdevice to the group"
    new-mggroupmember -GroupId $win11groupid -DirectoryObjectId  $compliantdeviceid
    }
}
}


##Windows 10
if ($null -ne $win10groupexist) {
    $allmembers = get-mggroupmember -All -GroupId $win10groupexist
##It exists, add members
write-host "Windows 10 Group Exists, adding members"
foreach ($noncompliantdevice in $noncompliantdevices) {
    $noncompliantdeviceid = ($alldevices | Where-Object displayName -eq $noncompliantdevice).id
    ##Check if already in the group
    write-host "Checking if $noncompliantdevice is already in the group"
    $groupmember = ($allmembers) | where-object ID -eq $noncompliantdeviceid
    if ($null -eq $groupmember) {
    write-host "Adding $noncompliantdevice to the group"
   new-mggroupmember -GroupId $win10groupexist -DirectoryObjectId  $noncompliantdeviceid
    }
}
}
else {
##Does not, create it first
write-host "Windows 10 Group does not exist, creating it"
$win10group = new-mggroup -DisplayName $w10groupname -Description "Devices Not Compliant with Windows 10" -SecurityEnabled -MailEnabled:$false -MailNickname $w10groupname
$win10groupid = $win10group.id
$allmembers = get-mggroupmember -All -GroupId $win10groupid
foreach ($noncompliantdevice in $noncompliantdevices) {
    $noncompliantdeviceid = ($alldevices | Where-Object displayName -eq $noncompliantdevice).id

    ##Check if already in the group
    write-host "Checking if $noncompliantdevice is already in the group"
    $groupmember = ($allmembers) | where-object ID -eq $noncompliantdeviceid
    if ($null -eq $groupmember) {
        write-host "Adding $noncompliantdevice to the group"
    new-mggroupmember -GroupId $win10groupid -DirectoryObjectId  $noncompliantdeviceid
    }
}
}