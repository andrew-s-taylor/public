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
  Version:        1.0.0
  Author:         Andrew Taylor
  WWW:            andrewstaylor.com
  Creation Date:  26/01/2023
  Purpose/Change: Initial script development
 
.EXAMPLE
N/A
#>

<#PSScriptInfo
.VERSION 1.0.0
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
Get-ScriptVersion -liveuri "https://raw.githubusercontent.com/andrew-s-taylor/public/main/Powershell%20Scripts/Intune/automate-w10-w11-devicegroups.ps1"


##Connect to Graph

Select-MgProfile -Name Beta
Connect-MgGraph -Scopes Device.Read.All, User.Read.All, Domain.Read.All, Directory.Read.All, DeviceManagementManagedDevices.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, Group.ReadWrite.All, GroupMember.ReadWrite.All, openid, profile, email, offline_access, Mail.Send


##Get Devices compliant/not compliant with windows 11
write-host "Inspecting devices for Windows 11 compliance"
$reporturi = "https://graph.microsoft.com/beta/deviceManagement/userExperienceAnalyticsWorkFromAnywhereMetrics('allDevices')/metricDevices?`$select=id,deviceName,managedBy,manufacturer,model,osDescription,osVersion,upgradeEligibility,azureAdJoinType,upgradeEligibility,ramCheckFailed,storageCheckFailed,processorCoreCountCheckFailed,processorSpeedCheckFailed,tpmCheckFailed,secureBootCheckFailed,processorFamilyCheckFailed,processor64BitCheckFailed,osCheckFailed&dtFilter=all&`$orderBy=osVersion asc"

$reportdata = (invoke-mggraphrequest -uri $reporturi -method GET).value

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
        $compliantdevices += $machine.id
    }
    else {
        $noncompliantdevices += $machine.id
    }
}

write-host "Creating AAD Groups"
##Create AAD Groups
write-host "Creating Windows 11 Group"
$win11groupexist = get-mggroup -filter "displayName eq '$w11groupname'"
write-host "Creating Windows 10 Group"
$win10groupexist = get-mggroup -filter "displayName eq '$w10groupname'"

##Windows 11
##Check if group exists
write-host "Checking if Windows 11 Group Exists"
if ($null -ne $win11groupexist) {
##It exists, add members
write-host "Windows 11 Group Exists, adding members"
foreach ($compliantdevice in $compliantdevices) {
    ##Check if already in the group
    write-host "Checking if $compliantdevice is already in the group"
    $groupmember = get-mggroupmember -GroupId $win11groupexist.id -MemberId $compliantdevice.id
    if ($null -eq $groupmember) {
    write-host "Adding $compliantdevice to the group"
    add-mggroupmember -GroupId $win11groupexist.id -MemberId $compliantdevice.id
    }
}
}
else {
##Does not, create it first
write-host "Windows 11 Group does not exist, creating it"
$win11group = new-mggroup -DisplayName $w11groupname -Description "Devices Compliant with Windows 11" -MailEnabled $false -SecurityEnabled $true
foreach ($compliantdevice in $compliantdevices) {
    ##Check if already in the group
    write-host "Checking if $compliantdevice is already in the group"
    $groupmember = get-mggroupmember -GroupId $win11group.id -MemberId $compliantdevice.id
    if ($null -eq $groupmember) {
        write-host "Adding $compliantdevice to the group"
    add-mggroupmember -GroupId $win11group.id -MemberId $compliantdevice.id
    }
}
}


##Windows 10
##Check if group exists
write-host "Checking if Windows 10 Group Exists"
if ($null -ne $win10groupexist) {
    ##It exists, add members
    write-host "Windows 10 Group Exists, adding members"
    foreach ($noncompliantdevice in $noncompliantdevices) {
        ##Check if already in the group
        write-host "Checking if $noncompliantdevice is already in the group"
        $groupmember = get-mggroupmember -GroupId $win10groupexist.id -MemberId $noncompliantdevice.id
        if ($null -eq $groupmember) {
            write-host "Adding $noncompliantdevice to the group"
            add-mggroupmember -GroupId $win10groupexist.id -MemberId $noncompliantdevice.id
        }
    }
    }
    else {
    ##Does not, create it first
    write-host "Windows 10 Group does not exist, creating it"
    $win10group = new-mggroup -DisplayName $w10groupname -Description "Devices Not Compliant with Windows 10" -MailEnabled $false -SecurityEnabled $true
    foreach ($noncompliantdevice in $noncompliantdevices) {
        ##Check if already in the group
        $groupmember = get-mggroupmember -GroupId $win10group.id -MemberId $noncompliantdevice.id
        if ($null -eq $groupmember) {
            write-host "Adding $noncompliantdevice to the group"
            add-mggroupmember -GroupId $win10group.id -MemberId $noncompliantdevice.id
        }
    }
    }