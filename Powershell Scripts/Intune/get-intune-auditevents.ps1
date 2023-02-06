<#PSScriptInfo
.VERSION 1.0
.GUID c8f44978-f4b9-45de-a688-07d361fb6747
.AUTHOR AndrewTaylor
.DESCRIPTION Display Intune Audit logs in gridview and exports selected events to CSV
.COMPANYNAME 
.COPYRIGHT GPL
.TAGS intune
.LICENSEURI https://github.com/andrew-s-taylor/public/blob/main/LICENSE
.PROJECTURI https://github.com/andrew-s-taylor/public
.ICONURI 
.EXTERNALMODULEDEPENDENCIES microsoft.graph.authentication
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
#>
<#
.SYNOPSIS
  Displays Audit events from Intune
.DESCRIPTION
Display Intune Audit logs in gridview and exports selected events to CSV

.INPUTS
None required
.OUTPUTS
GridView
.NOTES
  Version:        1.0
  Author:         Andrew Taylor
  WWW:            andrewstaylor.com
  Creation Date:  06/02/2023
  Purpose/Change: Initial script development
  
.EXAMPLE
N/A
#>
################################################################################################################

$ErrorActionPreference = "Continue"
##Start Logging to %TEMP%\intune.log
$date = get-date -format ddMMyyyy
Start-Transcript -Path $env:TEMP\intune-$date.log
################################################################################################################
###############################################################################################################
######                                         Install Modules                                           ######
###############################################################################################################
Write-Host "Installing Intune modules if required (current user scope)"

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication) {
    Write-Host "Microsoft Graph Already Installed"
} 
else {
    try {
        Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser -Repository PSGallery -Force 
    }
    catch [Exception] {
        $_.message 
    }
}

#Importing Modules
import-module microsoft.graph.authentication


Connect-MgGraph -Scopes "DeviceManagementApps.ReadWrite.All"

###############################################################################################################
######                                          Add Functions                                            ######
###############################################################################################################

Function Get-FileName($InitialDirectory)
 {
  [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
  $SaveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
  $SaveFileDialog.initialDirectory = $initialDirectory
  $SaveFileDialog.filter = "Comma Separated Values (*.csv)|*.csv|All Files (*.*)|(*.*)"
  $SaveFileDialog.ShowDialog() | Out-Null
  $SaveFileDialog.filename
 }


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
Get-ScriptVersion -liveuri "https://raw.githubusercontent.com/andrew-s-taylor/public/main/Powershell%20Scripts/Intune/get-intune-apps.ps1"

###############################################################################################################


$uri = "https://graph.microsoft.com/beta/deviceManagement/auditEvents"
$events = Invoke-MgGraphRequest -Uri $uri -Method GET -ContentType "application/json" -OutputType PSObject
$eventsvalues = $events.value
$policynextlink = ($events."@odata.nextlink")
while (($policynextlink -ne "") -and ($null -ne $policynextlink))
{

        $nextsettings = (Invoke-MgGraphRequest -Uri $policynextlink -Method GET -OutputType PSObject)
    $policynextlink = ($nextsettings."@odata.nextLink")
    $eventsvalues += $nextsettings.value
}

$eventsvalues =  $eventsvalues | select-object * -ExpandProperty Actor
$listofevents = @()
$eventsvalues | select-object Resource, userPrincipalName, displayName, category, activityType, activityDateTime, activityOperationType, id 
foreach ($event in $eventsvalues)
{
    $eventobject = [pscustomobject]@{
        changedItem = $event.Resources.displayName
        changedBy = $event.userPrincipalName
        change = $event.displayName
        changeCategory = $event.category
        activityType = $event.activityType
        activityDateTime = $event.activityDateTime
        id = $event.id
    }
    $listofevents += $eventobject
}

$selected = $listofevents | Out-GridView -PassThru

foreach ($item in $selected) {
$uri = "https://graph.microsoft.com/beta/deviceManagement/auditEvents/$selectedid"
$eventdetails = @()
write-host $uri
$changedcontent = (Invoke-MgGraphRequest -Uri $uri -Method GET -ContentType "application/json" -OutputType PSObject)
$eventobject = [pscustomobject]@{
    change = $changedcontent.displayName
    changeCategory = $changedcontent.category
    activityType = $changedcontent.activityType
    activityDateTime = $changedcontent.activityDateTime
    id = $changedcontent.id
    activity = $changedcontent.activity
    activityResult = $changedcontent.activityResult
    activityOperationType = $changedcontent.activityOperationType
    componentName = $changedcontent.componentName
    type = $changedcontent.actor.type
    auditActorType = $changedcontent.actor.auditActorType
    userPermissions = $changedcontent.actor.userPermissions
    applicationId = $changedcontent.actor.applicationId
    applicationDisplayName = $changedcontent.actor.applicationDisplayName
    userPrincipalName = $changedcontent.actor.userPrincipalName
    servicePrincipalName = $changedcontent.actor.servicePrincipalName
    ipAddress = $changedcontent.actor.ipAddress
    userId = $changedcontent.actor.userId
    remoteTenantId = $changedcontent.actor.remoteTenantId
    remoteUserId = $changedcontent.actor.remoteUserId
    resourcedisplayname = $changedcontent.resource.displayName
    resourcetype = $changedcontent.resource.type
    auditResourceType = $changedcontent.resource.auditResourceType
    resourceId = $changedcontent.resource.resourceId
}

$i = 0
foreach ($resource in $changedcontent.resources.modifiedproperties) {
    $name = "Name" + $i
    $oldvalue = "OldValue" + $i
    $newvalue = "NewValue" + $i
    $eventobject | Add-Member -MemberType NoteProperty -Name $name -Value $resource.displayName
    $eventobject | Add-Member -MemberType NoteProperty -Name $oldvalue -Value $resource.oldValue
    $eventobject | Add-Member -MemberType NoteProperty -Name $newvalue -Value $resource.newValue
    $i++
}

}


$SaveTo = Get-FileName -InitialDirectory $env:UserProfile

$eventobject | Export-Csv -Path $SaveTo -NoTypeInformation


Stop-Transcript