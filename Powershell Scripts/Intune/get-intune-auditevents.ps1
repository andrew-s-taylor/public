<#PSScriptInfo
.VERSION 1.2
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
  Version:        1.2
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
Write-Host "Importing Modules"
import-module microsoft.graph.authentication
Write-Host "Modules Imported"

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

###############################################################################################################
######                                        Connect to Graph                                           ######
###############################################################################################################

##Authenticate
Write-Host "Connecting to Graph"

Connect-ToGraph -Scopes "DeviceManagementApps.ReadWrite.All"
write-host "Connected to Graph"

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
Get-ScriptVersion -liveuri "https://raw.githubusercontent.com/andrew-s-taylor/public/main/Powershell%20Scripts/Intune/get-intune-auditevents.ps1"

###############################################################################################################

##Get all events
write-host "Getting all events from Intune"
$uri = "https://graph.microsoft.com/beta/deviceManagement/auditEvents"
$events = Invoke-MgGraphRequest -Uri $uri -Method GET -ContentType "application/json" -OutputType PSObject
##Select the value
$eventsvalues = $events.value
##Deal with pagination, grab all settings until no next link
$policynextlink = ($events."@odata.nextlink")
while (($policynextlink -ne "") -and ($null -ne $policynextlink))
{

        $nextsettings = (Invoke-MgGraphRequest -Uri $policynextlink -Method GET -OutputType PSObject)
    $policynextlink = ($nextsettings."@odata.nextLink")
    $eventsvalues += $nextsettings.value
}
##Expand nested array
$eventsvalues =  $eventsvalues | select-object * -ExpandProperty Actor

write-host "Audit Events Grabbed, displaying in GridView"
##Create an array to store tweaked output
$listofevents = @()
##Select specific values from the array
$eventsvalues =  $eventsvalues | select-object resources, userPrincipalName, displayName, category, activityType, activityDateTime, activityOperationType, id 
##Loop through the array and create a new object with the values we want
$counter = 0
foreach ($event in $eventsvalues)
{
    $counter++
    $id = $event.id
    Write-Progress -Activity 'Processing Entries' -CurrentOperation $id -PercentComplete (($counter / $eventsvalues.count) * 100)
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

##Display the array in a GridView
$selected = $listofevents | Out-GridView -PassThru


##### DEAL WITH EACH EVENT SELECTED

write-host "Getting details for each event selected"

##Create array to store it
$selectedevents = @()

##Loop through
foreach ($item in $selected) {
    ##Grab the details
    $selectedid = $item.id
$uri = "https://graph.microsoft.com/beta/deviceManagement/auditEvents/$selectedid"
write-host "Getting details for $selectedid"
$changedcontent = (Invoke-MgGraphRequest -Uri $uri -Method GET -ContentType "application/json" -OutputType PSObject)

##Create a new object with the values we want
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

##Resources is an open-ended array depending on the size of the policy
##We can't have multiple items in the object with the same name so we'll use an incrementing number

##Set to 0
$i = 0
##Loop through the array
foreach ($resource in $changedcontent.resources.modifiedproperties) {
    ##Create a new property with the name and value
    $name = "Name" + $i
    $oldvalue = "OldValue" + $i
    $newvalue = "NewValue" + $i
    $eventobject | Add-Member -MemberType NoteProperty -Name $name -Value $resource.displayName
    $eventobject | Add-Member -MemberType NoteProperty -Name $oldvalue -Value $resource.oldValue
    $eventobject | Add-Member -MemberType NoteProperty -Name $newvalue -Value $resource.newValue
    ##Increment
    $i++
}
$selectedevents += $eventobject
}

##Now save the output
write-host "Saving output to CSV"
##Prompt for save location
$SaveTo = Get-FileName -InitialDirectory $env:UserProfile

##Save it
$selectedevents | Export-Csv -Path $SaveTo -NoTypeInformation
write-host "Save Completed to $SaveTo"

##All done
Stop-Transcript