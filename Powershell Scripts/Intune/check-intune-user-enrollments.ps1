<#
.SYNOPSIS
  Lists users who are at or over device enrollment limit in either AAD or Intune
.DESCRIPTION
  Lists users who are at or over device enrollment limit in either AAD or Intune
  Displays all users in GridView
  Clicking on a user displays the devices, enrollment/registration date and the date last seen
  Checks through all Intune policies to find the one with the highest priority applicable to user
.INPUTS
None
.OUTPUTS
None
.NOTES
  Version:        1.0.2
  Author:         Andrew Taylor
  WWW:            andrewstaylor.com
  Creation Date:  09/01/2023
  Purpose/Change: Initial script development
 
.EXAMPLE
N/A
#>

<#PSScriptInfo
.VERSION 1.0.2
.GUID 979c8308-07a3-4918-9caf-58693fd44536
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

################################ INSTALL MODULES ############################################

Write-Host "Installing Microsoft Graph modules if required (current user scope)"

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication) {
    Write-Host "Microsoft Graph Authentication Already Installed"
} 
else {
    Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser -Repository PSGallery -Force -RequiredVersion 1.19.0 
    Write-Host "Microsoft Graph Authentication Installed"
}

if (Get-Module -ListAvailable -Name Microsoft.Graph.Users) {
    Write-Host "Microsoft Graph Users Already Installed "
} 
else {
    Install-Module -Name Microsoft.Graph.Users -Scope CurrentUser -Repository PSGallery -Force -RequiredVersion 1.19.0  
    Write-Host "Microsoft Graph Users Installed"
}

### IMPORT THEM
import-module Microsoft.Graph.Authentication
import-module Microsoft.Graph.Users

################################## END MODULES ##############################################

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
Get-ScriptVersion -liveuri "https://raw.githubusercontent.com/andrew-s-taylor/public/main/Powershell%20Scripts/Intune/check-intune-user-enrollments.ps1"

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
##############################################################################################################################################
##### UPDATE THESE VALUES IF AUTOMATED #######################################################################################################
##############################################################################################################################################
##Set to Yes
$automated = "No"

##Your Azure Tenant ID
$tenantid = "<YOUR TENANT ID>"

##Your App Registration Details
$clientId = "<YOUR CLIENT ID>"
$clientSecret = "<YOUR CLIENT SECRET>"

$EmailAddress = "<YOUR EMAIL ADDRESS>"

##From Address
$MailSender = "<YOUR FROM ADDRESS>"


##############################################################################################################################################

if ($automated -eq "No") {
################################## CONNECT TO GRAPH ##########################################
Connect-ToGraph -Scopes "Device.Read.All, User.Read.All, Domain.Read.All, Directory.Read.All, DeviceManagementManagedDevices.ReadWrite.All, openid, profile, email, offline_access, Mail.Send"

################################## END CONNECT TO GRAPH ######################################
}
else {
#Connect to GRAPH API
 
#Get Creds and connect
#Connect to Graph
write-host "Connecting to Graph"

Connect-ToGraph -AppId $clientId -AppSecret $clientSecret -Tenant $tenantid
write-host "Graph Connection Established"

}

##Create an array to store the users in so we can output later
$usersatrisk = @{}

##Get all users
write-host "Getting AAD Users" -ForegroundColor Green
$allusers = get-mguser -All


##Create an array for all limits so we can find the smallest
$userassignmentlimits = @()


##Get AAD Restrictions for the tenant
write-host "Getting AAD Restrictions" -ForegroundColor Green
$aaduri = "https://graph.microsoft.com/beta/policies/deviceRegistrationPolicy"
$aadrestriction = (Invoke-MgGraphRequest -Uri $aaduri -Method GET -OutputType PSObject).userDeviceQuota
write-host "AAD Restriction set to $aadrestriction" -ForegroundColor Green


##Get Intune Restrictions
write-host "Getting Intune Restrictions" -ForegroundColor Green
$allintuneuri = "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations?`$expand=*"
##Get all of the policies from Intune
$intunerestrictions = (Invoke-MgGraphRequest -Uri $allintuneuri -Method GET -OutputType PSObject).value | where-object '@odata.type' -eq "#microsoft.graph.deviceEnrollmentLimitConfiguration" | Sort-Object priority
##Get Default (priority of 0)
write-host "Getting Default Intune Restrictions" -ForegroundColor Green
$defaultrestriction = ($intunerestrictions | where-object 'priority' -eq 0).limit
##Add to the array
$userassignmentlimits += $defaultrestriction
write-host "Default Intune Restriction set to $defaultrestriction" -ForegroundColor Green

##Get all Intune Managed Devices
write-host "Getting Intune Managed Devices" -ForegroundColor Green
$alldevicesuri = "https://graph.microsoft.com/beta/deviceManagement/manageddevices/"
$alldevices = (Invoke-MgGraphRequest -Method GET -Uri $alldevicesuri -OutputType PSObject).value

##Find all devices
##Create an array to store the devices and users for counting later
$deviceenroller = @()
##Create an array with device ID and user for looping through in drill-down
$devicesperuser = @()
##Loop through devices, get details and store in custom object within array
write-host "Getting Device Details" -ForegroundColor Green
$counter = 0
foreach ($device in $alldevices) {
    $deviceid = $device.id
    $counter++
    Write-Progress -Activity 'Processing Devices' -CurrentOperation $deviceid -PercentComplete (($counter / $alldevices.count) * 100)
    $deviceenrolleruri = "https://graph.microsoft.com/beta/deviceManagement/manageddevices/$deviceid/users"
    $assignednames = (((Invoke-MgGraphRequest -Method GET -Uri $deviceenrolleruri -OutputType PSObject).value).identities).issuerAssignedId
    ##Add to array
    $deviceenroller += $assignednames
    ##Create object to store device ID and user
    $object = [pscustomobject]@{
        DeviceID = $deviceid
        UserName = $assignednames
    }
    ##Add object to array
    $devicesperuser += $object

}

##Get Group Assigned Enrollment Limits
write-host "Getting Group Assigned Enrollment Limits" -ForegroundColor Green
##Build an empty hash table to use, otherwise it's really slow!
$userpolicies = @()
##Ignore the defaults, we grabbed those earlier
$nondefaultintune = $intunerestrictions | Where-Object 'priority' -ne 0 | Sort-Object priority
foreach ($setlimits in $nondefaultintune) {
    ##Ignore anything not assigned
    if ($null -ne $setlimits.assignments) {
        $priority = $setlimits.priority
        $limit = $setlimits.limit
        $assignid = $setlimits.id
        ##Get Group Assignments for each policy
        $assignmenturi = "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations/" + $assignid + "?`$expand=assignments"
        $individualassignments = ((Invoke-MgGraphRequest -Uri $assignmenturi -Method GET -OutputType PSObject).assignments).target
        foreach ($assignment in $individualassignments) {
            ##Check if user is in the group and add to array
            $groupid = $assignment.groupID
            $policyid = $assignid
            ##Create object to store policy details
            $object = [pscustomobject]@{
                PolicyID = $policyid
                GroupID  = $groupid
                Limit    = $limit
                Priority = $priority
            }
            ##Add to array
            $userpolicies += $object

        }
    }
}

##Get a list of devices and their owners, we'll drill down properly later
write-host "Getting Registered Devices and Owners" -ForegroundColor Green
$registereddeviceuri = "https://graph.microsoft.com/beta/devices?`$expand=registeredOwners"
$allregistered = (Invoke-MgGraphRequest -Uri $registereddeviceuri -Method GET -OutputType PSObject).value | select-object -ExpandProperty RegisteredOwners | select-object ID, userPrincipalName

write-host "Checking  All Users" -ForegroundColor Green
##Now we need to loop through the users
$counter = 0
foreach ($user in $allusers) {
    ##Get User Details
    $userid = $user.id
    $username = $user.DisplayName
    $userupn = $user.UserPrincipalName
    $counter++
    Write-Progress -Activity 'Processing Users' -CurrentOperation $username -PercentComplete (($counter / $allusers.count) * 100)

    ##Get Users Groups
    $groupsuri = "https://graph.microsoft.com/v1.0/users/$userid/memberOf"
    $usergroups = (Invoke-MgGraphRequest -Uri $groupsuri -Method GET -OutputType PSObject).value | Select-Object ID

    ##Get User Assignments
    ##Policies are already in Priority order, loop through until the group hits
    foreach ($policy in $userpolicies) {
        $policygroupid = $policy.GroupID
        if ($usergroups -match $policygroupid) {
            ##Group found, add to array
            $userassignmentlimits += $policy.limit
            ##Stop there, we don't need anything else
            break
        }
    }
    
    ##Grab the final entry which if custom limits assigned will be the highest priority, if not array will only contain defaults anyway
    $lowestassignment = $userassignmentlimits | Select-Object -Last 1

    ##Get User Devices

    ##Check if registered is less than AAD Limit
    $registereddevices = (@($allregistered | where-object userPrincipalName -eq "$userupn" | Select-Object id)).count

    if ($registereddevices -ge $aadrestriction) {
        ##At limit, add to array
        $userdetails = $username + ":" + $userid
        $devicedetails = "Registered Devices - Total of " + $registereddevices + " Devices"
        $usersatrisk.add($userdetails, $devicedetails)
    }

    ##Check if managed is less than Intune limit
    ##Fine Devices for the user
    $devicecount = ($deviceenroller -match $userupn).Count

    if ($devicecount -ge $lowestassignment) {
        ##At limit, add to array
        $userdetails = $username + ":" + $userid
        $devicedetails = "Managed Devices - Total of " + $devicecount + " Devices"
        $usersatrisk.add($userdetails, $devicedetails)
    }

}

if ($automated -eq "No") {
write-host "Output into Grid-View" -ForegroundColor Green
##Output array for further selection
$selecteduser = $usersatrisk | Out-GridView -Title "Users at or above device limit" -OutputMode Single

##Check if Ok has been clicked
$checkforselection = $selecteduser.Name
If ($checkforselection)
{
   ##User Selected, continue
##########################################INDIVIDUAL USER ########################################

##Get User ID
$userid = ($selecteduser.Name -Split (":"))[1]


##Get Intune Limit
##Get User Details
write-host "Getting User Details" -ForegroundColor Green
$user = Get-MgUser -UserId $userid
$username = $user.DisplayName
$userupn = $user.UserPrincipalName
##Get Users Groups
write-host "Getting User Groups" -ForegroundColor Green
$groupsuri = "https://graph.microsoft.com/v1.0/users/$userid/memberOf"
$usergroups = (Invoke-MgGraphRequest -Uri $groupsuri -Method GET -OutputType PSObject).value | Select-Object ID

##Get User Assignments
write-host "Getting User Assignments" -ForegroundColor Green
foreach ($policy in $userpolicies) {
    $policygroupid = $policy.GroupID
    if ($usergroups -match $policygroupid) {
        ##Group found, add to array
        $userassignmentlimits += $policy.limit
        ##Stop there, we don't need anything else
        break
    }
}

$lowestassignment = $userassignmentlimits | Select-Object -Last 1
write-host "Intune Limit is $lowestassignment" -ForegroundColor Green

##Create an array to store device details
$userdevices = @()

##Get Registered Device
write-host "Getting Registered Devices for user $username" -ForegroundColor Green

$registereddeviceuri = "https://graph.microsoft.com/beta/users/$userid/registeredDevices"
$registereddevices = (Invoke-MgGraphRequest -Uri $registereddeviceuri -Method GET -OutputType PSObject).Value

foreach ($registereddevice in $registereddevices) {
    $deviceid = $registereddevice.id
    $displayname = $registereddevice.displayName
    $created = $registereddevice.registrationDateTime
    $lastseen = $registereddevice.approximateLastSignInDateTime
    $object = [pscustomobject]@{
        DeviceID    = $deviceid
        DisplayName = $displayname
        Created     = $created
        LastSeen    = $lastseen
        Type        = "Registered"
    }
    $userdevices += $object
}


##Get Managed Devices
write-host "Getting Managed Devices for user $username" -ForegroundColor Green
$manageddevicesperuser = $devicesperuser | Where-Object UserName -eq "$userupn" | Select-Object DeviceID
foreach ($manageddevice in $manageddevicesperuser) {
    $deviceid = $manageddevice.DeviceID
    $uri = "https://graph.microsoft.com/beta/deviceManagement/manageddevices/$deviceid/"
    $manageddevicedetails = Invoke-MgGraphRequest -Uri $uri -Method GET -OutputType PSObject
    $displayname = $manageddevicedetails.deviceName
    $created = $manageddevicedetails.enrolledDateTime
    $lastseen = $manageddevicedetails.lastSyncDateTime
    $object = [pscustomobject]@{
        DeviceID    = $deviceid
        DisplayName = $displayname
        Created     = $created
        LastSeen    = $lastseen
        Type        = "Managed"
    }
    $userdevices += $object
}

##Loop Through


$Title = "Devices for " + $username + " - AAD Limit: " + $aadrestriction + " - Intune Limit: " + $lowestassignment

$userdevices | Out-GridView -Title $Title

}
Else
{
    ##Nothing selected, exit
   exit
}
}
else {

##Automated, begin email

write-host "Automation started" -ForegroundColor Green
##Create an array to store device details
$userdevices = @()

foreach ($useratrisk in $usersatrisk) {
    ##Get User ID
$userid = ($useratrisk.Keys -Split (":"))[1]


##Get Intune Limit
##Get User Details
write-host "Getting User Details" -ForegroundColor Green
$user = Get-MgUser -UserId $userid
$username = $user.DisplayName
$userupn = $user.UserPrincipalName
##Get Users Groups
write-host "Getting User Groups" -ForegroundColor Green
$groupsuri = "https://graph.microsoft.com/v1.0/users/$userid/memberOf"
$usergroups = (Invoke-MgGraphRequest -Uri $groupsuri -Method GET -OutputType PSObject).value | Select-Object ID

##Get User Assignments
write-host "Getting User Assignments" -ForegroundColor Green
foreach ($policy in $userpolicies) {
    $policygroupid = $policy.GroupID
    if ($usergroups -match $policygroupid) {
        ##Group found, add to array
        $userassignmentlimits += $policy.limit
        ##Stop there, we don't need anything else
        break
    }
}

$lowestassignment = $userassignmentlimits | Select-Object -Last 1
write-host "Intune Limit is $lowestassignment" -ForegroundColor Green


##Get Registered Device
write-host "Getting Registered Devices for user $username" -ForegroundColor Green

$registereddeviceuri = "https://graph.microsoft.com/beta/users/$userid/registeredDevices"
$registereddevices = (Invoke-MgGraphRequest -Uri $registereddeviceuri -Method GET -OutputType PSObject).Value

foreach ($registereddevice in $registereddevices) {
    $deviceid = $registereddevice.id
    $displayname = $registereddevice.displayName
    $created = $registereddevice.registrationDateTime
    $lastseen = $registereddevice.approximateLastSignInDateTime
    $object = [pscustomobject]@{
        DeviceID    = $deviceid
        DisplayName = $displayname
        Created     = $created
        LastSeen    = $lastseen
        Type        = "Registered"
        User        = $userupn
    }
    $userdevices += $object
}


##Get Managed Devices
write-host "Getting Managed Devices for user $username" -ForegroundColor Green
$manageddevicesperuser = $devicesperuser | Where-Object UserName -eq "$userupn" | Select-Object DeviceID
foreach ($manageddevice in $manageddevicesperuser) {
    $deviceid = $manageddevice.DeviceID
    $uri = "https://graph.microsoft.com/beta/deviceManagement/manageddevices/$deviceid/"
    $manageddevicedetails = Invoke-MgGraphRequest -Uri $uri -Method GET -OutputType PSObject
    $displayname = $manageddevicedetails.deviceName
    $created = $manageddevicedetails.enrolledDateTime
    $lastseen = $manageddevicedetails.lastSyncDateTime
    $object = [pscustomobject]@{
        DeviceID    = $deviceid
        DisplayName = $displayname
        Created     = $created
        LastSeen    = $lastseen
        Type        = "Managed"
        User        = $userupn
    }
    $userdevices += $object
}

}

function ConvertTo-StringData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [HashTable[]]$HashTable
    )
    process {
        foreach ($item in $HashTable) {
            foreach ($entry in $item.GetEnumerator()) {
                "{0}   <br>   {1}" -f $entry.Key, $entry.Value
            }
        }
    }
}

$listofusers = $usersatrisk | ConvertTo-StringData
$listofdevices = $userdevices | out-string

#Send Mail    
$URLsend = "https://graph.microsoft.com/v1.0/users/$MailSender/sendMail"
$BodyJsonsend = @"
                    {
                        "message": {
                          "subject": "Users at Enrollment Limit",
                          "body": {
                            "contentType": "HTML",
                            "content": "The following users are on or over their limit<br>
                            $listofusers <br>
                            Devices: <br>
                            $listofdevices
                            "
                          },
                          "toRecipients": [
                            {
                              "emailAddress": {
                                "address": "$EmailAddress"
                              }
                            }
                          ]
                        },
                        "saveToSentItems": "false"
                      }
"@

Invoke-MgGraphRequest -Method POST -Uri $URLsend -Body $BodyJsonsend


}