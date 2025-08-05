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
  Version:        1.0.4
  Author:         Andrew Taylor
  WWW:            andrewstaylor.com
  Creation Date:  09/01/2023
  Purpose/Change: Initial script development
  Change: 05/08/2025 - Added scope
 
.EXAMPLE
N/A
#>

<#PSScriptInfo
.VERSION 1.0.4
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
Connect-ToGraph -Scopes "Device.Read.All, User.Read.All, Domain.Read.All, Directory.Read.All, DeviceManagementManagedDevices.ReadWrite.All, DeviceManagementServiceConfig.Read.All, openid, profile, email, offline_access, Mail.Send"

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
# SIG # Begin signature block
# MIIoUAYJKoZIhvcNAQcCoIIoQTCCKD0CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBgnFD6JclQnOYZ
# 8sre92PnLgG09V1SncZvqUx1oLgTvaCCIU0wggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggawMIIEmKADAgECAhAIrUCyYNKcTJ9ezam9k67ZMA0GCSqG
# SIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDAeFw0yMTA0MjkwMDAwMDBaFw0zNjA0MjgyMzU5NTlaMGkx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEzODQg
# MjAyMSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDVtC9C0Cit
# eLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYwn6SOaNhc9es0JAfhS0/TeEP0F9ce2vnS
# 1WcaUk8OoVf8iJnBkcyBAz5NcCRks43iCH00fUyAVxJrQ5qZ8sU7H/Lvy0daE6ZM
# swEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1hz1RGeiQIXhFLqGfLOEYwhrMxe6TSXBC
# Mo/7xuoc82VokaJNTIIRSFJo3hC9FFdd6BgTZcV/sk+FLEikVoQ11vkunKoAFdE3
# /hoGlMJ8yOobMubKwvSnowMOdKWvObarYBLj6Na59zHh3K3kGKDYwSNHR7OhD26j
# q22YBoMbt2pnLdK9RBqSEIGPsDsJ18ebMlrC/2pgVItJwZPt4bRc4G/rJvmM1bL5
# OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYoX7BzzosmJQayg9Rc9hUZTO1i4F4z8ujo
# 7AqnsAMrkbI2eb73rQgedaZlzLvjSFDzd5Ea/ttQokbIYViY9XwCFjyDKK05huzU
# tw1T0PhH5nUwjewwk3YUpltLXXRhTT8SkXbev1jLchApQfDVxW0mdmgRQRNYmtwm
# KwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZYIpkVMHMIRroOBl8ZhzNeDhFMJlP/2NP
# TLuqDQhTQXxYPUez+rbsjDIJAsxsPAxWEQIDAQABo4IBWTCCAVUwEgYDVR0TAQH/
# BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg67Y7+F8Rhvv+YXsIiGX0TkIwHwYDVR0j
# BBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0
# cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8E
# PDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVz
# dGVkUm9vdEc0LmNybDAcBgNVHSAEFTATMAcGBWeBDAEDMAgGBmeBDAEEATANBgkq
# hkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6PvDqZ01bgAhql+Eg08yy25nRm95RysQDK
# r2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V1T9J9Ce7FoFFUP2cvbaF4HZ+N3HLIvda
# qpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+3NiAGhEZGM1hmYFW9snjdufE5BtfQ/g+
# lP92OT2e1JnPSt0o618moZVYSNUa/tcnP/2Q0XaG3RywYFzzDaju4ImhvTnhOE7a
# brs2nfvlIVNaw8rpavGiPttDuDPITzgUkpn13c5UbdldAhQfQDN8A+KVssIhdXNS
# y0bYxDQcoqVLjc1vdjcshT8azibpGL6QB7BDf5WIIIJw8MzK7/0pNVwfiThV9zeK
# iwmhywvpMRr/LhlcOXHhvpynCgbWJme3kuZOX956rEnPLqR0kq3bPKSchh/jwVYb
# KyP/j7XqiHtwa+aguv06P0WmxOgWkVKLQcBIhEuWTatEQOON8BUozu3xGFYHKi8Q
# xAwIZDwzj64ojDzLj4gLDb879M4ee47vtevLt/B3E+bnKD+sEq6lLyJsQfmCXBVm
# zGwOysWGw/YmMwwHS6DTBwJqakAwSEs0qFEgu60bhQjiWQ1tygVQK+pKHJ6l/aCn
# HwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0YW6/aOImYIbqyK+p/pQd52MbOoZWeE4w
# gga0MIIEnKADAgECAhANx6xXBf8hmS5AQyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIx
# CzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3
# dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBH
# NDAeFw0yNTA1MDcwMDAwMDBaFw0zODAxMTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVT
# MRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1
# c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0eDHTCphBcr48RsAcrHXbo0Zo
# dLRRF51NrY0NlLWZloMsVO1DahGPNRcybEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi
# 6wuim5bap+0lgloM2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNg
# xVBdJkf77S2uPoCj7GH8BLuxBG5AvftBdsOECS1UkxBvMgEdgkFiDNYiOTx4OtiF
# cMSkqTtF2hfQz3zQSku2Ws3IfDReb6e3mmdglTcaarps0wjUjsZvkgFkriK9tUKJ
# m/s80FiocSk1VYLZlDwFt+cVFBURJg6zMUjZa/zbCclF83bRVFLeGkuAhHiGPMvS
# GmhgaTzVyhYn4p0+8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1
# ZlAeSpQl92QOMeRxykvq6gbylsXQskBBBnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9
# MmeOreGPRdtBx3yGOP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL6s36czwzsucuoKs7
# Yk/ehb//Wx+5kMqIMRvUBDx6z1ev+7psNOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bG
# RinZbI4OLu9BMIFm1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6
# X5uAiynM7Bu2ayBjUwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAd
# BgNVHQ4EFgQU729TSunkBnx6yuKQVvYv1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJx
# XWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUF
# BwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGln
# aWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJo
# dHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNy
# bDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQEL
# BQADggIBABfO+xaAHP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxj
# aaFdleMM0lBryPTQM2qEJPe36zwbSI/mS83afsl3YTj+IQhQE7jU/kXjjytJgnn0
# hvrV6hqWGd3rLAUt6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9rEVKChHyfpzee5kH0
# F8HABBgr0UdqirZ7bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y1IsA0QF8dTXqvcnT
# mpfeQh35k5zOCPmSNq1UH410ANVko43+Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKf
# ZxAvBAKqMVuqte69M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3ty9qIijanrUR3anzE
# wlvzZiiyfTPjLbnFRsjsYg39OlV8cipDoq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbh
# OhZ3ZRDUphPvSRmMThi0vw9vODRzW6AxnJll38F0cuJG7uEBYTptMSbhdhGQDpOX
# gpIUsWTjd6xpR6oaQf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud/v4+7RWsWCiKi9EO
# LLHfMR2ZyJ/+xhCx9yHbxtl5TPau1j/1MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wG
# WqbIiOWCnb5WqxL3/BAPvIXKUjPSxyZsq8WhbaM2tszWkPZPubdcMIIG7TCCBNWg
# AwIBAgIQCoDvGEuN8QWC0cR2p5V0aDANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQG
# EwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0
# IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0Ex
# MB4XDTI1MDYwNDAwMDAwMFoXDTM2MDkwMzIzNTk1OVowYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEy
# NTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZI
# hvcNAQEBBQADggIPADCCAgoCggIBANBGrC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3
# zBlCMGMyqJnfFNZx+wvA69HFTBdwbHwBSOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8Tch
# TySA2R4QKpVD7dvNZh6wW2R6kSu9RJt/4QhguSssp3qome7MrxVyfQO9sMx6ZAWj
# FDYOzDi8SOhPUWlLnh00Cll8pjrUcCV3K3E0zz09ldQ//nBZZREr4h/GI6Dxb2Uo
# yrN0ijtUDVHRXdmncOOMA3CoB/iUSROUINDT98oksouTMYFOnHoRh6+86Ltc5zjP
# KHW5KqCvpSduSwhwUmotuQhcg9tw2YD3w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KS
# uNLoZLc1Hf2JNMVL4Q1OpbybpMe46YceNA0LfNsnqcnpJeItK/DhKbPxTTuGoX7w
# JNdoRORVbPR1VVnDuSeHVZlc4seAO+6d2sC26/PQPdP51ho1zBp+xUIZkpSFA8vW
# doUoHLWnqWU3dCCyFG1roSrgHjSHlq8xymLnjCbSLZ49kPmk8iyyizNDIXj//cOg
# rY7rlRyTlaCCfw7aSUROwnu7zER6EaJ+AliL7ojTdS5PWPsWeupWs7NpChUk555K
# 096V1hE0yZIXe+giAwW00aHzrDchIc2bQhpp0IoKRR7YufAkprxMiXAJQ1XCmnCf
# gPf8+3mnAgMBAAGjggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zy
# Me39/dfzkXFjGVBDz2GM6DAfBgNVHSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezL
# TjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsG
# AQUFBwEBBIGIMIGFMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5j
# b20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdp
# Q2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNy
# dDBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGln
# aUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5j
# cmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEB
# CwUAA4ICAQBlKq3xHCcEua5gQezRCESeY0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZ
# D9gBq9fNaNmFj6Eh8/YmRDfxT7C0k8FUFqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/
# ML9lFfim8/9yJmZSe2F8AQ/UdKFOtj7YMTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu
# +WUqW4daIqToXFE/JQ/EABgfZXLWU0ziTN6R3ygQBHMUBaB5bdrPbF6MRYs03h4o
# bEMnxYOX8VBRKe1uNnzQVTeLni2nHkX/QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2h
# ECZpqyU1d0IbX6Wq8/gVutDojBIFeRlqAcuEVT0cKsb+zJNEsuEB7O7/cuvTQasn
# M9AWcIQfVjnzrvwiCZ85EE8LUkqRhoS3Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol
# /DJgddJ35XTxfUlQ+8Hggt8l2Yv7roancJIFcbojBcxlRcGG0LIhp6GvReQGgMgY
# xQbV1S3CrWqZzBt1R9xJgKf47CdxVRd/ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3oc
# CVccAvlKV9jEnstrniLvUxxVZE/rptb7IRE2lskKPIJgbaP5t2nGj/ULLi49xTcB
# ZU8atufk+EMF/cWuiC7POGT75qaL6vdCvHlshtjdNXOCIUjsarfNZzCCB1swggVD
# oAMCAQICEAixn82z2vOwMVVYCAEvAOkwDQYJKoZIhvcNAQELBQAwaTELMAkGA1UE
# BhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2Vy
# dCBUcnVzdGVkIEc0IENvZGUgU2lnbmluZyBSU0E0MDk2IFNIQTM4NCAyMDIxIENB
# MTAeFw0yMzExMTUwMDAwMDBaFw0yNjExMTcyMzU5NTlaMGMxCzAJBgNVBAYTAkdC
# MRQwEgYDVQQHEwtXaGl0bGV5IEJheTEeMBwGA1UEChMVQU5EUkVXU1RBWUxPUi5D
# T00gTFREMR4wHAYDVQQDExVBTkRSRVdTVEFZTE9SLkNPTSBMVEQwggIiMA0GCSqG
# SIb3DQEBAQUAA4ICDwAwggIKAoICAQDDpGJC6czR+GNYFFxe/fbhdAq8Fvy5nuu+
# vgvWmTiWM6at/wyGvNaFr/W+G9FsC6SVbtHzpAJsSOqHLuLn+td4wzFtBn1eHUaH
# bra8n7g7oreK53byQOgyLNGBucTZSk5GPACLwT9yMBM1A9X+eyeRogKaxxnqHOFL
# bcxLhgN8kqpbBhINIAnoVic51JId8jPF25LAtC7gZp2P3WSf/JLQsAnd/IH2RDvV
# Aw0pInuFU2N0+1RW04mh9G8PgL33EFctgksJMH55H2GoEhZCmq/jGMLu4KlV8a4d
# 1fxo72pej3TNAOxHE6ps6wkbb5FiEem6c/twCB+ha+sk7ht14iyC+rCv4hf/XeFN
# j4h9byf8X3YRo9K0N/zQUbFAQt5dcONS+avVF9TodZU9TrieoVf7mp5OiWN46Zvj
# n2e2Akxdh5M+cuofU+7GNC04uvFZrcWvxIBLRuiVTVbKj+1sBJEEcbv99KrY8qF/
# J80rhe05rEYJmdUgfiEnJXo7qkzXYXMnA4Yt/yCEoFSTUUvxemflUBn934ejm3UC
# 1cKE9CZyY2w/D8yddjqCoFYk0IZ3WmW5H6YlYnydbs1ia01ucBKx/qr7rR1beP7B
# GQFUuDzXznCV0dLNPy+SR5I7TOGhpetnwB4x4/SbApbrI+O3E+o0TiKkCOHo89bJ
# TqHJTnrQjQIDAQABo4ICAzCCAf8wHwYDVR0jBBgwFoAUaDfg67Y7+F8Rhvv+YXsI
# iGX0TkIwHQYDVR0OBBYEFNB3ThXz8WvWHm+TuSfVBIiZKyvfMD4GA1UdIAQ3MDUw
# MwYGZ4EMAQQBMCkwJwYIKwYBBQUHAgEWG2h0dHA6Ly93d3cuZGlnaWNlcnQuY29t
# L0NQUzAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwgbUGA1Ud
# HwSBrTCBqjBToFGgT4ZNaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
# VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAyMUNBMS5jcmwwU6BR
# oE+GTWh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENv
# ZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3JsMIGUBggrBgEFBQcBAQSB
# hzCBhDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMFwGCCsG
# AQUFBzAChlBodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVz
# dGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEzODQyMDIxQ0ExLmNydDAJBgNVHRME
# AjAAMA0GCSqGSIb3DQEBCwUAA4ICAQBJEYdj8DIsq2r6+umcMOj45duCsw3BmDEs
# VCjhFOG8pHDioL0ulds3mSLNA/6KnLd4QSkxhEkkFkgPyZK9RDAtOKiRzv08K/7A
# QwgwTLSfVwLTu+SfqKg3HDPoPD6Po44amCcyr24rFVL3bD6hZZeeb0s0bxxgAOoY
# 8g8mpBi0TnDWkhWRnYDitgDIUPBFC6xPEYq4tw9UTrqhplFiqnDvWqjxwX+cFMIm
# vIPfNLE16rjuYOE1pGakr8LdQRzJruvTEepaEQCtex7xXEonCuj5tM4ndSkts+J7
# RgeAn3IPPGhS6IN3Ij9rXzItsU56jdSvmJlPPeD5dZQqdcRb0+qa5tdAbOgVYil3
# w31RcV0wdJh6AzahovwfPq8X9s+7uX6FzwswWE/kN3MbaKb2bZNvTKU2PPBhw1Sb
# BTAY1+8zOmgjSrEygto2/dhfo5ZHPHJQkEJ5d1OI6sG4+Lq9SQT+UMUKa1ocHXtP
# jInw1adLx2bFWdKZ2DAikhuW1K98DlOxD99tQ8L7xLE4wsv1w4L8vIqVOsNxo3EE
# BZoKfwV/9CQh1/tOECdCZEfU0xWUdQfs4dwnCtWRLU7b7mX40N74l8JcLTS8uN72
# 3tSeVjU7NB4yV7H3W4WOZBOUYcn2sRQa9tSmMfm/nr2MqJSEtMEejXsOhai4HHOB
# nveMmmFU6jGCBlkwggZVAgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IENvZGUg
# U2lnbmluZyBSU0E0MDk2IFNIQTM4NCAyMDIxIENBMQIQCLGfzbPa87AxVVgIAS8A
# 6TANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkG
# CSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEE
# AYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBWIQ/4FesKz8KfX6ICPTtXvnrQ0EAhVp3l
# UYQDJCMTyTANBgkqhkiG9w0BAQEFAASCAgAq8h+Q4NcEciOUx9gFcRc95DNp/oX6
# W7FvKsG+x5eaDNdzc7/3oLxX/3pojpvVba9jJQKaawO28ejaGWZGyLdJlUBvzKgK
# 5ri4JP+Fpte51TAQ1hjc4FZzTltlx7pPe1TLCyXh9CI8LhVG+7W7tKn9cb6xMeNf
# OYsZiwbWeJH1g9anNlAih7CVBK/CwKP9hoxt1FqMzQwy6wWU/Ps2/mJz1vkLtVuJ
# gI5BMaJStFcwfr6ORKWkVGSF7AOxXTFY9u8XCD+90ux9KCcRNFeGHQxbLMUU47JG
# AXZlof5hPQSp8DL9SPH0Hjl+rJgSKV/LOtKegO2H7bmJD/GQoTspgbEZy5GxrDa9
# XukCUfu6mm59e4VMbRvod6UkTokuPvKi7jQjmrHu6AdGKH5LW/PpkMzfD3lIpIzS
# oSjSVZ6HQO1DSowiuCs1UzmQ8K5JSfZRyhDcRDpxyr9tvTt1hr6/TebOTfd547PJ
# AzIOma/lqulj1Lg7GMbdxNLOTu+rR5mMqlgeyWg7oLBdoHkY2wWYY8RgRZMd63Tn
# ZloWSTSHmmwF9qwWPpjlaGDeiIrN8WsPKK9OubMziJmMWjbco2jmII7yLouZvDeB
# +VUsMOPFRX0ac4NJxiNWZF+JltCjvMYmHkjQ6j6Nattm3IlZvZ3Le4JwLf5ELzbO
# 6E/0of+xRSAf9qGCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJ
# BgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGln
# aUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAy
# NSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG
# 9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNTA4MDUxNjU2MzVa
# MC8GCSqGSIb3DQEJBDEiBCAZqNr408aN9eEm2cPcl0KWJzsBi/amk7nDmzoCG4hL
# AjANBgkqhkiG9w0BAQEFAASCAgDL0ZdAwRn2Yq/8dgQlUa/V/UyemrzyAAMg6rKU
# vg/h26sLR7gmvW7p0dNJjuo3kXqg8wD904veCsUUVH038yroUL2simMpMiq76h/x
# e0ERGcF93Rtd8KpjdygoCiihn26eBNe/CGElai64/6V0558XVRtf6crY2bdjcm59
# JzMl60WaqThd574x6UDXCPyc8/D6jU5vB3+UXrKNV7vOtYUgRdbyeZwtTADbUuVS
# HpulcV/w57A8CyZnab7cxeuVhWggm6r+SfhdX7761fDCyvMSsXS+aBvTw+Vt1wZO
# xOurtyseD0SVL0LD8Lt+Zd32eU5qA2CdSM3Dttl41Q5Hgs2kXajILomrTskj9Qra
# CpqikmJcNDxMmY4VoksNK/U6YFA5fVlWPgLiuk+FYijIdcpDkeeeDfB+2U/QwJgl
# nOA4v8fcnYw9hDRqmC4jPaBLzwgkAxYU8bBX0wcfVbVXDpQzImm+RcpArsrLjNto
# Sjnu0V8DjyDlGWkmFbKtFWxYPv3SaE9bgMwmPbVOFvw6GMqAJ7CpPawiylrSX2UG
# 14RXitRWse8bnp0tp7Ri4CrP9UcVC6usWh1bnLefrBM/rohpq859i+ADOyWUZRf+
# 7HUBo+1DW9woOexEfxQfABFLsglmi+c6j4ZRpxTzdBt1WSgjCZ0sxVhlfVgA5LZ/
# ipBQwA==
# SIG # End signature block
