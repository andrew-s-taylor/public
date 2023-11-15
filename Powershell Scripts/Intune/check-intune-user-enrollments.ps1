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
  Version:        1.0.3
  Author:         Andrew Taylor
  WWW:            andrewstaylor.com
  Creation Date:  09/01/2023
  Purpose/Change: Initial script development
 
.EXAMPLE
N/A
#>

<#PSScriptInfo
.VERSION 1.0.3
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
# SIG # Begin signature block
# MIIoGQYJKoZIhvcNAQcCoIIoCjCCKAYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDQNoqb5euNCn/8
# MeceVhH4jRvSE79dYKNTzcdVGzzIbaCCIRwwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# twGpn1eqXijiuZQwggauMIIElqADAgECAhAHNje3JFR82Ees/ShmKl5bMA0GCSqG
# SIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDAeFw0yMjAzMjMwMDAwMDBaFw0zNzAzMjIyMzU5NTlaMGMx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMy
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcg
# Q0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDGhjUGSbPBPXJJUVXH
# JQPE8pE3qZdRodbSg9GeTKJtoLDMg/la9hGhRBVCX6SI82j6ffOciQt/nR+eDzMf
# UBMLJnOWbfhXqAJ9/UO0hNoR8XOxs+4rgISKIhjf69o9xBd/qxkrPkLcZ47qUT3w
# 1lbU5ygt69OxtXXnHwZljZQp09nsad/ZkIdGAHvbREGJ3HxqV3rwN3mfXazL6IRk
# tFLydkf3YYMZ3V+0VAshaG43IbtArF+y3kp9zvU5EmfvDqVjbOSmxR3NNg1c1eYb
# qMFkdECnwHLFuk4fsbVYTXn+149zk6wsOeKlSNbwsDETqVcplicu9Yemj052FVUm
# cJgmf6AaRyBD40NjgHt1biclkJg6OBGz9vae5jtb7IHeIhTZgirHkr+g3uM+onP6
# 5x9abJTyUpURK1h0QCirc0PO30qhHGs4xSnzyqqWc0Jon7ZGs506o9UD4L/wojzK
# QtwYSH8UNM/STKvvmz3+DrhkKvp1KCRB7UK/BZxmSVJQ9FHzNklNiyDSLFc1eSuo
# 80VgvCONWPfcYd6T/jnA+bIwpUzX6ZhKWD7TA4j+s4/TXkt2ElGTyYwMO1uKIqjB
# Jgj5FBASA31fI7tk42PgpuE+9sJ0sj8eCXbsq11GdeJgo1gJASgADoRU7s7pXche
# MBK9Rp6103a50g5rmQzSM7TNsQIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB
# /wIBADAdBgNVHQ4EFgQUuhbZbU2FL3MpdpovdYxqII+eyG8wHwYDVR0jBBgwFoAU
# 7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoG
# CCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29j
# c3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDig
# NqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZI
# hvcNAQELBQADggIBAH1ZjsCTtm+YqUQiAX5m1tghQuGwGC4QTRPPMFPOvxj7x1Bd
# 4ksp+3CKDaopafxpwc8dB+k+YMjYC+VcW9dth/qEICU0MWfNthKWb8RQTGIdDAiC
# qBa9qVbPFXONASIlzpVpP0d3+3J0FNf/q0+KLHqrhc1DX+1gtqpPkWaeLJ7giqzl
# /Yy8ZCaHbJK9nXzQcAp876i8dU+6WvepELJd6f8oVInw1YpxdmXazPByoyP6wCeC
# RK6ZJxurJB4mwbfeKuv2nrF5mYGjVoarCkXJ38SNoOeY+/umnXKvxMfBwWpx2cYT
# gAnEtp/Nh4cku0+jSbl3ZpHxcpzpSwJSpzd+k1OsOx0ISQ+UzTl63f8lY5knLD0/
# a6fxZsNBzU+2QJshIUDQtxMkzdwdeDrknq3lNHGS1yZr5Dhzq6YBT70/O3itTK37
# xJV77QpfMzmHQXh6OOmc4d0j/R0o08f56PGYX/sr2H7yRp11LB4nLCbbbxV7HhmL
# NriT1ObyF5lZynDwN7+YAN8gFk8n+2BnFqFmut1VwDophrCYoCvtlUG3OtUVmDG0
# YgkPCr2B2RP+v6TR81fZvAT6gt4y3wSJ8ADNXcL50CN/AAvkdgIm2fBldkKmKYcJ
# RyvmfxqkhQ/8mJb2VVQrH4D6wPIOK+XW+6kvRBVK5xMOHds3OBqhK/bt1nz8MIIG
# sDCCBJigAwIBAgIQCK1AsmDSnEyfXs2pvZOu2TANBgkqhkiG9w0BAQwFADBiMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQw
# HhcNMjEwNDI5MDAwMDAwWhcNMzYwNDI4MjM1OTU5WjBpMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0
# ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExMIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1bQvQtAorXi3XdU5WRuxiEL1M4zr
# PYGXcMW7xIUmMJ+kjmjYXPXrNCQH4UtP03hD9BfXHtr50tVnGlJPDqFX/IiZwZHM
# gQM+TXAkZLON4gh9NH1MgFcSa0OamfLFOx/y78tHWhOmTLMBICXzENOLsvsI8Irg
# nQnAZaf6mIBJNYc9URnokCF4RS6hnyzhGMIazMXuk0lwQjKP+8bqHPNlaJGiTUyC
# EUhSaN4QvRRXXegYE2XFf7JPhSxIpFaENdb5LpyqABXRN/4aBpTCfMjqGzLmysL0
# p6MDDnSlrzm2q2AS4+jWufcx4dyt5Big2MEjR0ezoQ9uo6ttmAaDG7dqZy3SvUQa
# khCBj7A7CdfHmzJawv9qYFSLScGT7eG0XOBv6yb5jNWy+TgQ5urOkfW+0/tvk2E0
# XLyTRSiDNipmKF+wc86LJiUGsoPUXPYVGUztYuBeM/Lo6OwKp7ADK5GyNnm+960I
# HnWmZcy740hQ83eRGv7bUKJGyGFYmPV8AhY8gyitOYbs1LcNU9D4R+Z1MI3sMJN2
# FKZbS110YU0/EpF23r9Yy3IQKUHw1cVtJnZoEUETWJrcJisB9IlNWdt4z4FKPkBH
# X8mBUHOFECMhWWCKZFTBzCEa6DgZfGYczXg4RTCZT/9jT0y7qg0IU0F8WD1Hs/q2
# 7IwyCQLMbDwMVhECAwEAAaOCAVkwggFVMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYD
# VR0OBBYEFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB8GA1UdIwQYMBaAFOzX44LScV1k
# TN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcD
# AzB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2lj
# ZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0
# cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmww
# HAYDVR0gBBUwEzAHBgVngQwBAzAIBgZngQwBBAEwDQYJKoZIhvcNAQEMBQADggIB
# ADojRD2NCHbuj7w6mdNW4AIapfhINPMstuZ0ZveUcrEAyq9sMCcTEp6QRJ9L/Z6j
# fCbVN7w6XUhtldU/SfQnuxaBRVD9nL22heB2fjdxyyL3WqqQz/WTauPrINHVUHmI
# moqKwba9oUgYftzYgBoRGRjNYZmBVvbJ43bnxOQbX0P4PpT/djk9ntSZz0rdKOtf
# JqGVWEjVGv7XJz/9kNF2ht0csGBc8w2o7uCJob054ThO2m67Np375SFTWsPK6Wrx
# oj7bQ7gzyE84FJKZ9d3OVG3ZXQIUH0AzfAPilbLCIXVzUstG2MQ0HKKlS43Nb3Y3
# LIU/Gs4m6Ri+kAewQ3+ViCCCcPDMyu/9KTVcH4k4Vfc3iosJocsL6TEa/y4ZXDlx
# 4b6cpwoG1iZnt5LmTl/eeqxJzy6kdJKt2zyknIYf48FWGysj/4+16oh7cGvmoLr9
# Oj9FpsToFpFSi0HASIRLlk2rREDjjfAVKM7t8RhWByovEMQMCGQ8M4+uKIw8y4+I
# Cw2/O/TOHnuO77Xry7fwdxPm5yg/rBKupS8ibEH5glwVZsxsDsrFhsP2JjMMB0ug
# 0wcCampAMEhLNKhRILutG4UI4lkNbcoFUCvqShyepf2gpx8GdOfy1lKQ/a+FSCH5
# Vzu0nAPthkX0tGFuv2jiJmCG6sivqf6UHedjGzqGVnhOMIIGwjCCBKqgAwIBAgIQ
# BUSv85SdCDmmv9s/X+VhFjANBgkqhkiG9w0BAQsFADBjMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0
# ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMB4XDTIzMDcxNDAw
# MDAwMFoXDTM0MTAxMzIzNTk1OVowSDELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMSAwHgYDVQQDExdEaWdpQ2VydCBUaW1lc3RhbXAgMjAyMzCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKNTRYcdg45brD5UsyPgz5/X
# 5dLnXaEOCdwvSKOXejsqnGfcYhVYwamTEafNqrJq3RApih5iY2nTWJw1cb86l+uU
# UI8cIOrHmjsvlmbjaedp/lvD1isgHMGXlLSlUIHyz8sHpjBoyoNC2vx/CSSUpIIa
# 2mq62DvKXd4ZGIX7ReoNYWyd/nFexAaaPPDFLnkPG2ZS48jWPl/aQ9OE9dDH9kgt
# XkV1lnX+3RChG4PBuOZSlbVH13gpOWvgeFmX40QrStWVzu8IF+qCZE3/I+PKhu60
# pCFkcOvV5aDaY7Mu6QXuqvYk9R28mxyyt1/f8O52fTGZZUdVnUokL6wrl76f5P17
# cz4y7lI0+9S769SgLDSb495uZBkHNwGRDxy1Uc2qTGaDiGhiu7xBG3gZbeTZD+BY
# QfvYsSzhUa+0rRUGFOpiCBPTaR58ZE2dD9/O0V6MqqtQFcmzyrzXxDtoRKOlO0L9
# c33u3Qr/eTQQfqZcClhMAD6FaXXHg2TWdc2PEnZWpST618RrIbroHzSYLzrqawGw
# 9/sqhux7UjipmAmhcbJsca8+uG+W1eEQE/5hRwqM/vC2x9XH3mwk8L9CgsqgcT2c
# kpMEtGlwJw1Pt7U20clfCKRwo+wK8REuZODLIivK8SgTIUlRfgZm0zu++uuRONhR
# B8qUt+JQofM604qDy0B7AgMBAAGjggGLMIIBhzAOBgNVHQ8BAf8EBAMCB4AwDAYD
# VR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAgBgNVHSAEGTAXMAgG
# BmeBDAEEAjALBglghkgBhv1sBwEwHwYDVR0jBBgwFoAUuhbZbU2FL3MpdpovdYxq
# II+eyG8wHQYDVR0OBBYEFKW27xPn783QZKHVVqllMaPe1eNJMFoGA1UdHwRTMFEw
# T6BNoEuGSWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRH
# NFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcmwwgZAGCCsGAQUFBwEBBIGD
# MIGAMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wWAYIKwYB
# BQUHMAKGTGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0
# ZWRHNFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcnQwDQYJKoZIhvcNAQEL
# BQADggIBAIEa1t6gqbWYF7xwjU+KPGic2CX/yyzkzepdIpLsjCICqbjPgKjZ5+PF
# 7SaCinEvGN1Ott5s1+FgnCvt7T1IjrhrunxdvcJhN2hJd6PrkKoS1yeF844ektrC
# QDifXcigLiV4JZ0qBXqEKZi2V3mP2yZWK7Dzp703DNiYdk9WuVLCtp04qYHnbUFc
# jGnRuSvExnvPnPp44pMadqJpddNQ5EQSviANnqlE0PjlSXcIWiHFtM+YlRpUurm8
# wWkZus8W8oM3NG6wQSbd3lqXTzON1I13fXVFoaVYJmoDRd7ZULVQjK9WvUzF4UbF
# KNOt50MAcN7MmJ4ZiQPq1JE3701S88lgIcRWR+3aEUuMMsOI5ljitts++V+wQtaP
# 4xeR0arAVeOGv6wnLEHQmjNKqDbUuXKWfpd5OEhfysLcPTLfddY2Z1qJ+Panx+VP
# NTwAvb6cKmx5AdzaROY63jg7B145WPR8czFVoIARyxQMfq68/qTreWWqaNYiyjvr
# moI1VygWy2nyMpqy0tg6uLFGhmu6F/3Ed2wVbK6rr3M66ElGt9V/zLY4wNjsHPW2
# obhDLN9OTH0eaHDAdwrUAuBcYLso/zjlUlrWrBciI0707NMX+1Br/wd3H3GXREHJ
# uEbTbDJ8WC9nR2XlG3O2mflrLAZG70Ee8PBf4NvZrZCARK+AEEGKMIIHWzCCBUOg
# AwIBAgIQCLGfzbPa87AxVVgIAS8A6TANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQG
# EwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0
# IFRydXN0ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0Ex
# MB4XDTIzMTExNTAwMDAwMFoXDTI2MTExNzIzNTk1OVowYzELMAkGA1UEBhMCR0Ix
# FDASBgNVBAcTC1doaXRsZXkgQmF5MR4wHAYDVQQKExVBTkRSRVdTVEFZTE9SLkNP
# TSBMVEQxHjAcBgNVBAMTFUFORFJFV1NUQVlMT1IuQ09NIExURDCCAiIwDQYJKoZI
# hvcNAQEBBQADggIPADCCAgoCggIBAMOkYkLpzNH4Y1gUXF799uF0CrwW/Lme676+
# C9aZOJYzpq3/DIa81oWv9b4b0WwLpJVu0fOkAmxI6ocu4uf613jDMW0GfV4dRodu
# tryfuDuit4rndvJA6DIs0YG5xNlKTkY8AIvBP3IwEzUD1f57J5GiAprHGeoc4Utt
# zEuGA3ySqlsGEg0gCehWJznUkh3yM8XbksC0LuBmnY/dZJ/8ktCwCd38gfZEO9UD
# DSkie4VTY3T7VFbTiaH0bw+AvfcQVy2CSwkwfnkfYagSFkKar+MYwu7gqVXxrh3V
# /Gjval6PdM0A7EcTqmzrCRtvkWIR6bpz+3AIH6Fr6yTuG3XiLIL6sK/iF/9d4U2P
# iH1vJ/xfdhGj0rQ3/NBRsUBC3l1w41L5q9UX1Oh1lT1OuJ6hV/uank6JY3jpm+Of
# Z7YCTF2Hkz5y6h9T7sY0LTi68Vmtxa/EgEtG6JVNVsqP7WwEkQRxu/30qtjyoX8n
# zSuF7TmsRgmZ1SB+ISclejuqTNdhcycDhi3/IISgVJNRS/F6Z+VQGf3fh6ObdQLV
# woT0JnJjbD8PzJ12OoKgViTQhndaZbkfpiVifJ1uzWJrTW5wErH+qvutHVt4/sEZ
# AVS4PNfOcJXR0s0/L5JHkjtM4aGl62fAHjHj9JsClusj47cT6jROIqQI4ejz1slO
# oclOetCNAgMBAAGjggIDMIIB/zAfBgNVHSMEGDAWgBRoN+Drtjv4XxGG+/5hewiI
# ZfROQjAdBgNVHQ4EFgQU0HdOFfPxa9Yeb5O5J9UEiJkrK98wPgYDVR0gBDcwNTAz
# BgZngQwBBAEwKTAnBggrBgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20v
# Q1BTMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzCBtQYDVR0f
# BIGtMIGqMFOgUaBPhk1odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEzODQyMDIxQ0ExLmNybDBToFGg
# T4ZNaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29k
# ZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAyMUNBMS5jcmwwgZQGCCsGAQUFBwEBBIGH
# MIGEMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXAYIKwYB
# BQUHMAKGUGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0
# ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3J0MAkGA1UdEwQC
# MAAwDQYJKoZIhvcNAQELBQADggIBAEkRh2PwMiyravr66Zww6Pjl24KzDcGYMSxU
# KOEU4bykcOKgvS6V2zeZIs0D/oqct3hBKTGESSQWSA/Jkr1EMC04qJHO/Twr/sBD
# CDBMtJ9XAtO75J+oqDccM+g8Po+jjhqYJzKvbisVUvdsPqFll55vSzRvHGAA6hjy
# DyakGLROcNaSFZGdgOK2AMhQ8EULrE8Riri3D1ROuqGmUWKqcO9aqPHBf5wUwia8
# g980sTXquO5g4TWkZqSvwt1BHMmu69MR6loRAK17HvFcSicK6Pm0zid1KS2z4ntG
# B4Cfcg88aFLog3ciP2tfMi2xTnqN1K+YmU894Pl1lCp1xFvT6prm10Bs6BViKXfD
# fVFxXTB0mHoDNqGi/B8+rxf2z7u5foXPCzBYT+Q3cxtopvZtk29MpTY88GHDVJsF
# MBjX7zM6aCNKsTKC2jb92F+jlkc8clCQQnl3U4jqwbj4ur1JBP5QxQprWhwde0+M
# ifDVp0vHZsVZ0pnYMCKSG5bUr3wOU7EP321DwvvEsTjCy/XDgvy8ipU6w3GjcQQF
# mgp/BX/0JCHX+04QJ0JkR9TTFZR1B+zh3CcK1ZEtTtvuZfjQ3viXwlwtNLy43vbe
# 1J5WNTs0HjJXsfdbhY5kE5RhyfaxFBr21KYx+b+evYyolIS0wR6New6FqLgcc4Ge
# 94yaYVTqMYIGUzCCBk8CAQEwfTBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGln
# aUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgQ29kZSBT
# aWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExAhAIsZ/Ns9rzsDFVWAgBLwDp
# MA0GCWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJ
# KoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQB
# gjcCARUwLwYJKoZIhvcNAQkEMSIEIMWgME0tNDCGmpOD0UgsrlBIozvdBV2PxnN9
# Fx4L1EAgMA0GCSqGSIb3DQEBAQUABIICAIFGy2SdTeQhQipPNq2DvOzEOLt9q4QT
# 91OsUiZRl91OQPbu//0dSDT0lYMyLn+91jcMsiK1exzKfotMkrdAnXVE892qFu6p
# SaRF7iHP0f7qrPz+nDaahDsVVnvvgQL06vkQDKpT2t2sBqtw5zNMqQOOnD7nN3Xt
# JlTi/i2Qv+QhtCxP/ISU4EI5RKw1zkE//kwnDMWXSTrH1woa1Lt75ZvsbcMZBaZ5
# pDKYpSu4J8minuGqhfi1loOZnVAE4ks4u3uz/8WMuOP/VWncj2PIa5OUTYKTrjRM
# M0yOxgp8rKWaR7MmJWXsgDG6/YyAL25KH/AeCYrc4QwR6OCnfhjHTlx386id3uy1
# i0sqzkMrFnnZZFLxiuJTJHjJgNLp9rZhq3DcDveZaHLpkzrIb5c60dvrJAWLl5y+
# 3g1mv4eVqIiByxRLgE9LkUE1QcVxm17ABqlxi4QbdPrh8WcfvDasQHEuAA7kGYJe
# aqmwx5fcxnRNhFpnpF+eAqVD3LkWraeAzh5DKeHvMtM6pbtPGUHpFQlgjlieKqzt
# IuDiMRaDw8EuvxMgOudyfdVYSf2QjztuCDFA6s9r/J9xw8Z4KzY0qOKXKYK1JSCX
# +tCh/s5bHLtGIzGWWgQWFVtf2MOSpVcFZAdo0lFySiGq68SeyRcRMwvNdjVljVE9
# apsV4MMS2KwcoYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkG
# A1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdp
# Q2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQ
# BUSv85SdCDmmv9s/X+VhFjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzEL
# BgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIzMTExNTIwNDYzNFowLwYJKoZI
# hvcNAQkEMSIEIKb9G/PZNgb2GZjATNHZ0FJdryE4QjMxzzw9BUxSBXy8MA0GCSqG
# SIb3DQEBAQUABIICAGz/nkEJr54sa9capYnLngukfhMLy/eZEHxY+IGnjWz0b28X
# c3TixQSOf71vp7ahS5Edx0/Q7+tWppFv3+o/h+gc6Ev4qDAxaPd/qUXcPL+TrL/Z
# RF0i8h9g0N/Mmqbrm7PWd3fAxdWJOIbI8Diz+iIiyygQOLiELLiPiWLKQDzFLHzZ
# mBmDufgtNuRYB5rA1wplHc2u8RUQhE1mPF0WaDq1xtp0RKf79jS6ZmRMIPwEpKhW
# HnnQqd4hvc/tlXOdRhS+NeYyzJNUbN3+Q9UlRFAqeKvoqIsij1LJWeFSb/Ejwli3
# 9MVKDRrfZOunE59ycf4Hk0malJ243MtK9GoWeJrduBTbbvgyrLFzK/lwx0b6mR9P
# lZo6aPSxIthXJJhVNVsYeAm8WaVTFPioXFybN5n96QkAVHTB6tH3y2T9oomFEccj
# sDsjPJWbukKuHJD338AGlmkI9+V8OpBLZBiZ5xpfFGqBYfQ5clM7oB/d7eygA3UC
# ylCI/Za4UHbqVxa4iO9QSWagL5G18lhBigYrGNqtRatcuAcBSyaqGYZJc7i8DrvE
# xMc907vRFwnsB3psBoWA7sn3KnuzA2rD5LnJR7gHXsdO6VjU6GbuOi+uMEslX4F4
# 0BvW2NcJV4JPzgpcgtN1V2hgh7++pkUM6PfWgj6w2T4Fyn8PQSuxpG1jqVW0
# SIG # End signature block
