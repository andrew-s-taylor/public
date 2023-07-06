<#
.SYNOPSIS
  Creates semi-dynamic AAD groups for Win11 and Win10 devices
.DESCRIPTION
  Checks for Device Compliance with Windows 11
  Creates Win11 group for compliant device
  Creates Win10 group for non-compliant
  Creates update rings for each
  Excludes groups from existing update rings
.INPUTS
None
.OUTPUTS
None
.NOTES
  Version:        1.0.1
  Author:         Andrew Taylor
  WWW:            andrewstaylor.com
  Creation Date:  26/01/2023
  Purpose/Change: Initial script development
 
.EXAMPLE
N/A
#>

<#PSScriptInfo
.VERSION 1.0.1
.GUID f6c74e33-2f3a-4187-9980-d29ee8abcceb
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

##App reg secret
$clientsecret = ""

##App reg ID
$clientid = ""

##Group Name for Windows 10 Devices
$w10groupname = ""

##Group Name for Windows 11 Devices
$w11groupname = ""

##Tenant ID for Connection
$tenantId = ""


###############################################################################################################

###############################################################################################################
######                                         Install Modules                                           ######
###############################################################################################################
Write-Host "Installing Intune modules if required (current user scope)"


Write-Host "Installing Microsoft Graph Groups modules if required (current user scope)"

#Install Graph Groups module if not available
if (Get-Module -ListAvailable -Name microsoft.graph.groups) {
    Write-Host "Microsoft Graph Groups Module Already Installed"
} 
else {
    try {
        Install-Module -Name microsoft.graph.groups -Scope CurrentUser -Repository PSGallery -Force -AllowClobber 
    }
    catch [Exception] {
        $_.message 
    }
}


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
Import-Module Microsoft.Graph.Groups
import-module microsoft.graph.authentication


###############################################################################################################
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
######                                     Graph Connection                                              ######
###############################################################################################################
##Connect using Secret
$tenantId = $tenant
 
#Get Creds and connect
#Connect to Graph
write-host "Connecting to Graph"
write-host $body
Connect-ToGraph -Tenant $tenantId -AppId $clientId -AppSecret $clientSecret
write-host "Graph Connection Established"


###############################################################################################################
###############################################################################################################
######                                           FUNCTIONS                                               ######
###############################################################################################################

Function Get-DeviceFeatureUpdates() {
    
    <#
    .SYNOPSIS
    This function is used to get device feature update policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets a device feature update policy
    .EXAMPLE
    Get-DeviceFeatureUpdates $id guid
    Returns any device feature update policy configured in Intune
    .NOTES
    NAME: Get-DeviceFeatureUpdates
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "Beta"
    $DCP_resource = "deviceManagement/windowsFeatureUpdateProfiles"
    
    try {
                    
        if ($id) {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id"
                (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
       
        }
                    
        else {
                    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
                (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
                    
        }
                    
    }
                    
    catch {
                    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
                        
                    
    }
                    
}


Function Get-DeviceFeatureUpdateAssignments() {
    
    <#
    .SYNOPSIS
    This function is used to get device feature update policy assignment from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets a device feature update policy assignment
    .EXAMPLE
    Get-DeviceFeatureUpdateAssignments $id guid
    Returns any device feature update policy assignment configured in Intune
    .NOTES
    NAME: Get-DeviceFeatureUpdateAssignments
    #>
    
    [cmdletbinding()]
    
    param
    (
        [Parameter(Mandatory = $true, HelpMessage = "Enter id (guid) for the Device Configuration Policy you want to check assignment")]
        $id
    )
    
    $graphApiVersion = "Beta"
    $DCP_resource = "deviceManagement/windowsFeatureUpdateProfiles"
    
    try {
    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id/assignments"
        (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
    }
    
    catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        
    
    }
    
}

Function Add-DeviceFeatureUpdateAssignment() {
    <#
    .SYNOPSIS
    This function is used to add a feature update policy assignment using the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and adds a feature update policy assignment
    .EXAMPLE
    Add-DeviceFeatureUpdateAssignment -ConfigurationPolicyId $ConfigurationPolicyId -TargetGroupId $TargetGroupId
    Adds a feature update policy assignment in Intune
    .NOTES
    NAME: Add-DeviceFeatureUpdateAssignment
    #>
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $ConfigurationPolicyId,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $TargetGroupId,
        [parameter(Mandatory = $true)]
        [ValidateSet("Included", "Excluded")]
        [ValidateNotNullOrEmpty()]
        [string]$AssignmentType
    )

    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/windowsFeatureUpdateProfiles/$ConfigurationPolicyId/assign"

    try {
        if (!$ConfigurationPolicyId) {
            write-host "No Configuration Policy Id specified, specify a valid Configuration Policy Id" -f Red
            break
        }
        if (!$TargetGroupId) {
            write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red
            break
        }
        # Checking if there are Assignments already configured in the Policy
        $DCPA = Get-DeviceFeatureUpdateAssignments -id $ConfigurationPolicyId
        $TargetGroups = @()
        if (@($DCPA).count -ge 1) {
            if ($DCPA.targetGroupId -contains $TargetGroupId) {
                Write-Host "Group with Id '$TargetGroupId' already assigned to Policy..." -ForegroundColor Red
            }
            # Looping through previously configured assignements
            $DCPA | ForEach-Object {
                $TargetGroup = New-Object -TypeName psobject
                if ($_.excludeGroup -eq $true) {
                    $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'
                }
                else {
                    $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'
                }
                $TargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value $_.targetGroupId
                $Target = New-Object -TypeName psobject
                $Target | Add-Member -MemberType NoteProperty -Name 'target' -Value $TargetGroup
                $TargetGroups += $Target
            }

            # Adding new group to psobject

            $TargetGroup = New-Object -TypeName psobject

            if ($AssignmentType -eq "Excluded") {
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'
            }
            elseif ($AssignmentType -eq "Included") {
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'
            }

            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value "$TargetGroupId"
            $Target = New-Object -TypeName psobject
            $Target | Add-Member -MemberType NoteProperty -Name 'target' -Value $TargetGroup
            $TargetGroups += $Target
        }
        else {

            # No assignments configured creating new JSON object of group assigned
            $TargetGroup = New-Object -TypeName psobject

            if ($AssignmentType -eq "Excluded") {
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'
            }
            elseif ($AssignmentType -eq "Included") {
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'
            }
            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value "$TargetGroupId"
            $Target = New-Object -TypeName psobject
            $Target | Add-Member -MemberType NoteProperty -Name 'target' -Value $TargetGroup
            $TargetGroups = $Target
        }

        # Creating JSON object to pass to Graph
        $Output = New-Object -TypeName psobject
        $Output | Add-Member -MemberType NoteProperty -Name 'assignments' -Value @($TargetGroups)
        $JSON = $Output | ConvertTo-Json -Depth 3

        # POST to Graph Service
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType "application/json"
    }
    catch {
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
    }
}

############################################################################################################

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


###############################################################################################################
######                                     Start the Magic                                               ######
###############################################################################################################

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
        $compliantdevices += $machine.deviceName
    }
    else {
        $noncompliantdevices += $machine.deviceName
    }
}

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
##It exists, add members
write-host "Windows 11 Group Exists, adding members"
foreach ($compliantdevice in $compliantdevices) {
    $compliantdeviceid = (Get-MgDevice -Filter "displayName eq '$compliantdevice'").id
    ##Check if already in the group
    write-host "Checking if $compliantdevice is already in the group"
    $groupmember = (get-mggroupmember -GroupId $win11groupexist) | where-object ID -eq $compliantdeviceid
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
foreach ($compliantdevice in $compliantdevices) {
    $compliantdeviceid = (Get-MgDevice -Filter "displayName eq '$compliantdevice'").id

    ##Check if already in the group
    write-host "Checking if $compliantdevice is already in the group"
    $groupmember = (get-mggroupmember -GroupId $win11groupid) | where-object ID -eq $compliantdeviceid
    if ($null -eq $groupmember) {
        write-host "Adding $compliantdevice to the group"
    new-mggroupmember -GroupId $win11groupid -DirectoryObjectId  $compliantdeviceid
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
        $noncompliantdeviceid = (Get-MgDevice -Filter "displayName eq '$noncompliantdevice'").id
        ##Check if already in the group
        write-host "Checking if $noncompliantdevice is already in the group"
        $groupmember = (get-mggroupmember -GroupId $win10groupexist) | where-object ID -eq $noncompliantdeviceid
        if ($null -eq $groupmember) {
            write-host "Adding $noncompliantdevice to the group"
            new-mggroupmember -GroupId $win10groupexist -DirectoryObjectId $noncompliantdeviceid
        }
    }
    }
    else {
    ##Does not, create it first
    write-host "Windows 10 Group does not exist, creating it"
    $win10group = new-mggroup -DisplayName $w10groupname -Description "Devices Not Compliant with Windows 10" -SecurityEnabled -MailEnabled:$false -MailNickname $w10groupname
    $win10groupid = $win10group.id
    foreach ($noncompliantdevice in $noncompliantdevices) {
        $noncompliantdeviceid = (Get-MgDevice -Filter "displayName eq '$noncompliantdevice'").id

        ##Check if already in the group
        $groupmember = (get-mggroupmember -GroupId $win10groupid) | where-object ID -eq $noncompliantdeviceid
        if ($null -eq $groupmember) {
            write-host "Adding $noncompliantdevice to the group"
            new-mggroupmember -GroupId $win10groupid -DirectoryObjectId  $noncompliantdeviceid
        }
    }
    }


##Get Current Feature Update Rings
write-host "Getting Current Feature Update Rings"
$currentrings = (Get-DeviceFeatureUpdates).value

##Add exclusion for both groups to each

$finalw10group = (get-mggroup -filter "displayName eq '$w10groupname'").id
$finalw11group = (get-mggroup -filter "displayName eq '$w11groupname'").id

write-host "Looping Through Rings"
foreach ($updatering in $currentrings) {
    if (($updatering.displayName -eq "Win11-Upgrade") -or ($updatering.displayName -eq "Win10-Upgrade")) {
        write-host "Not excluding from upgrade rings"
    }
    else {
    $policyid = $updatering.id
    $policycheck = Get-DeviceFeatureUpdateAssignments -id $policyid
    $policycheckassignments = $policycheck.target.groupid
    if (($policycheckassignments.contains($finalw10group) -or ($policycheck.contains($finalw11group)))) {
        write-host "Groups already excluded"
    }
    else {
        write-host "Adding group exclusions"
        Add-DeviceFeatureUpdateAssignment -ConfigurationPolicyId $policyid -TargetGroupId $finalw10group -AssignmentType Excluded
        Add-DeviceFeatureUpdateAssignment -ConfigurationPolicyId $policyid -TargetGroupId $finalw11group -AssignmentType Excluded
    
    }
    }

}

##Create new Feature Update Rings
##Check if it exists first
if ($currentrings.contains("Win11-Upgrade")) {
write-host "Win11-Upgrade already exists"
}
else {
##Windows 11
write-host "Creating Win11-Upgrade Ring"
$uri = "https://graph.microsoft.com/beta/windowsFeatureUpdateProfiles"
$json = @"
{
"displayName":"Win11-Upgrade",
"description":"Windows 11 Version 22H2",
"featureUpdateVersion":"Windows 11, version 22H2",
"roleScopeTagIds":["0"],
"rolloutSettings":{"offerStartDateTimeInUTC":null,"offerEndDateTimeInUTC":null,"offerIntervalInDays":null}
}
"@
$win11ring = (invoke-mggraphrequest -uri $uri -method POST -body $json -ContentType "application/json").id
$newwin11id = $win11ring.id
##Add Win11 Group and Exclude Win10
write-host "Adding Win11 Group and Excluding Win10"
Add-DeviceFeatureUpdateAssignment -ConfigurationPolicyId $newwin11id -TargetGroupId $finalw10group -AssignmentType Excluded
Add-DeviceFeatureUpdateAssignment -ConfigurationPolicyId $newwin11id -TargetGroupId $finalw11group -AssignmentType Included

}

##Windows 10
##Check if it exists first
if ($currentrings.contains("Win10-22H2")) {
    write-host "Win10-22H2 already exists"
    }
    else {
write-host "Creating Win10-22H2 Ring"
$uri = "https://graph.microsoft.com/beta/windowsFeatureUpdateProfiles"
$json = @"
{
"displayName":"Win10-22H2",
"description":"Windows 10 Version 22H2",
"featureUpdateVersion":"Windows 10, version 22H2",
"roleScopeTagIds":["0"],
"rolloutSettings":{"offerStartDateTimeInUTC":null,"offerEndDateTimeInUTC":null,"offerIntervalInDays":null}
}
"@
$win10ring = (invoke-mggraphrequest -uri $uri -method POST -body $json -ContentType "application/json").id

$newwin10id = $win10ring.id

##Add Win10 Group and Exclude Win11
write-host "Adding Win10 Group and Excluding Win11"
Add-DeviceFeatureUpdateAssignment -ConfigurationPolicyId $newwin10id -TargetGroupId $finalw10group -AssignmentType Included
Add-DeviceFeatureUpdateAssignment -ConfigurationPolicyId $newwin10id -TargetGroupId $finalw11group -AssignmentType Excluded
    }