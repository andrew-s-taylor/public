###############################################################################################################
######                                              Set Variables                                        ######
###############################################################################################################

##Mutli-tenant app reg secret
$clientsecret = ""

##Multi-tenant app reg ID
$clientid = ""

##Github Account Name
$w10groupname = ""

##Github Repo Name for CSV Checks
$w11groupname = ""

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

###############################################################################################################
######                                     Graph Connection                                              ######
###############################################################################################################
##Connect using Secret
$tenantId = $tenant
 
$body = @{
    grant_type    = "client_credentials";
    client_id     = $clientId;
    client_secret = $clientSecret;
    scope         = "https://graph.microsoft.com/.default";
}
 
$response = Invoke-RestMethod -Method Post -Uri https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token -Body $body
$accessToken = $response.access_token
 
$accessToken

#Get Creds and connect
#Connect to Graph
write-host "Connecting to Graph"
write-host $body
Select-MgProfile -Name Beta
Connect-MgGraph  -AccessToken $accessToken
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
$reporturi = "https://graph.microsoft.com/beta/$metadata#deviceManagement/userExperienceAnalyticsWorkFromAnywhereMetrics('allDevices')/metricDevices(id,deviceName,managedBy,manufacturer,model,osDescription,osVersion,upgradeEligibility,azureAdJoinType,ramCheckFailed,storageCheckFailed,processorCoreCountCheckFailed,processorSpeedCheckFailed,tpmCheckFailed,secureBootCheckFailed,processorFamilyCheckFailed,processor64BitCheckFailed,osCheckFailed)"

$reportdata = (invoke-mggraphrequest -uri $reporturi -method GET).value

$compliantdevices = ""
$noncompliantdevices = ""

##Create AAD Groups
$win11groupexist = get-mggroup -filter "displayName eq '$w11groupname'"
$win10groupexist = get-mggroup -filter "displayName eq '$w10groupname'"

##Windows 11
##Check if group exists
if ($null -ne $win11groupexist) {
##It exists, add members
foreach ($compliantdevice in $compliantdevices) {
    ##Check if already in the group
    $groupmember = get-mggroupmember -GroupId $win11groupexist.id -MemberId $compliantdevice.id
    if ($null -eq $groupmember) {
    add-mggroupmember -GroupId $win11groupexist.id -MemberId $compliantdevice.id
    }
}
}
else {
##Does not, create it first
$win11group = new-mggroup -DisplayName $w11groupname -Description "Devices Compliant with Windows 11" -MailEnabled $false -SecurityEnabled $true
foreach ($compliantdevice in $compliantdevices) {
    $groupmember = get-mggroupmember -GroupId $win11group.id -MemberId $compliantdevice.id
    if ($null -eq $groupmember) {
    add-mggroupmember -GroupId $win11group.id -MemberId $compliantdevice.id
    }
}
}


##Windows 10
##Check if group exists
if ($null -ne $win10groupexist) {
    ##It exists, add members
    foreach ($noncompliantdevice in $noncompliantdevices) {
        $groupmember = get-mggroupmember -GroupId $win10groupexist.id -MemberId $noncompliantdevice.id
        if ($null -eq $groupmember) {
            add-mggroupmember -GroupId $win10groupexist.id -MemberId $noncompliantdevice.id
        }
    }
    }
    else {
    ##Does not, create it first
    $win10group = new-mggroup -DisplayName $w10groupname -Description "Devices Not Compliant with Windows 10" -MailEnabled $false -SecurityEnabled $true
    foreach ($noncompliantdevice in $noncompliantdevices) {
        $groupmember = get-mggroupmember -GroupId $win10group.id -MemberId $noncompliantdevice.id
        if ($null -eq $groupmember) {
            add-mggroupmember -GroupId $win10group.id -MemberId $noncompliantdevice.id
        }
    }
    }



##Get Current Feature Update Rings
$currentrings = (Get-DeviceFeatureUpdates).value

##Add exclusion for both groups to each

$finalw10group = get-mggroup -filter "displayName eq '$w10groupname'"
$finalw11group = get-mggroup -filter "displayName eq '$w11groupname'"


foreach ($updatering in $currentrings) {
    $policyid = $updatering.id
    Add-DeviceFeatureUpdateAssignment -ConfigurationPolicyId $policyid -TargetGroupId $finalw10group -AssignmentType Excluded
    Add-DeviceFeatureUpdateAssignment -ConfigurationPolicyId $policyid -TargetGroupId $finalw11group -AssignmentType Excluded

}

##Create new Feature Update Rings

##Windows 11
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
Add-DeviceFeatureUpdateAssignment -ConfigurationPolicyId $newwin11id -TargetGroupId $finalw10group -AssignmentType Excluded
Add-DeviceFeatureUpdateAssignment -ConfigurationPolicyId $newwin11id -TargetGroupId $finalw11group -AssignmentType Included



##Windows 10

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
Add-DeviceFeatureUpdateAssignment -ConfigurationPolicyId $newwin10id -TargetGroupId $finalw10group -AssignmentType Included
Add-DeviceFeatureUpdateAssignment -ConfigurationPolicyId $newwin10id -TargetGroupId $finalw11group -AssignmentType Excluded
