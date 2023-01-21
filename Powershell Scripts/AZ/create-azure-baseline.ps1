$maximumfunctioncount = 32768
<#PSScriptInfo
.VERSION 2.0
.GUID dc073d99-ce85-4d7f-b1cd-ece81282fc3e
.AUTHOR AndrewTaylor
.DESCRIPTION Builds a set of Azure Security baselines
.Conditional access policy to block specified locations (created)
.Conditional access policy to require MFA except when on-prem (trust location created)
.Conditional access policy to block legacy authentication
.Conditional access policy to require MFA for admins
.Conditional access policy to require MFA for guests
Creates a Break Glass account exempt from all of the above
Creates Azure Admins Group
Created Azure PIM role for global admin (only if P2 licensed)
.COMPANYNAME 
.COPYRIGHT GPL
.TAGS AzureAD
.LICENSEURI https://github.com/andrew-s-taylor/public/blob/main/LICENSE
.PROJECTURI https://github.com/andrew-s-taylor/public
.ICONURI 
.EXTERNALMODULEDEPENDENCIES AzureAD
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
#>
<#
.SYNOPSIS
  Builds an Azure Security Baseline
.DESCRIPTION
 .Builds a set of Azure Security baselines
.Conditional access policy to block specified locations (created)
.Conditional access policy to require MFA except when on-prem (trust location created)
.Conditional access policy to block legacy authentication
.Conditional access policy to require MFA for admins
.Conditional access policy to require MFA for guests
.Creates a Break Glass account exempt from all of the above
.Creates Azure Admins Group
.Created Azure PIM role for global admin (only if P2 licensed)
.INPUTS
N/A
.OUTPUTS
Within Azure
.NOTES
  Version:        2.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  20/04/2022
  Updated:        28/10/2022
  Purpose/Change: Initial script development
  Change: Switched to Microsoft Graph from AAD
 
.EXAMPLE
N/A
#>
####################################################################### FUNCTIONS #######################################################################
##Password Generator
function Get-RandomPassword {
    param (
        [Parameter(Mandatory)]
        [int] $length,
        [int] $amountOfNonAlphanumeric = 1
    )
    Add-Type -AssemblyName 'System.Web'
    return [System.Web.Security.Membership]::GeneratePassword($length, $amountOfNonAlphanumeric)
}

####################################################################### END FUNCTIONS #######################################################################


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
Get-ScriptVersion -liveuri "https://raw.githubusercontent.com/andrew-s-taylor/public/main/Powershell%20Scripts/AZ/create-azure-baseline.ps1"




####################################################################### INSTALL MODULES #######################################################################
Write-Host "Installing Microsoft Graph modules if required (current user scope)"

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph) {
    Write-Host "Microsoft Graph Already Installed"
} 
else {
    try {
        Install-Module -Name Microsoft.Graph -Scope CurrentUser -Repository PSGallery -Force 
    }
    catch [Exception] {
        $_.message 
        exit
    }
}


# Load the Graph module
Import-Module microsoft.graph

####################################################################### END INSTALL MODULES #######################################################################


####################################################################### CREATE AAD OBJECTS #######################################################################
#Connect to Graph
Select-MgProfile -Name Beta
Connect-MgGraph -Scopes  	RoleAssignmentSchedule.ReadWrite.Directory, Domain.Read.All, Domain.ReadWrite.All, Directory.Read.All, Policy.ReadWrite.ConditionalAccess, DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, openid, profile, email, offline_access


##Get Tenant Details
##Grab Tenant ID
$domain = get-mgdomain | where-object IsDefault -eq $true

$suffix = $domain.Id

#Create Azure AD Groups
#Create Admins Groups
$admingrp = New-MGGroup -DisplayName "Azure-Global-Admins" -Description "Azure Global Admins (PIM Role)" -MailNickName "azureglobaladmins" -SecurityEnabled -IsAssignableToRole

##Create Azure AD Breakglass user
$PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
$bgpassword = Get-RandomPassword -Length 20
$PasswordProfile.Password = $bgpassword
$breakglass = New-MgUser -DisplayName "Azure BreakGlass Account" -PasswordProfile $PasswordProfile -UserPrincipalName "breakglass@$suffix" -AccountEnabled -MailNickName "BreakGlass" -PasswordPolicies "DisablePasswordExpiration"

####################################################################### END CREATE AAD OBJECTS #######################################################################


####################################################################### CONFIGURE PIM #######################################################################

##Create PIM if licensed for Global Admins
$uri = "https://graph.microsoft.com/beta/organization"
$tenantdetails = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
$tenantid = $tenantdetails.id
$licensing = $tenantdetails.AssignedPlans
$islicensed = $licensing.ServicePlanId -contains "eec0eb4f-6444-4f95-aba0-50c24d67f998"

if ($islicensed -eq $True) {
write-host "Azure AD P2 licensing in place, continuing"
##Get the PIM Role
$uri = "https://graph.microsoft.com/v1.0/directoryRoles"
$roles = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
$PIMrole = $roles | where-object DisplayName -eq "Global Administrator"

#Create the schedule without an end date
$schedule = New-Object Microsoft.Open.MSGraph.Model.AzureADMSPrivilegedSchedule
$schedule.Type = "Once"
$schedule.StartDateTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
$schedule.endDateTime = $null
#This bombs out if group isn't fully created so lets wait 30 seconds
start-sleep -s 30
#Create PIM role
#$assign = Open-AzureADMSPrivilegedRoleAssignmentRequest -ProviderId 'aadRoles' -ResourceId $tenantid -RoleDefinitionId $PIMrole.Id -SubjectId $admingrp.id -Type 'adminAdd' -AssignmentState 'Eligible' -schedule $schedule -reason "Baseline Build"
$roleid = $PIMrole.id
$principalId = $admingrp.id
$starttime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
$params = @{
	Action = "adminAssign"
	Justification = "Grants Breakglass access to everything"
	RoleDefinitionId = $roleid
	DirectoryScopeId = "/"
	PrincipalId = $principalId
	ScheduleInfo = @{
		StartDateTime = $starttime
		Expiration = @{
			Type = "NoExpiration"
		}
	}
}

$assign = New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -BodyParameter $params

if ($runmode -ne "silent") {
#Notify complete
Add-Type -AssemblyName PresentationCore,PresentationFramework
$msgBody = "PIM Assigned, Creating Conditional Access Policy"
[System.Windows.MessageBox]::Show($msgBody)
}
}
else {
write-host "Not Licensed for Azure PIM, skipping"
}

####################################################################### END CONFIGURE PIM #######################################################################




####################################################################### CREATE LOCATIONS #######################################################################
##Create Blocked Location

#New-AzureADMSNamedLocationPolicy -OdataType "#microsoft.graph.countryNamedLocation" -DisplayName "Blocked-Locations" -CountriesAndRegions 'CN', 'RU', 'KP', 'IN' -IncludeUnknownCountriesAndRegions $false
$params = @{
    "@odata.type" = "#microsoft.graph.countryNamedLocation"
    DisplayName = "Blocked Locations"
    CountriesAndRegions = @(
        "CN"
        "RU"
        "KP"
        "IN"
    )
    IncludeUnknownCountriesAndRegions = $false
    }
    
New-MgIdentityConditionalAccessNamedLocation -BodyParameter $params



##Prompt for WAN IP
[void][Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic')

$title = 'IP Range'
$msg   = 'Enter your WAN IP Range:'

$ipRanges2 = [Microsoft.VisualBasic.Interaction]::InputBox($msg, $title)





##Created Trusted Location
$ipRanges = New-Object -TypeName Microsoft.Open.MSGraph.Model.IpRange
$ipRanges.cidrAddress = $ipRanges2
#New-AzureADMSNamedLocationPolicy -OdataType "#microsoft.graph.ipNamedLocation" -DisplayName "Trusted-Range" -IsTrusted $true -IpRanges $ipRanges

$params = @{
    "@odata.type" = "#microsoft.graph.ipNamedLocation"
    DisplayName = "Trusted IP named location"
    IsTrusted = $true
    IpRanges = @(
        @{
            "@odata.type" = "#microsoft.graph.iPv4CidrRange"
            CidrAddress = $ipRanges
        }
    )
    }
    
    New-MgIdentityConditionalAccessNamedLocation -BodyParameter $params

####################################################################### END CREATE LOCATIONS #######################################################################





####################################################################### CREATE POLICIES #######################################################################
##Create Policies excluding breakglass

###Block Access from blocked countries
#Get Location ID
$location = Get-MgIdentityConditionalAccessNamedLocation | where-object DisplayName -eq "Blocked-Locations"
$locationid = $location.id
## Create Conditional Access Policy
$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet

## All Cloud Apps
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "All"
 
##All users except the Azure AD admins role and group
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeUsers = "All"
$conditions.Users.ExcludeUsers = $breakglass.ObjectID
$conditions.Locations = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessLocationCondition
$conditions.Locations.IncludeLocations = $locationid
 
##All devices
$conditions.ClientAppTypes = "All" 

$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls

##Block
$controls._Operator = "OR"
##Require device compliance
$controls.BuiltInControls = "block"

$name = "Conditional Access - Block Specific Locations"

##Disable initially just in case
$state = "Disabled"
 
New-MgIdentityConditionalAccessPolicy `
    -DisplayName $name `
    -State $state `
    -Conditions $conditions `
    -GrantControls $controls
######################################################################################################################################################################



##Require MFA Offsite
#Get Location ID
$location = Get-MgIdentityConditionalAccessNamedLocation | where-object DisplayName -eq "Trusted-Range"
$locationid = $location.id
## Create Conditional Access Policy
$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet

## All Cloud Apps
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "All"
 
##All users except the Azure AD admins role and group
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeUsers = "All"
$conditions.Users.ExcludeUsers = $breakglass.ObjectID
$conditions.Locations = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessLocationCondition
$conditions.Locations.IncludeLocations = "All"
$conditions.Locations.ExcludeLocations = $locationid
 
##All devices
$conditions.ClientAppTypes = "All" 

$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls

##Block
$controls._Operator = "OR"
##Require device compliance
$controls.BuiltInControls = "mfa"

$name = "Conditional Access - Require MFA Offsite"

##Disable initially just in case
$state = "Disabled"
 
New-MgIdentityConditionalAccessPolicy `
    -DisplayName $name `
    -State $state `
    -Conditions $conditions `
    -GrantControls $controls
######################################################################################################################################################################


##Block Legacy Auth
## Create Conditional Access Policy
$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet

## All Cloud Apps
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "All"
 
##All users except the Azure AD admins role and group
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeUsers = "All"
$conditions.Users.ExcludeUsers = $breakglass.ObjectID
 
##All devices
$conditions.ClientAppTypes = @('ExchangeActiveSync', 'Other')

$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls

##Block
$controls._Operator = "OR"
##Require device compliance
$controls.BuiltInControls = "block"

$name = "Conditional Access - Block Legacy Auth"

##Disable initially just in case
$state = "Disabled"
 
New-MgIdentityConditionalAccessPolicy `
    -DisplayName $name `
    -State $state `
    -Conditions $conditions `
    -GrantControls $controls

######################################################################################################################################################################


 ##Require MFA for Admins
## Create Conditional Access Policy
$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet

## All Cloud Apps
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "All"
 
##All users except the Azure AD admins role and group
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeRoles = @('62e90394-69f5-4237-9190-012177145e10', 'f28a1f50-f6e7-4571-818b-6a12f2af6b6c', '29232cdf-9323-42fd-ade2-1d097af3e4de', 'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9', '194ae4cb-b126-40b2-bd5b-6091b380977d', '729827e3-9c14-49f7-bb1b-9608f156bbb8', '966707d0-3269-4727-9be2-8c3a10f19b9d', 'b0f54661-2d74-4c50-afa3-1ec803f12efe', 'fe930be7-5e62-47db-91af-98c3a49a38b1')
$conditions.Users.ExcludeUsers = $breakglass.ObjectID
 
##All devices
$conditions.ClientAppTypes = "All"

$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls

##Block
$controls._Operator = "OR"
##Require device compliance
$controls.BuiltInControls = "mfa"

$name = "Conditional Access - Require MFA for Admins"

##Disable initially just in case
$state = "Disabled"
 
New-MgIdentityConditionalAccessPolicy `
    -DisplayName $name `
    -State $state `
    -Conditions $conditions `
    -GrantControls $controls
######################################################################################################################################################################



 ##Require MFA for Guests
## Create Conditional Access Policy
$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet

## All Cloud Apps
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "All"
 
##All users except the Azure AD admins role and group
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeUsers = "GuestsOrExternalUsers"
$conditions.Users.ExcludeUsers = $breakglass.ObjectID
 
##All devices
$conditions.ClientAppTypes = "All"

$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls

##Block
$controls._Operator = "OR"
##Require device compliance
$controls.BuiltInControls = "mfa"

$name = "Conditional Access - Require MFA for Guests"

##Disable initially just in case
$state = "Disabled"
 
New-MgIdentityConditionalAccessPolicy `
    -DisplayName $name `
    -State $state `
    -Conditions $conditions `
    -GrantControls $controls
    


####################################################################### END CREATE POLICIES ###############################################################################################
    

####################################################################### FINISHED ###############################################################################################

### POPUP BG Details
Add-Type -AssemblyName PresentationCore,PresentationFramework
$username = $breakglass.UserPrincipalName
$msgBody = "Breakglass Details

Username: $username
Password: $bgpassword"
[System.Windows.MessageBox]::Show($msgBody)