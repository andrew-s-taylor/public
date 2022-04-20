<#PSScriptInfo
.VERSION 1.0
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
  Version:        1.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  20/04/2022
  Purpose/Change: Initial script development
 
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



####################################################################### INSTALL MODULES #######################################################################
Write-Host "Installing AzureAD Preview modules if required (current user scope)"

#Install AZ Module if not available
if (Get-Module -ListAvailable -Name AzureADPreview) {
    Write-Host "AZ Ad Preview Module Already Installed"
} 
else {
    try {
        Install-Module -Name AzureADPreview -Scope CurrentUser -Repository PSGallery -Force -AllowClobber 
    }
    catch [Exception] {
        $_.message 
        exit
    }
}


#Group creation needs preview module so we need to remove non-preview first
# Unload the AzureAD module (or continue if it's already unloaded)
Remove-Module AzureAD -ErrorAction SilentlyContinue
# Load the AzureADPreview module
Import-Module AzureADPreview

####################################################################### END INSTALL MODULES #######################################################################


####################################################################### CREATE AAD OBJECTS #######################################################################
#Connect to Azure AD
Connect-AzureAD

##Get Tenant Details
##Grab Tenant ID
$tenantdetails = Get-AzureADTenantDetail
$domain = $tenantdetails.VerifiedDomains | select-object Name -First 1

$suffix = $domain.Name

#Create Azure AD Groups
#Create Admins Groups
$admingrp = New-AzureADMSGroup -DisplayName "Azure-Global-Admins" -Description "Azure Global Admins (PIM Role)" -MailEnabled $False -MailNickName "group" -SecurityEnabled $True -IsAssignableToRole $True

##Create Azure AD Breakglass user
$PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
$bgpassword = Get-RandomPassword -Length 20
$PasswordProfile.Password = $bgpassword
$breakglass = New-AzureADUser -DisplayName "Azure BreakGlass Account" -PasswordProfile $PasswordProfile -UserPrincipalName "breakglass@$suffix" -AccountEnabled $true -MailNickName "BreakGlass" -PasswordPolicies "DisablePasswordExpiration"

####################################################################### END CREATE AAD OBJECTS #######################################################################


####################################################################### CONFIGURE PIM #######################################################################

##Create PIM if licensed for Global Admins
$tenantid = $tenantdetails.ObjectID
$licensing = $tenantdetails.AssignedPlans
$islicensed = $licensing -contains "eec0eb4f-6444-4f95-aba0-50c24d67f998"

if ($islicensed -eq $True) {
write-host "Azure AD P2 licensing in place, continuing"
##Get the PIM Role
$PIMrole =Get-AzureADMSPrivilegedRoleDefinition -ProviderId aadRoles -ResourceId $tenantid | where-object DisplayName -eq "Global Administrator"

#Create the schedule without an end date
$schedule = New-Object Microsoft.Open.MSGraph.Model.AzureADMSPrivilegedSchedule
$schedule.Type = "Once"
$schedule.StartDateTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
$schedule.endDateTime = $null
#This bombs out if group isn't fully created so lets wait 30 seconds
start-sleep -s 30
#Create PIM role
$assign = Open-AzureADMSPrivilegedRoleAssignmentRequest -ProviderId 'aadRoles' -ResourceId $tenantid -RoleDefinitionId $PIMrole.Id -SubjectId $admingrp.id -Type 'adminAdd' -AssignmentState 'Eligible' -schedule $schedule -reason "Baseline Build"

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
New-AzureADMSNamedLocationPolicy -OdataType "#microsoft.graph.countryNamedLocation" -DisplayName "Blocked-Locations" -CountriesAndRegions 'CN', 'RU', 'KP', 'IN' -IncludeUnknownCountriesAndRegions $false




##Prompt for WAN IP
[void][Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic')

$title = 'IP Range'
$msg   = 'Enter your WAN IP Range:'

$ipRanges2 = [Microsoft.VisualBasic.Interaction]::InputBox($msg, $title)





##Created Trusted Location
$ipRanges = New-Object -TypeName Microsoft.Open.MSGraph.Model.IpRange
$ipRanges.cidrAddress = $ipRanges2
New-AzureADMSNamedLocationPolicy -OdataType "#microsoft.graph.ipNamedLocation" -DisplayName "Trusted-Range" -IsTrusted $true -IpRanges $ipRanges


####################################################################### END CREATE LOCATIONS #######################################################################





####################################################################### CREATE POLICIES #######################################################################
##Create Policies excluding breakglass

###Block Access from blocked countries
#Get Location ID
$location = get-AzureADMSNamedLocationPolicy | where-object DisplayName -eq "Blocked-Locations"
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
 
New-AzureADMSConditionalAccessPolicy `
    -DisplayName $name `
    -State $state `
    -Conditions $conditions `
    -GrantControls $controls
######################################################################################################################################################################



##Require MFA Offsite
#Get Location ID
$location = get-AzureADMSNamedLocationPolicy | where-object DisplayName -eq "Trusted-Range"
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
 
New-AzureADMSConditionalAccessPolicy `
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
 
New-AzureADMSConditionalAccessPolicy `
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
 
New-AzureADMSConditionalAccessPolicy `
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
 
New-AzureADMSConditionalAccessPolicy `
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