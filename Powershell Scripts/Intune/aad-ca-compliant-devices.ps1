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
Connect-MgGraph -Scopes PrivilegedAccess.ReadWrite.AzureAD, PrivilegedAccess.ReadWrite.AzureADGroup, PrivilegedAccess.ReadWrite.AzureResources, RoleAssignmentSchedule.ReadWrite.Directory, Domain.Read.All, Domain.ReadWrite.All, Directory.Read.All, Policy.ReadWrite.ConditionalAccess, DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, openid, profile, email, offline_access


#Get PIM role
$uri = "https://graph.microsoft.com/v1.0/directoryRoles"
$roles = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
$PIMrole = $roles | where-object DisplayName -eq "Azure AD Joined Device Local Administrator"


## Create Conditional Access Policy
$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet

## All Cloud Apps
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "All"
 
##All users except the Azure AD admins role and group
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeUsers = "All"
$conditions.Users.ExcludeRoles = $Pimrole.id
 
##All devices
$conditions.ClientAppTypes = "All"
 
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
 
$controls._Operator = "OR"
##Require device compliance
$controls.BuiltInControls = "CompliantDevice"

$name = "Conditional Access - Block NonCompliant Devices"

##Disable initially just in case
$state = "Disabled"
 
New-MgIdentityConditionalAccessPolicy `
    -DisplayName $name `
    -State $state `
    -Conditions $conditions `
    -GrantControls $controls