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

#Connect to Azure AD
Connect-AzureAD

#Get PIM role
$PIMrole =Get-AzureADMSPrivilegedRoleDefinition -ProviderId aadRoles -ResourceId $tenantid | where-object DisplayName -eq "Azure AD Joined Device Local Administrator"


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
 
New-AzureADMSConditionalAccessPolicy `
    -DisplayName $name `
    -State $state `
    -Conditions $conditions `
    -GrantControls $controls