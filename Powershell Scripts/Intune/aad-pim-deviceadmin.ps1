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

#Create Admins Groups
$admingrp = New-AzureADMSGroup -DisplayName "Intune-Device-Admins" -Description "Azure AD Joined Device Admins (PIM Role)" -MailEnabled $False -MailNickName "group" -SecurityEnabled $True -IsAssignableToRole $True

##Grab Tenant ID
$tenantdetails = Get-AzureADTenantDetail
$tenantid = $tenantdetails.ObjectID
##Get the PIM Role
$PIMrole =Get-AzureADMSPrivilegedRoleDefinition -ProviderId aadRoles -ResourceId $tenantid | where-object DisplayName -eq "Azure AD Joined Device Local Administrator"

#Create the schedule without an end date
$schedule = New-Object Microsoft.Open.MSGraph.Model.AzureADMSPrivilegedSchedule
$schedule.Type = "Once"
$schedule.StartDateTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
$schedule.endDateTime = $null
#This bombs out if group isn't fully created so lets wait 30 seconds
start-sleep -s 30
#Create PIM role
$assign = Open-AzureADMSPrivilegedRoleAssignmentRequest -ProviderId 'aadRoles' -ResourceId $tenantid -RoleDefinitionId $PIMrole.Id -SubjectId $admingrp.id -Type 'adminAdd' -AssignmentState 'Eligible' -schedule $schedule -reason "Environment Build"

if ($runmode -ne "silent") {
#Notify complete
Add-Type -AssemblyName PresentationCore,PresentationFramework
$msgBody = "PIM Assigned, Creating Conditional Access Policy"
[System.Windows.MessageBox]::Show($msgBody)
}
