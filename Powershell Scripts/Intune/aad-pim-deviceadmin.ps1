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


#Create Admins Groups
$admingrp = New-MgGroup -DisplayName "Intune-Device-Admins" -Description "Azure AD Joined Device Admins (PIM Role)" -MailNickName "group" -SecurityEnabled -IsAssignableToRole

##Grab Tenant ID
$domain = get-mgdomain | where-object IsDefault -eq $true

$suffix = $domain.Id
$uri = "https://graph.microsoft.com/beta/organization"
$tenantdetails = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
$tenantid = $tenantdetails.id
##Get the PIM Role
#Get PIM role
$uri = "https://graph.microsoft.com/v1.0/directoryRoles"
$roles = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
$PIMrole = $roles | where-object DisplayName -eq "Azure AD Joined Device Local Administrator"

#Create the schedule without an end date
$schedule = New-Object Microsoft.Open.MSGraph.Model.AzureADMSPrivilegedSchedule
$schedule.Type = "Once"
$schedule.StartDateTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
$schedule.endDateTime = $null
#This bombs out if group isn't fully created so lets wait 30 seconds
start-sleep -s 30
#Create PIM role
$roleid = $PIMrole.id
$groupid = $admingrp.id
$starttime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
$params = @{
	Action = "adminAssign"
	Justification = "Assign AD Admins Access"
	RoleDefinitionId = $roleid
	DirectoryScopeId = "/"
	PrincipalId = $groupid
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
