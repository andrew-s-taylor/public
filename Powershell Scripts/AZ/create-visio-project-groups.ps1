<#PSScriptInfo
.VERSION 1.0
.GUID 729ebf90-26fe-4795-92dc-ca8f570cdd22
.AUTHOR AndrewTaylor
.DESCRIPTION Builds dynamic AAD groups for licensed users of Visio and Project (including uninstall)
.COMPANYNAME 
.COPYRIGHT GPL
.TAGS az autopilot aad
.LICENSEURI https://github.com/andrew-s-taylor/public/blob/main/LICENSE
.PROJECTURI https://github.com/andrew-s-taylor/public
.ICONURI 
.EXTERNALMODULEDEPENDENCIES AzureADPreview
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
#>
<#
.SYNOPSIS
  Builds an AAD Dynamic Group
.DESCRIPTION
Builds dynamic AAD groups for licensed users of Visio and Project (including uninstall)

.INPUTS
None required
.OUTPUTS
Within Azure
.NOTES
  Version:        1.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  01/11/2021
  Purpose/Change: Initial script development
  
.EXAMPLE
N/A
#>

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




write-host "Importing Modules"
#Import AzureAD Preview Module
import-module -Name AzureADPreview

#Connectaz

#Get Creds and connect
write-host "Connect to Azure"
Connect-AzureAD


#Create Visio Install Group
New-AzureADMSGroup -DisplayName "Visio-Install" -Description "Dynamic group for Licensed Visio Users" -MailEnabled $False -MailNickName "group" -SecurityEnabled $True -GroupTypes "DynamicMembership" -MembershipRule "(user.assignedPlans -any (assignedPlan.servicePlanId -eq ""663a804f-1c30-4ff0-9915-9db84f0d1cea"" -and assignedPlan.capabilityStatus -eq ""Enabled""))" -MembershipRuleProcessingState "On"


#Create Visio Uninstall Group
New-AzureADMSGroup -DisplayName "Visio-Uninstall" -Description "Dynamic group for users without Visio license" -MailEnabled $False -MailNickName "group" -SecurityEnabled $True -GroupTypes "DynamicMembership" -MembershipRule "(user.assignedPlans -all (assignedPlan.servicePlanId -ne ""663a804f-1c30-4ff0-9915-9db84f0d1cea""))" -MembershipRuleProcessingState "On"

#Create Project Install Group
New-AzureADMSGroup -DisplayName "Project-Install" -Description "Dynamic group for Licensed Project Users" -MailEnabled $False -MailNickName "group" -SecurityEnabled $True -GroupTypes "DynamicMembership" -MembershipRule "(user.assignedPlans -any (assignedPlan.servicePlanId -eq ""fafd7243-e5c1-4a3a-9e40-495efcb1d3c3"" -and assignedPlan.capabilityStatus -eq ""Enabled""))" -MembershipRuleProcessingState "On"

#Create Project Uninstall Group
New-AzureADMSGroup -DisplayName "Project-Uninstall" -Description "Dynamic group for users without Project license" -MailEnabled $False -MailNickName "group" -SecurityEnabled $True -GroupTypes "DynamicMembership" -MembershipRule "(user.assignedPlans -all (assignedPlan.servicePlanId -ne ""fafd7243-e5c1-4a3a-9e40-495efcb1d3c3""))" -MembershipRuleProcessingState "On"
