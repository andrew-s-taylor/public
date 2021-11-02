<#PSScriptInfo
.VERSION 1.0
.GUID 729ebf90-26fe-4795-92dc-ca8f570cdd22
.AUTHOR AndrewTaylor
.DESCRIPTION Builds a dynamic AAD group for Autopilot Devices
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
Builds an AAD Dynamic Group for Autopilot Devices using ZTID tag

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


#Create Group
New-AzureADMSGroup -DisplayName "Autopilot-Devices" -Description "Dynamic group for Autopilot Devices" -MailEnabled $False -MailNickName "group" -SecurityEnabled $True -GroupTypes "DynamicMembership" -MembershipRule "(device.devicePhysicalIDs -any (_ -contains ""[ZTDid]""))" -MembershipRuleProcessingState "On"