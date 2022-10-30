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

Write-Host "Installing Graph modules if required (current user scope)"

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
      exit
  }
}

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





write-host "Importing Modules"

import-module -name microsoft.graph.groups



#Get Creds and connect
write-host "Connect to Graph"
Select-MgProfile -Name Beta
Connect-MgGraph -Scopes Group.ReadWrite.All, GroupMember.ReadWrite.All, openid, profile, email, offline_access


#AutoPilot Group using MG.Graph
New-MgGroup -DisplayName "Autopilot-Devices" -Description "Dynamic group for Autopilot Devices" -MailEnabled:$False -MailNickName "autopilotdevices" -SecurityEnabled -GroupTypes "DynamicMembership" -MembershipRule "$aprule" -MembershipRuleProcessingState "On"
