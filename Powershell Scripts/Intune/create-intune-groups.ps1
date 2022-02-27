<#PSScriptInfo
.VERSION 1.0
.GUID 9cb596f8-e4f4-4fbb-bf0b-8d5c227af59c
.AUTHOR AndrewTaylor
.DESCRIPTION Creates Intune groups via command line or GUI
.COMPANYNAME 
.COPYRIGHT GPL
.TAGS intune Azure AD
.LICENSEURI https://github.com/andrew-s-taylor/public/blob/main/LICENSE
.PROJECTURI https://github.com/andrew-s-taylor/public
.ICONURI 
.EXTERNALMODULEDEPENDENCIES azureAD
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
#>
<#
.SYNOPSIS
  Creates Intune Groups via command line or GUI
.DESCRIPTION
Creates groups for:
Autopilot Devices
Visio Users
Project Users
Office Users
Deployment Ring Groups
.INPUTS
GroupName (Optional):
Autopilot
Visio
Project
Office
Deployment
.OUTPUTS
None
.NOTES
  Version:        1.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  26/02/2022
  Purpose/Change: Initial script development
  
.EXAMPLE
N/A
#>

####################################################
### PARAMETERS ###
param (
    [string]$groupname = ""
)

### END PARAMATERS ###

### Install Modules ###


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
## END INSTALL MODULES ###

## IMPORT MODULES ###

#Group creation needs preview module so we need to remove non-preview first
# Unload the AzureAD module (or continue if it's already unloaded)
Remove-Module AzureAD -ErrorAction SilentlyContinue
# Load the AzureADPreview module
Import-Module AzureADPreview

## END IMPORT MODULES ###

### Connect to Azure AD ###
Connect-AzureAD

### Create Form ###

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

$IntuneAzureADGroups             = New-Object system.Windows.Forms.Form
$IntuneAzureADGroups.ClientSize  = New-Object System.Drawing.Point(396,431)
$IntuneAzureADGroups.text        = "Intune Azure AD Groups"
$IntuneAzureADGroups.TopMost     = $false
$IntuneAzureADGroups.BackColor   = [System.Drawing.ColorTranslator]::FromHtml("#ffffff")

$Label1                          = New-Object system.Windows.Forms.Label
$Label1.text                     = "Created by Andrew Taylor (andrewstaylor.com)"
$Label1.AutoSize                 = $true
$Label1.width                    = 25
$Label1.height                   = 10
$Label1.location                 = New-Object System.Drawing.Point(7,396)
$Label1.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',8)

$Autopilot                       = New-Object system.Windows.Forms.Button
$Autopilot.text                  = "Autopilot Devices"
$Autopilot.width                 = 157
$Autopilot.height                = 56
$Autopilot.location              = New-Object System.Drawing.Point(21,18)
$Autopilot.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$project                         = New-Object system.Windows.Forms.Button
$project.text                    = "MS Project Users"
$project.width                   = 157
$project.height                  = 56
$project.location                = New-Object System.Drawing.Point(219,16)
$project.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$Visio                           = New-Object system.Windows.Forms.Button
$Visio.text                      = "MS Visio Users"
$Visio.width                     = 157
$Visio.height                    = 56
$Visio.location                  = New-Object System.Drawing.Point(22,131)
$Visio.Font                      = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$Office                          = New-Object system.Windows.Forms.Button
$Office.text                     = "MS Office Users"
$Office.width                    = 157
$Office.height                   = 56
$Office.location                 = New-Object System.Drawing.Point(222,132)
$Office.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$rings                           = New-Object system.Windows.Forms.Button
$rings.text                      = "Deployment Rings"
$rings.width                     = 157
$rings.height                    = 56
$rings.location                  = New-Object System.Drawing.Point(114,245)
$rings.Font                      = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$Label2                          = New-Object system.Windows.Forms.Label
$Label2.text                     = "Name: Autopilot-Devices"
$Label2.AutoSize                 = $true
$Label2.width                    = 25
$Label2.height                   = 10
$Label2.location                 = New-Object System.Drawing.Point(13,83)
$Label2.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label3                          = New-Object system.Windows.Forms.Label
$Label3.text                     = "Name: Project-Install"
$Label3.AutoSize                 = $true
$Label3.width                    = 25
$Label3.height                   = 10
$Label3.location                 = New-Object System.Drawing.Point(220,83)
$Label3.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label4                          = New-Object system.Windows.Forms.Label
$Label4.text                     = "Name: Project-Uninstall"
$Label4.AutoSize                 = $true
$Label4.width                    = 25
$Label4.height                   = 10
$Label4.location                 = New-Object System.Drawing.Point(220,100)
$Label4.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label5                          = New-Object system.Windows.Forms.Label
$Label5.text                     = "Name: Visio-Install"
$Label5.AutoSize                 = $true
$Label5.width                    = 25
$Label5.height                   = 10
$Label5.location                 = New-Object System.Drawing.Point(23,195)
$Label5.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label6                          = New-Object system.Windows.Forms.Label
$Label6.text                     = "Name: Visio-Uninstall"
$Label6.AutoSize                 = $true
$Label6.width                    = 25
$Label6.height                   = 10
$Label6.location                 = New-Object System.Drawing.Point(24,214)
$Label6.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label7                          = New-Object system.Windows.Forms.Label
$Label7.text                     = "Name: Office-Install"
$Label7.AutoSize                 = $true
$Label7.width                    = 25
$Label7.height                   = 10
$Label7.location                 = New-Object System.Drawing.Point(227,199)
$Label7.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label8                          = New-Object system.Windows.Forms.Label
$Label8.text                     = "Name: Office-Uninstall"
$Label8.AutoSize                 = $true
$Label8.width                    = 25
$Label8.height                   = 10
$Label8.location                 = New-Object System.Drawing.Point(227,216)
$Label8.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label9                          = New-Object system.Windows.Forms.Label
$Label9.text                     = "Name: Intune-Preview-Users"
$Label9.AutoSize                 = $true
$Label9.width                    = 25
$Label9.height                   = 10
$Label9.location                 = New-Object System.Drawing.Point(90,334)
$Label9.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label10                         = New-Object system.Windows.Forms.Label
$Label10.text                    = "Name: Intune-Pilot-Users"
$Label10.AutoSize                = $true
$Label10.width                   = 25
$Label10.height                  = 10
$Label10.location                = New-Object System.Drawing.Point(103,312)
$Label10.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label11                         = New-Object system.Windows.Forms.Label
$Label11.text                    = "Name: Intune-VIP-Users"
$Label11.AutoSize                = $true
$Label11.width                   = 25
$Label11.height                  = 10
$Label11.location                = New-Object System.Drawing.Point(105,354)
$Label11.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$IntuneAzureADGroups.controls.AddRange(@($Label1,$Autopilot,$project,$Visio,$Office,$rings,$Label2,$Label3,$Label4,$Label5,$Label6,$Label7,$Label8,$Label9,$Label10,$Label11))

### Form Actions ###

##Autopilot Group Clicked
$Autopilot.Add_Click({ 
    #AutoPilot Group
    $autopilotgrp = New-AzureADMSGroup -DisplayName "Autopilot-Devices" -Description "Dynamic group for Autopilot Devices" -MailEnabled $False -MailNickName "group" -SecurityEnabled $True -GroupTypes "DynamicMembership" -MembershipRule "(device.devicePhysicalIDs -any (_ -contains ""[ZTDid]""))" -MembershipRuleProcessingState "On"
    Add-Type -AssemblyName PresentationCore,PresentationFramework
    $msgBody = "Group Autopilot-Devices created successfully"
    [System.Windows.MessageBox]::Show($msgBody)   
    write-host "Group Autopilot-Devices created successfully"
 })

##Deployment Rings Button Clicked
$rings.Add_Click({ 
    #Pilot Group
    $pilotgrp = New-AzureADMSGroup -DisplayName "Intune-Pilot-Users" -Description "Assigned group for Pilot Users" -MailEnabled $False -MailNickName "group" -SecurityEnabled $True
    #Preview Group
    $previewgrp = New-AzureADMSGroup -DisplayName "Intune-Preview-Users" -Description "Assigned group for Preview Users" -MailEnabled $False -MailNickName "group" -SecurityEnabled $True
    #VIP Group
    $vipgrp = New-AzureADMSGroup -DisplayName "Intune-VIP-Users" -Description "Assigned group for VIP Users" -MailEnabled $False -MailNickName "group" -SecurityEnabled $True
    Add-Type -AssemblyName PresentationCore,PresentationFramework
    $msgBody = "Groups Intune-Pilot-Users, Intune-Preview-Users, Intune-VIP-Users created successfully"
    [System.Windows.MessageBox]::Show($msgBody)   
    write-host "Groups Intune-Pilot-Users, Intune-Preview-Users, Intune-VIP-Users created successfully"
 })

##Office Button Clicked
$Office.Add_Click({  
    #Create Office Install Group
    $officeinstall = New-AzureADMSGroup -DisplayName "Office-Install" -Description "Dynamic group for users with an Office 365 Enterprise Apps License" -MailEnabled $False -MailNickName "group" -SecurityEnabled $True -GroupTypes "DynamicMembership" -MembershipRule "(user.assignedPlans -any (assignedPlan.servicePlanId -eq ""43de0ff5-c92c-492b-9116-175376d08c38"" -and assignedPlan.capabilityStatus -eq ""Enabled""))" -MembershipRuleProcessingState "On"
    #Create Office Uninstall Group
    $officeuninstall = New-AzureADMSGroup -DisplayName "Office-Uninstall" -Description "Dynamic group for users without an Office 365 Enterprise Apps License" -MailEnabled $False -MailNickName "group" -SecurityEnabled $True -GroupTypes "DynamicMembership" -MembershipRule "(user.assignedPlans -all (assignedPlan.servicePlanId -ne ""43de0ff5-c92c-492b-9116-175376d08c38""))" -MembershipRuleProcessingState "On"
    Add-Type -AssemblyName PresentationCore,PresentationFramework
    $msgBody = "Groups Office-Install, Office-Uninstall created successfully"
    [System.Windows.MessageBox]::Show($msgBody)   
    write-host "Groups Office-Install, Office-Uninstall created successfully"
})


##Visio Button Clicked
$Visio.Add_Click({ 
    #Create Visio Install Group
    write-host "hello"
    $visioinstall = New-AzureADMSGroup -DisplayName "Visio-Install" -Description "Dynamic group for Licensed Visio Users" -MailEnabled $False -MailNickName "group" -SecurityEnabled $True -GroupTypes "DynamicMembership" -MembershipRule "(user.assignedPlans -any (assignedPlan.servicePlanId -eq ""663a804f-1c30-4ff0-9915-9db84f0d1cea"" -and assignedPlan.capabilityStatus -eq ""Enabled""))" -MembershipRuleProcessingState "On"
    #Create Visio Uninstall Group
    $visiouninstall = New-AzureADMSGroup -DisplayName "Visio-Uninstall" -Description "Dynamic group for users without Visio license" -MailEnabled $False -MailNickName "group" -SecurityEnabled $True -GroupTypes "DynamicMembership" -MembershipRule "(user.assignedPlans -all (assignedPlan.servicePlanId -ne ""663a804f-1c30-4ff0-9915-9db84f0d1cea"" -and assignedPlan.capabilityStatus -ne ""Enabled""))" -MembershipRuleProcessingState "On"
    Add-Type -AssemblyName PresentationCore,PresentationFramework
    $msgBody = "Groups Visio-Install, Visio-Uninstall created successfully"
    [System.Windows.MessageBox]::Show($msgBody)   
    write-host "Groups Visio-Install, Visio-Uninstall created successfully"
 })



 ##Project Button Clicked
$project.Add_Click({  
    #Create Project Install Group
    $projectinstall = New-AzureADMSGroup -DisplayName "Project-Install" -Description "Dynamic group for Licensed Project Users" -MailEnabled $False -MailNickName "group" -SecurityEnabled $True -GroupTypes "DynamicMembership" -MembershipRule "(user.assignedPlans -any (assignedPlan.servicePlanId -eq ""fafd7243-e5c1-4a3a-9e40-495efcb1d3c3"" -and assignedPlan.capabilityStatus -eq ""Enabled""))" -MembershipRuleProcessingState "On"
    #Create Project Uninstall Group
    $projectuninstall = New-AzureADMSGroup -DisplayName "Project-Uninstall" -Description "Dynamic group for users without Project license" -MailEnabled $False -MailNickName "group" -SecurityEnabled $True -GroupTypes "DynamicMembership" -MembershipRule "(user.assignedPlans -all (assignedPlan.servicePlanId -ne ""fafd7243-e5c1-4a3a-9e40-495efcb1d3c3"" -and assignedPlan.capabilityStatus -ne ""Enabled""))" -MembershipRuleProcessingState "On"
    Add-Type -AssemblyName PresentationCore,PresentationFramework
    $msgBody = "Groups Project-Install, Project-Uninstall created successfully"
    [System.Windows.MessageBox]::Show($msgBody)   
    write-host "Groups Project-Install, Project-Uninstall created successfully"
})



#region Logic 

#endregion


#[void]$IntuneAzureADGroups.ShowDialog()
### Switch on Params ###

switch ($groupname) {
    "Autopilot"{
        #AutoPilot Group
        $autopilotgrp = New-AzureADMSGroup -DisplayName "Autopilot-Devices" -Description "Dynamic group for Autopilot Devices" -MailEnabled $False -MailNickName "group" -SecurityEnabled $True -GroupTypes "DynamicMembership" -MembershipRule "(device.devicePhysicalIDs -any (_ -contains ""[ZTDid]""))" -MembershipRuleProcessingState "On"
        write-host "Group Autopilot-Devices created successfully"
    break
    }
    "Visio"{
        #Create Visio Install Group
        $visioinstall = New-AzureADMSGroup -DisplayName "Visio-Install" -Description "Dynamic group for Licensed Visio Users" -MailEnabled $False -MailNickName "group" -SecurityEnabled $True -GroupTypes "DynamicMembership" -MembershipRule "(user.assignedPlans -any (assignedPlan.servicePlanId -eq ""663a804f-1c30-4ff0-9915-9db84f0d1cea"" -and assignedPlan.capabilityStatus -eq ""Enabled""))" -MembershipRuleProcessingState "On"
        #Create Visio Uninstall Group
        $visiouninstall = New-AzureADMSGroup -DisplayName "Visio-Uninstall" -Description "Dynamic group for users without Visio license" -MailEnabled $False -MailNickName "group" -SecurityEnabled $True -GroupTypes "DynamicMembership" -MembershipRule "(user.assignedPlans -all (assignedPlan.servicePlanId -ne ""663a804f-1c30-4ff0-9915-9db84f0d1cea"" -and assignedPlan.capabilityStatus -ne ""Enabled""))" -MembershipRuleProcessingState "On"
        write-host "Groups Visio-Install, Visio-Uninstall created successfully"
    break
    }
    "Project"{
        #Create Project Install Group
        $projectinstall = New-AzureADMSGroup -DisplayName "Project-Install" -Description "Dynamic group for Licensed Project Users" -MailEnabled $False -MailNickName "group" -SecurityEnabled $True -GroupTypes "DynamicMembership" -MembershipRule "(user.assignedPlans -any (assignedPlan.servicePlanId -eq ""fafd7243-e5c1-4a3a-9e40-495efcb1d3c3"" -and assignedPlan.capabilityStatus -eq ""Enabled""))" -MembershipRuleProcessingState "On"
        #Create Project Uninstall Group
        $projectuninstall = New-AzureADMSGroup -DisplayName "Project-Uninstall" -Description "Dynamic group for users without Project license" -MailEnabled $False -MailNickName "group" -SecurityEnabled $True -GroupTypes "DynamicMembership" -MembershipRule "(user.assignedPlans -all (assignedPlan.servicePlanId -ne ""fafd7243-e5c1-4a3a-9e40-495efcb1d3c3"" -and assignedPlan.capabilityStatus -ne ""Enabled""))" -MembershipRuleProcessingState "On"
        write-host "Groups Project-Install, Project-Uninstall created successfully"
    break
    }
    "Office" {
        #Create Office Install Group
        $officeinstall = New-AzureADMSGroup -DisplayName "Office-Install" -Description "Dynamic group for users with an Office 365 Enterprise Apps License" -MailEnabled $False -MailNickName "group" -SecurityEnabled $True -GroupTypes "DynamicMembership" -MembershipRule "(user.assignedPlans -any (assignedPlan.servicePlanId -eq ""43de0ff5-c92c-492b-9116-175376d08c38"" -and assignedPlan.capabilityStatus -eq ""Enabled""))" -MembershipRuleProcessingState "On"
        #Create Office Uninstall Group
        $officeuninstall = New-AzureADMSGroup -DisplayName "Office-Uninstall" -Description "Dynamic group for users without an Office 365 Enterprise Apps License" -MailEnabled $False -MailNickName "group" -SecurityEnabled $True -GroupTypes "DynamicMembership" -MembershipRule "(user.assignedPlans -all (assignedPlan.servicePlanId -ne ""43de0ff5-c92c-492b-9116-175376d08c38""))" -MembershipRuleProcessingState "On"
        write-host "Groups Office-Install, Office-Uninstall created successfully"
    break
    }
    "Deployment" {
        #Pilot Group
        $pilotgrp = New-AzureADMSGroup -DisplayName "Intune-Pilot-Users" -Description "Assigned group for Pilot Users" -MailEnabled $False -MailNickName "group" -SecurityEnabled $True
        #Preview Group
        $previewgrp = New-AzureADMSGroup -DisplayName "Intune-Preview-Users" -Description "Assigned group for Preview Users" -MailEnabled $False -MailNickName "group" -SecurityEnabled $True
        #VIP Group
        $vipgrp = New-AzureADMSGroup -DisplayName "Intune-VIP-Users" -Description "Assigned group for VIP Users" -MailEnabled $False -MailNickName "group" -SecurityEnabled $True
        write-host "Groups Intune-Pilot-Users, Intune-Preview-Users, Intune-VIP-Users created successfully"
    break
    }
    default {
        #Nothing selected, Launch Form
        write-host "No params set - Launching Form"
        [void]$IntuneAzureADGroups.ShowDialog()
         break
    }
}