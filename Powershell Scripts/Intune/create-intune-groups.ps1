<#PSScriptInfo
.VERSION 2.3
.GUID 9cb596f8-e4f4-4fbb-bf0b-8d5c227af59c
.AUTHOR AndrewTaylor
.DESCRIPTION Creates Intune groups via command line or GUI
.COMPANYNAME 
.COPYRIGHT GPL
.TAGS intune Azure AD
.LICENSEURI https://github.com/andrew-s-taylor/public/blob/main/LICENSE
.PROJECTURI https://github.com/andrew-s-taylor/public
.ICONURI 
.EXTERNALMODULEDEPENDENCIES microsoft.graph
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
  Version:        2.3
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  26/02/2022
  Modified Date:  30/10/2022
  Purpose/Change: Initial script development
  Change:   Switched from AAD to Graph Module
  
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



## END INSTALL MODULES ###
Function Connect-ToGraph {
    <#
.SYNOPSIS
Authenticates to the Graph API via the Microsoft.Graph.Authentication module.
 
.DESCRIPTION
The Connect-ToGraph cmdlet is a wrapper cmdlet that helps authenticate to the Intune Graph API using the Microsoft.Graph.Authentication module. It leverages an Azure AD app ID and app secret for authentication or user-based auth.
 
.PARAMETER Tenant
Specifies the tenant (e.g. contoso.onmicrosoft.com) to which to authenticate.
 
.PARAMETER AppId
Specifies the Azure AD app ID (GUID) for the application that will be used to authenticate.
 
.PARAMETER AppSecret
Specifies the Azure AD app secret corresponding to the app ID that will be used to authenticate.

.PARAMETER Scopes
Specifies the user scopes for interactive authentication.
 
.EXAMPLE
Connect-ToGraph -TenantId $tenantID -AppId $app -AppSecret $secret
 
-#>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $false)] [string]$Tenant,
        [Parameter(Mandatory = $false)] [string]$AppId,
        [Parameter(Mandatory = $false)] [string]$AppSecret,
        [Parameter(Mandatory = $false)] [string]$scopes
    )

    Process {
        Import-Module Microsoft.Graph.Authentication
        $version = (get-module microsoft.graph.authentication | Select-Object -expandproperty Version).major

        if ($AppId -ne "") {
            $body = @{
                grant_type    = "client_credentials";
                client_id     = $AppId;
                client_secret = $AppSecret;
                scope         = "https://graph.microsoft.com/.default";
            }
     
            $response = Invoke-RestMethod -Method Post -Uri https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token -Body $body
            $accessToken = $response.access_token
     
            $accessToken
            if ($version -eq 2) {
                write-host "Version 2 module detected"
                $accesstokenfinal = ConvertTo-SecureString -String $accessToken -AsPlainText -Force
            }
            else {
                write-host "Version 1 Module Detected"
                Select-MgProfile -Name Beta
                $accesstokenfinal = $accessToken
            }
            $graph = Connect-MgGraph  -AccessToken $accesstokenfinal 
            Write-Host "Connected to Intune tenant $TenantId using app-based authentication (Azure AD authentication not supported)"
        }
        else {
            if ($version -eq 2) {
                write-host "Version 2 module detected"
            }
            else {
                write-host "Version 1 Module Detected"
                Select-MgProfile -Name Beta
            }
            $graph = Connect-MgGraph -scopes $scopes
            Write-Host "Connected to Intune tenant $($graph.TenantId)"
        }
    }
}    
## IMPORT MODULES ###

# Load the Graph module
Import-Module microsoft.graph

## END IMPORT MODULES ###

#Connect to Graph
Connect-ToGraph -Scopes "RoleAssignmentSchedule.ReadWrite.Directory, Domain.Read.All, Domain.ReadWrite.All, Directory.Read.All, Policy.ReadWrite.ConditionalAccess, DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, openid, profile, email, offline_access"




####################################### Create Form ################################################

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
########################################### END FORM ###############################################


########################################### Form Actions ###############################################

##Autopilot Group Clicked
$Autopilot.Add_Click({ 
    #AutoPilot Group
    $autopilotgrp = New-MgGroup -DisplayName "Autopilot-Devices" -Description "Dynamic group for Autopilot Devices" -MailEnabled:$false -MailNickName "autopilotdevices" -SecurityEnabled -GroupTypes "DynamicMembership" -MembershipRule "(device.devicePhysicalIDs -any (_ -contains ""[ZTDid]""))" -MembershipRuleProcessingState "On"
    Add-Type -AssemblyName PresentationCore,PresentationFramework
    $msgBody = "Group Autopilot-Devices created successfully"
    [System.Windows.MessageBox]::Show($msgBody)   
    write-host "Group Autopilot-Devices created successfully"
 })

##Deployment Rings Button Clicked
$rings.Add_Click({ 
    #Pilot Group
    $pilotgrp = New-MgGroup -DisplayName "Intune-Pilot-Users" -Description "Assigned group for Pilot Users" -MailEnabled:$False -MailNickName "intunepilotusers" -SecurityEnabled
    #Preview Group
    $previewgrp = New-MgGroup -DisplayName "Intune-Preview-Users" -Description "Assigned group for Preview Users" -MailEnabled:$False -MailNickName "intunepreviewusers" -SecurityEnabled
    #VIP Group
    $vipgrp = New-MgGroup -DisplayName "Intune-VIP-Users" -Description "Assigned group for VIP Users" -MailEnabled:$False -MailNickName "intunevipusers" -SecurityEnabled
    Add-Type -AssemblyName PresentationCore,PresentationFramework
    $msgBody = "Groups Intune-Pilot-Users, Intune-Preview-Users, Intune-VIP-Users created successfully"
    [System.Windows.MessageBox]::Show($msgBody)   
    write-host "Groups Intune-Pilot-Users, Intune-Preview-Users, Intune-VIP-Users created successfully"
 })

##Office Button Clicked
$Office.Add_Click({  
    #Create Office Install Group
    $officeinstall = New-MgGroup -DisplayName "Office-Install" -Description "Dynamic group for users with an Office 365 Enterprise Apps License" -MailEnabled:$False -MailNickName "officeusers" -SecurityEnabled -GroupTypes "DynamicMembership" -MembershipRule "(user.assignedPlans -any (assignedPlan.servicePlanId -eq ""43de0ff5-c92c-492b-9116-175376d08c38"" -and assignedPlan.capabilityStatus -eq ""Enabled""))" -MembershipRuleProcessingState "On"
    #Create Office Uninstall Group
    $officeuninstall = New-MgGroup -DisplayName "Office-Uninstall" -Description "Dynamic group for users without an Office 365 Enterprise Apps License" -MailEnabled:$False -MailNickName "nonofficeusers" -SecurityEnabled -GroupTypes "DynamicMembership" -MembershipRule "(user.assignedPlans -all (assignedPlan.servicePlanId -ne ""43de0ff5-c92c-492b-9116-175376d08c38""))" -MembershipRuleProcessingState "On"
    Add-Type -AssemblyName PresentationCore,PresentationFramework
    $msgBody = "Groups Office-Install, Office-Uninstall created successfully"
    [System.Windows.MessageBox]::Show($msgBody)   
    write-host "Groups Office-Install, Office-Uninstall created successfully"
})


##Visio Button Clicked
$Visio.Add_Click({ 
    #Create Visio Install Group
    write-host "hello"
    $visioinstall = New-MgGroup -DisplayName "Visio-Install" -Description "Dynamic group for Licensed Visio Users" -MailEnabled:$False -MailNickName "visiousers" -SecurityEnabled -GroupTypes "DynamicMembership" -MembershipRule "(user.assignedPlans -any (assignedPlan.servicePlanId -eq ""663a804f-1c30-4ff0-9915-9db84f0d1cea"" -and assignedPlan.capabilityStatus -eq ""Enabled""))" -MembershipRuleProcessingState "On"
    #Create Visio Uninstall Group
    $visiouninstall = New-MgGroup -DisplayName "Visio-Uninstall" -Description "Dynamic group for users without Visio license" -MailEnabled:$False -MailNickName "nonvisiousers" -SecurityEnabled -GroupTypes "DynamicMembership" -MembershipRule "(user.assignedPlans -all (assignedPlan.servicePlanId -ne ""663a804f-1c30-4ff0-9915-9db84f0d1cea"" -and assignedPlan.capabilityStatus -ne ""Enabled""))" -MembershipRuleProcessingState "On"
    Add-Type -AssemblyName PresentationCore,PresentationFramework
    $msgBody = "Groups Visio-Install, Visio-Uninstall created successfully"
    [System.Windows.MessageBox]::Show($msgBody)   
    write-host "Groups Visio-Install, Visio-Uninstall created successfully"
 })



 ##Project Button Clicked
$project.Add_Click({  
    #Create Project Install Group
    $projectinstall = New-MgGroup -DisplayName "Project-Install" -Description "Dynamic group for Licensed Project Users" -MailEnabled:$False -MailNickName "projectusers" -SecurityEnabled -GroupTypes "DynamicMembership" -MembershipRule "(user.assignedPlans -any (assignedPlan.servicePlanId -eq ""fafd7243-e5c1-4a3a-9e40-495efcb1d3c3"" -and assignedPlan.capabilityStatus -eq ""Enabled""))" -MembershipRuleProcessingState "On"
    #Create Project Uninstall Group
    $projectuninstall = New-MgGroup -DisplayName "Project-Uninstall" -Description "Dynamic group for users without Project license" -MailEnabled:$False -MailNickName "nonprojectusers" -SecurityEnabled -GroupTypes "DynamicMembership" -MembershipRule "(user.assignedPlans -all (assignedPlan.servicePlanId -ne ""fafd7243-e5c1-4a3a-9e40-495efcb1d3c3"" -and assignedPlan.capabilityStatus -ne ""Enabled""))" -MembershipRuleProcessingState "On"
    Add-Type -AssemblyName PresentationCore,PresentationFramework
    $msgBody = "Groups Project-Install, Project-Uninstall created successfully"
    [System.Windows.MessageBox]::Show($msgBody)   
    write-host "Groups Project-Install, Project-Uninstall created successfully"
})

############################################# END FORM ACTION ################################################################


############################################ Switch on Params ##################################################################

switch ($groupname) {
    "Autopilot"{
        #AutoPilot Group
        $autopilotgrp = New-MgGroup -DisplayName "Autopilot-Devices" -Description "Dynamic group for Autopilot Devices" -MailEnabled:$false -MailNickName "autopilotdevices" -SecurityEnabled -GroupTypes "DynamicMembership" -MembershipRule "(device.devicePhysicalIDs -any (_ -contains ""[ZTDid]""))" -MembershipRuleProcessingState "On"
        write-host "Group Autopilot-Devices created successfully"
    break
    }
    "Visio"{
        #Create Visio Install Group
        $visioinstall = New-MgGroup -DisplayName "Visio-Install" -Description "Dynamic group for Licensed Visio Users" -MailEnabled:$False -MailNickName "visiousers" -SecurityEnabled -GroupTypes "DynamicMembership" -MembershipRule "(user.assignedPlans -any (assignedPlan.servicePlanId -eq ""663a804f-1c30-4ff0-9915-9db84f0d1cea"" -and assignedPlan.capabilityStatus -eq ""Enabled""))" -MembershipRuleProcessingState "On"
        #Create Visio Uninstall Group
        $visiouninstall = New-MgGroup -DisplayName "Visio-Uninstall" -Description "Dynamic group for users without Visio license" -MailEnabled:$False -MailNickName "nonvisiousers" -SecurityEnabled -GroupTypes "DynamicMembership" -MembershipRule "(user.assignedPlans -all (assignedPlan.servicePlanId -ne ""663a804f-1c30-4ff0-9915-9db84f0d1cea"" -and assignedPlan.capabilityStatus -ne ""Enabled""))" -MembershipRuleProcessingState "On"
            write-host "Groups Visio-Install, Visio-Uninstall created successfully"
    break
    }
    "Project"{
    #Create Project Install Group
    $projectinstall = New-MgGroup -DisplayName "Project-Install" -Description "Dynamic group for Licensed Project Users" -MailEnabled:$False -MailNickName "projectusers" -SecurityEnabled -GroupTypes "DynamicMembership" -MembershipRule "(user.assignedPlans -any (assignedPlan.servicePlanId -eq ""fafd7243-e5c1-4a3a-9e40-495efcb1d3c3"" -and assignedPlan.capabilityStatus -eq ""Enabled""))" -MembershipRuleProcessingState "On"
    #Create Project Uninstall Group
    $projectuninstall = New-MgGroup -DisplayName "Project-Uninstall" -Description "Dynamic group for users without Project license" -MailEnabled:$False -MailNickName "nonprojectusers" -SecurityEnabled -GroupTypes "DynamicMembership" -MembershipRule "(user.assignedPlans -all (assignedPlan.servicePlanId -ne ""fafd7243-e5c1-4a3a-9e40-495efcb1d3c3"" -and assignedPlan.capabilityStatus -ne ""Enabled""))" -MembershipRuleProcessingState "On"
        write-host "Groups Project-Install, Project-Uninstall created successfully"
    break
    }
    "Office" {
        #Create Office Install Group
        $officeinstall = New-MgGroup -DisplayName "Office-Install" -Description "Dynamic group for users with an Office 365 Enterprise Apps License" -MailEnabled:$False -MailNickName "officeusers" -SecurityEnabled -GroupTypes "DynamicMembership" -MembershipRule "(user.assignedPlans -any (assignedPlan.servicePlanId -eq ""43de0ff5-c92c-492b-9116-175376d08c38"" -and assignedPlan.capabilityStatus -eq ""Enabled""))" -MembershipRuleProcessingState "On"
        #Create Office Uninstall Group
        $officeuninstall = New-MgGroup -DisplayName "Office-Uninstall" -Description "Dynamic group for users without an Office 365 Enterprise Apps License" -MailEnabled:$False -MailNickName "nonofficeusers" -SecurityEnabled -GroupTypes "DynamicMembership" -MembershipRule "(user.assignedPlans -all (assignedPlan.servicePlanId -ne ""43de0ff5-c92c-492b-9116-175376d08c38""))" -MembershipRuleProcessingState "On"
            write-host "Groups Office-Install, Office-Uninstall created successfully"
    break
    }
    "Deployment" {
        #Pilot Group
        $pilotgrp = New-MgGroup -DisplayName "Intune-Pilot-Users" -Description "Assigned group for Pilot Users" -MailEnabled:$False -MailNickName "intunepilotusers" -SecurityEnabled
        #Preview Group
        $previewgrp = New-MgGroup -DisplayName "Intune-Preview-Users" -Description "Assigned group for Preview Users" -MailEnabled:$False -MailNickName "intunepreviewusers" -SecurityEnabled
        #VIP Group
        $vipgrp = New-MgGroup -DisplayName "Intune-VIP-Users" -Description "Assigned group for VIP Users" -MailEnabled:$False -MailNickName "intunevipusers" -SecurityEnabled
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
######################################################## END SWITCH ##############################################################

# SIG # Begin signature block
# MIIoGQYJKoZIhvcNAQcCoIIoCjCCKAYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBeVUX3HKPGF7zG
# /5pD+hqzjFSc3viTqi6JrUOZaJdIjqCCIRwwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggauMIIElqADAgECAhAHNje3JFR82Ees/ShmKl5bMA0GCSqG
# SIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDAeFw0yMjAzMjMwMDAwMDBaFw0zNzAzMjIyMzU5NTlaMGMx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMy
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcg
# Q0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDGhjUGSbPBPXJJUVXH
# JQPE8pE3qZdRodbSg9GeTKJtoLDMg/la9hGhRBVCX6SI82j6ffOciQt/nR+eDzMf
# UBMLJnOWbfhXqAJ9/UO0hNoR8XOxs+4rgISKIhjf69o9xBd/qxkrPkLcZ47qUT3w
# 1lbU5ygt69OxtXXnHwZljZQp09nsad/ZkIdGAHvbREGJ3HxqV3rwN3mfXazL6IRk
# tFLydkf3YYMZ3V+0VAshaG43IbtArF+y3kp9zvU5EmfvDqVjbOSmxR3NNg1c1eYb
# qMFkdECnwHLFuk4fsbVYTXn+149zk6wsOeKlSNbwsDETqVcplicu9Yemj052FVUm
# cJgmf6AaRyBD40NjgHt1biclkJg6OBGz9vae5jtb7IHeIhTZgirHkr+g3uM+onP6
# 5x9abJTyUpURK1h0QCirc0PO30qhHGs4xSnzyqqWc0Jon7ZGs506o9UD4L/wojzK
# QtwYSH8UNM/STKvvmz3+DrhkKvp1KCRB7UK/BZxmSVJQ9FHzNklNiyDSLFc1eSuo
# 80VgvCONWPfcYd6T/jnA+bIwpUzX6ZhKWD7TA4j+s4/TXkt2ElGTyYwMO1uKIqjB
# Jgj5FBASA31fI7tk42PgpuE+9sJ0sj8eCXbsq11GdeJgo1gJASgADoRU7s7pXche
# MBK9Rp6103a50g5rmQzSM7TNsQIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB
# /wIBADAdBgNVHQ4EFgQUuhbZbU2FL3MpdpovdYxqII+eyG8wHwYDVR0jBBgwFoAU
# 7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoG
# CCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29j
# c3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDig
# NqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZI
# hvcNAQELBQADggIBAH1ZjsCTtm+YqUQiAX5m1tghQuGwGC4QTRPPMFPOvxj7x1Bd
# 4ksp+3CKDaopafxpwc8dB+k+YMjYC+VcW9dth/qEICU0MWfNthKWb8RQTGIdDAiC
# qBa9qVbPFXONASIlzpVpP0d3+3J0FNf/q0+KLHqrhc1DX+1gtqpPkWaeLJ7giqzl
# /Yy8ZCaHbJK9nXzQcAp876i8dU+6WvepELJd6f8oVInw1YpxdmXazPByoyP6wCeC
# RK6ZJxurJB4mwbfeKuv2nrF5mYGjVoarCkXJ38SNoOeY+/umnXKvxMfBwWpx2cYT
# gAnEtp/Nh4cku0+jSbl3ZpHxcpzpSwJSpzd+k1OsOx0ISQ+UzTl63f8lY5knLD0/
# a6fxZsNBzU+2QJshIUDQtxMkzdwdeDrknq3lNHGS1yZr5Dhzq6YBT70/O3itTK37
# xJV77QpfMzmHQXh6OOmc4d0j/R0o08f56PGYX/sr2H7yRp11LB4nLCbbbxV7HhmL
# NriT1ObyF5lZynDwN7+YAN8gFk8n+2BnFqFmut1VwDophrCYoCvtlUG3OtUVmDG0
# YgkPCr2B2RP+v6TR81fZvAT6gt4y3wSJ8ADNXcL50CN/AAvkdgIm2fBldkKmKYcJ
# RyvmfxqkhQ/8mJb2VVQrH4D6wPIOK+XW+6kvRBVK5xMOHds3OBqhK/bt1nz8MIIG
# sDCCBJigAwIBAgIQCK1AsmDSnEyfXs2pvZOu2TANBgkqhkiG9w0BAQwFADBiMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQw
# HhcNMjEwNDI5MDAwMDAwWhcNMzYwNDI4MjM1OTU5WjBpMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0
# ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExMIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1bQvQtAorXi3XdU5WRuxiEL1M4zr
# PYGXcMW7xIUmMJ+kjmjYXPXrNCQH4UtP03hD9BfXHtr50tVnGlJPDqFX/IiZwZHM
# gQM+TXAkZLON4gh9NH1MgFcSa0OamfLFOx/y78tHWhOmTLMBICXzENOLsvsI8Irg
# nQnAZaf6mIBJNYc9URnokCF4RS6hnyzhGMIazMXuk0lwQjKP+8bqHPNlaJGiTUyC
# EUhSaN4QvRRXXegYE2XFf7JPhSxIpFaENdb5LpyqABXRN/4aBpTCfMjqGzLmysL0
# p6MDDnSlrzm2q2AS4+jWufcx4dyt5Big2MEjR0ezoQ9uo6ttmAaDG7dqZy3SvUQa
# khCBj7A7CdfHmzJawv9qYFSLScGT7eG0XOBv6yb5jNWy+TgQ5urOkfW+0/tvk2E0
# XLyTRSiDNipmKF+wc86LJiUGsoPUXPYVGUztYuBeM/Lo6OwKp7ADK5GyNnm+960I
# HnWmZcy740hQ83eRGv7bUKJGyGFYmPV8AhY8gyitOYbs1LcNU9D4R+Z1MI3sMJN2
# FKZbS110YU0/EpF23r9Yy3IQKUHw1cVtJnZoEUETWJrcJisB9IlNWdt4z4FKPkBH
# X8mBUHOFECMhWWCKZFTBzCEa6DgZfGYczXg4RTCZT/9jT0y7qg0IU0F8WD1Hs/q2
# 7IwyCQLMbDwMVhECAwEAAaOCAVkwggFVMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYD
# VR0OBBYEFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB8GA1UdIwQYMBaAFOzX44LScV1k
# TN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcD
# AzB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2lj
# ZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0
# cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmww
# HAYDVR0gBBUwEzAHBgVngQwBAzAIBgZngQwBBAEwDQYJKoZIhvcNAQEMBQADggIB
# ADojRD2NCHbuj7w6mdNW4AIapfhINPMstuZ0ZveUcrEAyq9sMCcTEp6QRJ9L/Z6j
# fCbVN7w6XUhtldU/SfQnuxaBRVD9nL22heB2fjdxyyL3WqqQz/WTauPrINHVUHmI
# moqKwba9oUgYftzYgBoRGRjNYZmBVvbJ43bnxOQbX0P4PpT/djk9ntSZz0rdKOtf
# JqGVWEjVGv7XJz/9kNF2ht0csGBc8w2o7uCJob054ThO2m67Np375SFTWsPK6Wrx
# oj7bQ7gzyE84FJKZ9d3OVG3ZXQIUH0AzfAPilbLCIXVzUstG2MQ0HKKlS43Nb3Y3
# LIU/Gs4m6Ri+kAewQ3+ViCCCcPDMyu/9KTVcH4k4Vfc3iosJocsL6TEa/y4ZXDlx
# 4b6cpwoG1iZnt5LmTl/eeqxJzy6kdJKt2zyknIYf48FWGysj/4+16oh7cGvmoLr9
# Oj9FpsToFpFSi0HASIRLlk2rREDjjfAVKM7t8RhWByovEMQMCGQ8M4+uKIw8y4+I
# Cw2/O/TOHnuO77Xry7fwdxPm5yg/rBKupS8ibEH5glwVZsxsDsrFhsP2JjMMB0ug
# 0wcCampAMEhLNKhRILutG4UI4lkNbcoFUCvqShyepf2gpx8GdOfy1lKQ/a+FSCH5
# Vzu0nAPthkX0tGFuv2jiJmCG6sivqf6UHedjGzqGVnhOMIIGwjCCBKqgAwIBAgIQ
# BUSv85SdCDmmv9s/X+VhFjANBgkqhkiG9w0BAQsFADBjMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0
# ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMB4XDTIzMDcxNDAw
# MDAwMFoXDTM0MTAxMzIzNTk1OVowSDELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMSAwHgYDVQQDExdEaWdpQ2VydCBUaW1lc3RhbXAgMjAyMzCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKNTRYcdg45brD5UsyPgz5/X
# 5dLnXaEOCdwvSKOXejsqnGfcYhVYwamTEafNqrJq3RApih5iY2nTWJw1cb86l+uU
# UI8cIOrHmjsvlmbjaedp/lvD1isgHMGXlLSlUIHyz8sHpjBoyoNC2vx/CSSUpIIa
# 2mq62DvKXd4ZGIX7ReoNYWyd/nFexAaaPPDFLnkPG2ZS48jWPl/aQ9OE9dDH9kgt
# XkV1lnX+3RChG4PBuOZSlbVH13gpOWvgeFmX40QrStWVzu8IF+qCZE3/I+PKhu60
# pCFkcOvV5aDaY7Mu6QXuqvYk9R28mxyyt1/f8O52fTGZZUdVnUokL6wrl76f5P17
# cz4y7lI0+9S769SgLDSb495uZBkHNwGRDxy1Uc2qTGaDiGhiu7xBG3gZbeTZD+BY
# QfvYsSzhUa+0rRUGFOpiCBPTaR58ZE2dD9/O0V6MqqtQFcmzyrzXxDtoRKOlO0L9
# c33u3Qr/eTQQfqZcClhMAD6FaXXHg2TWdc2PEnZWpST618RrIbroHzSYLzrqawGw
# 9/sqhux7UjipmAmhcbJsca8+uG+W1eEQE/5hRwqM/vC2x9XH3mwk8L9CgsqgcT2c
# kpMEtGlwJw1Pt7U20clfCKRwo+wK8REuZODLIivK8SgTIUlRfgZm0zu++uuRONhR
# B8qUt+JQofM604qDy0B7AgMBAAGjggGLMIIBhzAOBgNVHQ8BAf8EBAMCB4AwDAYD
# VR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAgBgNVHSAEGTAXMAgG
# BmeBDAEEAjALBglghkgBhv1sBwEwHwYDVR0jBBgwFoAUuhbZbU2FL3MpdpovdYxq
# II+eyG8wHQYDVR0OBBYEFKW27xPn783QZKHVVqllMaPe1eNJMFoGA1UdHwRTMFEw
# T6BNoEuGSWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRH
# NFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcmwwgZAGCCsGAQUFBwEBBIGD
# MIGAMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wWAYIKwYB
# BQUHMAKGTGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0
# ZWRHNFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcnQwDQYJKoZIhvcNAQEL
# BQADggIBAIEa1t6gqbWYF7xwjU+KPGic2CX/yyzkzepdIpLsjCICqbjPgKjZ5+PF
# 7SaCinEvGN1Ott5s1+FgnCvt7T1IjrhrunxdvcJhN2hJd6PrkKoS1yeF844ektrC
# QDifXcigLiV4JZ0qBXqEKZi2V3mP2yZWK7Dzp703DNiYdk9WuVLCtp04qYHnbUFc
# jGnRuSvExnvPnPp44pMadqJpddNQ5EQSviANnqlE0PjlSXcIWiHFtM+YlRpUurm8
# wWkZus8W8oM3NG6wQSbd3lqXTzON1I13fXVFoaVYJmoDRd7ZULVQjK9WvUzF4UbF
# KNOt50MAcN7MmJ4ZiQPq1JE3701S88lgIcRWR+3aEUuMMsOI5ljitts++V+wQtaP
# 4xeR0arAVeOGv6wnLEHQmjNKqDbUuXKWfpd5OEhfysLcPTLfddY2Z1qJ+Panx+VP
# NTwAvb6cKmx5AdzaROY63jg7B145WPR8czFVoIARyxQMfq68/qTreWWqaNYiyjvr
# moI1VygWy2nyMpqy0tg6uLFGhmu6F/3Ed2wVbK6rr3M66ElGt9V/zLY4wNjsHPW2
# obhDLN9OTH0eaHDAdwrUAuBcYLso/zjlUlrWrBciI0707NMX+1Br/wd3H3GXREHJ
# uEbTbDJ8WC9nR2XlG3O2mflrLAZG70Ee8PBf4NvZrZCARK+AEEGKMIIHWzCCBUOg
# AwIBAgIQCLGfzbPa87AxVVgIAS8A6TANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQG
# EwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0
# IFRydXN0ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0Ex
# MB4XDTIzMTExNTAwMDAwMFoXDTI2MTExNzIzNTk1OVowYzELMAkGA1UEBhMCR0Ix
# FDASBgNVBAcTC1doaXRsZXkgQmF5MR4wHAYDVQQKExVBTkRSRVdTVEFZTE9SLkNP
# TSBMVEQxHjAcBgNVBAMTFUFORFJFV1NUQVlMT1IuQ09NIExURDCCAiIwDQYJKoZI
# hvcNAQEBBQADggIPADCCAgoCggIBAMOkYkLpzNH4Y1gUXF799uF0CrwW/Lme676+
# C9aZOJYzpq3/DIa81oWv9b4b0WwLpJVu0fOkAmxI6ocu4uf613jDMW0GfV4dRodu
# tryfuDuit4rndvJA6DIs0YG5xNlKTkY8AIvBP3IwEzUD1f57J5GiAprHGeoc4Utt
# zEuGA3ySqlsGEg0gCehWJznUkh3yM8XbksC0LuBmnY/dZJ/8ktCwCd38gfZEO9UD
# DSkie4VTY3T7VFbTiaH0bw+AvfcQVy2CSwkwfnkfYagSFkKar+MYwu7gqVXxrh3V
# /Gjval6PdM0A7EcTqmzrCRtvkWIR6bpz+3AIH6Fr6yTuG3XiLIL6sK/iF/9d4U2P
# iH1vJ/xfdhGj0rQ3/NBRsUBC3l1w41L5q9UX1Oh1lT1OuJ6hV/uank6JY3jpm+Of
# Z7YCTF2Hkz5y6h9T7sY0LTi68Vmtxa/EgEtG6JVNVsqP7WwEkQRxu/30qtjyoX8n
# zSuF7TmsRgmZ1SB+ISclejuqTNdhcycDhi3/IISgVJNRS/F6Z+VQGf3fh6ObdQLV
# woT0JnJjbD8PzJ12OoKgViTQhndaZbkfpiVifJ1uzWJrTW5wErH+qvutHVt4/sEZ
# AVS4PNfOcJXR0s0/L5JHkjtM4aGl62fAHjHj9JsClusj47cT6jROIqQI4ejz1slO
# oclOetCNAgMBAAGjggIDMIIB/zAfBgNVHSMEGDAWgBRoN+Drtjv4XxGG+/5hewiI
# ZfROQjAdBgNVHQ4EFgQU0HdOFfPxa9Yeb5O5J9UEiJkrK98wPgYDVR0gBDcwNTAz
# BgZngQwBBAEwKTAnBggrBgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20v
# Q1BTMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzCBtQYDVR0f
# BIGtMIGqMFOgUaBPhk1odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEzODQyMDIxQ0ExLmNybDBToFGg
# T4ZNaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29k
# ZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAyMUNBMS5jcmwwgZQGCCsGAQUFBwEBBIGH
# MIGEMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXAYIKwYB
# BQUHMAKGUGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0
# ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3J0MAkGA1UdEwQC
# MAAwDQYJKoZIhvcNAQELBQADggIBAEkRh2PwMiyravr66Zww6Pjl24KzDcGYMSxU
# KOEU4bykcOKgvS6V2zeZIs0D/oqct3hBKTGESSQWSA/Jkr1EMC04qJHO/Twr/sBD
# CDBMtJ9XAtO75J+oqDccM+g8Po+jjhqYJzKvbisVUvdsPqFll55vSzRvHGAA6hjy
# DyakGLROcNaSFZGdgOK2AMhQ8EULrE8Riri3D1ROuqGmUWKqcO9aqPHBf5wUwia8
# g980sTXquO5g4TWkZqSvwt1BHMmu69MR6loRAK17HvFcSicK6Pm0zid1KS2z4ntG
# B4Cfcg88aFLog3ciP2tfMi2xTnqN1K+YmU894Pl1lCp1xFvT6prm10Bs6BViKXfD
# fVFxXTB0mHoDNqGi/B8+rxf2z7u5foXPCzBYT+Q3cxtopvZtk29MpTY88GHDVJsF
# MBjX7zM6aCNKsTKC2jb92F+jlkc8clCQQnl3U4jqwbj4ur1JBP5QxQprWhwde0+M
# ifDVp0vHZsVZ0pnYMCKSG5bUr3wOU7EP321DwvvEsTjCy/XDgvy8ipU6w3GjcQQF
# mgp/BX/0JCHX+04QJ0JkR9TTFZR1B+zh3CcK1ZEtTtvuZfjQ3viXwlwtNLy43vbe
# 1J5WNTs0HjJXsfdbhY5kE5RhyfaxFBr21KYx+b+evYyolIS0wR6New6FqLgcc4Ge
# 94yaYVTqMYIGUzCCBk8CAQEwfTBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGln
# aUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgQ29kZSBT
# aWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExAhAIsZ/Ns9rzsDFVWAgBLwDp
# MA0GCWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJ
# KoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQB
# gjcCARUwLwYJKoZIhvcNAQkEMSIEIGAfEQRGaN5NvU42SUzVxllsr1qjdWYMjCBa
# /lRUjZs1MA0GCSqGSIb3DQEBAQUABIICAKIlHttGya+2ocmyzx6bNA/0Afzixcoc
# zTpBL0qrTylNI8I8u1GpXwu5YLWIQCWvwjISk97qhSvsaAUjOgCl0zAO+pisO+E9
# EVe6n/GwsRDtHOvbxC4XaVorxGObNrAfpqmqVsLNNPmN7N+JsvZWf/vDh3/+sBbi
# +SZYiAOc539X5m7rzJ/i5OW9jRj6EMRNCw9MbU026yupY5UNTrKw/CCjetS/VzDV
# B0t8xhL4T2CcYrvKwjFXHpTNxRabsAO7R2VUG0gKdsMgqP130anSwBMLuKDlPPFD
# zwzlvGWWX6rpOzJ9R6SZInaWD1AeplNvwQgICWbJuiIoXt5FpVt6vc8cHnQFn97T
# s4yFvAzxAhjDmk8CGSLQx7gUH7jVgC6SrVgysAgcNB2VEWJCKky9tMvRm37dBckf
# I5Tf+GHdeLBxiW24GCFCAoxGhvT3OoZ9Fno10RHPwXaxd1GdBJdsgf3vfstQ363I
# L7QxMgvra3nNMvfhljG0Km0PYVQ92qG3W1ZikN67KFnFOKcSgMCVaoINSqAGfPlg
# dPMLV/I2iF6yeUxF9RZRQuPMiIYp9jSqNYi1M/OA8jzlALjZC2Ot3LOgGCslpEGZ
# X/iOZ/Q7QTTiWb6fBfgD6/AZ7geKEIEE2o4cQlgWbNodiQ6w2ZHlWTwFwhaPK3CM
# zxQVZvbmSx0boYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkG
# A1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdp
# Q2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQ
# BUSv85SdCDmmv9s/X+VhFjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzEL
# BgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIzMTExNTIwNDY0N1owLwYJKoZI
# hvcNAQkEMSIEILV1RdMlhVxm4oRXrNqdtUG4TpVMeJViV6JRH1qc+bqoMA0GCSqG
# SIb3DQEBAQUABIICACosJ/SU5gSCIaDB+Nbzms5s0i7ome2m2V4yrmxGCgZSVzRB
# /Zk7Pne4gVs072janTYCUOkSfYFwKOxtdEm3uTwmvaUOKbK727EiRHdhSNJTz/Mk
# WqXSJgUph2ECgfpEgIwSxW97eXEc/QktNWkYIifOrBxAsoMt3f67JVi0AodvcYDx
# Vjnj4kPBBP0MV83nsP8mSb4lpjFlRJQWdTyUPaoWobhickpmzzzTwD4lmdNlulVd
# JAOgeFIpVuUpARfWTQleEdREXpNbDpCqZxsoLBFcNpTVayep7ZSRMPN+ZyVVx3xt
# QELAfhDUjbaEQD2jTN1pIoPSNfjmSnVLA5T5nZSvmbxmWWDGZzwTNFwST8lQThKU
# D+w56xfjUH8YbFWXzSpws5cZIeFOFKpnOX8x2O+xZ/uD3VDilLFnbYcIUlMbrAp8
# iqxgz4uOKCnM85+mw70Zp5SNwWM+9KCUpQq7+Ax11IQVfso5bMlF5ZyeCWyb2Y16
# vufF75g2bX+1owxsItrmvGGO1kiBFK5tpfVZRuEou1AzTbcsNR6QQSaRF6+n7vK6
# MU+2PKRruMcDOLHsHzcIAai+H3p6GWRL8r0qfrsTWHirVEJkGHy4h2bO0DNLQ4/Y
# ZTsp/twYOAALktKpy2eOZ+aUQm8XmpieUwhi99v3ZQxgEmG1d9LHhA8fHpkQ
# SIG # End signature block
