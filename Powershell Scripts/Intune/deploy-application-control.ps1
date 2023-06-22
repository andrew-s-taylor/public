<#PSScriptInfo
.VERSION 1.0.0
.GUID ed937b40-9073-41c4-8ae9-4dc8fa2596d9 
.AUTHOR AndrewTaylor
.DESCRIPTION Enables Managed Installer and configures Application Control Policy
.COMPANYNAME 
.COPYRIGHT GPL
.TAGS intune endpoint MEM environment
.LICENSEURI https://github.com/andrew-s-taylor/public/blob/main/LICENSE
.PROJECTURI https://github.com/andrew-s-taylor/public
.ICONURI 
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
#>
<#
.SYNOPSIS
  Enables Managed Installer and configures Application Control Policy
.DESCRIPTION
.Enables Managed Installer
.Configures Application Control Policy
.Can use XML file or GUI settings
.Supports App Reg

.INPUTS
None Required
.OUTPUTS
In-Line Outputs
.NOTES
  Version:        1.0.0
  Author:         Andrew Taylor
  WWW:            andrewstaylor.com
  Creation Date:  22/06/2023
  Purpose/Change: Initial script development
.EXAMPLE
N/A
#>


[CmdletBinding()]
param(
    [Parameter(Mandatory = $False)] [String] $TenantId = "",
    [Parameter(Mandatory = $False)] [String] $AppId = "",
    [Parameter(Mandatory = $False)] [String] $AppSecret = ""
)


##########################################################################################

$ErrorActionPreference = "Continue"
##Start Logging to %TEMP%\intune.log
$date = get-date -format ddMMyyyy
Start-Transcript -Path $env:TEMP\intune-$date.log

###############################################################################################################
######                                         Install Modules                                           ######
###############################################################################################################

Write-Host "Installing Microsoft Graph modules if required (current user scope)"

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication) {
    Write-Host "Microsoft Graph Already Installed"
} 
else {
    try {
        Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser -Repository PSGallery -Force 
    }
    catch [Exception] {
        $_.message 
        exit
    }
}

#Importing Modules
import-module microsoft.graph.authentication

###############################################################################################################

##CONNECT

if ($AppId -ne "") {
    $body = @{
        grant_type    = "client_credentials";
        client_id     = $AppId;
        client_secret = $AppSecret;
        scope         = "https://graph.microsoft.com/.default";
    }

    $response = Invoke-RestMethod -Method Post -Uri https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token -Body $body
    $accessToken = $response.access_token

    $accessToken

    Select-MgProfile -Name Beta
    $graph = Connect-MgGraph  -AccessToken $accessToken 
    Write-Host "Connected to Intune tenant $TenantId using app-based authentication (Azure AD authentication not supported)"
}
else {
    $graph = Connect-MgGraph -scopes Group.ReadWrite.All, Device.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, DeviceManagementServiceConfig.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, GroupMember.ReadWrite.All
    Write-Host "Connected to Intune tenant $($graph.TenantId)"
}


###############################################################################################################

##Add Managed Installer

$posturl = "https://graph.microsoft.com/beta/deviceAppManagement/windowsManagementApp/setAsManagedInstaller"

$geturl = "https://graph.microsoft.com/beta/deviceAppManagement/windowsManagementApp/"

##Check if aleady enabled
write-host "Checking if Managed Installer is already enabled"
$checkmanagedinstaller = Invoke-MgGraphRequest -Method GET -Uri $geturl -OutputType PSObject

if ($checkmanagedinstaller.managedInstaller -eq "enabled") {
    write-host "Managed Installer Configured, nothing more to do"
}
else {
    ##Enable Managed Installer
    write-host "Enabling Managed Installer"
    Invoke-MgGraphRequest -Method POST -Uri $posturl -Body $body -OutputType PSObject
    write-host "Managed Installer Enabled"
}

##Add Profile
write-host "Configuring Profile"
$url = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"
$name = "Application Control"
$description = "Application Control Policy"
write-host "Checking for XML"
$wdacxml = ""

if ($wdacxml -eq "") {
write-host "No XML Detected, checking GUI values"
##Only for GUI configured
##Allow Managed installers?
$managedinstallers = "false"
write-host "Managed installers set to $managedinstallers"
##Allow Trusted Installers?
$trustedinstallers = "false"
write-host "Trusted installers set to $trustedinstallers"
##Enable Store or Audit only?
$windowsappcontrol = "enable"
write-host "Windows App Control set to $windowsappcontrol"
}

if ($windowsappcontrol -eq "enable") {
    $windowsappcontrol = "device_vendor_msft_policy_config_applicationcontrol_built_in_controls_enable_app_control_0"
}
else {
    $windowsappcontrol = "device_vendor_msft_policy_config_applicationcontrol_built_in_controls_enable_app_control_1"
}

##This uses just the built-in controls
$jsonpart1 = @"
{
	"description": "$description",
	"name": "$name",
	"platforms": "windows10",
	"roleScopeTagIds": [
		"0"
	],
	"settings": [
		{
			"@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
			"settingInstance": {
				"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
				"choiceSettingValue": {
					"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
					"children": [
						{
							"@odata.type": "#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance",
							"groupSettingCollectionValue": [
								{
									"children": [
										{
											"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
											"choiceSettingValue": {
												"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
												"children": [],
												"value": "$windowsappcontrol"
											},
											"settingDefinitionId": "device_vendor_msft_policy_config_applicationcontrol_built_in_controls_enable_app_control"
										}
"@

$jsonpart2a = @"
,{
    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingCollectionInstance",
    "choiceSettingCollectionValue": [
"@
$jsonmanagedyes = @"
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
            "children": [],
            "value": "device_vendor_msft_policy_config_applicationcontrol_built_in_controls_trust_apps_1"
        }
"@
$jsontrustedyes = @"
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
            "children": [],
            "value": "device_vendor_msft_policy_config_applicationcontrol_built_in_controls_trust_apps_0"
        }
"@
$jsonpart2b = @"
    ],
    "settingDefinitionId": "device_vendor_msft_policy_config_applicationcontrol_built_in_controls_trust_apps"
}
"@
$jsonpart3 = @"
]
}
],
"settingDefinitionId": "device_vendor_msft_policy_config_applicationcontrol_built_in_controls"
}
],
"settingValueTemplateReference": {
"settingValueTemplateId": "b28c7dc4-c7b2-4ce2-8f51-6ebfd3ea69d3"
},
"value": "device_vendor_msft_policy_config_applicationcontrol_built_in_controls_selected"
},
"settingDefinitionId": "device_vendor_msft_policy_config_applicationcontrol_policies_{policyguid}_policiesoptions",
"settingInstanceTemplateReference": {
"settingInstanceTemplateId": "1de98212-6949-42dc-a89c-e0ff6e5da04b"
}
}
}
],
"technologies": "mdm",
"templateReference": {
"templateId": "4321b946-b76b-4450-8afd-769c08b16ffc_1"
}
}
"@


if ($wdacxml -eq "") {
write-host "Populating JSON"
    ##Check if either are set
if ($managedinstallers -eq "true" -or $trustedinstallers -eq "true") {
    $json = $jsonpart1 + $jsonpart2a
    if ($managedinstallers -eq "true" -and $trustedinstallers -eq "true") {
        $json += $jsonmanagedyes + "," + $jsontrustedyes
        }
    else {
    if ($managedinstallers -eq "true") {
    $json += $jsonmanagedyes
    }
    if ($trustedinstallers -eq "true") {
    $json += $jsontrustedyes
    }
    }
    $json += $jsonpart2b + $jsonpart3
}
else {
    $json = $jsonpart1 + $jsonpart3
}

write-host "JSON Populated"
}
else {
write-host "XML Supplied, cleaning"
##Get the raw data
$rawdata = Get-Content $wdacxml -Raw
write-host "XML Ingested"
##Replace \ with \\
$rawdata = $rawdata -replace '\\', '\\'
write-host "Backslashes replaced"

##Escape the quotes
$rawdata = $rawdata -replace '"', '\"'
write-host "Quotes escaped"

##Replace newlines with \r\n
$rawdata = $rawdata -replace "`r`n", "\r\n"
write-host "Newlines replaced"

write-host "Populating JSON"
$json = @"
{
	"creationSource": null,
	"description": "$description",
	"name": "$name",
	"platforms": "windows10",
	"roleScopeTagIds": [
		"0"
	],
	"settings": [
		{
			"@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
			"settingInstance": {
				"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
				"choiceSettingValue": {
					"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
					"children": [
						{
							"@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
							"settingDefinitionId": "device_vendor_msft_policy_config_applicationcontrol_policies_{policyguid}_xml",
							"settingInstanceTemplateReference": {
								"settingInstanceTemplateId": "4d709667-63d7-42f2-8e1b-b780f6c3c9c7"
							},
							"simpleSettingValue": {
								"@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
								"settingValueTemplateReference": {
									"settingValueTemplateId": "88f6f096-dedb-4cf1-ac2f-4b41e303adb5"
								},
								"value": "$rawdata"
							}
						}
					],
					"settingValueTemplateReference": {
						"settingValueTemplateId": "b28c7dc4-c7b2-4ce2-8f51-6ebfd3ea69d3"
					},
					"value": "device_vendor_msft_policy_config_applicationcontrol_configure_xml_selected"
				},
				"settingDefinitionId": "device_vendor_msft_policy_config_applicationcontrol_policies_{policyguid}_policiesoptions",
				"settingInstanceTemplateReference": {
					"settingInstanceTemplateId": "1de98212-6949-42dc-a89c-e0ff6e5da04b"
				}
			}
		}
	],
	"technologies": "mdm",
	"templateReference": {
		"templateDisplayName": "Application Control",
		"templateDisplayVersion": "Version 1",
		"templateFamily": "endpointSecurityApplicationControl",
		"templateId": "4321b946-b76b-4450-8afd-769c08b16ffc_1"
	}
}
"@
write-host "JSON Populated"
}


##Create the policy
Write-host "Creating policy"
$policy = Invoke-MgGraphRequest -Uri $url -Method POST -Body $json -OutputType PSObject -ContentType "application/json"
write-host "Policy Created"

$policyid = $policy.id

##Assign the policy
Write-host "Assigning policy to Group ID $groupid"
$assignurl = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$policyid/assign"
$assignjson = @"
{
	"assignments": [
		{
			"target": {
				"@odata.type": "#microsoft.graph.groupAssignmentTarget",
				"groupId": "$groupid"
			}
		}
	]
}
"@

Invoke-MgGraphRequest -Uri $assignurl -Method POST -Body $assignjson -OutputType PSObject -ContentType "application/json"
write-host "Policy Assigned"
    
Stop-Transcript