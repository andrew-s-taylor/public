<#
.SYNOPSIS
Creates a new user on the device and assigns to administrators.  Configures LAPS to use the new user account
.DESCRIPTION
Creates a new user on the device and assigns to administrators.  Configures LAPS to use the new user account.
Password is randomly generated
.INPUTS
Account name $name
.OUTPUTS
None
.NOTES
  Version:        1.0.4
  Author:         Andrew Taylor
  WWW:            andrewstaylor.com
  Creation Date:  25/04/2023
  .EXAMPLE
N/A
#>

<#PSScriptInfo
.VERSION 1.0.4
.GUID 22204255-7dfa-4393-aba7-5c9a1fc765d9
.AUTHOR AndrewTaylor
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

##################################################################################################################################
#################                                                  PARAMS                                        #################
##################################################################################################################################

[cmdletbinding()]
    
param
(
    [string]$name

    )






##################################################################################################################################
#################                                                  INITIALIZATION                                #################
##################################################################################################################################
$ErrorActionPreference = "Continue"
##Start Logging to %TEMP%\intune.log
$date = get-date -format yyyyMMddTHHmmssffff
Start-Transcript -Path $env:TEMP\intune-$date.log

#Install MS Graph if not available


Write-Host "Installing Microsoft Graph modules if required (current user scope)"
#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication) {
    Write-Host "Microsoft Graph Authentication Already Installed"
} 
else {
        Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser -Repository PSGallery -Force -RequiredVersion 1.19.0 
        Write-Host "Microsoft Graph Authentication Installed"
}

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

write-host "Connecting to Graph"
Connect-ToGraph -Scopes Domain.Read.All, Directory.Read.All, DeviceManagementConfiguration.ReadWrite.All, openid, profile, email, offline_access, Policy.ReadWrite.DeviceConfiguration
write-host "Connected to Graph"


##Check if parameter has been passed
write-host "Checking for custom name"
$namecheck = $PSBoundParameters.ContainsKey('name')

if ($namecheck -eq $true) {
write-host "Custom name sent, setting account name"
##Custom name sent, set it
$accountname = $name
}
else {
write-host "No custom name sent, using lapsadmin"
##No custom name sent, generate one
$accountname = "lapsadmin"
}


function Get-RandomPassword {
    param (
        [Parameter(Mandatory)]
        [int] $length,
        [int] $amountOfNonAlphanumeric = 1
    )
    Add-Type -AssemblyName 'System.Web'
    return [System.Web.Security.Membership]::GeneratePassword($length, $amountOfNonAlphanumeric)
}


$password = Get-RandomPassword -Length 20


##Enable LAPS in AAD
write-host "Checking Azure Active Directory Settings"
$checkuri = "https://graph.microsoft.com/beta/policies/deviceRegistrationPolicy"
$currentpolicy = Invoke-MgGraphRequest -Method GET -Uri $checkuri -OutputType PSObject -ContentType "application/json"
$lapssetting = ($currentpolicy.localAdminPassword).isEnabled
if ($lapssetting -eq $false) {
write-host "LAPS is not enabled, enabling"
$newsetting = $true
$currentpolicy.localAdminPassword.isEnabled = $newsetting
$policytojson = $currentpolicy | ConvertTo-Json
Invoke-MgGraphRequest -Method PUT -Uri $checkuri -Body $policytojson -ContentType "application/json"
write-host "LAPS enabled"
}
else {
write-host "LAPS is already enabled"
}



write-host "Creating new user $accountname with password $password"
##Create Custom Policy for lapsadmin user
$customurl = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations"

$customjson = @"
{
	"@odata.type": "#microsoft.graph.windows10CustomConfiguration",
	"description": "Creates a new user to be used with LAPS",
	"displayName": "Windows-LAPS-User",
	"id": "00000000-0000-0000-0000-000000000000",
	"omaSettings": [
		{
			"@odata.type": "#microsoft.graph.omaSettingString",
			"description": "Create lapsadmin and set password",
			"displayName": "Create-User",
			"omaUri": "./Device/Vendor/MSFT/Accounts/Users/$accountname/Password",
			"value": "$password"
		},
		{
			"@odata.type": "#microsoft.graph.omaSettingInteger",
			"description": "Add to admins",
			"displayName": "Add-to-group",
			"omaUri": "./Device/Vendor/MSFT/Accounts/Users/$accountname/LocalUserGroup",
			"value": 2
		}
	],
	"roleScopeTagIds": [
		"0"
	]
}
"@

$policy = Invoke-MgGraphRequest -Method POST -Uri $customurl -Body $customjson -OutputType PSObject -ContentType "application/json"

write-host "Assigning policy to all devices"

$policyid = $policy.id

$assignurl = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$policyid/assign"

$assignjson = @"
{
	"assignments": [
		{
			"target": {
				"@odata.type": "#microsoft.graph.allDevicesAssignmentTarget"
			}
		}
	]
}
"@

Invoke-MgGraphRequest -Method POST -Uri $assignurl -Body $assignjson -ContentType "application/json" -OutputType PSObject

write-host "Policy created and assigned to all devices"


##Create LAPS policy to use new user account
write-host "Creating LAPS policy with new user account $accountname"
$lapsurl = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"
$lapsjson = @"
{
	"description": "Uses lapsadmin created via custom OMA-URI policy",
	"name": "LAPS Config",
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
							"settingDefinitionId": "device_vendor_msft_laps_policies_passwordagedays_aad",
							"simpleSettingValue": {
								"@odata.type": "#microsoft.graph.deviceManagementConfigurationIntegerSettingValue",
								"value": 30
							}
						}
					],
					"settingValueTemplateReference": {
						"settingValueTemplateId": "4d90f03d-e14c-43c4-86da-681da96a2f92"
					},
					"value": "device_vendor_msft_laps_policies_backupdirectory_1"
				},
				"settingDefinitionId": "device_vendor_msft_laps_policies_backupdirectory",
				"settingInstanceTemplateReference": {
					"settingInstanceTemplateId": "a3270f64-e493-499d-8900-90290f61ed8a"
				}
			}
		},
		{
			"@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
			"settingInstance": {
				"@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
				"settingDefinitionId": "device_vendor_msft_laps_policies_administratoraccountname",
				"settingInstanceTemplateReference": {
					"settingInstanceTemplateId": "d3d7d492-0019-4f56-96f8-1967f7deabeb"
				},
				"simpleSettingValue": {
					"@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
					"settingValueTemplateReference": {
						"settingValueTemplateId": "992c7fce-f9e4-46ab-ac11-e167398859ea"
					},
					"value": "$accountname"
				}
			}
		},
		{
			"@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
			"settingInstance": {
				"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
				"choiceSettingValue": {
					"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
					"children": [],
					"settingValueTemplateReference": {
						"settingValueTemplateId": "aa883ab5-625e-4e3b-b830-a37a4bb8ce01"
					},
					"value": "device_vendor_msft_laps_policies_passwordcomplexity_4"
				},
				"settingDefinitionId": "device_vendor_msft_laps_policies_passwordcomplexity",
				"settingInstanceTemplateReference": {
					"settingInstanceTemplateId": "8a7459e8-1d1c-458a-8906-7b27d216de52"
				}
			}
		},
		{
			"@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
			"settingInstance": {
				"@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
				"settingDefinitionId": "device_vendor_msft_laps_policies_passwordlength",
				"settingInstanceTemplateReference": {
					"settingInstanceTemplateId": "da7a1dbd-caf7-4341-ab63-ece6f994ff02"
				},
				"simpleSettingValue": {
					"@odata.type": "#microsoft.graph.deviceManagementConfigurationIntegerSettingValue",
					"settingValueTemplateReference": {
						"settingValueTemplateId": "d08f1266-5345-4f53-8ae1-4c20e6cb5ec9"
					},
					"value": 20
				}
			}
		},
		{
			"@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
			"settingInstance": {
				"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
				"choiceSettingValue": {
					"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
					"children": [],
					"settingValueTemplateReference": {
						"settingValueTemplateId": "68ff4f78-baa8-4b32-bf3d-5ad5566d8142"
					},
					"value": "device_vendor_msft_laps_policies_postauthenticationactions_1"
				},
				"settingDefinitionId": "device_vendor_msft_laps_policies_postauthenticationactions",
				"settingInstanceTemplateReference": {
					"settingInstanceTemplateId": "d9282eb1-d187-42ae-b366-7081f32dcfff"
				}
			}
		}
	],
	"technologies": "mdm",
	"templateReference": {
		"templateId": "adc46e5a-f4aa-4ff6-aeff-4f27bc525796_1"
	}
}
"@

$lapspolicy = Invoke-MgGraphRequest -Method POST -Uri $lapsurl -Body $lapsjson -ContentType "application/json" -OutputType PSObject

write-host "LAPS Policy created, assigning to all devices"

$lapspolicyid = $lapspolicy.id

$lapsassignurl = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$lapspolicyid/assign"

$lapsassignjson = @"
{
	"assignments": [
		{
			"target": {
				"@odata.type": "#microsoft.graph.allDevicesAssignmentTarget"
			}
		}
	]
}
"@

Invoke-MgGraphRequest -Method POST -Uri $lapsassignurl -Body $lapsassignjson -ContentType "application/json"

write-host "LAPS Policy assigned to all devices"

write-host "Completed, disconnecting from Graph"

Disconnect-MgGraph