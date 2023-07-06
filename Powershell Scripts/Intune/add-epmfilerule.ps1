<#
.SYNOPSIS
  Creates an Intune EPM File Rule from provided Filepath and optionally Group Name
.DESCRIPTION
Creates an Intune EPM Rule based on the Filehas of the Path provided.  Optionally assigns to a Group or All Users and can be configured as Automatic, or User Controlled
.PARAMETER Path
    The path to the .
.PARAMETER LiteralPath
    Specifies a path to one or more locations. Unlike Path, the value of 
    LiteralPath is used exactly as it is typed. No characters are interpreted 
    as wildcards. If the path includes escape characters, enclose it in single
    quotation marks. Single quotation marks tell Windows PowerShell not to 
    interpret any characters as escape sequences.
.INPUTS
None
.OUTPUTS
Creates a log file in %Temp%
.NOTES
  Version:        1.0.1
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  26/03/2023
  Purpose/Change: Initial script development

  .EXAMPLE
N/A
#>

<#PSScriptInfo
.VERSION 1.0.1
.GUID a154ec0b-3d01-4bfb-8890-258f85ba24df
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
    [Parameter(Mandatory=$true)]
    [string]$filepath #Path to the file
    ,  
    [string]$groupname #AAD Group Name, if left blank will default to All Users
    ,  
    [string]$elevationtype #Can be Auto or User, defaults to User
    , 
    [string]$tenant #Tenant ID (optional) for when automating and you want to use across tenants instead of hard-coded
    ,
    [string]$clientid #ClientID is the type of Azure AD App Reg ID
    ,
    [string]$clientsecret #ClientSecret is the type of Azure AD App Reg Secret
)

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

##Set the defaults
$groupcheck = $PSBoundParameters.ContainsKey('groupname')
$elevationcheck = $PSBoundParameters.ContainsKey('elevationtype')
$clientidcheck = $PSBoundParameters.ContainsKey('clientid')
$clientsecretcheck = $PSBoundParameters.ContainsKey('clientsecret')

if (($clientidcheck -eq $true) -and ($clientsecretcheck -eq $true)) {
##AAD Secret passed, use to login
$aadlogin = "yes"

}

if ($elevationcheck -eq $true) {
    if ($elevationtype -eq "Auto") {
        $elevationtype = "Auto"
        $typedescription = "Automatically approved "
    } else {
        $elevationtype = "User"
        $typedescription = "User approved "

    }
} else {
    $elevationtype = "User"
    $typedescription = "User approved "

}

##Connect to Graph
############################################################
############# CHANGE THIS TO USE IN AUTOMATION #############
############################################################
$automated = "no"
############################################################
if ($automated -eq "yes") {
    ##################################################################################################################################
    #################                                                  VARIABLES                                     #################
    ##################################################################################################################################
    
    $clientid = "YOUR_AAD_REG_ID"
    
    $clientsecret = "YOUR_CLIENT_SECRET"
        
    ##Only use if not set in script parameters
    $tenantcheck = $PSBoundParameters.ContainsKey('tenant')
    if ($tenantcheck -ne $true) {
    $tenant = "TENANT_ID"
    }
        
    ##################################################################################################################################
    #################                                             END  VARIABLES                                     #################
    ##################################################################################################################################
    }
    

##################################################################################################################################
#################                                                  INITIALIZATION                                #################
##################################################################################################################################
$ErrorActionPreference = "Continue"
##Start Logging to %TEMP%\intune.log
$date = get-date -format yyyyMMddTHHmmssffff
Start-Transcript -Path $env:TEMP\intune-$date.log

#Install MS Graph if not available


write-output "Installing Microsoft Graph modules if required (current user scope)"

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication) {
    write-output "Microsoft Graph Authentication Already Installed"
} 
else {
        Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser -Repository PSGallery -Force
        write-output "Microsoft Graph Authentication Installed"
}


# Load the Graph module
Import-Module microsoft.graph.authentication

if (($automated -eq "yes") -or ($aadlogin -eq "yes")) {
 
Connect-ToGraph -Tenant $tenant -AppId $clientid -AppSecret $clientsecret
write-output "Graph Connection Established"
}
else {
##Connect to Graph
Connect-ToGraph -Scopes Domain.Read.All, Directory.Read.All, DeviceManagementConfiguration.ReadWrite.All, openid, profile, email, offline_access, Group.ReadWrite.All
write-output "Graph Connection Established"

}

##################################################################################################################################
#################                                           Make it So                                           #################
##################################################################################################################################

##Get the Filehash
write-output "Getting Filehash for $filepath"
$hash = Get-FileHash -Path $filepath
$hash = $hash.Hash
write-output "Filehash is $hash"


##Get the Filename
write-output "Getting Filename for $filepath"
$filename = $filepath | Split-Path -Leaf
write-output "Filename is $filename"

##Get the Path only
write-output "Getting Path for $filepath"
$pathonly = ($filepath | Split-Path) -replace '\\','\\'
write-output "Path is $pathonly"

write-output "Setting JSON Values"
$addurl = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"

$json = @"
{
	"description": "EPM Policy for $filename in $pathonly",
	"name": "$filename EPM Policy",
	"platforms": "windows10",
	"roleScopeTagIds": [
		"0"
	],
	"settings": [
		{
			"@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
			"settingInstance": {
				"@odata.type": "#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance",
				"groupSettingCollectionValue": [
					{
						"children": [
							{
								"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
								"choiceSettingValue": {
									"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
									"children": [],
									"settingValueTemplateReference": {
										"settingValueTemplateId": "2ec26569-c08f-434c-af3d-a50ac4a1ce26"
									},
									"value": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_allusers"
								},
								"settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_appliesto",
								"settingInstanceTemplateReference": {
									"settingInstanceTemplateId": "0cde1c42-c701-44b1-94b7-438dd4536128"
								}
							},
							{
								"@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
								"settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_description",
								"settingInstanceTemplateReference": {
									"settingInstanceTemplateId": "b3714f3a-ead8-4682-a16f-ffa264c9d58f"
								},
								"simpleSettingValue": {
									"@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
									"settingValueTemplateReference": {
										"settingValueTemplateId": "5e82a1e9-ef4f-43ea-8031-93aace2ad14d"
									},
									"value": "$typedescription for $filename"
								}
							},
							{
								"@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
								"settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_filehash",
								"settingInstanceTemplateReference": {
									"settingInstanceTemplateId": "e4436e2c-1584-4fba-8e38-78737cbbbfdf"
								},
								"simpleSettingValue": {
									"@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
									"settingValueTemplateReference": {
										"settingValueTemplateId": "1adcc6f7-9fa4-4ce3-8941-2ce22cf5e404"
									},
									"value": "$hash"
								}
							},
"@
$json2user = @"
							{
								"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
								"choiceSettingValue": {
									"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
									"children": [
										{
											"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingCollectionInstance",
											"choiceSettingCollectionValue": [
												{
													"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
													"children": [],
													"value": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_ruletype_validation_1"
												}
											],
											"settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_ruletype_validation"
										}
									],
									"settingValueTemplateReference": {
										"settingValueTemplateId": "cb2ea689-ebc3-42ea-a7a4-c704bb13e3ad"
									},
									"value": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_self"
								},
								"settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_ruletype",
								"settingInstanceTemplateReference": {
									"settingInstanceTemplateId": "bc5a31ac-95b5-4ec6-be1f-50a384bb165f"
								}
							},
"@
$json2auto = @"
{
    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
    "choiceSettingValue": {
        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
        "children": [],
        "settingValueTemplateReference": {
            "settingValueTemplateId": "cb2ea689-ebc3-42ea-a7a4-c704bb13e3ad"
        },
        "value": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_automatic"
    },
    "settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_ruletype",
    "settingInstanceTemplateReference": {
        "settingInstanceTemplateId": "bc5a31ac-95b5-4ec6-be1f-50a384bb165f"
    }
},
"@
$json3 = @"
							{
								"@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
								"settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_filedescription",
								"settingInstanceTemplateReference": {
									"settingInstanceTemplateId": "5e10c5a9-d3ca-4684-b425-e52238cf3c8b"
								},
								"simpleSettingValue": {
									"@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
									"settingValueTemplateReference": {
										"settingValueTemplateId": "df3081ea-4ea7-4f34-ac87-49b2e84d4c4b"
									},
									"value": "$filename"
								}
							},
							{
								"@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
								"settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_name",
								"settingInstanceTemplateReference": {
									"settingInstanceTemplateId": "fdabfcf9-afa4-4dbf-a4ef-d5c1549065e1"
								},
								"simpleSettingValue": {
									"@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
									"settingValueTemplateReference": {
										"settingValueTemplateId": "03f003e5-43ef-4e7e-bf30-57f00781fdcc"
									},
									"value": "$filename Rule"
								}
							},
							{
								"@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
								"settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_filename",
								"settingInstanceTemplateReference": {
									"settingInstanceTemplateId": "0c1ceb2b-bbd4-46d4-9ba5-9ee7abe1f094"
								},
								"simpleSettingValue": {
									"@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
									"settingValueTemplateReference": {
										"settingValueTemplateId": "a165327c-f0e5-4c7d-9af1-d856b02191f7"
									},
									"value": "$filename"
								}
							},
							{
								"@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
								"settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_filepath",
								"settingInstanceTemplateReference": {
									"settingInstanceTemplateId": "c3b7fda4-db6a-421d-bf04-d485e9d0cfb1"
								},
								"simpleSettingValue": {
									"@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
									"settingValueTemplateReference": {
										"settingValueTemplateId": "f011bcfc-03cd-4b28-a1f4-305278d7a030"
									},
									"value": "$pathonly"
								}
							}
						]
					}
				],
				"settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}",
				"settingInstanceTemplateReference": {
					"settingInstanceTemplateId": "ee3d2e5f-6b3d-4cb1-af9b-37b02d3dbae2"
				}
			}
		}
	],
	"technologies": "endpointPrivilegeManagement",
	"templateReference": {
		"templateId": "cff02aad-51b1-498d-83ad-81161a393f56_1"
	}
}
"@


if ($elevationtype -eq "Auto") {
    write-output "It is an Auto approve rule, setting accordingly"
   $finaljson = $json + $json2auto + $json3
}
else {
    write-output "It is a User approve rule, setting accordingly including credential prompt"
    $finaljson = $json + $json2user + $json3
}
write-output "JSON Configured, creating policy"
$addpolicy = Invoke-MgGraphRequest -method POST -Uri $addurl -Body $finaljson -ContentType "application/json"
write-output "Policy created, assigning"



##Assign
$policyid = $addpolicy.id
$assignurl = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$policyid')/assign"


if ($groupcheck -eq $true) {
    write-output "Group set, assigning to group $groupname"
    ##Get the group ID from Graph
$groupid = (Invoke-MgGraphRequest -method GET -Uri "https://graph.microsoft.com/beta/groups?`$filter=displayName eq '$groupname'" -ContentType "application/json").value.id
##Group
$jsonassign = @"

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
}
else {
    write-output "No group set, assigning to all users"
##AllUsers
$jsonassign = @"
{
	"assignments": [
		{
			"target": {
				"@odata.type": "#microsoft.graph.allLicensedUsersAssignmentTarget"
			}
		}
	]
}
"@
}

##Assign It
Invoke-MgGraphRequest -method POST -Uri $assignurl -Body $jsonassign -ContentType "application/json"
write-output "Policy assigned, all done"
##All done
write-output "Disconnecting from Graph"
Stop-Transcript
Disconnect-MgGraph