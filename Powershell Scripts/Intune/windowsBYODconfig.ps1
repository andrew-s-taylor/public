<#
.SYNOPSIS
Blocks Personal Windows devices, enables MAM, creates MAM policy and CA policies for Windows BYOD protection
.DESCRIPTION
Blocks Personal Windows devices, enables MAM, creates MAM policy and CA policies for Windows BYOD protection.PARAMETER Path
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
  Version:        1.0.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  25/07/2023
  Updated: 25/07/2023
  Purpose/Change: Initial script development


  .EXAMPLE
N/A
#>

<#PSScriptInfo
.VERSION 1.0.0
.GUID f5a19f87-32c5-4758-a7b5-c99ee7f7f155
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
    [string]$tenant #Tenant ID
    ,
    [string]$clientid #ClientID is the type of Azure AD App Reg ID
    ,
    [string]$clientsecret #ClientSecret is the type of Azure AD App Reg Secret
    )

###############################################################################################################
######                                         Install Modules                                           ######
###############################################################################################################
Write-Host "Installing Intune modules if required (current user scope)"


Write-Host "Installing Microsoft Graph Groups modules if required (current user scope)"

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
    }
}

#Install Graph Device Management module if not available
if (Get-Module -ListAvailable -Name microsoft.graph.DeviceManagement.Enrolment) {
    Write-Host "Microsoft Graph Device Management Module Already Installed"
} 
else {
    try {
        Install-Module -Name microsoft.graph.DeviceManagement.Enrolment -Scope CurrentUser -Repository PSGallery -Force -AllowClobber 
    }
    catch [Exception] {
        $_.message 
    }
}

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
    }
}

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name microsoft.graph.devices.corporatemanagement ) {
    Write-Host "Microsoft Graph Already Installed"
} 
else {
    try {
        Install-Module -Name microsoft.graph.devices.corporatemanagement  -Scope CurrentUser -Repository PSGallery -Force 
    }
    catch [Exception] {
        $_.message 
    }
}



#Importing Modules
Import-Module Microsoft.Graph.Groups
Import-Module Microsoft.Graph.DeviceManagement.Enrolment
import-module microsoft.graph.authentication
import-module microsoft.graph.devices.corporatemanagement



###############################################################################################################
######                                          Add Functions                                            ######
###############################################################################################################
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

###############################################################################################################
######                                     Graph Connection                                              ######
###############################################################################################################
##Connect using Secret
write-host "Connecting to Graph"
if ($clientid) {
 
    Connect-ToGraph -Tenant $tenant -AppId $clientId -AppSecret $clientSecret
    write-output "Graph Connection Established"
    }
    else {
    ##Connect to Graph
    Select-MgProfile -Name Beta
    Connect-ToGraph -Scopes "Policy.Read.All, CloudPC.ReadWrite.All, DeviceManagementServiceConfig.ReadWrite.All, RoleAssignmentSchedule.ReadWrite.Directory, Domain.Read.All, Domain.ReadWrite.All, Directory.Read.All, Policy.ReadWrite.ConditionalAccess, DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, openid, profile, email, offline_access, DeviceManagementRBAC.Read.All, DeviceManagementRBAC.ReadWrite.All, Group.ReadWrite.All, Application.Read.All"
    }
write-host "Graph Connection Established"


###############################################################################################################
######                                     Process Blocking                                              ######
###############################################################################################################

##block personal devices
write-host "Blocking Personal Devices"
$url = "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations"
$json = @"
{
	"@odata.type": "#microsoft.graph.deviceEnrollmentPlatformRestrictionConfiguration",
	"description": "",
	"displayName": "Block Personal",
	"platformRestriction": {
		"blockedManufacturers": [],
		"osMaximumVersion": "",
		"osMinimumVersion": "",
		"personalDeviceEnrollmentBlocked": true,
		"platformBlocked": false
	},
	"platformType": "windows",
	"roleScopeTagIds": [
		"0"
	]
}
"@

$blockbyod = Invoke-MgGraphRequest -Method POST -Uri $url -Body $json -ContentType "application/json" -OutputType PSObject

$byodpolicyid = $blockbyod.id

$assignurl = "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations/$byodpolicyid/assign"

$assignjson = @"
{
	"enrollmentConfigurationAssignments": [
		{
			"target": {
				"@odata.type": "#microsoft.graph.allLicensedUsersAssignmentTarget"
			}
		}
	]
}
"@

Invoke-MgGraphRequest -Method POST -Uri $assignurl -Body $assignjson -ContentType "application/json" -OutputType PSObject

write-host "Personal Devices Blocked"

##Enable Connector

write-host "Enabling Connector"
$url = "https://graph.microsoft.com/beta/deviceManagement/mobileThreatDefenseConnectors"
$threatjson = @"
{
	"allowPartnerToCollectIOSApplicationMetadata": false,
	"allowPartnerToCollectIOSPersonalApplicationMetadata": false,
	"androidDeviceBlockedOnMissingPartnerData": false,
	"androidEnabled": false,
	"androidMobileApplicationManagementEnabled": false,
	"id": "c2b688fe-48c0-464b-a89c-67041aa8fcb2",
	"iosDeviceBlockedOnMissingPartnerData": false,
	"iosEnabled": false,
	"iosMobileApplicationManagementEnabled": false,
	"macDeviceBlockedOnMissingPartnerData": false,
	"macEnabled": false,
	"microsoftDefenderForEndpointAttachEnabled": false,
	"partnerUnresponsivenessThresholdInDays": 7,
	"partnerUnsupportedOsVersionBlocked": false,
	"windowsDeviceBlockedOnMissingPartnerData": false,
	"windowsEnabled": false,
	"windowsMobileApplicationManagementEnabled": true
}
"@
Invoke-MgGraphRequest -Method POST -Uri $url -Body $threatjson -ContentType "application/json" -OutputType PSObject

write-host "Connector Enabled"

##Create a group to use for BYOD

write-host "Creating BYOD Group"
$url = "https://graph.microsoft.com/beta/groups"
$groupjson = @"
{
    "displayName": "Windows BYOD Users",
    "description": "Windows BYOD Users",
    "mailEnabled": false,
    "mailNickname": "BYOD",
    "securityEnabled": true
}
"@
$byodgroup = Invoke-MgGraphRequest -Method POST -Uri $url -Body $groupjson -ContentType "application/json" -OutputType PSObject
$byodgroupid = $byodgroup.id

##Create MAM policy

write-host "Creating MAM Policy"
$url = "https://graph.microsoft.com/beta/deviceAppManagement/windowsManagedAppProtections"
$json = @"
{
	"@odata.type": "#microsoft.graph.windowsManagedAppProtection",
	"allowedDataIngestionLocations": [
		"oneDriveForBusiness",
		"sharePoint",
		"camera",
		"photoLibrary"
	],
	"allowedDataStorageLocations": [],
	"allowedInboundDataTransferSources": "none",
	"allowedOutboundClipboardSharingExceptionLength": 0,
	"allowedOutboundClipboardSharingLevel": "none",
	"allowedOutboundDataTransferDestinations": "none",
	"appActionIfAccountIsClockedOut": null,
	"appActionIfDeviceComplianceRequired": "block",
	"appActionIfMaximumPinRetriesExceeded": "block",
	"appActionIfSamsungKnoxAttestationRequired": null,
	"appActionIfUnableToAuthenticateUser": "block",
	"apps": [
		{
			"mobileAppIdentifier": {
				"@odata.type": "#microsoft.graph.windowsAppIdentifier",
				"windowsAppId": "com.microsoft.edge"
			}
		}
	],
	"assignments": [
		{
			"target": {
				"@odata.type": "#microsoft.graph.groupAssignmentTarget",
				"deviceAndAppManagementAssignmentFilterId": null,
				"deviceAndAppManagementAssignmentFilterType": "none",
				"groupId": "$byodgroupid"
			}
		}
	],
	"blockAfterCompanyPortalUpdateDeferralInDays": 0,
	"blockDataIngestionIntoOrganizationDocuments": false,
	"contactSyncBlocked": false,
	"customBrowserDisplayName": "",
	"customBrowserPackageId": "",
	"customBrowserProtocol": "",
	"customDialerAppDisplayName": "",
	"customDialerAppPackageId": "",
	"customDialerAppProtocol": "",
	"dataBackupBlocked": false,
	"description": "",
	"deviceComplianceRequired": false,
	"dialerRestrictionLevel": "allApps",
	"disableAppPinIfDevicePinIsSet": false,
	"displayName": "Windows MAM Edge Policy",
	"exemptedAppPackages": [],
	"exemptedAppProtocols": [
		{
			"name": "Default",
			"value": "skype;app-settings;calshow;itms;itmss;itms-apps;itms-appss;itms-services;"
		}
	],
	"fingerprintBlocked": false,
	"gracePeriodToBlockAppsDuringOffClockHours": null,
	"managedBrowser": "notConfigured",
	"managedBrowserToOpenLinksRequired": false,
	"maximumAllowedDeviceThreatLevel": "notConfigured",
	"maximumPinRetries": 5,
	"maximumRequiredOsVersion": null,
	"maximumWarningOsVersion": null,
	"maximumWipeOsVersion": null,
	"minimumPinLength": 4,
	"minimumRequiredAppVersion": null,
	"minimumRequiredCompanyPortalVersion": null,
	"minimumRequiredOsVersion": null,
	"minimumRequiredSdkVersion": null,
	"minimumWarningAppVersion": null,
	"minimumWarningCompanyPortalVersion": null,
	"minimumWarningOsVersion": null,
	"minimumWipeAppVersion": null,
	"minimumWipeCompanyPortalVersion": null,
	"minimumWipeOsVersion": null,
	"minimumWipeSdkVersion": null,
	"mobileThreatDefensePartnerPriority": null,
	"mobileThreatDefenseRemediationAction": "block",
	"notificationRestriction": "allow",
	"organizationalCredentialsRequired": false,
	"periodBeforePinReset": "P0D",
	"periodBeforePinResetRequired": false,
	"periodOfflineBeforeAccessCheck": "PT720M",
	"periodOfflineBeforeWipeIsEnforced": "P90D",
	"periodOnlineBeforeAccessCheck": "PT30M",
	"pinCharacterSet": "numeric",
	"pinRequired": true,
	"pinRequiredInsteadOfBiometric": true,
	"pinRequiredInsteadOfBiometricTimeout": "PT30M",
	"previousPinBlockCount": 0,
	"printBlocked": true,
	"roleScopeTagIds": [
		"0"
	],
	"saveAsBlocked": false,
	"shareWithBrowserVirtualSetting": "anyApp",
	"simplePinBlocked": false,
	"targetedAppManagementLevels": "unspecified",
	"warnAfterCompanyPortalUpdateDeferralInDays": 0,
	"wipeAfterCompanyPortalUpdateDeferralInDays": 0
}
"@

Invoke-MgGraphRequest -Method POST -Uri $url -Body $json -ContentType "application/json" -OutputType PSObject

write-host "MAM Policy Created"

##Block Non-Compliant
write-host "Creating Conditional Access Policy to block non-compliant devices from Client Apps"
$url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
$json = @'
{
	"conditions": {
		"applications": {
			"excludeApplications": [],
			"includeApplications": [
				"All"
			],
			"includeAuthenticationContextClassReferences": [],
			"includeUserActions": [],
			"networkAccess": null
		},
		"clientApplications": null,
		"clientAppTypes": [
			"mobileAppsAndDesktopClients",
			"exchangeActiveSync",
			"other"
		],
		"clients": null,
		"devices": {
			"deviceFilter": {
				"mode": "exclude",
				"rule": "device.deviceOwnership -eq \"Company\""
			},
			"excludeDevices": [],
			"includeDevices": []
		},
		"locations": null,
		"platforms": {
			"excludePlatforms": [],
			"includePlatforms": [
				"windows"
			]
		},
		"servicePrincipalRiskLevels": [],
		"signInRiskDetections": null,
		"signInRiskLevels": [],
		"times": null,
		"userRiskLevels": [],
		"users": {
			"excludeGroups": [],
			"excludeGuestsOrExternalUsers": null,
			"excludeRoles": [],
			"excludeUsers": [],
			"includeGroups": [],
			"includeGuestsOrExternalUsers": null,
			"includeRoles": [],
			"includeUsers": [
				"All"
			]
		}
	},
	"displayName": "Windows BYOD Block Non-Compliant",
	"grantControls": {
		"authenticationStrength": null,
		"builtInControls": [
			"compliantDevice"
		],
		"customAuthenticationFactors": [],
		"operator": "AND",
		"termsOfUse": []
	},
	"sessionControls": null,
	"state": "disabled"
}
'@

Invoke-MgGraphRequest -Method POST -Uri $url -Body $json -ContentType "application/json" -OutputType PSObject

write-host "Conditional Access Policy Created"

##Require App Protection
write-host "Creating Conditional Access Policy to require App Protection"
$url = "https://graph.microsoft.com/beta/identity/conditionalAccess/policies"
$json = @"
{
	"conditions": {
		"applications": {
			"excludeApplications": [],
			"includeApplications": [
				"All"
			],
			"includeAuthenticationContextClassReferences": [],
			"includeUserActions": [],
			"networkAccess": null
		},
		"clientApplications": null,
		"clientAppTypes": [
			"browser"
		],
		"clients": null,
		"devices": {
			"deviceFilter": {
				"mode": "exclude",
				"rule": "device.deviceOwnership -eq \"Company\""
			},
			"excludeDevices": [],
			"includeDevices": []
		},
		"locations": null,
		"platforms": {
			"excludePlatforms": [],
			"includePlatforms": [
				"windows"
			]
		},
		"servicePrincipalRiskLevels": [],
		"signInRiskDetections": null,
		"signInRiskLevels": [],
		"times": null,
		"userRiskLevels": [],
		"users": {
			"excludeGroups": [],
			"excludeGuestsOrExternalUsers": null,
			"excludeRoles": [],
			"excludeUsers": [],
			"includeGroups": [],
			"includeGuestsOrExternalUsers": null,
			"includeRoles": [],
			"includeUsers": [
				"All"
			]
		}
	},
	"displayName": "Windows MAM - Require App Protection Policy",
	"grantControls": {
		"authenticationStrength": null,
		"builtInControls": [
			"compliantApplication"
		],
		"customAuthenticationFactors": [],
		"operator": "AND",
		"termsOfUse": []
	},
	"sessionControls": {
		"applicationEnforcedRestrictions": null,
		"cloudAppSecurity": {
			"cloudAppSecurityType": "blockDownloads",
			"isEnabled": true
		},
		"continuousAccessEvaluation": null,
		"disableResilienceDefaults": null,
		"networkAccessSecurity": null,
		"persistentBrowser": null,
		"secureSignInSession": null,
		"signInFrequency": null
	},
	"state": "disabled"
}
"@

Invoke-MgGraphRequest -Method POST -Uri $url -Body $json -ContentType "application/json" -OutputType PSObject

write-host "Conditional Access Policy Created"

write-host "Completed"

Disconnect-MgGraph