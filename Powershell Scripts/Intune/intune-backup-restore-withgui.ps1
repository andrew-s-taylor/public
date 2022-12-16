<#
.SYNOPSIS
  Backs up Intune and AAD policies to Github then restores from any Commit.  Flat file backups
.DESCRIPTION
Backs up Intune and AAD policies to Github then restores from any Commit.  Flat file backups.  Displays a GUI to select what to backup and which restore point to use
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
  Version:        1.1.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  24/11/2022
  Purpose/Change: Initial script development
 
.EXAMPLE
N/A
#>

<#PSScriptInfo
.VERSION 1.0.10
.GUID 4bc67c81-0a03-4699-8313-3f31a9ec06ab
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
    [string]$type #Type can be "backup" or "restore"
    ,  
    [string]$selected #Selected can be "all" or literally anything else
    ,  
    [string]$reponame #Reponame is the github repo
    , 
    [string]$ownername #Ownername is the github account
    , 
    [string]$token #Token is the github token
    )

####### First check if running automated and bypass parameters to set variables below


############################################################
############################################################
############# CHANGE THIS TO USE IN AUTOMATION #############
############################################################
############################################################
$automated = "no"
############################################################



if ($automated -eq "yes") {
##################################################################################################################################
#################                                                  VARIABLES                                     #################
##################################################################################################################################

$selected = "all"

$reponame = "YOUR_REPONAME_HERE"

$ownername = "YOUR_OWNER_NAME_FOR_REPO"

$token = "YOUR_GITHUB_TOKEN"

$clientid = "YOUR_AAD_REG_ID"

$clientsecret = "YOUR_CLIENT_SECRET"

$tenant = "TENANT_ID"

$type = "backup"

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


Write-Host "Installing Microsoft Graph modules if required (current user scope)"

#Install MS Graph if not available
#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication) {
    Write-Host "Microsoft Graph Authentication Already Installed"
} 
else {
        Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser -Repository PSGallery -Force 
        Write-Host "Microsoft Graph Authentication Installed"
}

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name microsoft.graph.devices.corporatemanagement ) {
    Write-Host "Microsoft Graph Corporate Management Already Installed"
} 
else {
        Install-Module -Name microsoft.graph.devices.corporatemanagement  -Scope CurrentUser -Repository PSGallery -Force 
        Write-Host "Microsoft Graph Corporate Management Installed"
    }

    if (Get-Module -ListAvailable -Name Microsoft.Graph.Groups) {
        Write-Host "Microsoft Graph Groups Already Installed "
    } 
    else {
            Install-Module -Name Microsoft.Graph.Groups -Scope CurrentUser -Repository PSGallery -Force 
            Write-Host "Microsoft Graph Groups Installed"
    }
    
    #Install MS Graph if not available
    if (Get-Module -ListAvailable -Name Microsoft.Graph.DeviceManagement) {
        Write-Host "Microsoft Graph DeviceManagement Already Installed"
    } 
    else {
            Install-Module -Name Microsoft.Graph.DeviceManagement -Scope CurrentUser -Repository PSGallery -Force 
            Write-Host "Microsoft Graph DeviceManagement Installed"
    }

    #Install MS Graph if not available
    if (Get-Module -ListAvailable -Name Microsoft.Graph.identity.signins) {
        Write-Host "Microsoft Graph Identity SignIns Already Installed"
    } 
    else {
            Install-Module -Name Microsoft.Graph.Identity.SignIns -Scope CurrentUser -Repository PSGallery -Force 
            Write-Host "Microsoft Graph Identity SignIns Installed"
    }


# Load the Graph module
Import-Module microsoft.graph.authentication
import-module Microsoft.Graph.Identity.SignIns
import-module Microsoft.Graph.DeviceManagement
import-module microsoft.Graph.Groups
import-module microsoft.graph.devices.corporatemanagement

if ($automated -eq "yes") {
 
    $body = @{
        grant_type="client_credentials";
        client_id=$clientId;
        client_secret=$clientSecret;
        scope="https://graph.microsoft.com/.default";
    }
     
    $response = Invoke-RestMethod -Method Post -Uri https://login.microsoftonline.com/$tenant/oauth2/v2.0/token -Body $body
    $accessToken = $response.access_token
     
    $accessToken

    Select-MgProfile -Name Beta
Connect-MgGraph  -AccessToken $accessToken 
write-host "Graph Connection Established"
}
else {
##Connect to Graph
Select-MgProfile -Name Beta
Connect-MgGraph -Scopes DeviceManagementServiceConfig.ReadWrite.All, RoleAssignmentSchedule.ReadWrite.Directory, Domain.Read.All, Domain.ReadWrite.All, Directory.Read.All, Policy.ReadWrite.ConditionalAccess, DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, openid, profile, email, offline_access
}

###############################################################################################################
######                                          Add Functions                                            ######
###############################################################################################################

Function Get-IntuneApplication(){
    
    <#
    .SYNOPSIS
    This function is used to get applications from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any applications added
    .EXAMPLE
    Get-IntuneApplication
    Returns any applications configured in Intune
    .NOTES
    NAME: Get-IntuneApplication
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "Beta"
    $Resource = "deviceAppManagement/mobileApps"
    
        try {
    
            if($id){
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    
            }
    
            else {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value | Where-Object { ($_.'@odata.type').Contains("#microsoft.graph.winGetApp") }
    
            }
    
        }
    
        catch {
    
        }
    
    }



Function Get-DeviceConfigurationPolicyGP(){
    
    <#
    .SYNOPSIS
    This function is used to get device configuration policies from the Graph API REST interface - Group Policies
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device configuration policies
    .EXAMPLE
    Get-DeviceConfigurationPolicy
    Returns any device configuration policies configured in Intune
    .NOTES
    NAME: Get-DeviceConfigurationPolicyGP
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/groupPolicyConfigurations"
    
    try {
            if($id){
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)?`$filter=id eq '$id'"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
    
            }
    
            else {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
            }
        }
        catch {}
     
}


#############################################################################################################    

Function Get-ConditionalAccessPolicy(){
    
    <#
    .SYNOPSIS
    This function is used to get conditional access policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any conditional access policies
    .EXAMPLE
    Get-ConditionalAccessPolicy
    Returns any conditional access policies in Azure
    .NOTES
    NAME: Get-ConditionalAccessPolicy
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    

    $graphApiVersion = "beta"
    $DCP_resource = "identity/conditionalAccess/policies"
    
    try {
            if($id){
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    
            }
    
            else {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    
            }
        }
        catch {}
    
     
}

####################################################

Function Get-DeviceConfigurationPolicy(){
    
    <#
    .SYNOPSIS
    This function is used to get device configuration policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device configuration policies
    .EXAMPLE
    Get-DeviceConfigurationPolicy
    Returns any device configuration policies configured in Intune
    .NOTES
    NAME: Get-DeviceConfigurationPolicy
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/deviceConfigurations"
    
    try {
            if($id){
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)?`$filter=id eq '$id'"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
    
            }
    
            else {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
            }
        }
        catch {}
    
        
}
    
##########################################################################################

Function Get-GroupPolicyConfigurationsDefinitionValues()
{
	
    <#
    .SYNOPSIS
    This function is used to get device configuration policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device configuration policies
    .EXAMPLE
    Get-DeviceConfigurationPolicy
    Returns any device configuration policies configured in Intune
    .NOTES
    NAME: Get-GroupPolicyConfigurations
    #>
	
	[cmdletbinding()]
	Param (
		
		[Parameter(Mandatory = $true)]
		[string]$GroupPolicyConfigurationID
		
	)
	
	$graphApiVersion = "Beta"
	#$DCP_resource = "deviceManagement/groupPolicyConfigurations/$GroupPolicyConfigurationID/definitionValues?`$filter=enabled eq true"
	$DCP_resource = "deviceManagement/groupPolicyConfigurations/$GroupPolicyConfigurationID/definitionValues"
	
	try {	
		$uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
		(Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
		
    }
    catch{}
	

	
}

####################################################
Function Get-GroupPolicyConfigurationsDefinitionValuesPresentationValues()
{
	
    <#
    .SYNOPSIS
    This function is used to get device configuration policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device configuration policies
    .EXAMPLE
    Get-DeviceConfigurationPolicy
    Returns any device configuration policies configured in Intune
    .NOTES
    NAME: Get-GroupPolicyConfigurations
    #>
	
	[cmdletbinding()]
	Param (
		
		[Parameter(Mandatory = $true)]
		[string]$GroupPolicyConfigurationID,
		[string]$GroupPolicyConfigurationsDefinitionValueID
		
	)
	$graphApiVersion = "Beta"
	
	$DCP_resource = "deviceManagement/groupPolicyConfigurations/$GroupPolicyConfigurationID/definitionValues/$GroupPolicyConfigurationsDefinitionValueID/presentationValues"
	try {
		$uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
		(Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    }
    catch {}
		
	
}

Function Get-GroupPolicyConfigurationsDefinitionValuesdefinition ()
{
   <#
    .SYNOPSIS
    This function is used to get device configuration policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device configuration policies
    .EXAMPLE
    Get-DeviceConfigurationPolicy
    Returns any device configuration policies configured in Intune
    .NOTES
    NAME: Get-GroupPolicyConfigurations
    #>
	
	[cmdletbinding()]
	Param (
		
		[Parameter(Mandatory = $true)]
		[string]$GroupPolicyConfigurationID,
		[Parameter(Mandatory = $true)]
		[string]$GroupPolicyConfigurationsDefinitionValueID
		
	)
	$graphApiVersion = "Beta"
	$DCP_resource = "deviceManagement/groupPolicyConfigurations/$GroupPolicyConfigurationID/definitionValues/$GroupPolicyConfigurationsDefinitionValueID/definition"
	try {
		
		$uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
		
		$responseBody = Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject
    }
    catch{}
		
		
	$responseBody
}


Function Get-GroupPolicyDefinitionsPresentations ()
{
   <#
    .SYNOPSIS
    This function is used to get device configuration policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device configuration policies
    .EXAMPLE
    Get-DeviceConfigurationPolicy
    Returns any device configuration policies configured in Intune
    .NOTES
    NAME: Get-GroupPolicyConfigurations
    #>
	
	[cmdletbinding()]
	Param (
		
		
		[Parameter(Mandatory = $true)]
		[string]$groupPolicyDefinitionsID,
		[Parameter(Mandatory = $true)]
		[string]$GroupPolicyConfigurationsDefinitionValueID
		
	)
	$graphApiVersion = "Beta"
	$DCP_resource = "deviceManagement/groupPolicyConfigurations/$groupPolicyDefinitionsID/definitionValues/$GroupPolicyConfigurationsDefinitionValueID/presentationValues?`$expand=presentation"
		$uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
		try {
		(Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value.presentation
        }
        catch {}
		
	
}


####################################################
    
Function Get-DeviceConfigurationPolicySC(){
    
            <#
            .SYNOPSIS
            This function is used to get device configuration policies from the Graph API REST interface - SETTINGS CATALOG
            .DESCRIPTION
            The function connects to the Graph API Interface and gets any device configuration policies
            .EXAMPLE
            Get-DeviceConfigurationPolicySC
            Returns any device configuration policies configured in Intune
            .NOTES
            NAME: Get-DeviceConfigurationPolicySC
            #>
            
            [cmdletbinding()]
            
            param
            (
                $id
            )
            
            $graphApiVersion = "beta"
            $DCP_resource = "deviceManagement/configurationPolicies"
            try {
                    if($id){
            
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)?`$filter=id eq '$id'"
                    (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
            
                    }
            
                    else {
            
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
                    (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
            
                    }
                }
                catch {}
            
            
}
            
################################################################################################


####################################################
    
Function Get-DeviceProactiveRemediations(){
    
    <#
    .SYNOPSIS
    This function is used to get device proactive remediations from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device proactive remediations
    .EXAMPLE
    Get-DeviceproactiveRemediations
    Returns any device proactive remediations configured in Intune
    .NOTES
    NAME: Get-Deviceproactiveremediations
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/devicehealthscripts"
    try {
            if($id){
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    
            }
    
            else {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
            }
        }
        catch {}
    
   
}
    
################################################################################################
    
Function Get-DeviceCompliancePolicy(){
    
            <#
            .SYNOPSIS
            This function is used to get device compliance policies from the Graph API REST interface
            .DESCRIPTION
            The function connects to the Graph API Interface and gets any device compliance policies
            .EXAMPLE
            Get-DeviceCompliancepolicy
            Returns any device compliance policies configured in Intune
            .NOTES
            NAME: Get-devicecompliancepolicy
            #>
            
            [cmdletbinding()]
            
            param
            (
                $id
            )
            
            $graphApiVersion = "beta"
            $DCP_resource = "deviceManagement/deviceCompliancePolicies"
            try {
                    if($id){
            
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)?`$filter=id eq '$id'"
                    (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
            
                    }
            
                    else {
            
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
                    (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
            
                    }
                }
                catch {}
            
}
            
#################################################################################################
Function Get-DeviceSecurityPolicy(){
    
    <#
    .SYNOPSIS
    This function is used to get device security policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device security policies
    .EXAMPLE
    Get-DeviceSecurityPolicy
    Returns any device compliance policies configured in Intune
    .NOTES
    NAME: Get-DeviceSecurityPolicy
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/intents"
    try {
            if($id){
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    
            }
    
            else {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
            }
        }
        catch {}
   
}

#################################################################################################  

Function Get-ManagedAppProtectionAndroid(){

    <#
    .SYNOPSIS
    This function is used to get managed app protection configuration from the Graph API REST interface Android
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any managed app protection policy Android
    .EXAMPLE
    Get-ManagedAppProtectionAndroid
    .NOTES
    NAME: Get-ManagedAppProtectionAndroid
    #>
    
    param
    (
        $id
    )
    $graphApiVersion = "Beta"
    
            $Resource = "deviceAppManagement/androidManagedAppProtections"
        try {
            if($id){
            
                $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource('$id')"
                (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
        
                }
        
                else {
        
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
                    Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject  
        
                }
            }
            catch {}        
        
        
    
}

#################################################################################################  

Function Get-ManagedAppProtectionIOS(){

    <#
    .SYNOPSIS
    This function is used to get managed app protection configuration from the Graph API REST interface IOS
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any managed app protection policy IOS
    .EXAMPLE
    Get-ManagedAppProtectionIOS
    .NOTES
    NAME: Get-ManagedAppProtectionIOS
    #>
    param
    (
        $id
    )

    $graphApiVersion = "Beta"
    
                $Resource = "deviceAppManagement/iOSManagedAppProtections"
        try {
                if($id){
            
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource('$id')"
                    (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
            
                    }
            
                    else {
            
                        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
                        Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject
            
                    }
                }
                catch {}
        
}
    
####################################################
Function Get-GraphAADGroups(){
    
    <#
    .SYNOPSIS
    This function is used to get AAD Groups from the Graph API REST interface 
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any AAD Groups
    .EXAMPLE
    Get-GraphAADGroups
    Returns any AAD Groups
    .NOTES
    NAME: Get-GraphAADGroups
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "Groups"
    try {
            if($id){
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id"
            Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject
    
            }
    
            else {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)?`$Filter=onPremisesSyncEnabled ne true&`$count=true"
            #(Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
            Get-MgGroup | Where-Object OnPremisesSyncEnabled -NE true
    
            }
        }
        catch {}
    
}

#################################################################################################  

Function Get-AutoPilotProfile(){
    
                <#
                .SYNOPSIS
                This function is used to get autopilot profiles from the Graph API REST interface 
                .DESCRIPTION
                The function connects to the Graph API Interface and gets any autopilot profiles
                .EXAMPLE
                Get-AutoPilotProfile
                Returns any autopilot profiles configured in Intune
                .NOTES
                NAME: Get-AutoPilotProfile
                #>
                
                [cmdletbinding()]
                
                param
                (
                    $id
                )
                
                $graphApiVersion = "beta"
                $DCP_resource = "deviceManagement/windowsAutopilotDeploymentProfiles"
                try {
                        if($id){
                
                        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)?`$filter=id eq '$id'"
                        (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
                
                        }
                
                        else {
                
                        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
                        (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
                
                        }
                    }
                    catch {}
                
}

#################################################################################################

Function Get-AutoPilotESP(){
    
                    <#
                    .SYNOPSIS
                    This function is used to get autopilot ESP from the Graph API REST interface 
                    .DESCRIPTION
                    The function connects to the Graph API Interface and gets any autopilot ESP
                    .EXAMPLE
                    Get-AutoPilotESP
                    Returns any autopilot ESPs configured in Intune
                    .NOTES
                    NAME: Get-AutoPilotESP
                    #>
                    
                    [cmdletbinding()]
                    
                    param
                    (
                        $id
                    )
                    
                    $graphApiVersion = "beta"
                    $DCP_resource = "deviceManagement/deviceEnrollmentConfigurations"
                    try {
                            if($id){
                    
                            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)?`$filter=id eq '$id'"
                            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
                    
                            }
                    
                            else {
                    
                            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
                            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
                    
                            }
                        }
                        catch{}
}
                
#################################################################################################    

Function Get-DecryptedDeviceConfigurationPolicy(){

    <#
    .SYNOPSIS
    This function is used to decrypt device configuration policies from an json array with the use of the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and decrypt Windows custom device configuration policies that is encrypted
    .EXAMPLE
    Decrypt-DeviceConfigurationPolicy -dcps $DCPs
    Returns any device configuration policies configured in Intune in clear text without encryption
    .NOTES
    NAME: Decrypt-DeviceConfigurationPolicy
    #>
    
    [cmdletbinding()]
    
    param
    (
        $dcpid
    )
    
    $graphApiVersion = "Beta"
    $DCP_resource = "deviceManagement/deviceConfigurations"
    $dcp = Get-DeviceConfigurationPolicy -id $dcpid
        if ($dcp.'@odata.type' -eq "#microsoft.graph.windows10CustomConfiguration") {
            # Convert policy of type windows10CustomConfiguration
            foreach ($omaSetting in $dcp.omaSettings) {
                    if ($omaSetting.isEncrypted -eq $true) {
                        $DCP_resource_function = "$($DCP_resource)/$($dcp.id)/getOmaSettingPlainTextValue(secretReferenceValueId='$($omaSetting.secretReferenceValueId)')"
                        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource_function)"
                        $value = ((Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value)

                        #Remove any unnecessary properties
                        $omaSetting.PsObject.Properties.Remove("isEncrypted")
                        $omaSetting.PsObject.Properties.Remove("secretReferenceValueId")
                        $omaSetting.value = $value
                    }

            }
        }
    
    $dcp

}


Function Get-DeviceManagementScripts(){
    
    <#
    .SYNOPSIS
    This function is used to get device PowerShell scripts from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device scripts
    .EXAMPLE
    Get-DeviceManagementScripts
    Returns any device management scripts configured in Intune
    .NOTES
    NAME: Get-DeviceManagementScripts
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/devicemanagementscripts"
    try {
            if($id){
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    
            }
    
            else {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
            }
        }
        catch {}
    
   
}
    
################################################################################################


#################################################################################################
function getpolicyjson() {
        <#
    .SYNOPSIS
    This function is used to add a new device policy by copying an existing policy, manipulating the JSON and then adding via Graph
    .DESCRIPTION
    The function grabs an existing policy, decrypts if requires, renames, removes any GUIDs and then returns the JSON
    .EXAMPLE
    getpolicyjson -policy $policy -name $name
    .NOTES
    NAME: getpolicyjson
    #>

    param
    (
        $resource,
        $policyid
    )
    write-host $resource
    $graphApiVersion = "beta"
    switch ($resource) {
    "deviceManagement/deviceConfigurations" {
     $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
     $policy = Get-DecryptedDeviceConfigurationPolicy -dcpid $id
     $oldname = $policy.displayName
     $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
     $newname = $oldname + "-restore-" + $restoredate
     $policy.displayName = $newname

     ##Custom settings only for OMA-URI
             ##Remove settings which break Custom OMA-URI
        
             
             if ($null -ne $policy.omaSettings) {
                $policyconvert = $policy.omaSettings
             $policyconvert = $policyconvert | Select-Object -Property * -ExcludeProperty isEncrypted, secretReferenceValueId
             foreach ($pvalue in $policyconvert) {
             $unencoded = $pvalue.value
             $EncodedText =[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($unencoded))
                $pvalue.value = $EncodedText
             }
             $policy.omaSettings = $policyconvert

            }
         # Set SupportsScopeTags to $false, because $true currently returns an HTTP Status 400 Bad Request error.
    if ($policy.supportsScopeTags) {
        $policy.supportsScopeTags = $false
    }



        $policy.PSObject.Properties | Foreach-Object {
            if ($null -ne $_.Value) {
                if ($_.Value.GetType().Name -eq "DateTime") {
                    $_.Value = (Get-Date -Date $_.Value -Format s) + "Z"
                }
                if ($_.Value.GetType().Name -eq "isEncrypted") {
                    $_.Value = "false"
                }
            }
        }


    }

    "deviceManagement/groupPolicyConfigurations" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $policy = Get-DeviceConfigurationPolicyGP -id $id
        $oldname = $policy.DisplayName
        $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
        $newname = $oldname + "-restore-" + $restoredate
        $policy.displayName = $newname
            # Set SupportsScopeTags to $false, because $true currently returns an HTTP Status 400 Bad Request error.
       if ($policy.supportsScopeTags) {
           $policy.supportsScopeTags = $false
       }
   
           $policy.PSObject.Properties | Foreach-Object {
               if ($null -ne $_.Value) {
                   if ($_.Value.GetType().Name -eq "DateTime") {
                       $_.Value = (Get-Date -Date $_.Value -Format s) + "Z"
                   }
               }
           }
       }

    "deviceManagement/devicehealthscripts" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $policy = Get-DeviceProactiveRemediations -id $id
        $oldname = $policy.DisplayName
        $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
        $newname = $oldname + "-restore-" + $restoredate
        $policy.displayName = $newname
            # Set SupportsScopeTags to $false, because $true currently returns an HTTP Status 400 Bad Request error.
       if ($policy.supportsScopeTags) {
           $policy.supportsScopeTags = $false
       }
   
           $policy.PSObject.Properties | Foreach-Object {
               if ($null -ne $_.Value) {
                   if ($_.Value.GetType().Name -eq "DateTime") {
                       $_.Value = (Get-Date -Date $_.Value -Format s) + "Z"
                   }
               }
           }
       }

       "deviceManagement/devicemanagementscripts" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $policy = Get-DeviceManagementScripts -id $id
        $oldname = $policy.DisplayName
        $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
        $newname = $oldname + "-restore-" + $restoredate
        $policy.displayName = $newname
            # Set SupportsScopeTags to $false, because $true currently returns an HTTP Status 400 Bad Request error.
       if ($policy.supportsScopeTags) {
           $policy.supportsScopeTags = $false
       }
   
           $policy.PSObject.Properties | Foreach-Object {
               if ($null -ne $_.Value) {
                   if ($_.Value.GetType().Name -eq "DateTime") {
                       $_.Value = (Get-Date -Date $_.Value -Format s) + "Z"
                   }
               }
           }
       }
    

       "deviceManagement/configurationPolicies" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $policy = Get-DeviceConfigurationPolicysc -id $id
        $policy | Add-Member -MemberType NoteProperty -Name 'settings' -Value @() -Force
        #$settings = Invoke-MSGraphRequest -HttpMethod GET -Url "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$id/settings" | Get-MSGraphAllPages
        $settings = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$id/settings" -OutputType PSObject
        $settings = $settings.value
        $settings =  $settings | select-object * -ExcludeProperty '@odata.count'
        if ($settings -isnot [System.Array]) {
            $policy.Settings = @($settings)
        } else {
            $policy.Settings = $settings
        }
        
        #
        $oldname = $policy.Name
        $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
        $newname = $oldname + "-restore-" + $restoredate
        $policy.Name = $newname

    }
    
    "deviceManagement/deviceCompliancePolicies" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $policy = Get-DeviceCompliancePolicy -id $id
        $oldname = $policy.DisplayName
        $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
        $newname = $oldname + "-restore-" + $restoredate
        $policy.displayName = $newname
        
            $scheduledActionsForRule = @(
                @{
                    ruleName = "PasswordRequired"
                    scheduledActionConfigurations = @(
                        @{
                            actionType = "block"
                            gracePeriodHours = 0
                            notificationTemplateId = ""
                        }
                    )
                }
            )
            $policy | Add-Member -NotePropertyName scheduledActionsForRule -NotePropertyValue $scheduledActionsForRule
            
            
    }
    "deviceManagement/intents" {
        $policy = Get-DeviceSecurityPolicy -id $id
        $templateid = $policy.templateID
        $uri = "https://graph.microsoft.com/beta/deviceManagement/templates/$templateId/createInstance"
        #$template = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/templates/$templateid" -Headers $authToken -Method Get
        $template = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/templates/$templateid" -OutputType PSObject
        $template = $template
        #$templateCategory = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/templates/$templateid/categories" -Headers $authToken -Method Get
        $templateCategories = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/templates/$templateid/categories" -OutputType PSObject).Value
        #$intentSettingsDelta = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/intents/$id/categories/$($templateCategory.id)/settings" -Headers $authToken -Method Get).value
        $intentSettingsDelta = @()
        foreach ($templateCategory in $templateCategories) {
            # Get all configured values for the template categories
            Write-Verbose "Requesting Intent Setting Values"
            $intentSettingsDelta += (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/intents/$($policy.id)/categories/$($templateCategory.id)/settings").value
        }
        $oldname = $policy.displayName
        $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
        $newname = $oldname + "-restore-" + $restoredate
           $policy = @{
            "displayName" = $newname
            "description" = $policy.description
            "settingsDelta" = $intentSettingsDelta
            "roleScopeTagIds" = $policy.roleScopeTagIds
        }
        $policy | Add-Member -NotePropertyName displayName -NotePropertyValue $newname



    }
    "deviceManagement/windowsAutopilotDeploymentProfiles" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $policy = Get-AutoPilotProfile -id $id
        $oldname = $policy.displayName
        $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
        $newname = $oldname + "-restore-" + $restoredate
           $policy.displayName = $newname
    }
    "groups" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $policy = Get-GraphAADGroups -id $id
        $oldname = $policy.displayName
        $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
        $newname = $oldname + "-restore-" + $restoredate
           $policy.displayName = $newname
        $policy = $policy | Select-Object description, DisplayName, groupTypes, mailEnabled, mailNickname, securityEnabled, isAssignabletoRole, membershiprule, MembershipRuleProcessingState
    }
    "deviceManagement/deviceEnrollmentConfigurations" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $policy = Get-AutoPilotESP -id $id
        $oldname = $policy.displayName
        $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
        $newname = $oldname + "-restore-" + $restoredate
           $policy.displayName = $newname
    }
    "deviceAppManagement/managedAppPoliciesandroid" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/managedAppPolicies"
        #$policy = Invoke-RestMethod -Uri "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/managedAppPolicies('$id')" -Headers $authToken -Method Get
        $policy = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/managedAppPolicies('$id')" -OutputType PSObject
        $oldname = $policy.displayName
        $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
        $newname = $oldname + "-restore-" + $restoredate
           $policy.displayName = $newname
         # Set SupportsScopeTags to $false, because $true currently returns an HTTP Status 400 Bad Request error.
         if ($policy.supportsScopeTags) {
            $policy.supportsScopeTags = $false
        }
    
            $policy.PSObject.Properties | Foreach-Object {
                if ($null -ne $_.Value) {
                    if ($_.Value.GetType().Name -eq "DateTime") {
                        $_.Value = (Get-Date -Date $_.Value -Format s) + "Z"
                    }
                }
            }


    }
    "deviceAppManagement/managedAppPoliciesios" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/managedAppPolicies"
        #$policy = Invoke-RestMethod -Uri "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/managedAppPolicies('$id')" -Headers $authToken -Method Get
        $policy = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/managedAppPolicies('$id')" -OutputType PSObject
        $oldname = $policy.displayName
        $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
        $newname = $oldname + "-restore-" + $restoredate
           $policy.displayName = $newname
         # Set SupportsScopeTags to $false, because $true currently returns an HTTP Status 400 Bad Request error.
         if ($policy.supportsScopeTags) {
            $policy.supportsScopeTags = $false
        }
    
            $policy.PSObject.Properties | Foreach-Object {
                if ($null -ne $_.Value) {
                    if ($_.Value.GetType().Name -eq "DateTime") {
                        $_.Value = (Get-Date -Date $_.Value -Format s) + "Z"
                    }
                }
            }


    }

    "conditionalaccess" {
        $uri = "conditionalaccess"
        $policy = Get-ConditionalAccessPolicy -id $id
        $oldname = $policy.displayName
    }
    "deviceAppManagement/mobileApps" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/mobileApps"
        $policy = Get-IntuneApplication -id $id
        $oldname = $policy.displayName
        $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
        $newname = $oldname + "-restore-" + $restoredate
           $policy.displayName = $newname
        $policy = $policy | Select-Object * -ExcludeProperty uploadState, publishingState, isAssigned, dependentAppCount, supersedingAppCount, supersededAppCount
    }
    }

    ##We don't want to convert CA policy to JSON
    if (($resource -eq "conditionalaccess")) {
        $policy = $policy
    }
    else {
    # Remove any GUIDs or dates/times to allow Intune to regenerate
    $policy = $policy | Select-Object * -ExcludeProperty id, createdDateTime, LastmodifieddateTime, version, creationSource, odata.count | ConvertTo-Json -Depth 100
    }

    return $policy, $uri, $oldname

}


###############################################################################################################
#################################                   BACKUP             #######################################
###############################################################################################################

if ($type -eq "backup") {



###############################################################################################################
######                                          Grab the Profiles                                        ######
###############################################################################################################
$profiles = @()
$configuration = @()
##Get Config Policies
$configuration += Get-DeviceConfigurationPolicy | Select-Object ID, DisplayName, Description, @{N='Type';E={"Config Policy"}}

##Get Admin Template Policies
$configuration += Get-DeviceConfigurationPolicyGP | Select-Object ID, DisplayName, Description, @{N='Type';E={"Admin Template"}}


##Get Settings Catalog Policies
$configuration += Get-DeviceConfigurationPolicySC | Select-Object ID, @{N='DisplayName';E={$_.Name}}, Description , @{N='Type';E={"Settings Catalog"}}

##Get Compliance Policies
$configuration += Get-DeviceCompliancePolicy | Select-Object ID, DisplayName, Description, @{N='Type';E={"Compliance Policy"}}

##Get Proactive Remediations
$configuration += Get-DeviceProactiveRemediations | Select-Object ID, DisplayName, Description, @{N='Type';E={"Proactive Remediation"}}

##Get Device Scripts
$configuration += Get-DeviceManagementScripts | Select-Object ID, DisplayName, Description, @{N='Type';E={"PowerShell Script"}}

##Get Security Policies
$configuration += Get-DeviceSecurityPolicy | Select-Object ID, DisplayName, Description, @{N='Type';E={"Security Policy"}}

##Get Autopilot Profiles
$configuration += Get-AutoPilotProfile | Select-Object ID, DisplayName, Description, @{N='Type';E={"Autopilot Profile"}}

##Get AAD Groups
$configuration += Get-GraphAADGroups | Select-Object ID, DisplayName, Description, @{N='Type';E={"AAD Group"}}

##Get Autopilot ESP
$configuration += Get-AutoPilotESP | Select-Object ID, DisplayName, Description, @{N='Type';E={"Autopilot ESP"}}

##Get App Protection Policies
#Android
$androidapp = Get-ManagedAppProtectionAndroid | Select-Object -expandproperty Value
$configuration += $androidapp | Select-Object ID, DisplayName, Description, @{N='Type';E={"Android App Protection"}}
#IOS
$iosapp = Get-ManagedAppProtectionios | Select-Object -expandproperty Value
$configuration += $iosapp | Select-Object ID, DisplayName, Description, @{N='Type';E={"iOS App Protection"}}

##Get Conditional Access Policies
$configuration += Get-ConditionalAccessPolicy | Select-Object ID, DisplayName, @{N='Type';E={"Conditional Access Policy"}}

##Get Winget Apps
$configuration += Get-IntuneApplication | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Winget Application"}}

if ($automated -eq "yes") {
    $configuration2 = $configuration
    }
else {
    $configuration2 = $configuration | Out-GridView -PassThru -Title "Select policies to backup"

}
$configuration2 | foreach-object {

##Find out what it is
$id = $_.ID
write-host $id
$policy = Get-DeviceConfigurationPolicy -id $id
$catalog = Get-DeviceConfigurationPolicysc -id $id
$compliance = Get-DeviceCompliancePolicy -id $id
$security = Get-DeviceSecurityPolicy -id $id
$autopilot = Get-AutoPilotProfile -id $id
$esp = Get-AutoPilotESP -id $id
$android = Get-ManagedAppProtectionAndroid -id $id
$ios = Get-ManagedAppProtectionios -id $id
$gp = Get-DeviceConfigurationPolicyGP -id $id
$ca = Get-ConditionalAccessPolicy -id $id
$proac = Get-DeviceProactiveRemediations -id $id
$aad = Get-GraphAADGroups -id $id
$wingetapp = Get-IntuneApplication -id $id
$scripts = Get-DeviceManagementScripts -id $id






# Copy it
if ($null -ne $policy) {
    # Standard Device Configuratio Policy
write-host "It's a policy"
$id = $policy.id
$Resource = "deviceManagement/deviceConfigurations"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))

}
if ($null -ne $gp) {
    # Standard Device Configuratio Policy
write-host "It's an Admin Template"
$id = $gp.id
$Resource = "deviceManagement/groupPolicyConfigurations"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}
if ($null -ne $catalog) {
    # Settings Catalog Policy
write-host "It's a Settings Catalog"
$id = $catalog.id
$Resource = "deviceManagement/configurationPolicies"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))

}
if ($null -ne $compliance) {
    # Compliance Policy
write-host "It's a Compliance Policy"
$id = $compliance.id
$Resource = "deviceManagement/deviceCompliancePolicies"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}
if ($null -ne $proac) {
    # Proactive Remediations
write-host "It's a Proactive Remediation"
$id = $proac.id
$Resource = "deviceManagement/devicehealthscripts"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}
if ($null -ne $scripts) {
    # Device Scripts
    write-host "It's a PowerShell Script"
$id = $scripts.id
$Resource = "deviceManagement/devicemanagementscripts"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}

if ($null -ne $security) {
    # Security Policy
write-host "It's a Security Policy"
$id = $security.id
$Resource = "deviceManagement/intents"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}
if ($null -ne $autopilot) {
    # Autopilot Profile
write-host "It's an Autopilot Profile"
$id = $autopilot.id
$Resource = "deviceManagement/windowsAutopilotDeploymentProfiles"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}
if ($null -ne $esp) {
    # Autopilot ESP
write-host "It's an AutoPilot ESP"
$id = $esp.id
$Resource = "deviceManagement/deviceEnrollmentConfigurations"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}
if ($null -ne $android) {
    # Android App Protection
write-host "It's an Android App Protection Policy"
$id = $android.id
$Resource = "deviceAppManagement/managedAppPoliciesandroid"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}
if ($null -ne $ios) {
    # iOS App Protection
write-host "It's an iOS App Protection Policy"
$id = $ios.id
$Resource = "deviceAppManagement/managedAppPoliciesios"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}
if ($null -ne $aad) {
    # AAD Groups
write-host "It's an AAD Group"
$id = $aad.id
$Resource = "groups"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}
if ($null -ne $ca) {
    # Conditional Access
write-host "It's a Conditional Access Policy"
$id = $ca.id
$Resource = "ConditionalAccess"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}
if ($null -ne $wingetapp) {
    # Winget App
write-host "It's a Windows Application"
$id = $wingetapp.id
$Resource = "deviceAppManagement/mobileApps"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}
}

##Convert profiles to JSON
$profilesjson = $profiles | convertto-json -Depth 50 

##Encode profiles to base64
$profilesencoded =[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($profilesjson))


if ($selected -eq "all") {
$backupreason = "Automated Backup"
}
else {
##Prompt for Message
[void][Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic')

$title = 'Reason'
$msg   = 'Enter your backup reason:'

$backupreason = [Microsoft.VisualBasic.Interaction]::InputBox($msg, $title)
}
##Upload to GitHub
$date =get-date -format yyMMddmmss
$date = $date.ToString()
$readabledate = get-date -format dd-MM-yyyy-HH-mm-ss
$filename = "intunebackup-"+$date+".json"
$uri = "https://api.github.com/repos/$ownername/$reponame/contents/$filename"
$message = "$backupreason - $readabledate"
$body = '{{"message": "{0}", "content": "{1}" }}' -f $message, $profilesencoded
(Invoke-RestMethod -Uri $uri -Method put -Headers @{'Authorization'='bearer '+$token; 'Accept'='Accept: application/vnd.github+json'} -Body $body -ContentType "application/json")



}

#######################################################################################################################################
#########                                                   END BACKUP                         ########################################
#######################################################################################################################################




#######################################################################################################################################
#########                                                   RESTORE                            ########################################
#######################################################################################################################################

if ($type -eq "restore") {

        
###############################################################################################################
######                                          Get Commits                                              ######
###############################################################################################################
write-host "Finding Latest Backup Commit from Repo $reponame in $ownername GitHub"
$uri = "https://api.github.com/repos/$ownername/$reponame/commits"
$events = (Invoke-RestMethod -Uri $uri -Method Get -Headers @{'Authorization'='bearer '+$token; 'Accept'='Accept: application/vnd.github+json'}).commit
$events | Select-object message, url| Out-GridView -PassThru -Title "Select Backup to View" | ForEach-Object {

$eventsuri = $_.url
$commitid = Split-Path $eventsuri -Leaf
$commituri = "https://api.github.com/repos/$ownername/$reponame/commits/$commitid"
$commitfilename = ((Invoke-RestMethod -Uri $commituri -Method Get -Headers @{'Authorization'='token '+$token; 'Accept'='application/json'}).Files).raw_url
write-host "$commitfilename Found"
}


$filename = $commitfilename.Substring($commitfilename.LastIndexOf("/") + 1)

$commitfilename2 = " https://api.github.com/repos/$ownername/$reponame/contents/$filename"


$encodedbackup = (Invoke-RestMethod -Uri $commitfilename2 -Method Get -Headers @{'Authorization'='bearer '+$token; 'Accept'='Accept: application/vnd.github+json.raw';'Cache-Control'='no-cache'}).Content

##Decode backup from base64
$decodedbackup = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encodedbackup))



###############################################################################################################
######                                         GridView Policies within Backup                           ######
###############################################################################################################


$profilelist2 = $decodedbackup | ConvertFrom-Json
$oneormore = $profilelist2.SyncRoot
if ($null -ne $oneormore) {
$fullist = $profilelist2.SyncRoot
$profilelist3 = $profilelist2.SyncRoot | select-object Value
$looplist = $profilelist3
$profilelist = @()
foreach ($profiletemp in $fullist) {
    $value1 =  ($profiletemp.value)[2]
    $profilelist += $value1
}
}
else {
$fulllist = $profilelist2.value
$profilelist3 = $fulllist
$looplist = $profilelist3 | Select-Object -First 1
$profilelist = @()
    $value1 =  ($profilelist3)[2]
    $profilelist += $value1
}




if ($selected -eq "all") {
    $temp = $profilelist
    }
else {
    $temp = $profilelist | Out-GridView -Title "Select Object to Restore" -PassThru

}



###############################################################################################################
######                                                Restore Them                                       ######
###############################################################################################################


    ##Loop through array and create Profiles
        foreach ($toupload in $looplist) {
        ##Count items in new array
        $tocheck = $toupload.value
        ##Multi Item
        if ($null -ne $tocheck) {
            $profilevalue = $toupload.value
            }
            else {
            #Single Item, just grab the whole thing
            $profilevalue = $profilelist3
            }

            foreach ($tname in $temp) {
            if ($tname -eq $profilevalue[2]) {
            $policyuri =  $profilevalue[1]
            $policyjson =  $profilevalue[0]
            $id = $profilevalue[3]
            write-host $profilevalue[1]
            $policy = $policyjson
            ##If policy is conditional access, we need special config
            if ($policyuri -eq "conditionalaccess") {
                write-host "Creating Conditional Access Policy"
                $uri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
                $oldname = $Policy.DisplayName
                $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
                $NewDisplayName = $oldname + "-restore-" + $restoredate        
                $Parameters = @{
                    displayName     = $NewDisplayName
                    state           = $policy.State
                    conditions      = $policy.Conditions
                    grantControls   = $policy.GrantControls
                    sessionControls = $policy.SessionControls
                }
                $body = $Parameters | ConvertTo-Json -depth 50
               $null = Invoke-MgGraphRequest -Method POST -uri $uri -Body $body -ContentType "application/json"
            }
            else {

               # Add the policy
            $body = ([System.Text.Encoding]::UTF8.GetBytes($policyjson.tostring()))
            try {
            $copypolicy = Invoke-MgGraphRequest -Uri $policyuri -Method Post -Body $body  -ContentType "application/json; charset=utf-8"
            }
            catch {

            }



            ##If policy is an admin template, we need to loop through and add the settings
            if ($policyuri -eq "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations") {
                ##Now grab the JSON
                $GroupPolicyConfigurationsDefinitionValues = Get-GroupPolicyConfigurationsDefinitionValues -GroupPolicyConfigurationID $id
                $OutDefjson = @()
	                foreach ($GroupPolicyConfigurationsDefinitionValue in $GroupPolicyConfigurationsDefinitionValues)
	                    {
		                    $GroupPolicyConfigurationsDefinitionValue
		                    $DefinitionValuedefinition = Get-GroupPolicyConfigurationsDefinitionValuesdefinition -GroupPolicyConfigurationID $id -GroupPolicyConfigurationsDefinitionValueID $GroupPolicyConfigurationsDefinitionValue.id
		                    $DefinitionValuedefinitionID = $DefinitionValuedefinition.id
		                    $DefinitionValuedefinitionDisplayName = $DefinitionValuedefinition.displayName
                            $DefinitionValuedefinitionDisplayName = $DefinitionValuedefinitionDisplayName
		                    $GroupPolicyDefinitionsPresentations = Get-GroupPolicyDefinitionsPresentations -groupPolicyDefinitionsID $id -GroupPolicyConfigurationsDefinitionValueID $GroupPolicyConfigurationsDefinitionValue.id
		                    $DefinitionValuePresentationValues = Get-GroupPolicyConfigurationsDefinitionValuesPresentationValues -GroupPolicyConfigurationID $id -GroupPolicyConfigurationsDefinitionValueID $GroupPolicyConfigurationsDefinitionValue.id
		                    $OutDef = New-Object -TypeName PSCustomObject
                            $OutDef | Add-Member -MemberType NoteProperty -Name "definition@odata.bind" -Value "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$definitionValuedefinitionID')"
                            $OutDef | Add-Member -MemberType NoteProperty -Name "enabled" -value $($GroupPolicyConfigurationsDefinitionValue.enabled.tostring().tolower())
                                if ($DefinitionValuePresentationValues) {
                                    $i = 0
                                    $PresValues = @()
                                    foreach ($Pres in $DefinitionValuePresentationValues) {
                                        $P = $pres | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version
                                        $GPDPID = $groupPolicyDefinitionsPresentations[$i].id
                                        $P | Add-Member -MemberType NoteProperty -Name "presentation@odata.bind" -Value "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$definitionValuedefinitionID')/presentations('$GPDPID')"
                                        $PresValues += $P
                                        $i++
                                    }
                                $OutDef | Add-Member -MemberType NoteProperty -Name "presentationValues" -Value $PresValues
                                }
		                    $OutDefjson += ($OutDef | ConvertTo-Json -Depth 10).replace("\u0027","'")
                            foreach ($json in $OutDefjson) {
                                $graphApiVersion = "beta"
                                $policyid = $copypolicy.id
                                $DCP_resource = "deviceManagement/groupPolicyConfigurations/$($policyid)/definitionValues"
                                $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
			                    #Invoke-RestMethod -ErrorAction SilentlyContinue -Uri $uri -Headers $authToken -Method Post -Body $json -ContentType "application/json"
                                try {
                                Invoke-MgGraphRequest -Uri $uri -Method Post -Body $json -ContentType "application/json"
                                }
                                catch {}
                            }
                        }
            }

        }
    
            }


        }
        }

    }
#######################################################################################################################################
#########                                                   END RESTORE                        ########################################
#######################################################################################################################################

        ##Clear Tenant Connections
        Disconnect-MgGraph

Stop-Transcript