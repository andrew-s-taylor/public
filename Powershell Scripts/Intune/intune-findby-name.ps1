<#
.SYNOPSIS
Searches Intune for ANYTHING by name and returns the ID, Type and URI
.DESCRIPTION
Searches Intune for ANYTHING by name and returns the ID, Type and URI
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
Outputs name, ID, Type and URI
.NOTES
  Version:        1.0.5
  Author:         Andrew Taylor
  WWW:            andrewstaylor.com
  Creation Date:  27/01/2023
  .EXAMPLE
N/A
#>

<#PSScriptInfo
.VERSION 1.0.5
.GUID 967db1ba-9bbe-4709-bec1-61773b7add2b
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
    [string]$name #Type can be "backup" or "restore"

    )

############################################################
############################################################
############# CHANGE THIS TO USE IN AUTOMATION #############
############################################################
############################################################
$automated = "no"
############################################################

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
Import-Module microsoft.graph.authentication
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
Connect-MgGraph -Scopes DeviceManagementServiceConfig.ReadWrite.All, RoleAssignmentSchedule.ReadWrite.Directory, Domain.Read.All, Domain.ReadWrite.All, Directory.Read.All, Policy.ReadWrite.ConditionalAccess, DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, openid, profile, email, offline_access, DeviceManagementRBAC.Read.All, DeviceManagementRBAC.ReadWrite.All
}
##################################################################################################################################
#################                                           Check for Script Updates                             #################
##################################################################################################################################
Function Get-ScriptVersion(){
    
    <#
    .SYNOPSIS
    This function is used to check if the running script is the latest version
    .DESCRIPTION
    This function checks GitHub and compares the 'live' version with the one running
    .EXAMPLE
    Get-ScriptVersion
    Returns a warning and URL if outdated
    .NOTES
    NAME: Get-ScriptVersion
    #>
    
    [cmdletbinding()]
    
    param
    (
        $liveuri
    )
$contentheaderraw = (Invoke-WebRequest -Uri $liveuri -Method Get)
$contentheader = $contentheaderraw.Content.Split([Environment]::NewLine)
$liveversion = (($contentheader | Select-String 'Version:') -replace '[^0-9.]','') | Select-Object -First 1
$currentversion = ((Get-Content -Path $PSCommandPath | Select-String -Pattern "Version: *") -replace '[^0-9.]','') | Select-Object -First 1
if ($liveversion -ne $currentversion) {
write-warning "Script has been updated, please download the latest version from $liveuri"
}
}
Get-ScriptVersion -liveuri "https://raw.githubusercontent.com/andrew-s-taylor/public/main/Powershell%20Scripts/Intune/intune-findby-name.ps1"



###############################################################################################################
######                                          Add Functions                                            ######
###############################################################################################################

Function Get-IntuneApplicationbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get applications from the Graph API REST interface by name
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any applications added
    .EXAMPLE
    Get-IntuneApplicationbyName
    Returns any applications configured in Intune
    .NOTES
    NAME: Get-IntuneApplicationbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "Beta"
    $Resource = "deviceAppManagement/mobileApps"
    
        try {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayname eq '$name'"
            $app = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value | Where-Object { ($_.'@odata.type').Contains("#microsoft.graph.winGetApp") }
    
    
        }
    
        catch {
    
        }
        $myid = $app.id
        if ($null -ne $myid) {
        $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
        $type = "Winget Application"
        }
        else {
            $fulluri = ""
            $type = ""
        }
        $output = "" | Select-Object -Property id,fulluri, type    
        $output.id = $myid
        $output.fulluri = $fulluri
        $output.type = $type
        return $output
    }



Function Get-DeviceConfigurationPolicyGPbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get device configuration policies from the Graph API REST interface - Group Policies
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device configuration policies
    .EXAMPLE
    Get-DeviceConfigurationPolicyGPbyName
    Returns any device configuration policies configured in Intune
    .NOTES
    NAME: Get-DeviceConfigurationPolicyGPbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/groupPolicyConfigurations"
    
    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayname eq '$name'"
        $GP = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value

        }
        catch {}
        $myid = $GP.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Group Policy Configuration"
            }
            else {
                $fulluri = ""
                $type = ""
            }
            $output = "" | Select-Object -Property id,fulluri, type    
            $output.id = $myid
            $output.fulluri = $fulluri
            $output.type = $type
            return $output
    
}


#############################################################################################################    

Function Get-ConditionalAccessPolicybyName(){
    
    <#
    .SYNOPSIS
    This function is used to get conditional access policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any conditional access policies
    .EXAMPLE
    Get-ConditionalAccessPolicybyName
    Returns any conditional access policies in Azure
    .NOTES
    NAME: Get-ConditionalAccessPolicybyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    

    $graphApiVersion = "beta"
    $Resource = "identity/conditionalAccess/policies"
    
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayname eq '$name'"
        $CA = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $CA.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Conditional Access"
            }
            else {
                $fulluri = ""
                $type = ""
            }
            $output = "" | Select-Object -Property id,fulluri, type    
            $output.id = $myid
            $output.fulluri = $fulluri
            $output.type = $type
            return $output
    
     
}

####################################################

Function Get-DeviceConfigurationPolicybyName(){
    
    <#
    .SYNOPSIS
    This function is used to get device configuration policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device configuration policies
    .EXAMPLE
    Get-DeviceConfigurationPolicybyName
    Returns any device configuration policies configured in Intune
    .NOTES
    NAME: Get-DeviceConfigurationPolicybyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/deviceConfigurations"
    
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayname eq '$name'"
        $DC = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $DC.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Configuration Policy"
            }
            else {
                $fulluri = ""
                $type = ""
            }
            $output = "" | Select-Object -Property id,fulluri, type    
            $output.id = $myid
            $output.fulluri = $fulluri
            $output.type = $type
            return $output
    }
    
    
Function Get-DeviceConfigurationPolicySCbyName(){
    
            <#
            .SYNOPSIS
            This function is used to get device configuration policies from the Graph API REST interface - SETTINGS CATALOG
            .DESCRIPTION
            The function connects to the Graph API Interface and gets any device configuration policies
            .EXAMPLE
            Get-DeviceConfigurationPolicySCbyName
            Returns any device configuration policies configured in Intune
            .NOTES
            NAME: Get-DeviceConfigurationPolicySCbyName
            #>
            
            [cmdletbinding()]
            
            param
            (
                $name
            )
            
            $graphApiVersion = "beta"
            $Resource = "deviceManagement/configurationPolicies"
            try {

    
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=name eq '$name'"
                $SC = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
            
                }
                catch {}
                $myid = $SC.id
                if ($null -ne $myid) {
                    $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
                    $type = "Settings Catalog"
                    }
                    else {
                        $fulluri = ""
                        $type = ""
                    }
                    $output = "" | Select-Object -Property id,fulluri, type    
                    $output.id = $myid
                    $output.fulluri = $fulluri
                    $output.type = $type
                    return $output
                                
}
            
################################################################################################


####################################################
    
Function Get-DeviceProactiveRemediationsbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get device proactive remediations from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device proactive remediations
    .EXAMPLE
    Get-DeviceProactiveRemediationsbyName
    Returns any device proactive remediations configured in Intune
    .NOTES
    NAME: Get-DeviceProactiveRemediationsbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/devicehealthscripts"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $PR = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $PR.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Proactive Remediation"
            }
            else {
                $fulluri = ""
                $type = ""
            }
            $output = "" | Select-Object -Property id,fulluri, type    
            $output.id = $myid
            $output.fulluri = $fulluri
            $output.type = $type
            return $output
    
}
    
################################################################################################
    
Function Get-DeviceCompliancePolicybyName(){
    
            <#
            .SYNOPSIS
            This function is used to get device compliance policies from the Graph API REST interface
            .DESCRIPTION
            The function connects to the Graph API Interface and gets any device compliance policies
            .EXAMPLE
            Get-DeviceCompliancePolicybyName
            Returns any device compliance policies configured in Intune
            .NOTES
            NAME: Get-DeviceCompliancePolicybyName
            #>
            
            [cmdletbinding()]
            
            param
            (
                $name
            )
            
            $graphApiVersion = "beta"
            $Resource = "deviceManagement/deviceCompliancePolicies"
            try {

    
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
                $CP = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
            
                }
                catch {}
                $myid = $CP.id
                if ($null -ne $myid) {
                    $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
                    $type = "Compliance Policy"
                    }
                    else {
                        $fulluri = ""
                        $type = ""
                    }
                    $output = "" | Select-Object -Property id,fulluri, type    
                    $output.id = $myid
                    $output.fulluri = $fulluri
                    $output.type = $type
                    return $output
                                
}


Function Get-DeviceCompliancePolicyScriptsbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get device compliance policy scripts from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device compliance policies
    .EXAMPLE
    Get-DeviceCompliancePolicyScriptsbyName
    Returns any device compliance policy scripts configured in Intune
    .NOTES
    NAME: Get-DeviceCompliancePolicyScriptsbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/deviceComplianceScripts"
    try {


        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $CP = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $CP.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Compliance Policy Script"
            }
            else {
                $fulluri = ""
                $type = ""
            }
            $output = "" | Select-Object -Property id,fulluri, type    
            $output.id = $myid
            $output.fulluri = $fulluri
            $output.type = $type
            return $output
                        
}
            
#################################################################################################
Function Get-DeviceSecurityPolicybyName(){
    
    <#
    .SYNOPSIS
    This function is used to get device security policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device security policies
    .EXAMPLE
    Get-DeviceSecurityPolicybyName
    Returns any device compliance policies configured in Intune
    .NOTES
    NAME: Get-DeviceSecurityPolicybyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/intents"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $SP = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $SP.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Security Policy"
            }
            else {
                $fulluri = ""
                $type = ""
            }
            $output = "" | Select-Object -Property id,fulluri, type    
            $output.id = $myid
            $output.fulluri = $fulluri
            $output.type = $type
            return $output
    
}

#################################################################################################  

Function Get-ManagedAppProtectionAndroidbyName(){

    <#
    .SYNOPSIS
    This function is used to get managed app protection configuration from the Graph API REST interface Android
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any managed app protection policy Android
    .EXAMPLE
    Get-ManagedAppProtectionAndroidbyName
    .NOTES
    NAME: Get-ManagedAppProtectionAndroidbyName
    #>
    
    param
    (
        $name
    )
    $graphApiVersion = "Beta"
     $Resource = "deviceAppManagement/androidManagedAppProtections"
            try {

    
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
                $AAP = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
            
                }
                catch {}
                $myid = $AAP.id
                if ($null -ne $myid) {
                    $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
                    $type = "Android App Protection Policy"
                    }
                    else {
                        $fulluri = ""
                        $type = ""
                    }
                    $output = "" | Select-Object -Property id,fulluri, type    
                    $output.id = $myid
                    $output.fulluri = $fulluri
                    $output.type = $type
                    return $output
                        
}

#################################################################################################  

Function Get-ManagedAppProtectionIOSbyName(){

    <#
    .SYNOPSIS
    This function is used to get managed app protection configuration from the Graph API REST interface IOS
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any managed app protection policy IOS
    .EXAMPLE
    Get-ManagedAppProtectionIOSbyName
    .NOTES
    NAME: Get-ManagedAppProtectionIOSbyName
    #>
    param
    (
        $name
    )

    $graphApiVersion = "Beta"
    
                $Resource = "deviceAppManagement/iOSManagedAppProtections"
                try {

    
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
                    $IAP = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
                
                    }
                    catch {}
                    $myid = $IAP.id
                    if ($null -ne $myid) {
                        $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
                        $type = "iOS App Protection Policy"
                        }
                        else {
                            $fulluri = ""
                            $type = ""
                        }
                        $output = "" | Select-Object -Property id,fulluri, type    
                        $output.id = $myid
                        $output.fulluri = $fulluri
                        $output.type = $type
                        return $output
                    }
    
Function Get-AutoPilotProfilebyName(){
    
                <#
                .SYNOPSIS
                This function is used to get autopilot profiles from the Graph API REST interface 
                .DESCRIPTION
                The function connects to the Graph API Interface and gets any autopilot profiles
                .EXAMPLE
                Get-AutoPilotProfilebyName
                Returns any autopilot profiles configured in Intune
                .NOTES
                NAME: Get-AutoPilotProfilebyName
                #>
                
                [cmdletbinding()]
                
                param
                (
                    $name
                )
                
                $graphApiVersion = "beta"
                $Resource = "deviceManagement/windowsAutopilotDeploymentProfiles"
                try {

    
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
                    $AP = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
                
                    }
                    catch {}
                    $myid = $AP.id
                    if ($null -ne $myid) {
                        $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
                        $type = "Autopilot Profile"
                        }
                        else {
                            $fulluri = ""
                            $type = ""
                        }
                        $output = "" | Select-Object -Property id,fulluri, type    
                        $output.id = $myid
                        $output.fulluri = $fulluri
                        $output.type = $type
                        return $output
                                
}

#################################################################################################

Function Get-AutoPilotESPbyName(){
    
                    <#
                    .SYNOPSIS
                    This function is used to get autopilot ESP from the Graph API REST interface 
                    .DESCRIPTION
                    The function connects to the Graph API Interface and gets any autopilot ESP
                    .EXAMPLE
                    Get-AutoPilotESPbyName
                    Returns any autopilot ESPs configured in Intune
                    .NOTES
                    NAME: Get-AutoPilotESPbyName
                    #>
                    
                    [cmdletbinding()]
                    
                    param
                    (
                        $name
                    )
                    
                    $graphApiVersion = "beta"
                    $Resource = "deviceManagement/deviceEnrollmentConfigurations"
                    try {

    
                        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
                        $ESP = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
                    
                        }
                        catch {}
                        $myid = $ESP.id
                        if ($null -ne $myid) {
                            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
                            $type = "Autopilot ESP"
                            }
                            else {
                                $fulluri = ""
                                $type = ""
                            }
                            $output = "" | Select-Object -Property id,fulluri, type    
                            $output.id = $myid
                            $output.fulluri = $fulluri
                            $output.type = $type
                            return $output
                        }
                
#################################################################################################    


Function Get-DeviceManagementScriptsbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get device PowerShell scripts from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device scripts
    .EXAMPLE
    Get-DeviceManagementScriptsbyName
    Returns any device management scripts configured in Intune
    .NOTES
    NAME: Get-DeviceManagementScriptsbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/devicemanagementscripts"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $Script = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $Script.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "PowerShell Script"
            }
            else {
                $fulluri = ""
                $type = ""
            }
            $output = "" | Select-Object -Property id,fulluri, type    
            $output.id = $myid
            $output.fulluri = $fulluri
            $output.type = $type
            return $output
    
   
}

Function Get-Win365UserSettingsbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get Windows 365 User Settings Policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device scriptsWindows 365 User Settings Policies
    .EXAMPLE
    Get-Win365UserSettingsbyName
    Returns any Windows 365 User Settings Policies configured in Intune
    .NOTES
    NAME: Get-Win365UserSettingsbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/virtualEndpoint/userSettings"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $W365User = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $W365User.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Win365 User Settings"
            }
            else {
                $fulluri = ""
                $type = ""
            }
            $output = "" | Select-Object -Property id,fulluri, type    
            $output.id = $myid
            $output.fulluri = $fulluri
            $output.type = $type
            return $output
        
   
}

Function Get-Win365ProvisioningPoliciesbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get Windows 365 Provisioning Policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Windows 365 Provisioning Policies
    .EXAMPLE
    Get-Win365ProvisioningPoliciesbyName
    Returns any Windows 365 Provisioning Policies configured in Intune
    .NOTES
    NAME: Get-Win365ProvisioningPoliciesbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/virtualEndpoint/provisioningPolicies"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $W365Prov = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $W365Prov.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "W365 Provisioning Policy"
            }
            else {
                $fulluri = ""
                $type = ""
            }
            $output = "" | Select-Object -Property id,fulluri, type    
            $output.id = $myid
            $output.fulluri = $fulluri
            $output.type = $type
            return $output
       
}

Function Get-IntunePolicySetsbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune policy sets from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune policy sets
    .EXAMPLE
    Get-IntunePolicySetsbyName
    Returns any policy sets configured in Intune
    .NOTES
    NAME: Get-IntunePolicySetsbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceAppManagement/policySets"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $Policyset = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $Policyset.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Policy Set"
            }
            else {
                $fulluri = ""
                $type = ""
            }
            $output = "" | Select-Object -Property id,fulluri, type    
            $output.id = $myid
            $output.fulluri = $fulluri
            $output.type = $type
            return $output
       
}

Function Get-EnrollmentConfigurationsbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune enrollment configurations from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune enrollment configurations
    .EXAMPLE
    Get-EnrollmentConfigurationsbyName
    Returns any enrollment configurations configured in Intune
    .NOTES
    NAME: Get-EnrollmentConfigurationsbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/deviceEnrollmentConfigurations"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $EC = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $EC.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Enrollment Configuration"
            }
            else {
                $fulluri = ""
                $type = ""
            }
            $output = "" | Select-Object -Property id,fulluri, type    
            $output.id = $myid
            $output.fulluri = $fulluri
            $output.type = $type
            return $output
          
}
    

Function Get-DeviceCategoriesbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune device categories from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune device categories
    .EXAMPLE
    Get-DeviceCategoriesbyName
    Returns any device categories configured in Intune
    .NOTES
    NAME: Get-DeviceCategoriesbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/deviceCategories"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $DC = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $DC.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Device Category"
            }
            else {
                $fulluri = ""
                $type = ""
            }
            $output = "" | Select-Object -Property id,fulluri, type    
            $output.id = $myid
            $output.fulluri = $fulluri
            $output.type = $type
            return $output
    }


Function Get-DeviceFiltersbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune device filters from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune device filters
    .EXAMPLE
    Get-DeviceFiltersbyName
    Returns any device filters configured in Intune
    .NOTES
    NAME: Get-DeviceFiltersbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/assignmentFilters"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $DF = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $DF.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Device Filter"
            }
            else {
                $fulluri = ""
                $type = ""
            }
            $output = "" | Select-Object -Property id,fulluri, type    
            $output.id = $myid
            $output.fulluri = $fulluri
            $output.type = $type
            return $output
    }


Function Get-BrandingProfilesbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune Branding Profiles from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune Branding Profiles
    .EXAMPLE
    Get-BrandingProfilesbyName
    Returns any Branding Profiles configured in Intune
    .NOTES
    NAME: Get-BrandingProfilesbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/intuneBrandingProfiles"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $BP = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $BP.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Branding Profile"
            }
            else {
                $fulluri = ""
                $type = ""
            }
            $output = "" | Select-Object -Property id,fulluri, type    
            $output.id = $myid
            $output.fulluri = $fulluri
            $output.type = $type
            return $output
        
   
}


Function Get-AdminApprovalsbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune admin approvals from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune admin approvals
    .EXAMPLE
    Get-AdminApprovalsbyName
    Returns any admin approvals configured in Intune
    .NOTES
    NAME: Get-AdminApprovalsbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/operationApprovalPolicies"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $AdminAp = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $AdminAp.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Admin Approval"
            }
            else {
                $fulluri = ""
                $type = ""
            }
            $output = "" | Select-Object -Property id,fulluri, type    
            $output.id = $myid
            $output.fulluri = $fulluri
            $output.type = $type
            return $output
       
}

Function Get-OrgMessagesbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune organizational messages from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune organizational messages
    .EXAMPLE
    Get-OrgMessagesbyName
    Returns any organizational messages configured in Intune
    .NOTES
    NAME: Get-OrgMessagesbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/organizationalMessageDetails"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $OM = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $OM.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Organization Message"
            }
            else {
                $fulluri = ""
                $type = ""
            }
            $output = "" | Select-Object -Property id,fulluri, type    
            $output.id = $myid
            $output.fulluri = $fulluri
            $output.type = $type
            return $output
       
}


Function Get-IntuneTermsbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune terms and conditions from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune terms and conditions
    .EXAMPLE
    Get-IntuneTermsbyName
    Returns any terms and conditions configured in Intune
    .NOTES
    NAME: Get-IntuneTermsbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/termsAndConditions"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $Terms = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $Terms.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Terms and Conditions"
            }
            else {
                $fulluri = ""
                $type = ""
            }
            $output = "" | Select-Object -Property id,fulluri, type    
            $output.id = $myid
            $output.fulluri = $fulluri
            $output.type = $type
            return $output
        
   
}

Function Get-IntuneRolesbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune custom roles from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune custom roles
    .EXAMPLE
    Get-IntuneRolesbyName
    Returns any custom roles configured in Intune
    .NOTES
    NAME: Get-IntuneRolesbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/roleDefinitions"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $Roles = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $Roles.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Custom Role"
            }
            else {
                $fulluri = ""
                $type = ""
            }
            $output = "" | Select-Object -Property id,fulluri, type    
            $output.id = $myid
            $output.fulluri = $fulluri
            $output.type = $type
            return $output
        
   
}
################################################################################################
####################################################
Function Get-GraphAADGroupsbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get AAD Groups from the Graph API REST interface 
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any AAD Groups
    .EXAMPLE
    Get-GraphAADGroupsbyName
    Returns any AAD Groups
    .NOTES
    NAME: Get-GraphAADGroupsbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "Groups"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $AAD = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $AAD.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "AAD Group"
            }
            else {
                $fulluri = ""
                $type = ""
            }
            $output = "" | Select-Object -Property id,fulluri, type    
            $output.id = $myid
            $output.fulluri = $fulluri
            $output.type = $type
            return $output
        
}

#################################################################################################  
function Get-DetailsbyName () {
    <#
    .SYNOPSIS
    This function is used to get  ID and URI from only the name
    .DESCRIPTION
    This function is used to get  ID and URI from only the name
    .EXAMPLE
    Get-DetailsbyName
    Returns ID and full URI
    .NOTES
    NAME: Get-DetailsbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )

    $id = ""
    while ($id -eq "") {
$check = Get-DeviceConfigurationPolicybyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-DeviceConfigurationPolicySCbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-DeviceCompliancePolicybyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-DeviceCompliancePolicyscriptsbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-DeviceSecurityPolicybyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-AutoPilotProfilebyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-AutoPilotESPbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-ManagedAppProtectionAndroidbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-ManagedAppProtectioniosbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-DeviceConfigurationPolicyGPbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-ConditionalAccessPolicybyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-DeviceProactiveRemediationsbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-GraphAADGroupsbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-IntuneApplicationbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-DeviceManagementScriptsbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-Win365UserSettingsbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-Win365ProvisioningPoliciesbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-IntunePolicySetsbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-EnrollmentConfigurationsbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-DeviceCategoriesbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-DeviceFiltersbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-BrandingProfilesbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-AdminApprovalsbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
#$orgmessages = Get-OrgMessages -id $id
$check = Get-IntuneTermsbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-IntuneRolesbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
    }
    $output = "" | Select-Object -Property id,uri, type    
        $output.id = $id
        $output.uri = $uri
        $output.type = $type
        return $output
}

##################################################################################################################################
#################                                                  Execution                                     #################
##################################################################################################################################



$details = Get-DetailsbyName -name $name
$foundid = $details.id
$founduri = $details.uri
$foundtype = $details.type

write-host "Policy Name: $name"
write-host "Policy ID: $foundid"
write-host "Policy URI: $founduri"
write-host "Policy Type: $foundtype"