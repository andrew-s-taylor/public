[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Scope='Function', Target='Get-MSGraphAllPages')]
<#PSScriptInfo
.VERSION 2.1.2
.GUID ec2a6c43-35ad-48cd-b23c-da987f1a528b
.AUTHOR AndrewTaylor
.DESCRIPTION Copies any Intune Policy via Microsoft Graph to "Copy of (policy name)".  Displays list of policies using GridView to select which to copy.  Cross tenant version
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
  Copies an Intune Policy.  Cross tenant version
.DESCRIPTION
Copies any Intune Policy via Microsoft Graph to "Copy of (policy name)".  Displays list of policies using GridView to select which to copy.  Cross tenant version

.INPUTS
None
.OUTPUTS
Creates a log file in %Temp%
.NOTES
  Version:        2.1.2
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  25/07/2022
  Updated: 28/08/2022
  Purpose/Change: Initial script development
  Change: Added support for multiple policy selection
  Change: Added Module installation
  Change: Declared $configuration as array

  
.EXAMPLE
N/A
#>


$ErrorActionPreference = "Continue"
##Start Logging to %TEMP%\intune.log
$date = get-date -format ddMMyyyy
Start-Transcript -Path $env:TEMP\intune-$date.log

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph.Intune) {
    Write-Host "Microsoft Graph Already Installed"
} 
else {
    try {
        Install-Module -Name Microsoft.Graph.Intune -Scope CurrentUser -Repository PSGallery -Force 
    }
    catch [Exception] {
        $_.message 
        exit
    }
}


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
Import-Module Microsoft.Graph.Intune

#Group creation needs preview module so we need to remove non-preview first
# Unload the AzureAD module (or continue if it's already unloaded)
Remove-Module AzureAD -force -ErrorAction SilentlyContinue
# Load the AzureADPreview module
Import-Module AzureADPreview




###############################################################################################################
######                                          Add Functions                                            ######
###############################################################################################################



function Get-AuthToken {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthToken
    Authenticates you with the Graph API interface
    .NOTES
    NAME: Get-AuthToken
    #>
    
    [cmdletbinding()]
    
    param
    (
        [Parameter(Mandatory=$true)]
        $User
    )
    
    $userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User
    
    $tenant = $userUpn.Host
    
    Write-Host "Checking for AzureAD module..."
    
        $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable
    
        if ($AadModule -eq $null) {
    
            Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"
            $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable
    
        }
    
        if ($AadModule -eq $null) {
            write-host
            write-host "AzureAD Powershell module not installed..." -f Red
            write-host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
            write-host "Script can't continue..." -f Red
            write-host
            exit
        }
    
    # Getting path to ActiveDirectory Assemblies
    # If the module count is greater than 1 find the latest version
    
        if($AadModule.count -gt 1){
    
            $Latest_Version = ($AadModule | select version | Sort-Object)[-1]
    
            $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }
    
                # Checking if there are multiple versions of the same module found
    
                if($AadModule.count -gt 1){
    
                $aadModule = $AadModule | select -Unique
    
                }
    
            $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
            $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    
        }
    
        else {
    
            $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
            $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    
        }
    
    [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
    
    [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null
    
    $clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
    
    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
    
    $resourceAppIdURI = "https://graph.microsoft.com"
    
    $authority = "https://login.microsoftonline.com/$Tenant"
    
        try {
    
        $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
    
        # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
        # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession
    
        $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"
    
        $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")
    
        $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId).Result
    
            # If the accesstoken is valid then create the authentication header
    
            if($authResult.AccessToken){
    
            # Creating header for Authorization token
    
            $authHeader = @{
                'Content-Type'='application/json'
                'Authorization'="Bearer " + $authResult.AccessToken
                'ExpiresOn'=$authResult.ExpiresOn
                }
    
            return $authHeader
    
            }
    
            else {
    
            Write-Host
            Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
            Write-Host
            break
    
            }
    
        }
    
        catch {
    
        write-host $_.Exception.Message -f Red
        write-host $_.Exception.ItemName -f Red
        write-host
        break
    
        }
    
    }
    
###############################################################################################################

function Get-MSGraphAllPages {
    [CmdletBinding(
        ConfirmImpact = 'Medium',
        DefaultParameterSetName = 'SearchResult'
    )]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'NextLink', ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias('@odata.nextLink')]
        [string]$NextLink,

        [Parameter(Mandatory = $true, ParameterSetName = 'SearchResult', ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [PSObject]$SearchResult
    )

    begin {}

    process {
        if ($PSCmdlet.ParameterSetName -eq 'SearchResult') {
            # Set the current page to the search result provided
            $page = $SearchResult

            # Extract the NextLink
            $currentNextLink = $page.'@odata.nextLink'

            # We know this is a wrapper object if it has an "@odata.context" property
            if (Get-Member -InputObject $page -Name '@odata.context' -Membertype Properties) {
                $values = $page.value
            } else {
                $values = $page
            }

            # Output the values
            if ($values) {
                $values | Write-Output
            }
        }

        while (-Not ([string]::IsNullOrWhiteSpace($currentNextLink)))
        {
            # Make the call to get the next page
            try {
                $page = Get-MSGraphNextPage -NextLink $currentNextLink
            } catch {
                throw
            }

            # Extract the NextLink
            $currentNextLink = $page.'@odata.nextLink'

            # Output the items in the page
            $values = $page.value
            if ($values) {
                $values | Write-Output
            }
        }
    }

    end {}
}
#############################################################################################################    


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
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).value
    
            }
    
            else {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
    
            }
    
        }
    
        catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        
    
        }
    
}
    
##########################################################################################


    
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
                    (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).value
            
                    }
            
                    else {
            
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
                    (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
            
                    }
            
                }
            
                catch {
            
                $ex = $_.Exception
                $errorResponse = $ex.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($errorResponse)
                $reader.BaseStream.Position = 0
                $reader.DiscardBufferedData()
                $responseBody = $reader.ReadToEnd();
                Write-Host "Response content:`n$responseBody" -f Red
                Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
                write-host
                
            
                }
            
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
                    (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).value
            
                    }
            
                    else {
            
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
                    (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
            
                    }
            
                }
            
                catch {
            
                $ex = $_.Exception
                $errorResponse = $ex.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($errorResponse)
                $reader.BaseStream.Position = 0
                $reader.DiscardBufferedData()
                $responseBody = $reader.ReadToEnd();
                Write-Host "Response content:`n$responseBody" -f Red
                Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
                write-host
                
            
                }
            
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
            
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)?`$filter=id eq '$id'"
                    (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).value
            
                    }
            
                    else {
            
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
                    (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
            
                    }
            
                }
            
                catch {
            
                $ex = $_.Exception
                $errorResponse = $ex.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($errorResponse)
                $reader.BaseStream.Position = 0
                $reader.DiscardBufferedData()
                $responseBody = $reader.ReadToEnd();
                Write-Host "Response content:`n$responseBody" -f Red
                Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
                write-host
                
            
                }
            
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
    
        try {
            $Resource = "deviceAppManagement/androidManagedAppProtections"
        
            if($id){
            
                $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource('$id')"
                (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get)
        
                }
        
                else {
        
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
                    Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get  
        
                }
                
        
                 
        
        }
    
        catch {
        

        }
    
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
    
        try {
        
                   
                $Resource = "deviceAppManagement/iOSManagedAppProtections"
        
                if($id){
            
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource('$id')"
                    (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get)
            
                    }
            
                    else {
            
                        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
                        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get  
            
                    }
        
        }
    
        catch {
        

        
        
        }
    
}
    
####################################################


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
                        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).value
                
                        }
                
                        else {
                
                        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
                        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
                
                        }
                
                    }
                
                    catch {
                
                    $ex = $_.Exception
                    $errorResponse = $ex.Response.GetResponseStream()
                    $reader = New-Object System.IO.StreamReader($errorResponse)
                    $reader.BaseStream.Position = 0
                    $reader.DiscardBufferedData()
                    $responseBody = $reader.ReadToEnd();
                    Write-Host "Response content:`n$responseBody" -f Red
                    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
                    write-host
                    
                
                    }
                
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
                            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).value
                    
                            }
                    
                            else {
                    
                            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
                            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
                    
                            }
                    
                        }
                    
                        catch {
                    
                        $ex = $_.Exception
                        $errorResponse = $ex.Response.GetResponseStream()
                        $reader = New-Object System.IO.StreamReader($errorResponse)
                        $reader.BaseStream.Position = 0
                        $reader.DiscardBufferedData()
                        $responseBody = $reader.ReadToEnd();
                        Write-Host "Response content:`n$responseBody" -f Red
                        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
                        write-host
                        
                    
                        }
                    
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
                try {

                    if ($omaSetting.isEncrypted -eq $true) {
                        $DCP_resource_function = "$($DCP_resource)/$($dcp.id)/getOmaSettingPlainTextValue(secretReferenceValueId='$($omaSetting.secretReferenceValueId)')"
                        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource_function)"
                        $value = ((Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value)

                        #Remove any unnecessary properties
                        $omaSetting.PsObject.Properties.Remove("isEncrypted")
                        $omaSetting.PsObject.Properties.Remove("secretReferenceValueId")
                        $omaSetting.value = $value
                    }

                }            
                catch {
            
                    $ex = $_.Exception
                    $errorResponse = $ex.Response.GetResponseStream()
                    $reader = New-Object System.IO.StreamReader($errorResponse)
                    $reader.BaseStream.Position = 0
                    $reader.DiscardBufferedData()
                    $responseBody = $reader.ReadToEnd();
                    Write-Host "Response content:`n$responseBody" -f Red
                    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
                    write-host
                    break
                
                }
            }
        }
    
    $dcp

}

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
     $newname = "Copy Of " + $oldname
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
        $settings = Invoke-RestMethod -headers $authToken -method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$id/settings" | Get-MSGraphAllPages

        if ($settings -isnot [System.Array]) {
            $policy.Settings = @($settings)
        } else {
            $policy.Settings = $settings
        }
        
        #
        $oldname = $policy.Name
        $newname = "Copy Of " + $oldname
        $policy.Name = $newname

    }
    "deviceManagement/deviceCompliancePolicies" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $policy = Get-DeviceCompliancePolicy -id $id
        $oldname = $policy.DisplayName
        $newname = "Copy Of " + $oldname
        $policy.DisplayName = $newname
        
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
        $template = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/templates/$templateid" -Headers $authToken -Method Get
        $templateCategory = Invoke-RestMethod -Uri -Url "https://graph.microsoft.com/beta/deviceManagement/templates/$templateid/categories" -Headers $authToken -Method Get | Get-MSGraphAllPages
        $intentSettingsDelta = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/intents/$id/categories/$($templateCategory.id)/settings" -Headers $authToken -Method Get).value
        $oldname = $policy.displayName
        $newname = "Copy Of " + $oldname
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
        $newname = "Copy Of " + $oldname
        $policy.displayName = $newname
    }
    "deviceManagement/deviceEnrollmentConfigurations" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $policy = Get-AutoPilotESP -id $id
        $oldname = $policy.displayName
        $newname = "Copy Of " + $oldname
        $policy.displayName = $newname
    }
    "deviceAppManagement/managedAppPoliciesandroid" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/managedAppPolicies"
        $policy = Invoke-RestMethod -Uri "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/managedAppPolicies('$id')" -Headers $authToken -Method Get
        $oldname = $policy.displayName
        $newname = "Copy Of " + $oldname
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
        $policy = Invoke-RestMethod -Uri "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/managedAppPolicies('$id')" -Headers $authToken -Method Get
        $oldname = $policy.displayName
        $newname = "Copy Of " + $oldname
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
    }


    

    # Remove any GUIDs or dates/times to allow Intune to regenerate
    $policy = $policy | Select-Object * -ExcludeProperty id, createdDateTime, LastmodifieddateTime, version, creationSource | ConvertTo-Json -Depth 100


    return $policy, $uri

}





###############################################################################################################
######                                          MS Graph Implementations                                 ######
###############################################################################################################



#Authenticate for MS Graph
#region Authentication

write-host

# Checking if authToken exists before running authentication
if($global:authToken){

    # Setting DateTime to Universal time to work in all timezones
    $DateTime = (Get-Date).ToUniversalTime()

    # If the authToken exists checking when it expires
    $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes

        if($TokenExpires -le 0){

        write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
        write-host

            # Defining User Principal Name if not present

            if($User -eq $null -or $User -eq ""){

            $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
            Write-Host

            }

        $global:authToken = Get-AuthToken -User $User

        }
}

# Authentication doesn't exist, calling Get-AuthToken function

else {

    if($User -eq $null -or $User -eq ""){

    $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
    Write-Host

    }

# Getting the authorization token

$tenant = Read-Host -Prompt "Please specify your source tenant email address"
$global:authToken = Get-AuthToken -User $tenant

}

#endregion



###############################################################################################################
######                                          Grab the Profiles                                        ######
###############################################################################################################
$profiles = @()
$configuration = @()
##Get Config Policies
$configuration += Get-DeviceConfigurationPolicy | Select-Object ID, DisplayName, Description

##Get Settings Catalog Policies
$configuration += Get-DeviceConfigurationPolicySC | Select-Object ID, @{N='DisplayName';E={$_.Name}}, Description

##Get Compliance Policies
$configuration += Get-DeviceCompliancePolicy | Select-Object ID, DisplayName, Description


##Get Security Policies
$configuration += Get-DeviceSecurityPolicy | Select-Object ID, DisplayName, Description

##Get Autopilot Profiles
$configuration += Get-AutoPilotProfile | Select-Object ID, DisplayName, Description


##Get Autopilot ESP
$configuration += Get-AutoPilotESP | Select-Object ID, DisplayName, Description

##Get App Protection Policies
#Android
$androidapp = Get-ManagedAppProtectionAndroid | Select-Object -expandproperty Value
$configuration += $androidapp | Select-Object ID, DisplayName, Description
#IOS
$iosapp = Get-ManagedAppProtectionios | Select-Object -expandproperty Value
$configuration += $iosapp | Select-Object ID, DisplayName, Description


$configuration | Out-GridView -PassThru | ForEach-Object {

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




# Copy it
if ($null -ne $policy) {
    # Standard Device Configuratio Policy
write-host "It's a policy"
$id = $policy.id
$Resource = "deviceManagement/deviceConfigurations"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1]))

}
if ($null -ne $catalog) {
    # Settings Catalog Policy
write-host "It's a Settings Catalog"
$id = $catalog.id
$Resource = "deviceManagement/configurationPolicies"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1]))

}
if ($null -ne $compliance) {
    # Compliance Policy
write-host "It's a Compliance Policy"
$id = $compliance.id
$Resource = "deviceManagement/deviceCompliancePolicies"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1]))

}
if ($null -ne $security) {
    # Security Policy
write-host "It's a Security Policy"
$id = $security.id
$Resource = "deviceManagement/intents"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1]))

}
if ($null -ne $autopilot) {
    # Autopilot Profile
write-host "It's an Autopilot Profile"
$id = $autopilot.id
$Resource = "deviceManagement/windowsAutopilotDeploymentProfiles"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1]))

}
if ($null -ne $esp) {
    # Autopilot ESP
write-host "It's an AutoPilot ESP"
$id = $esp.id
$Resource = "deviceManagement/deviceEnrollmentConfigurations"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1]))

}
if ($null -ne $android) {
    # Android App Protection
write-host "It's an Android App Protection Policy"
$id = $android.id
$Resource = "deviceAppManagement/managedAppPoliciesandroid"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1]))

}
if ($null -ne $ios) {
    # iOS App Protection
write-host "It's an iOS App Protection Policy"
$id = $ios.id
$Resource = "deviceAppManagement/managedAppPoliciesios"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1]))

}
}


        ##Clear Tenant Connections

        if ($global:authToken)
{
    Clear-Variable -Name authToken -Scope Global
}
else{
    Write-Host "The authtoken is null."
}

if ($global:authResult)
{
    Clear-Variable -Name authResult -Scope Global
}
else{
    Write-Host "The authtoken is null."
}
        
        ##Get new Tenant details
        $tenant2 = Read-Host -Prompt "Please specify your destination tenant email address"
        ##Conenct and copy
        $global:authToken = Get-AuthToken -user $tenant2


    ##Loop through array and create Profiles
        foreach ($toupload in $profiles) {
            $policyuri =  $toupload[1]
            $policyjson =  $toupload[0]
                try {
               # Add the policy
            $body = ([System.Text.Encoding]::UTF8.GetBytes($policyjson.tostring()))
            Invoke-RestMethod -Uri $policyuri -Headers $authToken -Method Post -Body $body  -ContentType "application/json; charset=utf-8"  
            #invoke-MSGraphRequest -Url $uri -HttpMethod POST -Content $body
            }
            catch {
                Write-Error $_.Exception 
                
            }
            }

Stop-Transcript