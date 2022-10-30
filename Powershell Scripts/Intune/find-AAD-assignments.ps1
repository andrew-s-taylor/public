##WRAPPER for
##https://gist.github.com/ztrhgf/82916840c02e7e369a6f7dff171fa3d2
##Original script by Ondrej Sebela


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


# Load the Graph module
Import-Module microsoft.graph


# TODO resit filtry u assignmetu??
# TODO kde to pujde tak pouzit $filter=isAssigned eq true
# TODO udelat configurtion profil pro kazdy typ a zkontrolovat ze kazdy umim dohledat
function Get-IntuneAssignment {
    [CmdletBinding()]
    [Alias("Search-IntuneAssignment")]
    param (
        [string] $accountId,

        # TODO ignorovat clenstvi ve skupinach jen v include nebo i exclude?
        [switch] $justExplicitAssignments,

        # TODO
        [switch] $includeIndirectAssignments,

        [ValidateSet('app', 'compliancePolicy', 'configurationPolicy', 'deviceManagementPSHScripts', 'administrativeTemplate', 'deviceManagementShellScripts', 'remediationScript', 'endpointSecurity', 'windowsAutopilotDeploymentProfiles', 'deviceEnrollmentConfigurations', 'windowsFeatureUpdateProfiles', 'windowsQualityUpdateProfiles')]
        [string[]] $assignmentType = ('app', 'compliancePolicy', 'configurationPolicy', 'deviceManagementPSHScripts', 'administrativeTemplate', 'deviceManagementShellScripts', 'remediationScript', 'endpointSecurity', 'windowsAutopilotDeploymentProfiles', 'deviceEnrollmentConfigurations', 'windowsFeatureUpdateProfiles', 'windowsQualityUpdateProfiles')
    )

    # throw "rozdelane"

    #region helper functions
    function Get-IntuneSecurityPolicy {
    <#
    .SYNOPSIS
    This function is used to get the all Intune Endpoint Security policies:
     - Account Protection policies
     - Antivirus policies
     - Attack Surface Reduction
     - Defender policies
     - Disk Encryption policies
     - Endpoint Detection and Response
     - Firewall
     - Security Baselines

    Including policy assignments and settings.

    .DESCRIPTION
    This function is used to get the all Intune Endpoint Security policies:
     - Account Protection policies
     - Antivirus policies
     - Attack Surface Reduction
     - Defender policies
     - Disk Encryption policies
     - Endpoint Detection and Response
     - Firewall
     - Security Baselines

    Including policy assignments and settings.

    .EXAMPLE
    Connect-MSGraph
    Get-IntuneSecurityBaseline

    Returns all existing Intune's Endpoint Security policies.

    .NOTES
    Based on https://www.powershellgallery.com/packages/IntuneDocumentation/2.0.19/Content/Internal%5CGet-SecBaselinesBeta.ps1.
    #>

    [Alias("Get-IntuneEndpointSecurityPolicy")]
    [CmdletBinding()]
    param ()

    try {
        #region process: Security Baselines, Antivirus policies, Defender policies, Disk Encryption policies, Account Protection policies (not 'Local User Group Membership')
        $uri = "https://graph.microsoft.com/beta/deviceManagement/intents"
        $templates = (Invoke-MSGraphRequest -Url $uri -HttpMethod GET -ErrorAction Stop).Value
        foreach ($template in $templates) {
            Write-Verbose "Processing intent $($template.id), template $($template.templateId)"

            $settings = Invoke-MSGraphRequest -Url "https://graph.microsoft.com/beta/deviceManagement/intents/$($template.id)/settings"
            $templateDetail = Invoke-MSGraphRequest -Url "https://graph.microsoft.com/beta/deviceManagement/templates/$($template.templateId)"

            $template | Add-Member Noteproperty -Name 'platforms' -Value $templateDetail.platformType -Force # to match properties of second function region objects
            $template | Add-Member Noteproperty -Name 'type' -Value "$($templateDetail.templateType)-$($templateDetail.templateSubtype)" -Force

            $templSettings = @()
            foreach ($setting in $settings.value) {
                # $settingDef = Invoke-MSGraphRequest -Url "https://graph.microsoft.com/beta/deviceManagement/settingDefinitions/$($setting.id)" -ErrorAction SilentlyContinue
                # $displayName = $settingDef.Value.displayName
                # if($null -eq $displayName){
                $displayName = $setting.definitionId -replace "deviceConfiguration--", "" -replace "admx--", "" -replace "_", " "
                # }
                if ($null -eq $setting.value) {
                    if ($setting.definitionId -eq "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallRules") {
                        $v = $setting.valueJson | ConvertFrom-Json
                        foreach ($item in $v) {
                            $templSettings += [PSCustomObject]@{
                                Name  = "FW Rule - $($item.displayName)"
                                Value = ($item | ConvertTo-Json)
                            }
                        }
                    } else {
                        $v = ""
                        $templSettings += [PSCustomObject]@{ Name = $displayName; Value = $v }
                    }
                } else {
                    $v = $setting.value
                    $templSettings += [PSCustomObject]@{ Name = $displayName; Value = $v }
                }
            }

            $template | Add-Member Noteproperty -Name Settings -Value $templSettings -Force
            $template | Add-Member Noteproperty -Name 'settingCount' -Value $templSettings.count -Force # to match properties of second function region objects
            $assignments = Invoke-MSGraphRequest -Url "https://graph.microsoft.com/beta/deviceManagement/intents/$($template.id)/assignments"
            $template | Add-Member Noteproperty -Name Assignments -Value $assignments.Value -Force
            $template | select -Property * -ExcludeProperty templateId
        }
        #endregion process: Security Baselines, Antivirus policies, Defender policies, Disk Encryption policies, Account Protection policies (not 'Local User Group Membership')

        #region process: Account Protection policies (just 'Local User Group Membership'), Firewall, Endpoint Detection and Response, Attack Surface Reduction
        Invoke-MSGraphRequest -HttpMethod GET -Url 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?$select=id,name,description,isAssigned,platforms,lastModifiedDateTime,settingCount,roleScopeTagIds,templateReference&$expand=Assignments,Settings' | Get-MSGraphAllPages | ? { $_.templateReference.templateFamily -like "endpointSecurity*" } | select -Property id, @{n = 'displayName'; e = { $_.name } }, description, isAssigned, lastModifiedDateTime, roleScopeTagIds, platforms, @{n = 'type'; e = { $_.templateReference.templateFamily } }, templateReference, @{n = 'settings'; e = { $_.settings | % { [PSCustomObject]@{
                        # trying to have same format a.k.a. name/value as in previous function region
                        Name  = $_.settinginstance.settingDefinitionId
                        Value = $(
                            # property with setting value isn't always same, try to get the used one
                            $valuePropertyName = $_.settinginstance | Get-Member -MemberType NoteProperty | ? name -Like "*value" | select -ExpandProperty name
                            if ($valuePropertyName) {
                                Write-Verbose "Value property $valuePropertyName was found"
                                $_.settinginstance.$valuePropertyName
                            } else {
                                Write-Verbose "Value property wasn't found, therefore saving whole object as value"
                                $_.settinginstance
                            }
                        )
                    } } }
        }, settingCount, assignments -ExcludeProperty 'assignments@odata.context', 'settings', 'settings@odata.context', 'technologies', 'name', 'templateReference'
        #endregion process: Account Protection policies (just 'Local User Group Membership'), Firewall, Endpoint Detection and Response, Attack Surface Reduction
    } catch {
        throw $_
    }
}

    # check whether there is at least one assignment that includes one of the groups searched account is member of and at the same time, there is none exclude rule
    function _isApplied {
        $input | ? {
            $isAssigned = $false
            $isExcluded = $false

            $policy = $_

            Write-Verbose "Processing policy '$($policy.displayName)' ($($policy.id))"

            if (!$accountId) {
                # if no account specified, return all assignments
                return $true
            }

            foreach ($assignment in $policy.assignments) {
                if (!$isAssigned -and ($assignment.target.groupId -in $accountMemberOfGroup.objectid -and $assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget')) {
                    Write-Verbose "INCLUDE: There is assignment for group $($assignment.target.groupId)"
                    $isAssigned = $true
                } elseif (!$isAssigned -and !$justExplicitAssignments -and ($assignment.target.'@odata.type' -in '#microsoft.graph.allDevicesAssignmentTarget', '#microsoft.graph.allLicensedUsersAssignmentTarget')) {
                    Write-Verbose "INCLUDE: There is assignment for 'All devices or All users'"
                    $isAssigned = $true
                } elseif ($assignment.target.groupId -in $accountMemberOfGroup.objectid -and $assignment.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                    Write-Verbose "EXCLUDE: There is exclude assignment for group $($assignment.target.groupId)"
                    $isExcluded = $true
                    break
                }
            }

            if ($isExcluded -or !$isAssigned) {
                Write-Verbose "Policy ISN'T applied to searched account"
                return $false
            } else {
                Write-Verbose "Policy IS applied to searched account"
                return $true
            }
        }
    }
    #endregion helper functions

    # assignment cannot be targeted to user/device but group, i.e. get account membership
    $objectType = $null
    $accountObj = $null

    if ($accountId) {
        $accountObj = Get-AzureADObjectByObjectId -ObjectIds $accountId -Types group, user, device -ErrorAction Stop
        $objectType = $accountObj.ObjectType
        if (!$objectType) {
            throw "Undefined object. It is not user, group or device."
        }
        Write-Verbose "$accountId belongs to $objectType"

        switch ($objectType) {
            'device' {
                if ($includeIndirectAssignments) {
                    $accountMemberOfGroup = Get-AzureADDeviceMembership -deviceObjectId $accountId -transitiveMemberOf | select -ExpandProperty MemberOf
                } else {
                    $accountMemberOfGroup = Get-AzureADDeviceMembership -deviceObjectId $accountId | select -ExpandProperty MemberOf
                }
            }

            'user' {
                if ($includeIndirectAssignments) {
                    # TODO
                } else {
                    $accountMemberOfGroup = Get-AzureADUserMembership -ObjectId $accountId -All:$true
                }
            }

            'group' {
                if ($includeIndirectAssignments) {
                    # TODO
                } else {
                    $accountMemberOfGroup = Get-AzureADGroup -ObjectId $accountId
                }
            }

            default {
                throw "Undefined object type $objectType"
            }
        }
    }

    #region get assignment
    $appliedApp = $null
    $appliedCompliancePolicy = $null
    $appliedDeviceConfigPolicy = $null
    $appliedDeviceConfigPSHScript = $null
    $appliedDeviceConfigShellScript = $null
    $appliedAdministrativeTemplate = $null
    $appliedEndpointSecurityPolicy = $null
    $appliedWindowsAutopilotDeploymentProfile = $null
    $appliedDeviceEnrollmentConfiguration = $null
    $appliedWindowsFeatureUpdateProfile = $null
    $allWindowsQualityUpdateProfiles = $null

    # Apps
    if ($assignmentType -contains 'app') {
        # https://graph.microsoft.com/beta/deviceAppManagement/mobileApps
        Write-Verbose "Processing Apps"
        $allApps = Get-IntuneMobileApp -Select id, displayName, lastModifiedDateTime, assignments -Expand assignments
        $appliedApp = $allApps | _isApplied
    }

    # Device Compliance
    if ($assignmentType -contains 'compliancePolicy') {
        Write-Verbose "Processing Compliance policies"
        # https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies
        $allCompliancePolicies = Get-IntuneDeviceCompliancePolicy -Select id, displayName, lastModifiedDateTime, assignments -Expand assignments
        $appliedCompliancePolicy = $allCompliancePolicies | _isApplied
    }

    # Device Configuration
    if ($assignmentType -contains 'configurationPolicy') {
        # TODO nevraci vsechny conf policy co jsou videt v GUI!
        # ale melo by obsahovat update ringy
        Write-Verbose "Processing Configuration policies"
        # returns just https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations
        $allDeviceConfigPolicies = Get-IntuneDeviceConfigurationPolicy -Select id, displayName, lastModifiedDateTime, assignments -Expand assignments | select -Property * -ExcludeProperty 'assignments@odata.context'
        $appliedDeviceConfigPolicy = $allDeviceConfigPolicies | _isApplied
    }

    # Device Configuration Powershell Scripts
    if ($assignmentType -contains 'deviceManagementPSHScripts') {
        Write-Verbose "Processing PowerShell scripts"
        $uri = 'https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts?$expand=Assignments'
        $allDeviceConfigPSHScripts = Invoke-MSGraphRequest -Url $uri | Get-MSGraphAllPages
        $appliedDeviceConfigPSHScript = $allDeviceConfigPSHScripts | _isApplied
    }

    # Device Configuration Shell Scripts
    if ($assignmentType -contains 'deviceManagementShellScripts') {
        Write-Verbose "Processing Shell scripts"
        $uri = 'https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts?$expand=Assignments'
        $allDeviceConfigShellScripts = Invoke-MSGraphRequest -Url $uri | Get-MSGraphAllPages
        $appliedDeviceConfigShellScript = $allDeviceConfigShellScripts | _isApplied
    }

    # Remediation Scripts
    if ($assignmentType -contains 'remediationScript') {
        Write-Verbose "Processing Remediation (Health) scripts"
        $uri = 'https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts?$expand=Assignments'
        $allRemediationScripts = Invoke-MSGraphRequest -Url $uri | Get-MSGraphAllPages
        $appliedRemediationScript = $allRemediationScripts | _isApplied
    }

    # Administrative templates
    if ($assignmentType -contains 'administrativeTemplate') {
        Write-Verbose "Processing Administrative templates"
        $uri = 'https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations?$expand=Assignments'
        $allAdministrativeTemplates = Invoke-MSGraphRequest -Url $uri | Get-MSGraphAllPages
        $appliedAdministrativeTemplate = $allAdministrativeTemplates | _isApplied
    }

    # Security Baselines, Antivirus policies, Defender policies, Disk Encryption policies, Account Protection policies, Local User Group Membership, Firewall, Endpoint detection and response, Attack surface reduction
    if ($assignmentType -contains 'endpointSecurity') {
        Write-Verbose "Processing Endpoint Security policies"
        $allEndpointSecurityPolicies = Get-IntuneSecurityPolicy
        $appliedEndpointSecurityPolicy = $allEndpointSecurityPolicies | _isApplied
    }

    # Windows Autopilot Deployment profile
    if ($assignmentType -contains 'windowsAutopilotDeploymentProfiles') {
        Write-Verbose "Processing Windows Autopilot Deployment profile"
        $uri = 'https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeploymentProfiles?$expand=Assignments'
        $allWindowsAutopilotDeploymentProfiles = Invoke-MSGraphRequest -Url $uri | Get-MSGraphAllPages
        $appliedWindowsAutopilotDeploymentProfile = $allWindowsAutopilotDeploymentProfiles | _isApplied
    }

    # ESP, WHFB, Enrollment Limit, Enrollment Platform Restrictions configurations
    if ($assignmentType -contains 'deviceEnrollmentConfigurations') {
        Write-Verbose "Processing ESP, WHFB, Enrollment Limit, Enrollment Platform Restrictions configurations"
        $uri = 'https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations?$expand=Assignments'
        $allDeviceEnrollmentConfigurations = Invoke-MSGraphRequest -Url $uri | Get-MSGraphAllPages
        $appliedDeviceEnrollmentConfiguration = $allDeviceEnrollmentConfigurations | _isApplied
    }

    # Windows Feature Update profiles
    if ($assignmentType -contains 'windowsFeatureUpdateProfiles') {
        Write-Verbose "Processing Windows Feature Update profiles"
        $uri = 'https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles?$expand=Assignments'
        $allWindowsFeatureUpdateProfiles = Invoke-MSGraphRequest -Url $uri | Get-MSGraphAllPages
        $appliedWindowsFeatureUpdateProfile = $allWindowsFeatureUpdateProfiles | _isApplied
    }

    # Windows Quality Update profiles
    if ($assignmentType -contains 'windowsQualityUpdateProfiles') {
        Write-Verbose "Processing Windows Quality Update profiles"
        $uri = 'https://graph.microsoft.com/beta/deviceManagement/windowsQualityUpdateProfiles?$expand=Assignments'
        $allWindowsQualityUpdateProfiles = Invoke-MSGraphRequest -Url $uri | Get-MSGraphAllPages
        $appliedWindowsQualityUpdateProfile = $allWindowsQualityUpdateProfiles | _isApplied
    }

    # Update rings for Windows 10 and later should be part of configurationPolicy

    # https://learn.microsoft.com/en-us/graph/api/resources/intune-shared-devicemanagement?view=graph-rest-beta
    # 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies' = = Settings Catalog
    # 'https://graph.microsoft.com/beta/deviceManagement/enrollmentProfiles' = = MacOs enrollment profil? ale nic nevraci!

    # MAM Android
    # Get-IntuneAppProtectionPolicyAndroid
    # https://www.powershellgallery.com/packages/IntuneDocumentation/2.0.19/Content/Internal%5CGet-MAM_Android_Assignment.ps1

    # MAM iOS
    # Get-IntuneAppProtectionPolicyIos
    # https://www.powershellgallery.com/packages/IntuneDocumentation/2.0.19/Content/Internal%5CGet-MAM_iOS_Assignment.ps1

    # MAM Windows
    # https://www.powershellgallery.com/packages/IntuneDocumentation/2.0.19/Content/Internal%5CGet-MAM_Windows_Assignment.ps1

    # Managed App Config Assignments
    # https://www.powershellgallery.com/packages/IntuneDocumentation/2.0.19/Content/Internal%5CGet-ManagedAppConfig_Assignment.ps1

    # Get-IntuneWindowsInformationProtectionPolicy
    #endregion get assignment

    #region output result
    if ($accountId) {
        $resultProperty = [ordered]@{
            ObjectType    = $objectType
            ObjectId      = $accountId
            DisplayName   = $accountObj.DisplayName
            MemberOfGroup = $accountMemberOfGroup | select DisplayName, ObjectId
        }
    } else {
        $resultProperty = [PSCustomObject]@{}
    }

    $resultProperty.AppAssignment = $appliedApp
    $resultProperty.CompliancePolicyAssignment = $appliedCompliancePolicy
    $resultProperty.ConfigurationPolicyAssignment = $appliedDeviceConfigPolicy
    $resultProperty.DeviceConfigPSHScriptAssignment = $appliedDeviceConfigPSHScript
    $resultProperty.DeviceConfigShellScriptAssignment = $appliedDeviceConfigShellScript
    $resultProperty.AdministrativeTemplateAssignment = $appliedAdministrativeTemplate
    $resultProperty.EndpointSecurityPolicyAssignment = $appliedEndpointSecurityPolicy
    $resultProperty.WindowsAutopilotDeploymentProfileAssignment = $appliedWindowsAutopilotDeploymentProfile
    $resultProperty.DeviceEnrollmentConfigurationAssignment = $appliedDeviceEnrollmentConfiguration
    $resultProperty.WindowsFeatureUpdateProfileAssignment = $appliedWindowsFeatureUpdateProfile
    $resultProperty.WindowsQualityUpdateProfilesAssignment = $appliedWindowsQualityUpdateProfile

    New-Object -TypeName PSCustomObject -Property $resultProperty
    #endregion output result
}
Connect-AzureAD
$fullpolicies = @()
Get-MgGroup -All $true | Select-object ID, DisplayName, Description | Out-GridView -PassThru -Title "Select Azure AD Groups" | ForEach-Object {
    $ID = $_.id
    write-host $ID
    $assignments = Get-IntuneAssignment -accountId $ID
    $scripts = ($assignments.DeviceConfigPSHScriptAssignment) | Select-Object DisplayName, Description, @{N='Type';E={"Script"}}
    foreach ($script in $scripts) {
        $fullpolicies += $script
    }
    $config = ($assignments.ConfigurationPolicyAssignment) | Select-Object DisplayName, Description, @{N='Type';E={"Config Policy"}}
    foreach ($conf in $config) {
        $fullpolicies += $conf
    }
    $security = ($assignments.EndpointSecurityPolicyAssignment) | Select-Object DisplayName, Description, @{N='Type';E={"Security Policy"}}
    foreach ($sec in $security) {
        $fullpolicies += $sec
    }
    $autopilot = ($assignments.WindowsAutopilotDeploymentProfileAssignment) | Select-Object DisplayName, Description, @{N='Type';E={"Autopilot Profile"}}
    foreach ($auto in $autopilot) {
        $fullpolicies += $auto
    }
    $enrollment = ($assignments.DeviceEnrollmentConfigurationAssignment) | Select-Object DisplayName, Description, @{N='Type';E={"Enrollment Config"}}
    foreach ($enroll in $enrollment) {
        $fullpolicies += $enroll
    }
    $feature = ($assignments.WindowsFeatureUpdateProfileAssignment) | Select-Object DisplayName, Description, @{N='Type';E={"Feature Update"}}
    foreach ($feat in $feature) {
        $fullpolicies += $feat
    }
    $quality = ($assignments.WindowsQualityUpdateProfilesAssignment) | Select-Object DisplayName, Description, @{N='Type';E={"Quality Update"}}
    foreach ($qual in $quality) {
        $fullpolicies += $qual
    }
    $compliance = ($assignments.CompliancePolicyAssignment) | Select-Object DisplayName, Description, @{N='Type';E={"Compliance Policy"}}
    foreach ($comp in $compliance) {
        $fullpolicies += $comp
    }
    $app = ($assignments.AppAssignment) | Select-Object DisplayName, Description, @{N='Type';E={"Application"}}
    foreach ($apps in $app) {
        $fullpolicies += $apps
    }
    $template = ($assignments.AdministrativeTemplateAssignment) | Select-Object DisplayName, Description, @{N='Type';E={"Admin Template"}}
    foreach ($tem in $template) {
        $fullpolicies += $tem
    }
    $shell = ($assignments.DeviceConfigShellScriptAssignment) | Select-Object DisplayName, Description, @{N='Type';E={"Shell Script"}}
    foreach ($sh in $shell) {
        $fullpolicies += $sh
    }
    $fullpolicies | Out-GridView
}
