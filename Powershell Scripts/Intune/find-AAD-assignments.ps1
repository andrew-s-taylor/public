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

# SIG # Begin signature block
# MIIoGQYJKoZIhvcNAQcCoIIoCjCCKAYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDbHN9l1uGHO3SC
# X3LCB7ozNJM9tJSo09SnQPnOqA3S/aCCIRwwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# gjcCARUwLwYJKoZIhvcNAQkEMSIEIMNLsqO6ykShR8OYc7g/tUepvHUsTvCXArFK
# oTqwprHwMA0GCSqGSIb3DQEBAQUABIICAGF8hFIDrrzsslphf+zELEprD13f2DYw
# EvwDuQEtHZY893kvalfJRY0iYFVV2x2xOf0pkejulWeK+7ZmYbfN5VbD1a5USr0V
# Ff3uv2/GhI0wUabxeFWdStCUt3Wse2u2n2RvCgUqQVXVQnQYmrh2HcmDlHUD33Js
# ULle7b2UdnsZDLks1V5mmyJgckGPlEFLo4fnI0lMTakQ9DluKYzUDETkCUudtpnM
# GavZKA8LrHgq+R40qd4e/xDr4ul5/fuMYTchPCZ6EUSCn6XZWGoe8n439CUPOyDY
# ZRe3NAv2mWmtoDVufaBxUZW83eEQAbvSvU2VMGakBHIYI6p4t+jPHd2n2y7QHd3u
# ALdc3kjGpWbgpXTD3BWoTZ4Ewv+UrhbFPfjsfpj8/b7ARYKMIgBo1unJBlUWJhaD
# oEJTuDdQ6k//h/ZVaNosB5NisadyFH69DLyb9sGB+4yb8Ihl7okQhHgYK/KhBC2N
# PKGOOJSJUO2jQnxErmNxHbMPAkbLTJKvXPGSeV/gOWo/pbeZ48xnUpxAghmnrZr3
# FMmu8PNEIBQddFd30ugXV/udX3rXSLNlDnWZJYCdxTELpDCu62K4OgV2ELDMUHFu
# hTowo3lcWny9TTqH5hAR1uv3VIvjX8BafICzTJ3poroCzl5GMOlC/XOOb/6Qh22I
# LctA1C0RXHxkoYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkG
# A1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdp
# Q2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQ
# BUSv85SdCDmmv9s/X+VhFjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzEL
# BgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIzMTExNTIwNDcyNFowLwYJKoZI
# hvcNAQkEMSIEIIRex/ibLxrt0V5SXgn73Z6S7dZ0sFPZi8zZ/pU1/ujxMA0GCSqG
# SIb3DQEBAQUABIICADgZiA8CMHYKps0KlXUYwnmvjoO8586AkbL/iyAJbSra1jDW
# Zfw25fNFhRAOXreD1PYDBuhpz75n6YKPlRkcBi/W+9P24JobR1tyAbkFje0AlFm3
# Qfk1qoleHOSFqc68y4u44uGzUMknVV1q7WoYFoT8snLtgcM1QwjrbIjjhxO1qFHg
# 0MEmCwdGcjuktqUkCdt6d94SAxVPwU+k982VuLgazkjwtWO8wrnmI7Q1EQdREy/b
# GnYbGucyccHXSg2ukQHOKWzkJrroRtZjGrI4ndYoAS3nrKX94dUEeVX2jfnLSaPF
# YlBGQ65JrqSUNfMseHBUjcf05AfOwmRvKe3VIlqv++OdoWwDHRMvnmvI082FTYZe
# UKrZPN7Ap0xyITd3xVNSMJ+YCjRERjPGdsm0jheydE59pIK4lyrEm9N9PUnViaI9
# 9TzXXqsLrfzJ19+fEtC4HPrVLLGTwaSMcjsKtWnbFcq6+aoMchbXcWFMNsNL3zEM
# K89l1KH0xru/5I+/fuDbu1u9bXmZ5/CJ/M4m9iLiYGoSUGYG7vAxOwgmf9blTAqz
# oH4ZeKSUJBKrM3Z1tSNqyOO2DdTiItY5PkkK94FFm1DvaYd6hYWSBAjtJBL+xOre
# fJ1fBAr+Z/tIXrQABeF7iXFVdMVWWAuytPsizFfi0+5e5N/LqPXj8XW/qRiH
# SIG # End signature block
