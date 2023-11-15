<#PSScriptInfo
.VERSION 2.0.6
.GUID 29d19c3c-8a33-4ada-a7a7-f39bfb439c1b
.AUTHOR AndrewTaylor
.DESCRIPTION Assigns everything within Intune with options to select.  Batch assignment to selected group of all policies, scripts and apps
.COMPANYNAME
.COPYRIGHT GPL
.TAGS intune endpoint MEM environment
.LICENSEURI https://github.com/andrew-s-taylor/public/blob/main/LICENSE
.PROJECTURI https://github.com/andrew-s-taylor/public
.ICONURI
.EXTERNALMODULEDEPENDENCIES microsoft.graph.intune, AzureADPreview
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
#>
<#
.SYNOPSIS
  Bulk Intune Assigment
.DESCRIPTION
Assigns everything within Intune with options to select.  Batch assignment to selected group of all policies, scripts and apps
.INPUTS
Runmode:
GUI to select AAD group and what to assign
.OUTPUTS
Within Azure
.NOTES
  Version:        2.0.6
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  23/03/2022
  Amended Date:   30/10/2022
  Purpose/Change: Initial script development
  Change: Added option to set apps as Required
  Change: Switched to Graph Authentication
.EXAMPLE
N/A
#>
$ErrorActionPreference = "Continue"

##Start Logging to %TEMP%\intune.log

$date = get-date -format ddMMyyyy

Start-Transcript -Path $env:TEMP\intune-$date.log

###############################################################################################################

######                                         Install Modules                                           ######

###############################################################################################################

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
Import-Module microsoft.graph.authentication  

###############################################################################################################
######                                          Add Functions                                            ######
###############################################################################################################

Function Get-DeviceConfigurationPolicy() { 
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

        $name

    )

   

    $graphApiVersion = "beta"

    $DCP_resource = "deviceManagement/deviceConfigurations"

   

    try {

   

        if ($Name) {

   

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)?`$filter=displayName eq '$name'"

            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value

   

        }

   

        else {

   

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"

            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value

   

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

   

####################################################

 

 

####################################################

   

Function Get-DeviceConfigurationPolicySC() {

   

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

        $name

    )

           

    $graphApiVersion = "beta"

    $DCP_resource = "deviceManagement/configurationPolicies"

           

    try {

           

        if ($Name) {

           

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)?`$filter=name eq '$name'"

                    (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value

           

        }

           

        else {

           

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"

                    (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value

           

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

           

####################################################

 

 

####################################################

   

Function Get-DeviceCompliancePolicy() {

   

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

        $name

    )

           

    $graphApiVersion = "beta"

    $DCP_resource = "deviceManagement/deviceCompliancePolicies"

           

    try {

           

        if ($Name) {

            

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)?`$filter=name eq '$name'"

                    (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value

           

        }

           

        else {

           

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"

                    (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value

            

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

           

 

Function Get-DeviceSecurityPolicy() {

   

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

        $name

    )

           

    $graphApiVersion = "beta"

    $DCP_resource = "deviceManagement/intents"

           

    try {

           

        if ($Name) {

           

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)?`$filter=name eq '$name'"

                    (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value

           

        }

           

        else {

           

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"

                    (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value

           

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

 

 

Function Get-DeviceManagementScripts() {

   

    <#

            .SYNOPSIS

            This function is used to get device management scripts from the Graph API REST interface

            .DESCRIPTION

            The function connects to the Graph API Interface and gets any device management scripts

            .EXAMPLE

            Get-DeviceManagementScripts

            Returns any device management scripts configured in Intune

            .NOTES

            NAME: Get-DeviceManagementScripts

            #>

           

    [cmdletbinding()]

           

    param

    (

        $name

    )

           

    $graphApiVersion = "beta"

    $DCP_resource = "deviceManagement/deviceManagementScripts"

           

    try {

           

        if ($Name) {

           

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)?`$filter=name eq '$name'"

                    (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value

           

        }

            

        else {

           

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"

                    (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value

           

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

           

####################################################

   

 

 

Function Get-AutoPilotProfile() {

   

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

        $name

    )

                

    $graphApiVersion = "beta"

    $DCP_resource = "deviceManagement/windowsAutopilotDeploymentProfiles"

               

    try {

               

        if ($Name) {

               

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)?`$filter=displayName eq '$name'"

                        (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value

               

        }

               

        else {

               

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"

                        (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value

               

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

               

####################################################      

 

 

Function Get-ESPConfiguration() {

   

    <#

                    .SYNOPSIS

                    This function is used to get ESP Configurations from the Graph API REST interface

                    .DESCRIPTION

                    The function connects to the Graph API Interface and gets any ESP Configurations

                    .EXAMPLE

                    Get-ESPConfiguration

                    Returns any ESP Configurations in Intune

                    .NOTES

                    NAME: Get-ESPConfiguration

                    #>

                   

    [cmdletbinding()]

                   

    param

    (

        $name

    )

                   

    $graphApiVersion = "beta"

    $DCP_resource = "devicemanagement/deviceEnrollmentConfigurations"

                   

    try {

                   

        if ($Name) {

                   

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)?`$filter=displayName eq '$name'"

                            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value

                   

        }

                    

        else {

                   

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"

                            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value

                   

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

                   

####################################################

Function Get-DeviceConfigurationPolicyAssignment() {

   

    <#

    .SYNOPSIS

    This function is used to get device configuration policy assignment from the Graph API REST interface

    .DESCRIPTION

    The function connects to the Graph API Interface and gets a device configuration policy assignment

    .EXAMPLE

    Get-DeviceConfigurationPolicyAssignment $id guid

    Returns any device configuration policy assignment configured in Intune

    .NOTES

    NAME: Get-DeviceConfigurationPolicyAssignment

    #>

   

    [cmdletbinding()]

   

    param

    (

        [Parameter(Mandatory = $true, HelpMessage = "Enter id (guid) for the Device Configuration Policy you want to check assignment")]

        $id

    )

   

    $graphApiVersion = "Beta"

    $DCP_resource = "deviceManagement/deviceConfigurations"

   

    try {

   

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id/groupAssignments"

        (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value

   

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

 

Function Get-DeviceConfigurationPolicyAssignmentSC() {

   

    <#

        .SYNOPSIS

        This function is used to get device configuration policy assignment from the Graph API REST interface - SETTINGS CATALOG Version

        .DESCRIPTION

        The function connects to the Graph API Interface and gets a device configuration policy assignment

        .EXAMPLE

        Get-DeviceConfigurationPolicyAssignmentSC $id guid

        Returns any device configuration policy assignment configured in Intune

        .NOTES

        NAME: Get-DeviceConfigurationPolicyAssignmentSC

        #>

       

    [cmdletbinding()]

       

    param

    (

        [Parameter(Mandatory = $true, HelpMessage = "Enter id (guid) for the Device Configuration Policy you want to check assignment")]

        $id

    )

       

    $graphApiVersion = "Beta"

    $DCP_resource = "deviceManagement/configurationPolicies"

       

    try {

       

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id/Assignments"

            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value

       

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

 

Function Add-DeviceManagementScriptAssignment() {

    <#

.SYNOPSIS

This function is used to add a device configuration policy assignment using the Graph API REST interface

.DESCRIPTION

The function connects to the Graph API Interface and adds a device configuration policy assignment

.EXAMPLE

Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $ConfigurationPolicyId -TargetGroupId $TargetGroupId

Adds a device configuration policy assignment in Intune

.NOTES

NAME: Add-DeviceConfigurationPolicyAssignment

#>

 

    [cmdletbinding()]

 

    param

    (

        $ScriptId,

        $TargetGroupId

    )

 

    $graphApiVersion = "Beta"

    $Resource = "deviceManagement/deviceManagementScripts/$ScriptId/assign"

 

    try {

 

        if (!$ScriptId) {

 

            write-host "No Script Policy Id specified, specify a valid Script Policy Id" -f Red

            break

 

        }

 

        if (!$TargetGroupId) {

 

            write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red

            break

 

        }

 

        $JSON = @"

{

    "deviceManagementScriptGroupAssignments":  [

        {

            "@odata.type":  "#microsoft.graph.deviceManagementScriptGroupAssignment",

            "targetGroupId": "$TargetGroupId",

            "id": "$ScriptId"

        }

    ]

}

"@

 

        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"

        Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType "application/json"

 

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

 

 

Function Get-DeviceCompliancePolicyAssignment() {

   

    <#

        .SYNOPSIS

        This function is used to get device compliance policy assignment from the Graph API REST interface

        .DESCRIPTION

        The function connects to the Graph API Interface and gets a device compliance policy assignment

        .EXAMPLE

        Get-DeviceCompliancePolicyAssignment $id guid

        Returns any device compliance policy assignment configured in Intune

        .NOTES

        NAME: Get-DeviceCompliancePolicyAssignment

        #>

       

    [cmdletbinding()]

       

    param

    (

        [Parameter(Mandatory = $true, HelpMessage = "Enter id (guid) for the Device Configuration Policy you want to check assignment")]

        $id

    )

       

    $graphApiVersion = "Beta"

    $DCP_resource = "deviceManagement/devicecompliancePolicies"

       

    try {

       

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id/assignments"

            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value

       

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

 

Function Get-DeviceSecurityPolicyAssignment() {

   

    <#

        .SYNOPSIS

        This function is used to get device security policy assignment from the Graph API REST interface

        .DESCRIPTION

        The function connects to the Graph API Interface and gets a device compliance policy assignment

        .EXAMPLE

        Get-DeviceSecurityPolicyAssignment $id guid

        Returns any device security policy assignment configured in Intune

        .NOTES

        NAME: Get-DeviceSecurityPolicyAssignment

        #>

       

    [cmdletbinding()]

       

    param

    (

        [Parameter(Mandatory = $true, HelpMessage = "Enter id (guid) for the Device Security Policy you want to check assignment")]

        $id

    )

       

    $graphApiVersion = "Beta"

    $DCP_resource = "deviceManagement/intents"

       

    try {

       

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id/Assignments"

            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value

       

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

   

####################################################

 

 

Function Get-AutoPilotProfileAssignments() {

   

    <#

        .SYNOPSIS

        This function is used to get AutoPilot Profile assignment from the Graph API REST interface

        .DESCRIPTION

        The function connects to the Graph API Interface and gets an Autopilot profile assignment

        .EXAMPLE

        Get-AutoPilotProfileAssignments $id guid

        Returns any autopilot profile assignment configured in Intune

        .NOTES

        NAME: Get-AutoPilotProfileAssignments

        #>

       

    [cmdletbinding()]

       

    param

    (

        [Parameter(Mandatory = $true, HelpMessage = "Enter id (guid) for the Autopilot Profile you want to check assignment")]

        $id

    )

       

    $graphApiVersion = "Beta"

    $DCP_resource = "deviceManagement/windowsAutopilotDeploymentProfiles"

       

    try {

       

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id/Assignments"

            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value

       

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

   

####################################################

   

Function Add-DeviceConfigurationPolicyAssignment() {

   

    <#

    .SYNOPSIS

    This function is used to add a device configuration policy assignment using the Graph API REST interface

    .DESCRIPTION

    The function connects to the Graph API Interface and adds a device configuration policy assignment

    .EXAMPLE

    Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $ConfigurationPolicyId -TargetGroupId $TargetGroupId

    Adds a device configuration policy assignment in Intune

    .NOTES

    NAME: Add-DeviceConfigurationPolicyAssignment

    #>

   

    [cmdletbinding()]

   

    param

    (

        [parameter(Mandatory = $true)]

        [ValidateNotNullOrEmpty()]

        $ConfigurationPolicyId,

   

        [parameter(Mandatory = $true)]

        [ValidateNotNullOrEmpty()]

        $TargetGroupId,

   

        [parameter(Mandatory = $true)]

        [ValidateSet("Included", "Excluded")]

        [ValidateNotNullOrEmpty()]

        [string]$AssignmentType

    )

   

    $graphApiVersion = "Beta"

    $Resource = "deviceManagement/deviceConfigurations/$ConfigurationPolicyId/assign"

       

    try {

   

        if (!$ConfigurationPolicyId) {

   

            write-host "No Configuration Policy Id specified, specify a valid Configuration Policy Id" -f Red

            break

   

        }

   

        if (!$TargetGroupId) {

   

            write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red

            break

   

        }

   

        # Checking if there are Assignments already configured in the Policy

        $DCPA = Get-DeviceConfigurationPolicyAssignment -id $ConfigurationPolicyId

   

        $TargetGroups = @()

   

        if (@($DCPA).count -ge 1) {

               

            if ($DCPA.targetGroupId -contains $TargetGroupId) {

   

                Write-Host "Group with Id '$TargetGroupId' already assigned to Policy..." -ForegroundColor Red

                Write-Host

               

    

            }

   

            # Looping through previously configured assignements

   

            $DCPA | foreach {

   

                $TargetGroup = New-Object -TypeName psobject

        

                if ($_.excludeGroup -eq $true) {

   

                    $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'

        

                }

        

                else {

        

                    $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'

        

                }

   

                $TargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value $_.targetGroupId

   

                $Target = New-Object -TypeName psobject

                $Target | Add-Member -MemberType NoteProperty -Name 'target' -Value $TargetGroup

   

                $TargetGroups += $Target

   

            }

   

            # Adding new group to psobject

            $TargetGroup = New-Object -TypeName psobject

   

            if ($AssignmentType -eq "Excluded") {

   

                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'

        

            }

        

            elseif ($AssignmentType -eq "Included") {

        

                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'

        

            }

        

            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value "$TargetGroupId"

   

            $Target = New-Object -TypeName psobject

            $Target | Add-Member -MemberType NoteProperty -Name 'target' -Value $TargetGroup

   

            $TargetGroups += $Target

   

        }

   

        else {

   

            # No assignments configured creating new JSON object of group assigned

               

            $TargetGroup = New-Object -TypeName psobject

   

            if ($AssignmentType -eq "Excluded") {

   

                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'

        

            }

        

            elseif ($AssignmentType -eq "Included") {

        

                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'

        

            }

        

            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value "$TargetGroupId"

   

            $Target = New-Object -TypeName psobject

            $Target | Add-Member -MemberType NoteProperty -Name 'target' -Value $TargetGroup

   

            $TargetGroups = $Target

   

        }

   

        # Creating JSON object to pass to Graph

        $Output = New-Object -TypeName psobject

   

        $Output | Add-Member -MemberType NoteProperty -Name 'assignments' -Value @($TargetGroups)

   

        $JSON = $Output | ConvertTo-Json -Depth 3

   

        # POST to Graph Service

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"

        Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType "application/json"

   

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

 

Function Add-DeviceConfigurationPolicyAssignmentSC() {

   

    <#

        .SYNOPSIS

        This function is used to add a device configuration policy assignment using the Graph API REST interface  Settings Catalog

        .DESCRIPTION

        The function connects to the Graph API Interface and adds a device configuration policy assignment

        .EXAMPLE

        Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $ConfigurationPolicyId -TargetGroupId $TargetGroupId

        Adds a device configuration policy assignment in Intune

        .NOTES

        NAME: Add-DeviceConfigurationPolicyAssignment

        #>

       

    [cmdletbinding()]

       

    param

    (

        [parameter(Mandatory = $true)]

        [ValidateNotNullOrEmpty()]

        $ConfigurationPolicyId,

        

        [parameter(Mandatory = $true)]

        [ValidateNotNullOrEmpty()]

        $TargetGroupId,

       

        [parameter(Mandatory = $true)]

        [ValidateSet("Included", "Excluded")]

        [ValidateNotNullOrEmpty()]

        [string]$AssignmentType

    )

       

    $graphApiVersion = "Beta"

    $Resource = "deviceManagement/configurationPolicies/$ConfigurationPolicyId/assign"

           

    try {

       

        if (!$ConfigurationPolicyId) {

       

            write-host "No Configuration Policy Id specified, specify a valid Configuration Policy Id" -f Red

            break

       

        }

       

        if (!$TargetGroupId) {

       

            write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red

            break

       

        }

       

        # Checking if there are Assignments already configured in the Policy

        $DCPA = Get-DeviceConfigurationPolicyAssignmentSC -id $ConfigurationPolicyId

       

        $TargetGroups = @()

       

        if (@($DCPA).count -ge 1) {

                   

            if ($DCPA.targetGroupId -contains $TargetGroupId) {

       

                Write-Host "Group with Id '$TargetGroupId' already assigned to Policy..." -ForegroundColor Red

                Write-Host

                   

        

            }

       

            # Looping through previously configured assignements

       

            $DCPA | foreach {

       

                $TargetGroup = New-Object -TypeName psobject

            

                if ($_.excludeGroup -eq $true) {

       

                    $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'

            

                }

            

                else {

            

                    $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'

            

                }

       

                $TargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value $_.targetGroupId

       

                $Target = New-Object -TypeName psobject

                $Target | Add-Member -MemberType NoteProperty -Name 'target' -Value $TargetGroup

       

                $TargetGroups += $Target

       

            }

       

            # Adding new group to psobject

            $TargetGroup = New-Object -TypeName psobject

       

            if ($AssignmentType -eq "Excluded") {

       

                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'

            

            }

            

            elseif ($AssignmentType -eq "Included") {

            

                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'

            

            }

            

            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value "$TargetGroupId"

       

            $Target = New-Object -TypeName psobject

            $Target | Add-Member -MemberType NoteProperty -Name 'target' -Value $TargetGroup

       

            $TargetGroups += $Target

       

        }

       

        else {

       

            # No assignments configured creating new JSON object of group assigned

                   

            $TargetGroup = New-Object -TypeName psobject

       

            if ($AssignmentType -eq "Excluded") {

       

                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'

            

            }

            

            elseif ($AssignmentType -eq "Included") {

            

                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'

            

            }

            

            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value "$TargetGroupId"

       

            $Target = New-Object -TypeName psobject

            $Target | Add-Member -MemberType NoteProperty -Name 'target' -Value $TargetGroup

       

            $TargetGroups = $Target

       

        }

       

        # Creating JSON object to pass to Graph

        $Output = New-Object -TypeName psobject

       

        $Output | Add-Member -MemberType NoteProperty -Name 'assignments' -Value @($TargetGroups)

       

        $JSON = $Output | ConvertTo-Json -Depth 3

       

        # POST to Graph Service

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"

        Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType "application/json"

       

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

 

   

 

Function Add-DeviceCompliancePolicyAssignment() {

 

    <#

.SYNOPSIS

This function is used to add a device compliance policy assignment using the Graph API REST interface

.DESCRIPTION

The function connects to the Graph API Interface and adds a device compliance policy assignment

.EXAMPLE

Add-DeviceCompliancePolicyAssignment -CompliancePolicyId $CompliancePolicyId -TargetGroupId $TargetGroupId

Adds a device compliance policy assignment in Intune

.NOTES

NAME: Add-DeviceCompliancePolicyAssignment

#>

 

    [cmdletbinding()]

 

    param

    (

        $CompliancePolicyId,

        $TargetGroupId

    )

 

    $graphApiVersion = "v1.0"

    $Resource = "deviceManagement/deviceCompliancePolicies/$CompliancePolicyId/assign"

   

    try {

 

        if (!$CompliancePolicyId) {

 

            write-host "No Compliance Policy Id specified, specify a valid Compliance Policy Id" -f Red

            break

 

        }

 

        if (!$TargetGroupId) {

 

            write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red

            break

 

        }

 

        $JSON = @"

    {

        "assignments": [

        {

            "target": {

            "@odata.type": "#microsoft.graph.groupAssignmentTarget",

            "groupId": "$TargetGroupId"

            }

        }

        ]

    }

   

"@

 

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"

        Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType "application/json"

 

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

 

 

 

Function Add-ESPAssignment() {

 

    <#

    .SYNOPSIS

    This function is used to add an ESP policy assignment using the Graph API REST interface

    .DESCRIPTION

    The function connects to the Graph API Interface and adds an ESP policy assignment

    .EXAMPLE

    Add-ESPAssignment -Id $Id -TargetGroupId $TargetGroupId

    .NOTES

    NAME: Add-ESPAssignment

    #>

   

    [cmdletbinding()]

   

    param

    (

        $Id,

        $TargetGroupId

    )

   

    $graphApiVersion = "beta"

    $Resource = "deviceManagement/deviceEnrollmentConfigurations"       

        

    try {

   

        if (!$id) {

   

            write-host "No ESP Policy Id specified, specify a valid ESP Policy Id" -f Red

            break

   

        }

   

        if (!$TargetGroupId) {

   

            write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red

            break

   

        }

   

        $json = @"

            {

                "enrollmentConfigurationAssignments": [

                    {

                        "target": {

                            "@odata.type": "#microsoft.graph.groupAssignmentTarget",

                            "groupId": "$TargetGroupId"

                        }

                    }

                ]

            }

"@

   

        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$id/assign"

        Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType "application/json"

   

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

 
Function Add-DeviceSecurityPolicyAssignment() {

 

    <#

    .SYNOPSIS

    This function is used to add a Security policy assignment using the Graph API REST interface

    .DESCRIPTION

    The function connects to the Graph API Interface and adds a Security policy assignment

    .EXAMPLE

    Add-DeviceSecurityPolicyAssignment -Id $Id -TargetGroupId $TargetGroupId

    .NOTES

    NAME: Add-DeviceSecurityPolicyAssignment

    #>

   

    [cmdletbinding()]

   

    param

    (

        $Id,

        $TargetGroupId

    )

   

    $graphApiVersion = "beta"

    $Resource = "deviceManagement/intents/$Id/assign"       

        

    try {

   

        if (!$id) {

   

            write-host "No Security Policy Id specified, specify a valid Security Policy Id" -f Red

            break

   

        }

   

        if (!$TargetGroupId) {

   

            write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red

            break

   

        }

   

        $JSON = @"

            {
        
                "assignments": [
        
                {
        
                    "target": {
        
                    "@odata.type": "#microsoft.graph.groupAssignmentTarget",
        
                    "groupId": "$TargetGroupId"
        
                    }
        
                }
        
                ]
        
            }
        
           
"@

   

        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"

        Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType "application/json"

   

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

Function Add-ESPAssignment() {

 

    <#
    
        .SYNOPSIS
    
        This function is used to add an ESP policy assignment using the Graph API REST interface
    
        .DESCRIPTION
    
        The function connects to the Graph API Interface and adds an ESP policy assignment
    
        .EXAMPLE
    
        Add-ESPAssignment -Id $Id -TargetGroupId $TargetGroupId
    
        .NOTES
    
        NAME: Add-ESPAssignment
    
        #>
    
       
    
    [cmdletbinding()]
    
       
    
    param
    
    (
    
        $Id,
    
        $TargetGroupId
    
    )
    
       
    
    $graphApiVersion = "beta"
    
    $Resource = "deviceManagement/deviceEnrollmentConfigurations"       
    
            
    
    try {
    
       
    
        if (!$id) {
    
       
    
            write-host "No ESP Policy Id specified, specify a valid ESP Policy Id" -f Red
    
            break
    
       
    
        }
    
       
    
        if (!$TargetGroupId) {
    
       
    
            write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red
    
            break
    
       
    
        }
    
       
    
        $json = @"
    
                {
    
                    "enrollmentConfigurationAssignments": [
    
                        {
    
                            "target": {
    
                                "@odata.type": "#microsoft.graph.groupAssignmentTarget",
    
                                "groupId": "$TargetGroupId"
    
                            }
    
                        }
    
                    ]
    
                }
    
"@
    
       
    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$id/assign"
    
        Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType "application/json"
    
       
    
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
    
Function Add-AutoPilotProfileAssignment() {

   

    <#

        .SYNOPSIS

        This function is used to add an autopilot profile assignment using the Graph API REST interface

        .DESCRIPTION

        The function connects to the Graph API Interface and adds an autopilot profile assignment

        .EXAMPLE

        Add-AutoPilotProfileAssignment -Id $ConfigurationPolicyId -TargetGroupId $TargetGroupId

        Adds a device configuration policy assignment in Intune

        .NOTES

        NAME: Add-AutoPilotProfileAssignment

        #>

       

    [cmdletbinding()]
    param
    
    (
    
        $Id,
    
        $TargetGroupId
    
    )

    $graphApiVersion = "beta"
    $Resource = "deviceManagement/windowsAutopilotDeploymentProfiles"        
    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$id/assignments"        
    
   
    $full_assignment_id = $Id + "_" + $TargetGroupId + "_0" 
    
    $json = @"
    {
        "id": "$full_assignment_id",
        "target": {
            "@odata.type": "#microsoft.graph.groupAssignmentTarget",
            "groupId": "$TargetGroupId"
        }
    }
"@
    
    Write-Verbose "POST $uri`n$json"
    
    try {
        Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType "application/json"
    }
    catch {
        Write-Error $_.Exception 
                
    }

        

  
}

 

 

Function Add-ApplicationAssignment() {

 

    <#

.SYNOPSIS

This function is used to add an application assignment using the Graph API REST interface

.DESCRIPTION

The function connects to the Graph API Interface and adds a application assignment

.EXAMPLE

Add-ApplicationAssignment -ApplicationId $ApplicationId -TargetGroupId $TargetGroupId -InstallIntent $InstallIntent

Adds an application assignment in Intune

.NOTES

NAME: Add-ApplicationAssignment

#>

 

    [cmdletbinding()]

 

    param

    (

        $ApplicationId,

        $TargetGroupId,

        $InstallIntent

    )

 

    $graphApiVersion = "Beta"

    $Resource = "deviceAppManagement/mobileApps/$ApplicationId/assign"

   

    try {

 

        if (!$ApplicationId) {

 

            write-host "No Application Id specified, specify a valid Application Id" -f Red

            break

 

        }

 

        if (!$TargetGroupId) {

 

            write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red

            break

 

        }

 

       

        if (!$InstallIntent) {

 

            write-host "No Install Intent specified, specify a valid Install Intent - available, notApplicable, required, uninstall, availableWithoutEnrollment" -f Red

            break

 

        }

 

        $JSON = @"

{

    "mobileAppAssignments": [

    {

        "@odata.type": "#microsoft.graph.mobileAppAssignment",

        "target": {

        "@odata.type": "#microsoft.graph.groupAssignmentTarget",

        "groupId": "$TargetGroupId"

        },

        "intent": "$InstallIntent"

    }

    ]

}

"@

 

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"

        Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType "application/json"

 

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

 

 

 

Function Get-IntuneApplication() {

 

    <#

.SYNOPSIS

This function is used to get applications from the Graph API REST interface

.DESCRIPTION

The function connects to the Graph API Interface and gets any applications added

.EXAMPLE

Get-IntuneApplication

.NOTES

NAME: Get-IntuneApplication

#>

 

    [cmdletbinding()]

 

    $graphApiVersion = "Beta"

    $Resource = "deviceAppManagement/mobileApps"

   

    try {

       

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"

    (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value

 

    }

   

    catch {

 

        $ex = $_.Exception

        Write-Host "Request to $Uri failed with HTTP Status $([int]$ex.Response.StatusCode) $($ex.Response.StatusDescription)" -f Red

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

######                                          Launch Form                                              ######

###############################################################################################################
#Connect to Graph
Connect-ToGraph -Scopes "RoleAssignmentSchedule.ReadWrite.Directory, Domain.Read.All, Domain.ReadWrite.All, Directory.Read.All, Policy.ReadWrite.ConditionalAccess, DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, openid, profile, email, offline_access"


 
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

$Form = New-Object system.Windows.Forms.Form
$Form.ClientSize = New-Object System.Drawing.Point(400, 686)
$Form.text = "Form"
$Form.TopMost = $false

$Label1 = New-Object system.Windows.Forms.Label
$Label1.text = "Select Azure AD group"
$Label1.AutoSize = $true
$Label1.width = 25
$Label1.height = 10
$Label1.location = New-Object System.Drawing.Point(16, 73)
$Label1.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10)

$aad = New-Object system.Windows.Forms.ComboBox
$aad.text = "AADGroup"
$aad.width = 201
$aad.height = 20
$aad.location = New-Object System.Drawing.Point(170, 69)
$aadgroups = get-mggroup -All | select-object DisplayName
ForEach ($aadgroup in $aadgroups) {
    $aad.Items.Add($aadgroup.DisplayName) 
}
$aad.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10)

$Label2 = New-Object system.Windows.Forms.Label
$Label2.text = "What would you like to assign?"
$Label2.AutoSize = $true
$Label2.width = 25
$Label2.height = 10
$Label2.location = New-Object System.Drawing.Point(89, 110)
$Label2.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 12)

$Submit = New-Object system.Windows.Forms.Button
$Submit.text = "Assign"
$Submit.width = 60
$Submit.height = 30
$Submit.location = New-Object System.Drawing.Point(161, 641)
$Submit.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10)

$config = New-Object system.Windows.Forms.CheckBox
$config.text = "Config Policies"
$config.AutoSize = $false
$config.width = 200
$config.height = 20
$config.location = New-Object System.Drawing.Point(32, 155)
$config.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10)

$settings = New-Object system.Windows.Forms.CheckBox
$settings.text = "Settings Catalog"
$settings.AutoSize = $false
$settings.width = 200
$settings.height = 20
$settings.location = New-Object System.Drawing.Point(34, 190)
$settings.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10)

$compliance = New-Object system.Windows.Forms.CheckBox
$compliance.text = "Compliance Policies"
$compliance.AutoSize = $false
$compliance.width = 200
$compliance.height = 20
$compliance.location = New-Object System.Drawing.Point(34, 223)
$compliance.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10)

$security = New-Object system.Windows.Forms.CheckBox
$security.text = "Security Policies"
$security.AutoSize = $false
$security.width = 200
$security.height = 20
$security.location = New-Object System.Drawing.Point(34, 260)
$security.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10)

$scripts = New-Object system.Windows.Forms.CheckBox
$scripts.text = "Scripts"
$scripts.AutoSize = $false
$scripts.width = 200
$scripts.height = 20
$scripts.location = New-Object System.Drawing.Point(32, 297)
$scripts.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10)

$autopilot = New-Object system.Windows.Forms.CheckBox
$autopilot.text = "AutoPilot Profiles"
$autopilot.AutoSize = $false
$autopilot.width = 200
$autopilot.height = 20
$autopilot.location = New-Object System.Drawing.Point(34, 331)
$autopilot.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10)

$esp = New-Object system.Windows.Forms.CheckBox
$esp.text = "Enrollment Status Pages"
$esp.AutoSize = $false
$esp.width = 200
$esp.height = 20
$esp.location = New-Object System.Drawing.Point(34, 364)
$esp.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10)

$windows = New-Object system.Windows.Forms.CheckBox
$windows.text = "Windows Apps"
$windows.AutoSize = $false
$windows.width = 200
$windows.height = 20
$windows.location = New-Object System.Drawing.Point(34, 397)
$windows.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10)

$macos = New-Object system.Windows.Forms.CheckBox
$macos.text = "MacOS Apps"
$macos.AutoSize = $false
$macos.width = 200
$macos.height = 20
$macos.location = New-Object System.Drawing.Point(34, 429)
$macos.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10)

$android = New-Object system.Windows.Forms.CheckBox
$android.text = "Android Apps"
$android.AutoSize = $false
$android.width = 200
$android.height = 20
$android.location = New-Object System.Drawing.Point(34, 502)
$android.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10)

$ios = New-Object system.Windows.Forms.CheckBox
$ios.text = "iOS Apps"
$ios.AutoSize = $false
$ios.width = 200
$ios.height = 20
$ios.location = New-Object System.Drawing.Point(34, 464)
$ios.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10)

$Ewfewijpeqwj = New-Object system.Windows.Forms.Label
$Ewfewijpeqwj.text = "Enter your email for AzureAD and Graph"
$Ewfewijpeqwj.AutoSize = $true
$Ewfewijpeqwj.width = 25
$Ewfewijpeqwj.height = 10
$Ewfewijpeqwj.location = New-Object System.Drawing.Point(17, 15)
$Ewfewijpeqwj.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10)

$email = New-Object system.Windows.Forms.TextBox
$email.multiline = $false
$email.width = 309
$email.height = 20
$email.location = New-Object System.Drawing.Point(50, 36)
$email.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10)

$Label3 = New-Object system.Windows.Forms.Label
$Label3.text = "Application Assignment Type:"
$Label3.AutoSize = $true
$Label3.width = 25
$Label3.height = 10
$Label3.location = New-Object System.Drawing.Point(31, 543)
$Label3.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10)

$ComboBox1 = New-Object system.Windows.Forms.ComboBox
$ComboBox1.text = "Available"
$ComboBox1.width = 100
$ComboBox1.height = 20
@('Required', 'Available') | ForEach-Object { [void] $ComboBox1.Items.Add($_) }
$ComboBox1.location = New-Object System.Drawing.Point(127, 572)
$ComboBox1.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10)

$Form.controls.AddRange(@($Label1, $aad, $Label2, $Submit, $config, $settings, $compliance, $security, $scripts, $autopilot, $esp, $windows, $macos, $android, $ios, $Ewfewijpeqwj, $email, $Label3, $ComboBox1))

$Submit.Add_Click({ 
 
   

 

 

 

 

        ###############################################################################################################

        ######                                          Group Details                                           ######

        ###############################################################################################################


        ##Get Group ID


        $aadgroup2 = $aad.SelectedItem
        $intunegrp = Get-MgGroup -Filter "DisplayName eq '$aadgroup2'" | Select-Object Id, DisplayName
 

        ###############################################################################################################

        ######                                          MS Graph Implementations                                 ######

        ###############################################################################################################



        ###############################################################################################################

        ######                                          Assign Everything                                        ######

        ###############################################################################################################

        $assignmenttype = $comboBox1.SelectedItem
 

        ##Anything to Ignore, Add here

        $dontuse = ""

 

 
        if ($config.checked -eq $True) {
            ##Assign Config Policies

            $configuration = Get-DeviceConfigurationPolicy

 

            foreach ($policy in $configuration) {

                if ($dontuse.contains($policy.displayName )) {

 

                    write-host "NOT Assigning" + $policy.displayName

 

                }

                else {

                    Write-Host "Assigned $($intunegrp.DisplayName) to $($policy.displayName)/$($policy.id)" -ForegroundColor Green

 

                    Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $policy.id -TargetGroupId $intunegrp.Id -AssignmentType Included

                }

 

            }
            Add-Type -AssemblyName PresentationCore, PresentationFramework
            $msgBody = "Config Policies Assigned"
            [System.Windows.MessageBox]::Show($msgBody)   
 
        }
 

 
        if ($settings.checked -eq $True) {
            ##Assign Settings Catalog Policies

            $configurationsc = Get-DeviceConfigurationPolicySC

 

            foreach ($policy in $configurationsc) {

                if ($dontuse.contains($policy.name )) {

                    write-host "NOT Assigning" + $policy.name

 

                }

                else {

                    Write-Host "Assigned $($intunegrp.DisplayName) to $($policy.displayName)/$($policy.id)" -ForegroundColor Green

 

                    Add-DeviceConfigurationPolicyAssignmentSC -ConfigurationPolicyId $policy.id -TargetGroupId $intunegrp.Id -AssignmentType Included
  
                }

 

            }
            Add-Type -AssemblyName PresentationCore, PresentationFramework
            $msgBody = "Settings Catalog Assigned"
            [System.Windows.MessageBox]::Show($msgBody) 
        }
 

 
        if ($compliance.checked -eq $True) {
            ##Assign Compliance Policies

            $compliance = Get-DeviceCompliancePolicy

 

            foreach ($policy in $compliance) {

                if ($dontuse.contains($policy.displayName )) {

                    write-host "NOT Assigning" + $policy.displayName

 

                }

                else {

                    Write-Host "Assigned $($intunegrp.DisplayName) to $($policy.displayName)/$($policy.id)" -ForegroundColor Green

                    Add-DeviceCompliancePolicyAssignment -CompliancePolicyId $policy.id -TargetGroupId $intunegrp.Id

                }

 

            }
            Add-Type -AssemblyName PresentationCore, PresentationFramework
            $msgBody = "Compliance Policies Assigned"
            [System.Windows.MessageBox]::Show($msgBody)   
        }
 

        if ($security.checked -eq $True) {
            ##Assign Security Policies

            $security = Get-DeviceSecurityPolicy

 

            foreach ($policy in $security) {

                if ($dontuse.contains($policy.displayName )) {

                    write-host "NOT Assigning" + $policy.displayName

 

                }

                else {

                    Write-Host "Assigned $($intunegrp.DisplayName) to $($policy.displayName)/$($policy.id)" -ForegroundColor Green

                    Add-DeviceSecurityPolicyAssignment -Id $policy.id -TargetGroupId $intunegrp.Id
  
                }

 

            }
            Add-Type -AssemblyName PresentationCore, PresentationFramework
            $msgBody = "Security Policies Assigned"
            [System.Windows.MessageBox]::Show($msgBody) 
        }
 

 
        if ($scripts.checked -eq $True) {
            ##Assign Scripts

            $scripts = Get-DeviceManagementScripts

 

            foreach ($script in $scripts) {

                if ($dontuse.contains($script.displayName )) {

                    write-host "NOT Assigning" + $script.displayName

 

                }

                else {

                    Write-Host "Assigned $($intunegrp.DisplayName) to $($script.displayName)/$($script.id)" -ForegroundColor Green

                    Add-DeviceManagementScriptAssignment -ScriptId $script.id -TargetGroupId $intunegrp.Id
  
                }

 

            }
            Add-Type -AssemblyName PresentationCore, PresentationFramework
            $msgBody = "Scripts Assigned"
            [System.Windows.MessageBox]::Show($msgBody) 
        }
 

 
        if ($autopilot.checked -eq $True) {
            ##Assign Autopilot Profile

            $approfiles = Get-AutoPilotProfile

            foreach ($approfile in $approfiles) {
                Add-AutoPilotProfileAssignment -Id $approfile.id -TargetGroupId $intunegrp.Id
                Write-Host "Assigned $($intunegrp.DisplayName) to $($approfile.displayName)/$($approfile.id)" -ForegroundColor Green
 
            }
            Add-Type -AssemblyName PresentationCore, PresentationFramework
            $msgBody = "Autopilot Profiles Assigned"
            [System.Windows.MessageBox]::Show($msgBody)  
        }
 

 
        if ($esp.Checked -eq $True) {
            ##Assign ESP

            $espprofiles = Get-ESPConfiguration

            foreach ($espprofile in $espprofiles) {
                Add-ESPAssignment -Id $espprofile.Id -TargetGroupId $intunegrp.Id
                Write-Host "Assigned $($intunegrp.DisplayName) to $($espprofile.displayName)/$($espprofile.id)" -ForegroundColor Green
            }
            Add-Type -AssemblyName PresentationCore, PresentationFramework
            $msgBody = "ESP Assigned"
            [System.Windows.MessageBox]::Show($msgBody)   
        }
 

 

        #Get Apps
        write-host "Getting Applications"
        $apps = Get-IntuneApplication

 

        ##Query
        ##Windows app types
        $windowslist = "#microsoft.graph.officeSuiteApp", "#microsoft.graph.windowsMicrosoftEdgeApp", "#microsoft.graph.microsoftStoreForBusinessApp", "#microsoft.graph.win32LobApp", "#microsoft.graph.windowsUniversalAppX", "#microsoft.graph.windowsMobileMSI", "#microsoft.graph.microsoftStoreForBusinessContainedApp", "#microsoft.graph.webApp", "#microsoft.graph.windowsAppX", "#microsoft.graph.windowsUniversalAppXContainedApp"
        ##Set array
        $windowsapps = @()
        ##iOS App Types
        $ioslist = "#microsoft.graph.iosVppApp", "#microsoft.graph.iosLobApp", "#microsoft.graph.iosStoreApp", "#microsoft.graph.managedIOSLobApp", "#microsoft.graph.managedIOSStoreApp"
        ##Set Array
        $iosapps = @()
        ##Android app types
        $androidlist = "#microsoft.graph.managedAndroidStoreApp", "#microsoft.graph.androidForWorkApp", "#microsoft.graph.androidLobApp", "#microsoft.graph.androidManagedStoreWebApp", "#microsoft.graph.androidStoreApp", "#microsoft.graph.managedAndroidLobApp"
        ##Set Array
        $androidapps = @()
        ##MacOS App Types
        $macoslist = "#microsoft.graph.macOSLobApp", "#microsoft.graph.macOSIncludedApp", "#microsoft.graph.macOsVppApp", "#microsoft.graph.macOSOfficeSuiteApp", "#microsoft.graph.macOSMicrosoftEdgeApp", "#microsoft.graph.macOSDmgApp", "#microsoft.graph.macOSMdatpApp"
        ##Set Array
        $macosapps = @()

 

        ##Windows

        foreach ($app in $apps) {

            if ($windowslist.contains($app."@Odata.type" )) {

                $windowsapps += $app

            }

        }

 

 

        ##IOS

        foreach ($app in $apps) {

            if ($ioslist.contains($app."@Odata.type" )) {

                $iosapps += $app

            }

        }

 

        ##Android

        foreach ($app in $apps) {

            if ($androidlist.contains($app."@Odata.type" )) {

                $androidapps += $app

            }

        }

 

        ##MacOS

        foreach ($app in $apps) {

            if ($macoslist.contains($app."@Odata.type" )) {

                $macosapps += $app

            }

        }

 
        if ($windows.checked -eq $True) {
            ##Assign Windows apps

            foreach ($windowsapp in $windowsapps) {
                Add-ApplicationAssignment -ApplicationId $windowsapp.id -TargetGroupId $intunegrp.Id -InstallIntent $assignmenttype
                Write-Host "Assigned $($intunegrp.DisplayName) to $($windowsapp.displayName)/$($windowsapp.id)" -ForegroundColor Green
            }
            Add-Type -AssemblyName PresentationCore, PresentationFramework
            $msgBody = "Windows Apps Assigned"
            [System.Windows.MessageBox]::Show($msgBody)   
        }
 

        if ($macos.checked -eq $True) {
            ##Assign MAC apps

            foreach ($macosapp in $macosapps) {
                Add-ApplicationAssignment -ApplicationId $macosapp.id -TargetGroupId $intunegrp.Id -InstallIntent "Required"
                Write-Host "Assigned $($intunegrp.DisplayName) to $($macosapp.displayName)/$($macosapp.id)" -ForegroundColor Green

            }
            Add-Type -AssemblyName PresentationCore, PresentationFramework
            $msgBody = "MacOS Apps Assigned"
            [System.Windows.MessageBox]::Show($msgBody)   
        }
 
 
        if ($android.Checked -eq $True) {
            ##Assign Android apps

            foreach ($androidapp in $androidapps) {
                Add-ApplicationAssignment -ApplicationId $androidapp.id -TargetGroupId $intunegrp.Id -InstallIntent $assignmenttype
                Write-Host "Assigned $($intunegrp.DisplayName) to $($androidapp.displayName)/$($androidapp.id)" -ForegroundColor Green

            }
            Add-Type -AssemblyName PresentationCore, PresentationFramework
            $msgBody = "Android Apps Assigned"
            [System.Windows.MessageBox]::Show($msgBody)   
        }

        if ($ios.checked -eq $True) {
            ##Assign iOS apps

            foreach ($iosapp in $iosapps) {
                Add-ApplicationAssignment -ApplicationId $iosapp.id -TargetGroupId $intunegrp.Id -InstallIntent $assignmenttype
                Write-Host "Assigned $($intunegrp.DisplayName) to $($iosapp.displayName)/$($iosapp.id)" -ForegroundColor Green

            }
            Add-Type -AssemblyName PresentationCore, PresentationFramework
            $msgBody = "iOS Apps Assigned"
            [System.Windows.MessageBox]::Show($msgBody)   
        }
 
    })


[void]$Form.ShowDialog()
 
# SIG # Begin signature block
# MIIoGQYJKoZIhvcNAQcCoIIoCjCCKAYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA//f8XCSXYBAz4
# 3+tZlTtgd7jYpO7i+kn0vhAC82hOY6CCIRwwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# gjcCARUwLwYJKoZIhvcNAQkEMSIEIKCi9dvI75I4sa4CVS3nYYuvi3wPTBeLoa/L
# /QgwrvEhMA0GCSqGSIb3DQEBAQUABIICAE9SNCB+e1q8YRARTGDJVT2w7ZB90HDo
# W5DeNkphmmhUBjdPtScnqyuVVHcwuMS1uIKi0xvK4fXEwJAZaoLqaIAxzYWVk/Kf
# RX7SCDLxZH/GvaGbuJhoEeZnxmdke5rCsx1tKvxawiDMzfm7Ox22Fk++qQh1xEvC
# O0wd+dlH9MA2VjFitdBGUV8xmU0ZvJ6g3vivq8AIUAeRb3PM+ngW1FbUYtvn73Qh
# 0JwVd7R1zc7Ds6Npvl8E1WPeSwqUYtFofe/LQlE/AmlELztywu2m5c++8+FLrxKw
# lPcJgwpuLx0Gni23HrmjexaAKLH+Tv1QH3gxKYreS1C5F3GUoye1Ij+ubYEMXlci
# wkH5OCeJWnxymdDgW5bdTGTutPHHkiK1ifSQ4MhhDxBFeAyAORNxHUYUUDXu+JPF
# WlZWoqCMzs9HNELY/ZdjXzM3zEKT/BkKbCEkwMTXMApSOqfFIuJhDLBKDL3rQ5jF
# j8xdwun1OJ2uSHz/0IPZcSnIihbOj/fk0uoQo/pXWi3RcVTjpv7SCuZhDRTsSX/D
# vhbo012ivMhYHvoriEzmI8/YxG/ZMBHEzVtzq/F3VupnxwFfj7yZHUYvqtE262r+
# r4ddr1OXG9RaZtyUHAT5yEAMVcEA/JF7QmlsvT1GxRD93MOs35hioNJFt4cPXahy
# owGaVg3KdEhToYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkG
# A1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdp
# Q2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQ
# BUSv85SdCDmmv9s/X+VhFjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzEL
# BgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIzMTExNTIwNDYxOFowLwYJKoZI
# hvcNAQkEMSIEILIlC+I4pUqq7NPafGe/trwLeA05E3acurT/BHGv/FHRMA0GCSqG
# SIb3DQEBAQUABIICACHLue4A3WD3DJ8c/LivvznzM3u1oHQm6czuPCMhBGYS4yhJ
# QBzariGxfq7xU2hzR9+OLUqKDVN7+GmMbNyKo/Gg4cloAL34V2R5c8r0DBtWuQ5e
# GGcfP9nyf8NLGXSiRXGorwD+r1OVhvBvhgSbN8oGtlOC8V3ucZ+Kvf/Zr0BJIkd7
# +xIBMlwsAjR+v4aSRV6VDSTxu6V1/ZlfXkNA0GwpiAKVjl9kxq4JVN4Cu01+xKYD
# nJy6e/WOotQgltFJVdEGhWHYDDiFSKvcbLeLGq6zNLeH0S19phO3z4BxLNmBhmzP
# kROEShWugfHGG9BvR7KoBXwHHNJO+FmpMSwpHaBPH02feSJEWJkcUONOwqCNBwi5
# u4abLU5hfwxqLcwGYTZ/ekvJQm/dO/rvfStFRiPLZE6qEQioP0vXf1BHZnp1vMV/
# TvSomtcz6yf8lDV14T9XZKetozKejWrepQQFMtBu9ugQXqR4hWtIeH9ldmDz52oy
# hUOu5PEBM1mzYT054n+tYO08w+/ETWixLjEUWnuty7ZQfBAj2GIGilzm7MGvYEUm
# OuH4tAtSR0eArcm1xOym0U60IvREqmyR56FTjQ8lnXywZ1SQXaXRdJtdIZ/UKbBj
# cDDMjA8K2Ccy1/IGiBBFmaK1/o1JGSlVVtllSbxh2b6paNUWWxYUoUFXjhhg
# SIG # End signature block
