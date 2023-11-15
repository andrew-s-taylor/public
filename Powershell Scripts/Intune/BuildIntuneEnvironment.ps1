<#PSScriptInfo
.VERSION 3.0.4
.GUID 729ebf90-26fe-4795-92dc-ca8f570cdd22
.AUTHOR AndrewTaylor
.DESCRIPTION Builds an Intune environment using intunebackupandrestore
.COMPANYNAME 
.COPYRIGHT GPL
.TAGS intune endpoint MEM environment
.LICENSEURI https://github.com/andrew-s-taylor/public/blob/main/LICENSE
.PROJECTURI https://github.com/andrew-s-taylor/public
.ICONURI 
.EXTERNALMODULEDEPENDENCIES microsoft.graph.intune intunebackupandrestore
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
#>
<#
.SYNOPSIS
  Builds an Intune Environment
.DESCRIPTION
Builds an Intune environment using intunebackupandrestore

.INPUTS
None required
.OUTPUTS
Within Azure
.NOTES
  Version:        3.0.4
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  21/08/2021
  Modified Date:  24/02/2023
  Purpose/Change: Initial script development
  Reason: Fixed issue with Update ring assignments
  Change: Switched to Graph SDK
  Change: Removed MS Graph Module
  
.EXAMPLE
N/A
#>

$version = "3.0.2"
###############################################################################################################
######                                         Install Modules                                           ######
###############################################################################################################
Write-Host "Installing Intune modules if required (current user scope)"

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


#Install MS Intune Backup and Restore if not available
if (Get-Module -ListAvailable -Name IntuneBackupAndRestore) {
    Write-Host "Intune Backup and Restore Already Installed"
} 
else {
    try {
        Install-Module -Name IntuneBackupAndRestore -Scope CurrentUser -Repository PSGallery -Force 
    }
    catch [Exception] {
        $_.message 
        exit
    }
}


#Importing Modules
Import-Module IntuneBackupAndRestore
import-module microsoft.graph.authentication
import-module microsoft.graph.groups

###############################################################################################################
######                                          Add Functions                                            ######
###############################################################################################################



    
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
        $name
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/deviceConfigurations"
    
        try {
    
            if($Name){
    
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
        break
    
        }
    
    }
    
    ####################################################


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
                $name
            )
            
            $graphApiVersion = "beta"
            $DCP_resource = "deviceManagement/configurationPolicies"
            
                try {
            
                    if($Name){
            
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
                break
            
                }
            
            }
            
            ####################################################
    


            Function Get-AutoPilotProfile(){
    
                <#
                .SYNOPSIS
                This function is used to get device configuration policies from the Graph API REST interface - AUTPILOT
                .DESCRIPTION
                The function connects to the Graph API Interface and gets any device configuration policies
                .EXAMPLE
                Get-AutoPilotProfile
                Returns any device configuration policies configured in Intune
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
                
                        if($Name){
                
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
                    break
                
                    }
                
                }
                
                ####################################################       
    Function Get-DeviceConfigurationPolicyAssignment(){
    
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
        [Parameter(Mandatory=$true,HelpMessage="Enter id (guid) for the Device Configuration Policy you want to check assignment")]
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
        break
    
        }
    
    }

    Function Get-DeviceConfigurationPolicyAssignmentSC(){
    
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
            [Parameter(Mandatory=$true,HelpMessage="Enter id (guid) for the Device Configuration Policy you want to check assignment")]
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
            break
        
            }
        
        }
    
    ####################################################


    Function Get-AutoPilotProfileAssignments(){
    
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
            [Parameter(Mandatory=$true,HelpMessage="Enter id (guid) for the Autopilot Profile you want to check assignment")]
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
            break
        
            }
        
        }
    
    ####################################################
    
    Function Add-DeviceConfigurationPolicyAssignment(){
    
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
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $ConfigurationPolicyId,
    
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $TargetGroupId,
    
        [parameter(Mandatory=$true)]
        [ValidateSet("Included","Excluded")]
        [ValidateNotNullOrEmpty()]
        [string]$AssignmentType
    )
    
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceConfigurations/$ConfigurationPolicyId/assign"
        
        try {
    
            if(!$ConfigurationPolicyId){
    
                write-host "No Configuration Policy Id specified, specify a valid Configuration Policy Id" -f Red
                break
    
            }
    
            if(!$TargetGroupId){
    
                write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red
                break
    
            }
    
            # Checking if there are Assignments already configured in the Policy
            $DCPA = Get-DeviceConfigurationPolicyAssignment -id $ConfigurationPolicyId
    
            $TargetGroups = @()
    
            if(@($DCPA).count -ge 1){
                
                if($DCPA.targetGroupId -contains $TargetGroupId){
    
                Write-Host "Group with Id '$TargetGroupId' already assigned to Policy..." -ForegroundColor Red
                Write-Host
                break
    
                }
    
                # Looping through previously configured assignements
    
                $DCPA | foreach {
    
                $TargetGroup = New-Object -TypeName psobject
         
                    if($_.excludeGroup -eq $true){
    
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
    
                    if($AssignmentType -eq "Excluded"){
    
                        $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'
         
                    }
         
                    elseif($AssignmentType -eq "Included") {
         
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
    
                    if($AssignmentType -eq "Excluded"){
    
                        $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'
         
                    }
         
                    elseif($AssignmentType -eq "Included") {
         
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
        Invoke-MgGraphRequest -Uri $uri -Method POST -Body $JSON -ContentType "application/json"
    
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



    Function Add-DeviceConfigurationPolicyAssignmentSC(){
    
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
            [parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            $ConfigurationPolicyId,
        
            [parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            $TargetGroupId,
        
            [parameter(Mandatory=$true)]
            [ValidateSet("Included","Excluded")]
            [ValidateNotNullOrEmpty()]
            [string]$AssignmentType
        )
        
        $graphApiVersion = "Beta"
        $Resource = "deviceManagement/configurationPolicies/$ConfigurationPolicyId/assign"
            
            try {
        
                if(!$ConfigurationPolicyId){
        
                    write-host "No Configuration Policy Id specified, specify a valid Configuration Policy Id" -f Red
                    break
        
                }
        
                if(!$TargetGroupId){
        
                    write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red
                    break
        
                }
        
                # Checking if there are Assignments already configured in the Policy
                $DCPA = Get-DeviceConfigurationPolicyAssignmentSC -id $ConfigurationPolicyId
        
                $TargetGroups = @()
        
                if(@($DCPA).count -ge 1){
                    
                    if($DCPA.targetGroupId -contains $TargetGroupId){
        
                    Write-Host "Group with Id '$TargetGroupId' already assigned to Policy..." -ForegroundColor Red
                    Write-Host
                    break
        
                    }
        
                    # Looping through previously configured assignements
        
                    $DCPA | foreach {
        
                    $TargetGroup = New-Object -TypeName psobject
             
                        if($_.excludeGroup -eq $true){
        
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
        
                        if($AssignmentType -eq "Excluded"){
        
                            $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'
             
                        }
             
                        elseif($AssignmentType -eq "Included") {
             
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
        
                        if($AssignmentType -eq "Excluded"){
        
                            $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'
             
                        }
             
                        elseif($AssignmentType -eq "Included") {
             
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
            Invoke-MgGraphRequest -Uri $uri -Method POST -Body $JSON -ContentType "application/json"
        
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



        
    Function Add-AutoPilotProfileAssignment(){
    
        <#
        .SYNOPSIS
        This function is used to add an autopilot profile assignment using the Graph API REST interface
        .DESCRIPTION
        The function connects to the Graph API Interface and adds an autopilot profile assignment
        .EXAMPLE
        Add-AutoPilotProfileAssignment -ConfigurationPolicyId $ConfigurationPolicyId -TargetGroupId $TargetGroupId
        Adds a device configuration policy assignment in Intune
        .NOTES
        NAME: Add-AutoPilotProfileAssignment
        #>
        
        [cmdletbinding()]
        
        param
        (
            [parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            $ConfigurationPolicyId,
        
            [parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            $TargetGroupId,
        
            [parameter(Mandatory=$true)]
            [ValidateSet("Included","Excluded")]
            [ValidateNotNullOrEmpty()]
            [string]$AssignmentType
        )
        
        $graphApiVersion = "Beta"
        $Resource = "deviceManagement/windowsAutopilotDeploymentProfiles/$ConfigurationPolicyId/assignments"
            
            try {
        
                if(!$ConfigurationPolicyId){
        
                    write-host "No Configuration Policy Id specified, specify a valid Configuration Policy Id" -f Red
                    break
        
                }
        
                if(!$TargetGroupId){
        
                    write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red
                    break
        
                }
        
                # Checking if there are Assignments already configured in the Policy
                $DCPA = Get-AutoPilotProfileAssignments -id $ConfigurationPolicyId
        
                $TargetGroups = @()
        
                if(@($DCPA).count -ge 1){
                    
                    if($DCPA.targetGroupId -contains $TargetGroupId){
        
                    Write-Host "Group with Id '$TargetGroupId' already assigned to Policy..." -ForegroundColor Red
                    Write-Host
                    break
        
                    }
        
                    # Looping through previously configured assignements
        
                    $DCPA | foreach {
        
                    $TargetGroup = New-Object -TypeName psobject
             
                        if($_.excludeGroup -eq $true){
        
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
        
                        if($AssignmentType -eq "Excluded"){
        
                            $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'
             
                        }
             
                        elseif($AssignmentType -eq "Included") {
             
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
        
                        if($AssignmentType -eq "Excluded"){
        
                            $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'
             
                        }
             
                        elseif($AssignmentType -eq "Included") {
             
                            $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.deviceAndAppManagementAssignmentTarget'
                            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'deviceAndAppManagementAssignmentFilterType' -Value 'include'
             
                        }
             
                    $TargetGroup | Add-Member -MemberType NoteProperty -Name 'deviceAndAppManagementAssignmentFilterId' -Value "$TargetGroupId"
        
                    $Target = New-Object -TypeName psobject
                    $Target | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.windowsAutopilotDeploymentProfileAssignment'
                    $Target | Add-Member -MemberType NoteProperty -Name 'target' -Value $TargetGroup
                    $Target | Add-Member -MemberType NoteProperty -Name 'sourceId' -Value $TargetGroupId
                    $Target | Add-Member -MemberType NoteProperty -Name 'source' -Value "direct"
        
                    $TargetGroups = $Target
        
                }
        
            # Creating JSON object to pass to Graph
            $Output = New-Object -TypeName psobject
        
            $Output | Add-Member -MemberType NoteProperty -Name 'assignments' -Value @($TargetGroups)
        
            $JSON = $Output | ConvertTo-Json -Depth 4
        
            # POST to Graph Service
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Invoke-MgGraphRequest -Uri $uri -Method POST -Body $JSON -ContentType "application/json"
        
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


<# This form was created using POSHGUI.com  a free online gui designer for PowerShell
.NAME
    Intune
#>

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

$CreateIntuneEnv                 = New-Object system.Windows.Forms.Form
$CreateIntuneEnv.ClientSize      = New-Object System.Drawing.Point(397,379)
$CreateIntuneEnv.text            = "Create Intune Environment Version $version"
$CreateIntuneEnv.TopMost         = $false
$CreateIntuneEnv.BackColor       = [System.Drawing.ColorTranslator]::FromHtml("#ffffff")

$Label1                          = New-Object system.Windows.Forms.Label
$Label1.text                     = "Created by Andrew Taylor (andrewstaylor.com)"
$Label1.AutoSize                 = $true
$Label1.width                    = 25
$Label1.height                   = 10
$Label1.location                 = New-Object System.Drawing.Point(4,348)
$Label1.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label2                          = New-Object system.Windows.Forms.Label
$Label2.text                     = "Client Name"
$Label2.AutoSize                 = $true
$Label2.width                    = 25
$Label2.height                   = 10
$Label2.location                 = New-Object System.Drawing.Point(10,22)
$Label2.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label3                          = New-Object system.Windows.Forms.Label
$Label3.text                     = "Tenant ID"
$Label3.AutoSize                 = $true
$Label3.width                    = 25
$Label3.height                   = 10
$Label3.location                 = New-Object System.Drawing.Point(10,66)
$Label3.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label4                          = New-Object system.Windows.Forms.Label
$Label4.text                     = "HomePage"
$Label4.AutoSize                 = $true
$Label4.width                    = 25
$Label4.height                   = 10
$Label4.location                 = New-Object System.Drawing.Point(10,109)
$Label4.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label5                          = New-Object system.Windows.Forms.Label
$Label5.text                     = "Background URL"
$Label5.AutoSize                 = $true
$Label5.width                    = 25
$Label5.height                   = 10
$Label5.location                 = New-Object System.Drawing.Point(10,156)
$Label5.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label6                          = New-Object system.Windows.Forms.Label
$Label6.text                     = "Background Filename"
$Label6.AutoSize                 = $true
$Label6.width                    = 25
$Label6.height                   = 40
$Label6.location                 = New-Object System.Drawing.Point(10,215)
$Label6.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$clientname                      = New-Object system.Windows.Forms.TextBox
$clientname.multiline            = $false
$clientname.width                = 200
$clientname.height               = 20
$clientname.location             = New-Object System.Drawing.Point(151,22)
$clientname.Font                 = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$tenantid                        = New-Object system.Windows.Forms.TextBox
$tenantid.multiline              = $false
$tenantid.width                  = 200
$tenantid.height                 = 20
$tenantid.location               = New-Object System.Drawing.Point(151,66)
$tenantid.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$homepage                        = New-Object system.Windows.Forms.TextBox
$homepage.multiline              = $false
$homepage.width                  = 200
$homepage.height                 = 20
$homepage.location               = New-Object System.Drawing.Point(151,109)
$homepage.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$bgurl                           = New-Object system.Windows.Forms.TextBox
$bgurl.multiline                 = $false
$bgurl.width                     = 200
$bgurl.height                    = 20
$bgurl.location                  = New-Object System.Drawing.Point(151,156)
$bgurl.Font                      = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$bgname                          = New-Object system.Windows.Forms.TextBox
$bgname.multiline                = $false
$bgname.width                    = 200
$bgname.height                   = 20
$bgname.location                 = New-Object System.Drawing.Point(151,215)
$bgname.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$build                           = New-Object system.Windows.Forms.Button
$build.text                      = "Build"
$build.width                     = 153
$build.height                    = 72
$build.location                  = New-Object System.Drawing.Point(113,257)
$build.Font                      = New-Object System.Drawing.Font('Microsoft Sans Serif',19)

$Label7                          = New-Object system.Windows.Forms.Label
$Label7.text                     = " (inc extension)"
$Label7.AutoSize                 = $true
$Label7.width                    = 25
$Label7.height                   = 10
$Label7.location                 = New-Object System.Drawing.Point(29,231)
$Label7.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$CreateIntuneEnv.controls.AddRange(@($Label1,$Label2,$Label3,$Label4,$Label5,$Label6,$clientname,$tenantid,$homepage,$bgurl,$bgname,$build,$Label7))

$build.Add_Click({ 

    $clientnameout = $clientname.Text
    $tenantidout = $tenantid.Text
    $homepageout = $homepage.Text
    $bloburl = $bgurl.Text
    $backgroundfilename = $bgname.Text

###############################################################################################################
######                                          Deploy                                                   ######
###############################################################################################################




###############################################################################################################
######                                          Group Creation                                           ######
###############################################################################################################


#Create Azure AD Groups

#AutoPilot Group
$autopilotgrp = New-MgGroup -DisplayName "Autopilot-Devices" -Description "Dynamic group for Autopilot Devices" -MailEnabled:$False -MailNickName "autopilotdevices" -SecurityEnabled -GroupTypes "DynamicMembership" -MembershipRule "(device.devicePhysicalIDs -any (_ -contains ""[ZTDid]""))" -MembershipRuleProcessingState "On"

#Pilot Group
$pilotgrp = New-MgGroup -DisplayName "Intune-Pilot-Users" -Description "Assigned group for Pilot Users" -MailEnabled:$False -MailNickName "pilotusers" -SecurityEnabled

#Preview Group
$previewgrp = New-MgGroup -DisplayName "Intune-Preview-Users" -Description "Assigned group for Preview Users" -MailEnabled:$False -MailNickName "previewusers" -SecurityEnabled

#VIP Group
$vipgrp = New-MgGroup -DisplayName "Intune-VIP-Users" -Description "Assigned group for VIP Users" -MailEnabled:$False -MailNickName "vipusers" -SecurityEnabled


#Notify complete
Add-Type -AssemblyName PresentationCore,PresentationFramework
$msgBody = "Autopilot AAD Group Created, moving on to Intune Deployment"
[System.Windows.MessageBox]::Show($msgBody)

##Connect to Intune
Connect-ToGraph -Scopes "Policy.ReadWrite.ConditionalAccess, CloudPC.ReadWrite.All, DeviceManagementServiceConfig.ReadWrite.All, RoleAssignmentSchedule.ReadWrite.Directory, Domain.Read.All, Domain.ReadWrite.All, Directory.Read.All, Policy.ReadWrite.ConditionalAccess, DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, openid, profile, email, offline_access, DeviceManagementRBAC.Read.All, DeviceManagementRBAC.ReadWrite.All"


###############################################################################################################
######                                          Create Dir                                               ######
###############################################################################################################

#Create path for files
$DirectoryToCreate = "c:\temp"
if (-not (Test-Path -LiteralPath $DirectoryToCreate)) {
    
    try {
        New-Item -Path $DirectoryToCreate -ItemType Directory -ErrorAction Stop | Out-Null #-Force
    }
    catch {
        Write-Error -Message "Unable to create directory '$DirectoryToCreate'. Error was: $_" -ErrorAction Stop
    }
    "Successfully created directory '$DirectoryToCreate'."

}
else {
    "Directory already existed"
}


$random = Get-Random -Maximum 1000 
$random = $random.ToString()
$date =get-date -format yyMMddmmss
$date = $date.ToString()
$path2 = $random + "-"  + $date
$path = "c:\temp\" + $path2 + "\"

New-Item -ItemType Directory -Path $path


$pathvar = [PSCustomObject]@{value=$path}

Write-Host "Directory Created"

#Set Paths
    $url = "https://github.com/andrew-s-taylor/Intune-Config/archive/main.zip"
    $pathaz = "c:\temp\" + $path2 + "\Intune-Config"
    $output = "c:\temp\" + $path2 + "\main.zip"



###############################################################################################################
######                                          Extract                                                  ######
###############################################################################################################
#Download Files
Invoke-WebRequest -Uri $url -OutFile $output -Method Get


#Unzip them
Expand-Archive $output -DestinationPath $path -Force

#Remove Zip file downloaded
remove-item $output -Force


#Notify complete
Add-Type -AssemblyName PresentationCore,PresentationFramework
$msgBody = "Files saves to $path"
[System.Windows.MessageBox]::Show($msgBody)


###############################################################################################################
######                                          Edit Scripts                                             ######
###############################################################################################################


##Device Script
$devicescript = $path + "\Intune-Config-main\Device Management Scripts\Script Content\Device Config.ps1"

#Update Client Name
(Get-Content -path $devicescript -Raw ) `
-replace '<CLIENTREPLACENAME>',$clientnameout | Set-Content -Path $devicescript


#Update O365 Tenant
(Get-Content -path $devicescript -Raw ) `
-replace '<CLIENTTENANT>',$tenantidout | Set-Content -Path $devicescript


#Update Client Homepage
(Get-Content -path $devicescript -Raw ) `
-replace '<CLIENTHOMEPAGE>',$homepageout | Set-Content -Path $devicescript

#Update Background location
(Get-Content -path $devicescript -Raw ) `
-replace '<BACKGROUNDBLOBURL>',$bloburl | Set-Content -Path $devicescript


#Update Background Name
(Get-Content -path $devicescript -Raw ) `
-replace '<BACKGROUNDFILENAME>',$backgroundfilename | Set-Content -Path $devicescript


##User Script
$userscript = $path + "\Intune-Config-main\Device Management Scripts\Script Content\User-Config.ps1"
(Get-Content -path $userscript -Raw ) `
-replace '<BACKGROUNDFILENAME>',$backgroundfilename | Set-Content -Path $userscript

##Restore
Start-IntuneRestoreConfig -Path $pathaz


###############################################################################################################
######                                          Create Autpilot Profile                                  ######
###############################################################################################################

$graphApiVersion = "beta"
$Resource = "deviceManagement/windowsAutopilotDeploymentProfiles"
$uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"

$profilename = "Autopilot Profile"
$json = @"
{
    "@odata.type": "#microsoft.graph.azureADWindowsAutopilotDeploymentProfile",
    "displayName": "$profilename",
    "description": "OOBE Autopilot Profile",
    "language": "en-GB",
    "extractHardwareHash": true,
    "deviceNameTemplate": "%SERIAL%",
    "deviceType": "windowsPc",
    "enableWhiteGlove": true,
    "outOfBoxExperienceSettings": {
        "hidePrivacySettings": true,
        "hideEULA": true,
        "userType": "standard",
        "deviceUsageType": "singleUser",
        "skipKeyboardSelectionPage": false,
        "hideEscapeLink": true
    },
    "enrollmentStatusScreenSettings": {
        "@odata.type": "microsoft.graph.windowsEnrollmentStatusScreenSettings",
        "hideInstallationProgress": false,
        "allowDeviceUseBeforeProfileAndAppInstallComplete": true,
        "blockDeviceSetupRetryByUser": true,
        "allowLogCollectionOnInstallFailure": true,
        "installProgressTimeoutInMinutes": 120,
        "allowDeviceUseOnInstallFailure": true
    }
}
"@
    

    Write-Verbose "POST $uri`n$json"

    try {
        Invoke-MgGraphRequest -Uri $uri -Method POST -Body $json -ContentType "application/json"
    }
    catch {
        Write-Error $_.Exception 
        break
    }


##########################################endregion##############################################################


###############################################################################################################
######                                     Create Enrollment Status Page                                 ######
###############################################################################################################


$graphApiVersion = "beta"
$Resource = "deviceManagement/deviceEnrollmentConfigurations"
$uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
$json = @"
    {
        "@odata.type": "#microsoft.graph.windows10EnrollmentCompletionPageConfiguration",
        "displayName": "AutoPilot Enrollment",
        "description": "Custom Enrollment Status",
        "showInstallationProgress": true,
        "blockDeviceSetupRetryByUser": false,
        "allowDeviceResetOnInstallFailure": false,
        "allowLogCollectionOnInstallFailure": true,
        "customErrorMessage": "Enter your custom error here",
        "installProgressTimeoutInMinutes": 120,
        "allowDeviceUseOnInstallFailure": true
}
"@

Write-Verbose "POST $uri`n$json"

try {
    $enrollment = Invoke-MgGraphRequest -Uri $uri -Method POST -Body $json -ContentType "application/json"

}
catch {
    Write-Error $_.Exception 
    break
}



##Assign it
        # Defining Variables

        $id = $enrollment.id
        #Remove extra text from the ID
        #$id2 = $id3.split('_')
        #$id = $id2[0]

        $groupid = $autopilotgrp.id       
        $graphApiVersion = "beta"
        $Resource = "deviceManagement/deviceEnrollmentConfigurations"        
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$id/assign"        





$json = @"
    {
        "enrollmentConfigurationAssignments": [
            {
                "target": {
                    "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                    "groupId": "$groupid"
                }
            }
        ]
    }
"@

        Write-Verbose "POST $uri`n$json"

        try {
            Invoke-MgGraphRequest -Uri $uri -Method POST -Body $json -ContentType "application/json"
        }
        catch {
            Write-Error $_.Exception 
            break
        }


#######################################################



###############################################################################################################
######                                          Assign Autopilot Profile                                 ######
###############################################################################################################


        # Defining Variables
        $ap1 = Get-AutoPilotProfile -name $profilename
$id = $ap1.id
        $graphApiVersion = "beta"
        $Resource = "deviceManagement/windowsAutopilotDeploymentProfiles"        
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$id/assignments"        

$groupid = $autopilotgrp.id

        $full_assignment_id = $id + "_" + $groupid + "_0" 

$json = @"
{
    "id": "$full_assignment_id",
    "target": {
        "@odata.type": "#microsoft.graph.groupAssignmentTarget",
        "groupId": "$groupid"
    }
}
"@

        Write-Verbose "POST $uri`n$json"

        try {
            Invoke-MgGraphRequest -Uri $uri -Method POST -Body $json -ContentType "application/json"
        }
        catch {
            Write-Error $_.Exception 
            break
        }



#########################################################################


###############################################################################################################
######                             Assign Windows Update Rings                                           ######
###############################################################################################################

#Assign Windows Update Rings
#Pilot Ring
$PolicyName = "Pilot Ring"

$DCP = Get-DeviceConfigurationPolicy -name "$PolicyName"

if($DCP){

    $Assignment = Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $DCP.id -TargetGroupId $pilotgrp.id -AssignmentType Included
    Write-Host "Assigned '$pilotgrp.Name' to $($DCP.displayName)/$($DCP.id)" -ForegroundColor Green
    Write-Host

}

else {

    Write-Host "Can't find Device Configuration Policy with name '$PolicyName'..." -ForegroundColor Red
    Write-Host 

}



#Preview Ring
$PolicyName = "Preview Ring"

$DCP = Get-DeviceConfigurationPolicy -name "$PolicyName"

if($DCP){

    $Assignment = Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $DCP.id -TargetGroupId $previewgrp.id -AssignmentType Included
    Write-Host "Assigned '$previewgrp' to $($DCP.displayName)/$($DCP.id)" -ForegroundColor Green
    Write-Host

}

else {

    Write-Host "Can't find Device Configuration Policy with name '$PolicyName'..." -ForegroundColor Red
    Write-Host 

}



#VIP Ring
$PolicyName = "VIP Channel"

$DCP = Get-DeviceConfigurationPolicy -name "$PolicyName"

if($DCP){

    $Assignment = Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $DCP.id -TargetGroupId $vipgrp.id -AssignmentType Included
    Write-Host "Assigned '$vipgrp' to $($DCP.displayName)/$($DCP.id)" -ForegroundColor Green
    Write-Host

}

else {

    Write-Host "Can't find Device Configuration Policy with name '$PolicyName'..." -ForegroundColor Red
    Write-Host 

}


#Broad Ring
$PolicyName = "Broad Ring"

$DCP = Get-DeviceConfigurationPolicy -name "$PolicyName"

if($DCP){

    $Assignment = Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $DCP.id -TargetGroupId $vipgrp.id -AssignmentType Excluded
    $Assignment = Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $DCP.id -TargetGroupId $pilotgrp.id -AssignmentType Excluded
    $Assignment = Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $DCP.id -TargetGroupId $previewgrp.id -AssignmentType Excluded
    $Assignment = Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $DCP.id -TargetGroupId $autopilotgrp.id -AssignmentType Included
    Write-Host "Assigned exclusion groups to $($DCP.displayName)/$($DCP.id)" -ForegroundColor Green
    Write-Host

}

else {

    Write-Host "Can't find Device Configuration Policy with name '$PolicyName'..." -ForegroundColor Red
    Write-Host 

}




###############################################################################################################
######                                          Assign Office Update Rings                               ######
###############################################################################################################


#Assign Office Update Rings

#Pilot Ring
$PolicyName = "Office-PilotRing"

$DCP = Get-DeviceConfigurationPolicySC -name "$PolicyName"

if($DCP){

    $Assignment = Add-DeviceConfigurationPolicyAssignmentSC -ConfigurationPolicyId $DCP.id -TargetGroupId $pilotgrp.id -AssignmentType Included
    Write-Host "Assigned '$pilotgrp' to $($DCP.displayName)/$($DCP.id)" -ForegroundColor Green
    Write-Host

}

else {

    Write-Host "Can't find Device Configuration Policy with name '$PolicyName'..." -ForegroundColor Red
    Write-Host 

}



#Preview Ring
$PolicyName = "Office-PreviewRing"

$DCP = Get-DeviceConfigurationPolicySC -name "$PolicyName"

if($DCP){

    $Assignment = Add-DeviceConfigurationPolicyAssignmentSC -ConfigurationPolicyId $DCP.id -TargetGroupId $previewgrp.id -AssignmentType Included
    Write-Host "Assigned '$previewgrp' to $($DCP.displayName)/$($DCP.id)" -ForegroundColor Green
    Write-Host

}

else {

    Write-Host "Can't find Device Configuration Policy with name '$PolicyName'..." -ForegroundColor Red
    Write-Host 

}



#VIP Ring
$PolicyName = "Office-VIPRing"

$DCP = Get-DeviceConfigurationPolicySC -name "$PolicyName"

if($DCP){

    $Assignment = Add-DeviceConfigurationPolicyAssignmentSC -ConfigurationPolicyId $DCP.id -TargetGroupId $vipgrp.id -AssignmentType Included
    Write-Host "Assigned '$vipgrp' to $($DCP.displayName)/$($DCP.id)" -ForegroundColor Green
    Write-Host

}

else {

    Write-Host "Can't find Device Configuration Policy with name '$PolicyName'..." -ForegroundColor Red
    Write-Host 

}


#Broad Ring
$PolicyName = "CONNECT: Office-BroadRing"

$DCP = Get-DeviceConfigurationPolicySC -name "$PolicyName"

if($DCP){
$vipuser = $vipgrp.Id
$pilotuser = $pilotgrp.Id
$previewuser = $previewgrp.Id
$intuneuser = $autopilotgrp.Id
    $graphApiVersion = "Beta"
    $configid = $dcp.id
        $Resource = "deviceManagement/configurationPolicies/$configid/assign"

$JSON =@"
{
    "assignments":  [
                        {
                            "target":  {
                                           "@odata.type":  "#microsoft.graph.groupAssignmentTarget",
                                           "deviceAndAppManagementAssignmentFilterId":  null,
                                           "deviceAndAppManagementAssignmentFilterType":  "none",
                                           "groupId":  "$intuneuser"
                                       }
                        },
                        {
                            "target":  {
                                           "@odata.type":  "#microsoft.graph.exclusionGroupAssignmentTarget",
                                           "deviceAndAppManagementAssignmentFilterId":  null,
                                           "deviceAndAppManagementAssignmentFilterType":  "none",
                                           "groupId":  "$previewuser"
                                       }
                        },
                        {
                            "target":  {
                                           "@odata.type":  "#microsoft.graph.exclusionGroupAssignmentTarget",
                                           "deviceAndAppManagementAssignmentFilterId":  null,
                                           "deviceAndAppManagementAssignmentFilterType":  "none",
                                           "groupId":  "$pilotuser"
                                       }
                        },
                        {
                            "target":  {
                                           "@odata.type":  "#microsoft.graph.exclusionGroupAssignmentTarget",
                                           "deviceAndAppManagementAssignmentFilterId":  null,
                                           "deviceAndAppManagementAssignmentFilterType":  "none",
                                           "groupId":  "$vipuser"
                                       }
                        }
                    ]
}
"@
        
            # POST to Graph Service
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Invoke-MgGraphRequest -Uri $uri -Method POST -Body $JSON -ContentType "application/json"
    Write-Host "Assigned all exclusion groups to $($DCP.displayName)/$($DCP.id)" -ForegroundColor Green
    Write-Host

}

else {

    Write-Host "Can't find Device Configuration Policy with name '$PolicyName'..." -ForegroundColor Red
    Write-Host 

}
###############################################################################################################
######                                          DONE                                                     ######
###############################################################################################################
Add-Type -AssemblyName PresentationCore,PresentationFramework
$msgBody = "Environment Built"
[System.Windows.MessageBox]::Show($msgBody)



 })


Disconnect-MgGraph


[void]$CreateIntuneEnv.ShowDialog()

# SIG # Begin signature block
# MIIoGQYJKoZIhvcNAQcCoIIoCjCCKAYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDoePQGmLzTOIx4
# yOiC/oMlApWq1/bhR6ko/z7fm1nws6CCIRwwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# gjcCARUwLwYJKoZIhvcNAQkEMSIEIFF7GzgwNeHhofMMZP6p1dorsJM8YfaCZDkq
# EJE0JcsWMA0GCSqGSIb3DQEBAQUABIICAC6SvErmMkxIFyteb2XK1OZTxdmoZJTk
# mikYQ9T5WlylK0+0Yur7pDoUL9n4q/eduWOipj5SpbzXjj2HXnSi+u9C6EWjVoPd
# tOhh1u5VJDiGZ2iRvK4zCV37GsKMFrin9kVH82aqvoxXFMrcRpw2H4JfRs+ReHVt
# 3qZ38jtbRcHebipIzlZ4dUdPzOufiShoEskYiGfHZbMxtUfUKP9VyYusHa/7nk+e
# pH8aXkDCiPFKdH+FTuPuBig2cUGi8725/VbWZoGs1LjHNb4J+F+A1AdEAElwPkDY
# dXmIBAwB1+6Xnvfw1VklC1onen51yxWjePWzaS4qoMdYnhLlKix6Hx+4hLY7ZaxA
# 0Orbdvj/DJIirEfpEaDkhuCz2TtE1QAS98rUG1+EXTcwvluLdcBXYscI61iQT82k
# lfBQQXnBbya6IBiSDFwH6lzpbYxwQP2xWvS9wrnnoSZU9GdjRXPnr040nytE6otV
# 6ih9wU+ojkEQDTnuBi7bwK3IrzH7Dc6CK5oFRU2Chrh4RxlFDheoQxTca7o5Xzx6
# 1i42wultA9x/ProDNINyX0oGnY+2nsgt0tru1gZ8liAdvNhWJVqT7J+KE0nEDh1n
# k/gc+Ic7o3IudFshm5rMPS5+3+wKjRDCeA9+RpK4TZFmQt2QkOh1sYWfFVq2uike
# 9LHyVD70k86yoYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkG
# A1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdp
# Q2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQ
# BUSv85SdCDmmv9s/X+VhFjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzEL
# BgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIzMTExNTIwNDYxMlowLwYJKoZI
# hvcNAQkEMSIEIGth/Ja8qIi8jCL3mJGuOenCDI05R7wKDrU8sVVDmcQ3MA0GCSqG
# SIb3DQEBAQUABIICAGKdHU3k5lec2a6se0IHC+W9lOIqDO+Ml3vYMJ5uzBRVlZ32
# fIuQlao3+yrsqEFThjgKQzvq7U2uQIn1gj4lUg518tHHa+qbYreyKPitiUyFrKWZ
# 9MsMN7W8NyqePzDMgsQnEO6bIHW4fkAAIdFBpQtH5OioTuNU+iXU2ZlqfpB3f/Kk
# Golqxo7U+1fH/TldxKNOFUERNQMGwlxoEdqmGLEcd8JUHgBFEqEjAowNqNuhpi4P
# x1ahs3NRrHK9NqTYq+2tIpUsPy0M1+xfYXQiKFI8lefHG1/TVMxIn9mbOaJ/FGVH
# SkG302PqbRkApZQChymE2HSJV8llDuzLF9HKBXokBpmAqDQSwUAisWBStdSmuXij
# L4iXFf4tBEO8EbeZOsdrBOF3lmxOCli6cK0UdL/NXxf9LpAp42lZBc/14r+hejTv
# 7grsc18VafG+dThJf3rMWV1tVYC+CeGp49cHZA0bL4WYvcaxgTi3ASfyEvqC8Ou/
# i2K/QbfvrT1ixg8lpbVVv8GAwEmEcXwWLwpUjfLUhO3mOu6wYcEEF6RpThzLM9Ux
# tod+adWDAAdDcqXcyS6HJwhffL7AoCJgxVEmJR6TubsxEZFpZgsyXdOaBk4KSfX5
# vencls63Tx1ko6BKkPTbO86eAOSlCGD25lzXOPxfpI98HnTvoKCgytVOW9Yc
# SIG # End signature block
