<#PSScriptInfo
.VERSION 3.0.0
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
  Version:        3.0.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  21/08/2021
  Modified Date:  31/10/2022
  Purpose/Change: Initial script development
  Reason: Fixed issue with Update ring assignments
  Change: Switched to Graph SDK
  
.EXAMPLE
N/A
#>

$version = "2.1"
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
Import-Module Microsoft.Graph.Intune
import-module microsoft.graph.authentication
import-module microsoft.graph.groups



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
write-host "Script has been updated, please download the latest version from $liveuri" -ForegroundColor Red
}
}
Get-ScriptVersion -liveuri "https://raw.githubusercontent.com/andrew-s-taylor/public/main/Powershell%20Scripts/Intune/BuildIntuneEnvironment.ps1"




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
Connect-MSGraph


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
