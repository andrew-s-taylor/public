###############################################################################################################
######                                          Add Functions                                            ######
###############################################################################################################

Function New-WordTable {
    [cmdletbinding(
        DefaultParameterSetName='Table'
    )]
    Param (
        [parameter()]
        [object]$WordObject,
        [parameter()]
        [object]$Object,
        [parameter()]
        [int]$Columns,
        [parameter()]
        [int]$Rows,
        [parameter(ParameterSetName='Table')]
        [switch]$AsTable,
        [parameter(ParameterSetName='List')]
        [switch]$AsList,
        [parameter()]
        [string]$TableStyle,
        [parameter()]
        [Microsoft.Office.Interop.Word.WdDefaultTableBehavior]$TableBehavior = 'wdWord9TableBehavior',
        [parameter()]
        [Microsoft.Office.Interop.Word.WdAutoFitBehavior]$AutoFitBehavior = 'wdAutoFitFixed'
    )
    #Specifying 0 index ensures we get accurate data from a single object
    $Properties = $Object[0].psobject.properties.name
    $Range = @($Word.Selection.Paragraphs)[-1].Range
    $Table = $WordObject.Selection.Tables.add($Range,$Rows,$Columns,$TableBehavior,$AutoFitBehavior)
 
    Switch ($PSCmdlet.ParameterSetName) {
        'Table' {
            If (-NOT $PSBoundParameters.ContainsKey('TableStyle')) {
                $Table.Style = "Medium Shading 1 - Accent 1"
            }
            $c = 1
            $r = 1
            #Build header
            $Properties | ForEach {
                Write-Verbose "Adding $($_)"
                $Table.cell($r,$c).range.Bold=1
                $Table.cell($r,$c).range.text = $_
                $c++
            }  
            $c = 1    
            #Add Data
            For ($i=0; $i -lt (($Object | Measure-Object).Count); $i++) {
                $Properties | ForEach {
                    $Table.cell(($i+2),$c).range.Bold=0
                    $Table.cell(($i+2),$c).range.text = $Object[$i].$_
                    $c++
                }
                $c = 1 
            }                 
        }
        'List' {
            If (-NOT $PSBoundParameters.ContainsKey('TableStyle')) {
                $Table.Style = "Light Shading - Accent 1"
            }
            $c = 1
            $r = 1
            $Properties | ForEach {
            $output = $Object.$_
            if ([string]::IsNullOrEmpty($output)) {
            $data = "null"
            }
            else {
            if ($output -is [string]) {
            $data = $output

            }
            else {
            $data = $output.ToString()

            }
            }

                $Table.cell($r,$c).range.Bold=1
                $Table.cell($r,$c).range.text = $_
                $c++
                $Table.cell($r,$c).range.Bold=0
                $Table.cell($r,$c).range.text = $data
                $c--
                $r++
            }
        }
    }

}


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

    Function Get-IntuneApplicationAssignments(){
    
        <#
        .SYNOPSIS
        This function is used to get application assignments from the Graph API REST interface
        .DESCRIPTION
        The function connects to the Graph API Interface and gets any application assignments
        .EXAMPLE
        Get-IntuneApplicationAssignments
        Returns any application assignments configured in Intune
        .NOTES
        NAME: Get-IntuneApplicationAssignments
        #>
        
        [cmdletbinding()]
        
        param
        (
            [Parameter(Position=0,mandatory=$true)]
            $id
        )
        
        $graphApiVersion = "Beta"
        $Resource = "deviceAppManagement/mobileApps"
        
            try {
                        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id/assignments"
                (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
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


Function Get-DeviceConfigurationPolicyGPAssignments(){
    
    <#
    .SYNOPSIS
    This function is used to get Group Policy assignments from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any group policy assignments
    .EXAMPLE
    Get-DeviceConfigurationPolicyGPAssignments
    Returns any group policy assignments configured in Intune
    .NOTES
    NAME: Get-DeviceConfigurationPolicyGPAssignments
    #>
    
    [cmdletbinding()]
    
    param
    (
        [Parameter(Position=0,mandatory=$true)]
        $id
    )
    
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/groupPolicyConfigurations"
    
        try {
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id/assignments"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
        }
    
        catch {
    
        }
    
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

Function Get-DeviceConfigurationPolicyAssignments(){
    
    <#
    .SYNOPSIS
    This function is used to get configuration Policy assignments from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any configuration policy assignments
    .EXAMPLE
    Get-DeviceConfigurationPolicyAssignments
    Returns any configuration policy assignments configured in Intune
    .NOTES
    NAME: Get-DeviceConfigurationPolicyAssignments
    #>
    
    [cmdletbinding()]
    
    param
    (
        [Parameter(Position=0,mandatory=$true)]
        $id
    )
    
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceConfigurations"
    
        try {
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id/assignments"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
        }
    
        catch {
    
        }
    
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

Function Get-DeviceConfigurationPolicySCAssignments(){
    
    <#
    .SYNOPSIS
    This function is used to get settings catalog Policy assignments from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any settings catalog policy assignments
    .EXAMPLE
    Get-DeviceConfigurationPolicySCAssignments
    Returns any settings catalog policy assignments configured in Intune
    .NOTES
    NAME: Get-DeviceConfigurationPolicySCAssignments
    #>
    
    [cmdletbinding()]
    
    param
    (
        [Parameter(Position=0,mandatory=$true)]
        $id
    )
    
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/configurationPolicies"
    
        try {
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id/assignments"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
        }
    
        catch {
    
        }
    
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

Function Get-DeviceProactiveRemediationsAssignments(){
    
    <#
    .SYNOPSIS
    This function is used to get proactive remediation assignments from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any proactive remediation assignments
    .EXAMPLE
    Get-DeviceProactiveRemediationsAssignments
    Returns any proactive remediation assignments configured in Intune
    .NOTES
    NAME: Get-DeviceProactiveRemediationsAssignments
    #>
    
    [cmdletbinding()]
    
    param
    (
        [Parameter(Position=0,mandatory=$true)]
        $id
    )
    
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/devicehealthscripts"
    
        try {
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id/assignments"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
        }
    
        catch {
    
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
                    (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
            
                    }
            
                    else {
            
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
                    (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
            
                    }
                }
                catch {}
            
}

Function Get-DeviceCompliancePolicyAssignments(){
    
    <#
    .SYNOPSIS
    This function is used to get compliance policy assignments from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any compliance policy assignments
    .EXAMPLE
    Get-DeviceCompliancePolicyAssignments
    Returns any compliance policy assignments configured in Intune
    .NOTES
    NAME: Get-DeviceCompliancePolicyAssignments
    #>
    
    [cmdletbinding()]
    
    param
    (
        [Parameter(Position=0,mandatory=$true)]
        $id
    )
    
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceCompliancePolicies"
    
        try {
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id/assignments"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
        }
    
        catch {
    
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

Function Get-DeviceSecurityPolicyAssignments(){
    
    <#
    .SYNOPSIS
    This function is used to get security policy assignments from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any security policy assignments
    .EXAMPLE
    Get-DeviceSecurityPolicyAssignments
    Returns any security policy assignments configured in Intune
    .NOTES
    NAME: Get-DeviceSecurityPolicyAssignments
    #>
    
    [cmdletbinding()]
    
    param
    (
        [Parameter(Position=0,mandatory=$true)]
        $id
    )
    
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/intents"
    
        try {
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id/assignments"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
        }
    
        catch {
    
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

Function Get-ManagedAppProtectionAndroidAssignments(){
    
    <#
    .SYNOPSIS
    This function is used to get Android app protection policy assignments from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Android app protection  policy assignments
    .EXAMPLE
    Get-ManagedAppProtectionAndroidAssignments
    Returns any Android app protection  policy assignments configured in Intune
    .NOTES
    NAME: Get-ManagedAppProtectionAndroidAssignments
    #>
    
    [cmdletbinding()]
    
    param
    (
        [Parameter(Position=0,mandatory=$true)]
        $id
    )
    
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/androidManagedAppProtections"
    
        try {
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id/assignments"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
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

Function Get-ManagedAppProtectionIOSAssignments(){
    
    <#
    .SYNOPSIS
    This function is used to get iOS app protection policy assignments from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any iOS app protection  policy assignments
    .EXAMPLE
    Get-ManagedAppProtectionIOSAssignments
    Returns any iOS app protection  policy assignments configured in Intune
    .NOTES
    NAME: Get-ManagedAppProtectionIOSAssignments
    #>
    
    [cmdletbinding()]
    
    param
    (
        [Parameter(Position=0,mandatory=$true)]
        $id
    )
    
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/iOSManagedAppProtections"
    
        try {
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id/assignments"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
        }
    
        catch {
    
        }
    
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

Function Get-AutoPilotProfileAssignments(){
    
    <#
    .SYNOPSIS
    This function is used to get autopilot profile assignments from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any autopilot profile assignments
    .EXAMPLE
    Get-AutoPilotProfileAssignments
    Returns any autopilot profile assignments configured in Intune
    .NOTES
    NAME: Get-AutoPilotProfileAssignments
    #>
    
    [cmdletbinding()]
    
    param
    (
        [Parameter(Position=0,mandatory=$true)]
        $id
    )
    
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/windowsAutopilotDeploymentProfiles"
    
        try {
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id/assignments"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
        }
    
        catch {
    
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
                            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
                    
                            }
                    
                            else {
                    
                            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
                            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
                    
                            }
                        }
                        catch{}
}

Function Get-AutoPilotESPAssignments(){
    
    <#
    .SYNOPSIS
    This function is used to get autopilot ESP assignments from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any autopilot ESP assignments
    .EXAMPLE
    Get-AutoPilotESPAssignments
    Returns any autopilot ESP assignments configured in Intune
    .NOTES
    NAME: Get-AutoPilotESPAssignments
    #>
    
    [cmdletbinding()]
    
    param
    (
        [Parameter(Position=0,mandatory=$true)]
        $id
    )
    
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceEnrollmentConfigurations"
    
        try {
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id/assignments"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
        }
    
        catch {
    
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

Function Get-DeviceManagementScriptsAssignments(){
    
    <#
    .SYNOPSIS
    This function is used to get PowerShell script assignments from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any PowerShell script assignments
    .EXAMPLE
    Get-DeviceManagementScriptsAssignments
    Returns any PowerShell script assignments configured in Intune
    .NOTES
    NAME: Get-DeviceManagementScriptsAssignments
    #>
    
    [cmdletbinding()]
    
    param
    (
        [Parameter(Position=0,mandatory=$true)]
        $id
    )
    
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/devicemanagementscripts"
    
        try {
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id/assignments"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
        }
    
        catch {
    
        }
    
    }
    
################################################################################################
Function Get-Win365UserSettings(){
    
    <#
    .SYNOPSIS
    This function is used to get Windows 365 User Settings Policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device scriptsWindows 365 User Settings Policies
    .EXAMPLE
    Get-Win365UserSettings
    Returns any Windows 365 User Settings Policies configured in Intune
    .NOTES
    NAME: Get-Win365UserSettings
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/virtualEndpoint/userSettings"
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

Function Get-Win365UserSettingsAssignments(){
    
    <#
    .SYNOPSIS
    This function is used to get Windows 365 User Settings Policies assignments from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Windows 365 User Settings Policies assignments
    .EXAMPLE
    Get-Win365UserSettingsAssignments
    Returns any Windows 365 User Settings Policies assignments configured in Intune
    .NOTES
    NAME: Get-Win365UserSettingsAssignments
    #>
    
    [cmdletbinding()]
    
    param
    (
        [Parameter(Position=0,mandatory=$true)]
        $id
    )
    
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/virtualEndpoint/userSettings"
    
        try {
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id/assignments"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
        }
    
        catch {
    
        }
    
    }

Function Get-Win365ProvisioningPolicies(){
    
    <#
    .SYNOPSIS
    This function is used to get Windows 365 Provisioning Policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device scriptsWindows 365 Provisioning Policies
    .EXAMPLE
    Get-Win365ProvisioningPolicies
    Returns any Windows 365 Provisioning Policies configured in Intune
    .NOTES
    NAME: Get-Win365ProvisioningPolicies
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/virtualEndpoint/provisioningPolicies"
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

Function Get-Win365ProvisioningPoliciesAssignments(){
    
    <#
    .SYNOPSIS
    This function is used to get Windows 365 Provisioning Policies assignments from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Windows 365 Provisioning Policies assignments
    .EXAMPLE
    Get-Win365ProvisioningPoliciesAssignments
    Returns any Windows 365 Provisioning Policies assignments configured in Intune
    .NOTES
    NAME: Get-Win365ProvisioningPoliciesAssignments
    #>
    
    [cmdletbinding()]
    
    param
    (
        [Parameter(Position=0,mandatory=$true)]
        $id
    )
    
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/virtualEndpoint/provisioningPolicies"
    
        try {
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id/assignments"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
        }
    
        catch {
    
        }
    
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
    $id = $policyid
    write-host $resource
    $graphApiVersion = "beta"
    switch ($resource) {
    "deviceManagement/deviceConfigurations" {
     $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
     $policy = Get-DecryptedDeviceConfigurationPolicy -dcpid $id
     $assignment = Get-DeviceConfigurationPolicyAssignments -id $id
     $type = "Configuration Policy"

    }

    "deviceManagement/groupPolicyConfigurations" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $policy = Get-DeviceConfigurationPolicyGP -id $id
        $assignment = Get-DeviceConfigurationPolicyGPAssignments -id $id
        $type = "Admin Template"
       }

    "deviceManagement/devicehealthscripts" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $policy = Get-DeviceProactiveRemediations -id $id
        $assignment = Get-DeviceProactiveRemediationsAssignments -id $id
        $type = "Proactive Remedation"
       }

       "deviceManagement/devicemanagementscripts" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $policy = Get-DeviceManagementScripts -id $id
        $assignment = Get-DeviceManagementScriptsAssignments -id $id
        $type = "PowerShell Script"
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
        
        $assignment = get-deviceconfigurationpolicyscassignments -id $id
        $type = "Settings Catalog"

    }
    
    "deviceManagement/deviceCompliancePolicies" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $policy = Get-DeviceCompliancePolicy -id $id
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
            $assignment = Get-DeviceCompliancePolicyAssignments -id $id
            $type = "Compliance Policy"
            
            
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
           $policy = @{
            "displayName" = $policy.DisplayName
            "description" = $policy.description
            "settingsDelta" = $intentSettingsDelta
            "roleScopeTagIds" = $policy.roleScopeTagIds
        }
        $policy | Add-Member -NotePropertyName displayName -NotePropertyValue $newname
        $assignment = Get-DeviceSecurityPolicyAssignments -id $id
        $type = "Security Policy"



    }
    "deviceManagement/windowsAutopilotDeploymentProfiles" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $policy = Get-AutoPilotProfile -id $id
        $assignment = Get-AutoPilotProfileAssignments -id $id
        $type = "AutoPilot Profile"
    }
    "deviceManagement/deviceEnrollmentConfigurations" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $policy = Get-AutoPilotESP -id $id
        $assignment = Get-AutoPilotESPAssignments -id $id
        $type = "AutoPilot ESP"
    }
    "deviceManagement/virtualEndpoint/userSettings" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $policy = Get-Win365UserSettings -id $id
        $assignment = Get-Win365UserSettingsAssignments -id $id
        $type = "Windows 365 User Settings"
    }
    "deviceManagement/virtualEndpoint/provisioningPolicies" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $policy = Get-Win365ProvisioningPolicies -id $id
        $assignment = Get-Win365ProvisioningPoliciesAssignments -id $id
        $type = "Windows 365 Provisioning Policy"
    }
    "deviceAppManagement/managedAppPoliciesandroid" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/managedAppPolicies"
        $policy = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/managedAppPolicies('$id')" -OutputType PSObject
        $assignment = Get-ManagedAppProtectionAndroidAssignments -id $id
        $type = "Android App Protection Policy"

    }
    "deviceAppManagement/managedAppPoliciesios" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/managedAppPolicies"
        #$policy = Invoke-RestMethod -Uri "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/managedAppPolicies('$id')" -Headers $authToken -Method Get
        $policy = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/managedAppPolicies('$id')" -OutputType PSObject
        $assignment = Get-ManagedAppProtectioniOSAssignments -id $id
        $type = "iOS App Protection Policy"
    }

    "conditionalaccess" {
        $uri = "conditionalaccess"
        $policy = Get-ConditionalAccessPolicy -id $id
        $assignment = "Not Available for Conditional Access"
        $type = "Conditional Access Policy"
    }
    "deviceAppManagement/mobileApps" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/mobileApps"
        $policy = Get-IntuneApplication -id $id
        $assignment = Get-IntuneApplicationAssignments -id $id
        $type = "Intune Application"
        }
    }


    return $policy, $type, $assignment

}



###############################################################################################################
######                                          Grab the Profiles                                        ######
###############################################################################################################
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

##Get Win365 User Settings
$configuration += Get-Win365UserSettings | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Win365 User Settings"}}

##Get Win365 Provisioning Policies
$configuration += Get-Win365ProvisioningPolicies | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Win365 Provisioning Policy"}}


$configuration | foreach-object {

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
$win365usersettings = Get-Win365UserSettings -id $id
$win365provisioning = Get-Win365ProvisioningPolicies -id $id




$Word = New-Object -ComObject Word.Application
$Word.Visible = $True
$Document = $Word.Documents.Add()
$Selection = $Word.Selection

#### ADD TITLE PAGE
#### ADD TABLE OF CONTENTS
#### SET TO HIDDEN AND SAVE

# Copy it
if ($null -ne $policy) {
    # Standard Device Configuratio Policy
write-host "It's a policy"
$id = $policy.id
$Resource = "deviceManagement/deviceConfigurations"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$policycode = $copypolicy[0]
$policytype = $copypolicy[1]
$policyassignments = ($copypolicy[2]).value
$policyname = $policycode.displayName

##Table Heading
$selection.Style='Heading 1' 
$selection.TypeText($policytype + " --> " + $policyname) 
$Selection.TypeParagraph()
$Selection.TypeParagraph()
##Table One
New-WordTable -WordObject $word -Object $policycode -Columns 2 -Rows ($policycode.PSObject.Properties | Measure-Object).Count -AsList
##Assignments
$allassignments = $policyassignments.target
$selection.EndKey(6,0)
$Selection.TypeParagraph()
$Selection.TypeParagraph()

##Table Two
$selection.Style='Heading 2'
$selection.TypeText($policytype + " --> " + $policyname + " -- Assignments")  
$Selection.TypeParagraph()
$includedgroups = @()
$excludedgroups = @()
foreach ($assignment in $allassignments) {
$assignmenttype = $assignment.'@odata.type'
$assignmentgroupid = $assignment.groupId
$groupname = (Get-GraphAADGroups -id $assignmentgroupid).displayName
if ($assignmenttype -eq "#microsoft.graph.groupAssignmentTarget") {

##Included
$includedgroups += $groupname + " - " + $assignmentgroupid
}

if ($assignmenttype -eq "#microsoft.graph.exclusionGroupAssignmentTarget") {
##Excluded
$excludedgroups += $groupname + " - " + $assignmentgroupid
}

}

$includedcount = $includedgroups.Count
$excludedcount = $excludedgroups.Count

if ($includedcount -ge 1) {
$selection.Style='Heading 3'
$selection.TypeText($policytype + " --> " + $policyname + " --> Included Assignments") 
foreach ($group in $includedgroups) {
$Selection.TypeParagraph()
$selection.Style='Normal'

$selection.TypeText($group) 
$selection.Style='Normal'
$Selection.TypeParagraph()
}

}


if ($excludedcount -ge 1) {
$selection.Style='Heading 3'
$selection.TypeText($policytype + " --> " + $policyname + " --> Excluded Assignments") 
foreach ($group in $excludedgroups) {
$Selection.TypeParagraph()
$selection.Style='Normal'

$selection.TypeText($group) 
$selection.Style='Normal'
$Selection.TypeParagraph()
}

}






}
if ($null -ne $gp) {
    # Standard Device Configuration Policy
write-host "It's an Admin Template"
$id = $gp.id
$Resource = "deviceManagement/groupPolicyConfigurations"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$policycode = $copypolicy[0]
$policytype = $copypolicy[1]
$policyassignments = $copypolicy[2]
}
if ($null -ne $catalog) {
    # Settings Catalog Policy
write-host "It's a Settings Catalog"
$id = $catalog.id
$Resource = "deviceManagement/configurationPolicies"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$policycode = $copypolicy[0]
$policytype = $copypolicy[1]
$policyassignments = $copypolicy[2]

}
if ($null -ne $compliance) {
    # Compliance Policy
write-host "It's a Compliance Policy"
$id = $compliance.id
$Resource = "deviceManagement/deviceCompliancePolicies"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$policycode = $copypolicy[0]
$policytype = $copypolicy[1]
$policyassignments = $copypolicy[2]
}
if ($null -ne $proac) {
    # Proactive Remediations
write-host "It's a Proactive Remediation"
$id = $proac.id
$Resource = "deviceManagement/devicehealthscripts"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$policycode = $copypolicy[0]
$policytype = $copypolicy[1]
$policyassignments = $copypolicy[2]
}
if ($null -ne $scripts) {
    # Device Scripts
    write-host "It's a PowerShell Script"
$id = $scripts.id
$Resource = "deviceManagement/devicemanagementscripts"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$policycode = $copypolicy[0]
$policytype = $copypolicy[1]
$policyassignments = $copypolicy[2]
}

if ($null -ne $security) {
    # Security Policy
write-host "It's a Security Policy"
$id = $security.id
$Resource = "deviceManagement/intents"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$policycode = $copypolicy[0]
$policytype = $copypolicy[1]
$policyassignments = $copypolicy[2]
}
if ($null -ne $autopilot) {
    # Autopilot Profile
write-host "It's an Autopilot Profile"
$id = $autopilot.id
$Resource = "deviceManagement/windowsAutopilotDeploymentProfiles"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$policycode = $copypolicy[0]
$policytype = $copypolicy[1]
$policyassignments = $copypolicy[2]
}
if ($null -ne $esp) {
    # Autopilot ESP
write-host "It's an AutoPilot ESP"
$id = $esp.id
$Resource = "deviceManagement/deviceEnrollmentConfigurations"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$policycode = $copypolicy[0]
$policytype = $copypolicy[1]
$policyassignments = $copypolicy[2]
}
if ($null -ne $android) {
    # Android App Protection
write-host "It's an Android App Protection Policy"
$id = $android.id
$Resource = "deviceAppManagement/managedAppPoliciesandroid"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$policycode = $copypolicy[0]
$policytype = $copypolicy[1]
$policyassignments = $copypolicy[2]
}
if ($null -ne $ios) {
    # iOS App Protection
write-host "It's an iOS App Protection Policy"
$id = $ios.id
$Resource = "deviceAppManagement/managedAppPoliciesios"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$policycode = $copypolicy[0]
$policytype = $copypolicy[1]
$policyassignments = $copypolicy[2]
}
if ($null -ne $aad) {
    # AAD Groups
write-host "It's an AAD Group"
$id = $aad.id
$Resource = "groups"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$policycode = $copypolicy[0]
$policytype = $copypolicy[1]
$policyassignments = $copypolicy[2]
}
if ($null -ne $ca) {
    # Conditional Access
write-host "It's a Conditional Access Policy"
$id = $ca.id
$Resource = "ConditionalAccess"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$policycode = $copypolicy[0]
$policytype = $copypolicy[1]
$policyassignments = $copypolicy[2]
}
if ($null -ne $wingetapp) {
    # Winget App
write-host "It's a Windows Application"
$id = $wingetapp.id
$Resource = "deviceAppManagement/mobileApps"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$policycode = $copypolicy[0]
$policytype = $copypolicy[1]
$policyassignments = $copypolicy[2]
}
if ($null -ne $win365usersettings) {
    # W365 User Settings
write-host "It's a W365 User Setting"
$id = $win365usersettings.id
$Resource = "deviceManagement/virtualEndpoint/userSettings"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$policycode = $copypolicy[0]
$policytype = $copypolicy[1]
$policyassignments = $copypolicy[2]
}
if ($null -ne $win365provisioning) {
    # W365 Provisioning Policy
write-host "It's a W365 Provisioning Policy"
$id = $win365provisioning.id
$Resource = "deviceManagement/virtualEndpoint/provisioningPolicies"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$policycode = $copypolicy[0]
$policytype = $copypolicy[1]
$policyassignments = $copypolicy[2]
}
}