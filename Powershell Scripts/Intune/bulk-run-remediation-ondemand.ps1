<#PSScriptInfo
.VERSION 1.0.0
.GUID 26fabcfd-1773-409e-a952-a8f94fbe660b
.AUTHOR AndrewTaylor
.DESCRIPTION Bulk Run remediations on demand
.COMPANYNAME 
.COPYRIGHT GPL
.TAGS intune endpoint MEM 
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
 Bulk Run remediations on demand
.DESCRIPTION
.Bulk Run remediations on demand

.INPUTS
Device ID and Remediation ID (from Gridview)
.OUTPUTS
In-Line Outputs
.NOTES
  Version:        1.0.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  06/09/2023
  Purpose/Change: Initial script development
.EXAMPLE
N/A
#>

[cmdletbinding()]
    
param
(
    [string]$tenant #Tenant ID (optional) for when automating and you want to use across tenants instead of hard-coded
    ,
    [string]$clientid #ClientID is the type of Azure AD App Reg ID
    ,
    [string]$clientsecret #ClientSecret is the type of Azure AD App Reg Secret
    ,
    [string]$remediationid #ID of the remediation
    ,
    [string[]]$deviceid #ID of the device

    )


###############################################################################################################
######                                         Install Modules                                           ######
###############################################################################################################
Write-Host "Installing Intune modules if required (current user scope)"

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication) {
    Write-Host "Microsoft Graph Already Installed"
} 
else {

        Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser -Repository PSGallery -Force 

}

import-module microsoft.graph.authentication

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
######                                        Graph Connection                                           ######
###############################################################################################################

Write-Verbose "Connecting to Microsoft Graph"

if ($clientid -and $clientsecret -and $tenant) {
Connect-ToGraph -Tenant $tenant -AppId $clientid -AppSecret $clientsecret
write-output "Graph Connection Established"
}
else {
##Connect to Graph
Connect-ToGraph -scopes "Group.ReadWrite.All, Device.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, DeviceManagementServiceConfig.ReadWrite.All, GroupMember.ReadWrite.All, Domain.ReadWrite.All, Organization.Read.All"
}
Write-Verbose "Graph connection established"

###############################################################################################################
######                                          Add Functions                                            ######
###############################################################################################################
function getallpagination () {
    [cmdletbinding()]
        
    param
    (
        $url
    )
        $response = (Invoke-MgGraphRequest -uri $url -Method Get -OutputType PSObject)
        $alloutput = $response.value
        
        $alloutputNextLink = $response."@odata.nextLink"
        
        while ($null -ne $alloutputNextLink) {
            $alloutputResponse = (Invoke-MGGraphRequest -Uri $alloutputNextLink -Method Get -outputType PSObject)
            $alloutputNextLink = $alloutputResponse."@odata.nextLink"
            $alloutput += $alloutputResponse.value
        }
        
        return $alloutput
        }

        function getdevicesandusers() {
            $alldevices = getallpagination -url "https://graph.microsoft.com/beta/devicemanagement/manageddevices"
            $outputarray = @()
            foreach ($value in $alldevices) {
                $objectdetails = [pscustomobject]@{
                    DeviceID = $value.id
                    DeviceName = $value.deviceName
                    OSVersion = $value.operatingSystem
                    PrimaryUser = $value.userPrincipalName
                }
            
            
                $outputarray += $objectdetails
            
            }
            
            return $outputarray
            }

###############################################################################################################
######                                              Execution                                            ######
###############################################################################################################
write-output "Checking if remediation set in parameters"
if (!$remediationid) {
write-output "Remediation not set, getting all remediations"
$remediations = getallpagination -url "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts"

write-output "Select remediation"
$selectedremediation = $remediations | Select-Object displayName, id | Out-GridView -PassThru -Title "Select Remediation"
$displayname = $selectedremediation.displayName
write-output "Remediation $displayname selected"
            


$remediationid = $selectedremediation.id
}
else {
    write-output "Remediation set as $remediationid from parameters"
}

write-output "Checking if device set in parameters"
if (!$deviceid) {
    write-output "No parameter set, grabbing devices"
$devices = getdevicesandusers

write-output "Select devices"
$selecteddevices = $devices | Select-Object DeviceID, DeviceName, OSVersion, PrimaryUser | Out-GridView -PassThru -Title "Select Devices"

write-output "Devices selected"
}
else {
    write-output "Devices set from parameters"
    $selecteddevices = $deviceid
}
$json = @"
{
	"ScriptPolicyId": "$remediationid",
}
"@
$count = 0
$alldevicecount = $selecteddevices.count
foreach ($device in $selecteddevices) {
    $count++
    write-output "Running remediation on $device.DeviceName ($count of $alldevicecount)"
    $deviceid = $device.DeviceID
    $url = "https://graph.microsoft.com/beta/deviceManagement/managedDevices('$deviceID')/initiateOnDemandProactiveRemediation"
    Invoke-MgGraphRequest -uri $url -Method Post -Body $json -ContentType "application/json"

}

