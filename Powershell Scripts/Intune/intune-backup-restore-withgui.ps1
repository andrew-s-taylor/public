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
  Version:        5.0.9
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  24/11/2022
  Updated: 17/05/2023
  Purpose/Change: Initial script development
  Change: Added support for W365 Provisioning Policies
  Change: Added support for W365 User Settings Policies
  Change: Added support for Policy Sets
  Change: Added support for Enrollment Configuration Policies
  Change: Added support for Device Categories
  Change: Added support for Device Filters
  Change: Added support for Branding Profiles
  Change: Added support for Admin Approvals
  Change: Added support for Intune Terms
  Change: Added support for custom roles
  Change: Added fix for large Settings Catalog Policies (thanks Jordan in the blog comments)
  Change: Added support for pagination when grabbing Settings Catalog policies (thanks to randomsunrize on GitHub)
  Change: Switched do-until for while loop for pagination
  Change: Added Tenant ID as an optional parameter for when using as automated backup, but multi-tenant to reduce the number of scripts required
  Change: Added option to not rename policies when restoring
  Change: Added Tenant ID to start of filename for multi-tenant use
  Change: Added better control over tenant parameter
  Change: Bug fixes on Settings Catalog pagination
  Change: Fixed pagination
  Change: Tested with 1.21.0 and removed forced version
  Change: Updated scopes for Win365
  Change: Added support for custom compliance scripts
  Change: Added support for Azure Devops Repo as well as GitHub
  Change: Performance improvement (significantly faster)
  Change: Removed pagination error (whitespace)
  Change: Added extra parameters to trigger backup or restore via ID or Name without GUI at single policy level
  Change: Added support for webhook
  Change: Replaced write-host with write-output for use with Azure Automation Runbook
  Change: Added parameter for filename to skip grid-view on automated restore
  Change: Bypass script check when running on webhook
  Change: Github fix to cope with large files
  Change: Added webhook password for extra security
  Change: Pagination fix (again)
  Change: Added support for Windows Hello for Business Config
  Change: Fixed issue with security settings not importing
  Change: Conditional Access Fix
  Change: Checked if ID is a string for Admin Template copying
  Change: Update to handle Authentication Strength in CA policies


  .EXAMPLE
N/A
#>

<#PSScriptInfo
.VERSION 5.0.9
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
    [string[]]$name #Item Name
    ,  
    [string[]]$id #Item ID
    ,  
    [string]$selected #Selected can be "all" or literally anything else
    ,  
    [string]$reponame #Reponame is the github/Azure Devops repo
    , 
    [string]$ownername #Ownername is the github account/ Azure Devops Org
    , 
    [string]$token #Token is the github/devops token
    , 
    [string]$project #Project is the project when using Azure Devops
    , 
    [string]$repotype #Repotype is the type of repo, github or azuredevops, defaults to github
    , 
    [string]$tenant #Tenant ID (optional) for when automating and you want to use across tenants instead of hard-coded
    ,
    [string]$clientid #ClientID is the type of Azure AD App Reg ID
    ,
    [string]$clientsecret #ClientSecret is the type of Azure AD App Reg Secret
    ,
    [object] $WebHookData #Webhook data for Azure Automation

    )

##WebHook Data

if ($WebHookData){

    $bodyData = ConvertFrom-Json -InputObject $WebHookData.RequestBody

$type = ((($bodyData.type) | out-string).trim())
$selected = ((($bodyData.selected) | out-string).trim())
$reponame = ((($bodyData.reponame) | out-string).trim())
$ownername = ((($bodyData.ownername) | out-string).trim())
$token = ((($bodyData.token) | out-string).trim())
$project = ((($bodyData.project) | out-string).trim())
$repotype = ((($bodyData.repotype) | out-string).trim())
$tenant = ((($bodyData.tenant) | out-string).trim())
$clientid = ((($bodyData.clientid) | out-string).trim())
$clientsecret = ((($bodyData.clientsecret) | out-string).trim())
$policyid = ((($bodyData.policyid) | out-string).trim())
$postedfilename = ((($bodyData.filename) | out-string).trim())

$keycheck = ((($bodyData.webhooksecret) | out-string).trim())

##Lets add some security, check if a password has been sent in the header

##Set my password
$webhooksecret = ""

##Check if the password is correct
if ($keycheck -ne $webhooksecret) {
    write-output "Webhook password incorrect, exiting"
    exit
}


if ($policyid) {
    ##Create array from $policyid exploded on ","
$policyid2 = $policyid -split ","
$inputid = @()
foreach ($poid in $policyid2) {
    $inputid += $poid.trim()
}
    $idcheck = $true
}
   $aadlogin = "yes"
}
else {
    write-output "No Webhook data, checking for parameters"


##Defaulting to github if nothing set above
$repocheck = $PSBoundParameters.ContainsKey('repotype')

if ($repocheck -ne $true) {
    write-output "No Repo Type set, defaulting to GitHub"
    $repoType = "github"
}
else {
    "Using $repotype for repo type"
}

##Check if parameters have been set
$namecheck = $PSBoundParameters.ContainsKey('name')
$idcheck = $PSBoundParameters.ContainsKey('id')
$clientidcheck = $PSBoundParameters.ContainsKey('clientid')
$clientsecretcheck = $PSBoundParameters.ContainsKey('clientsecret')

if (($clientidcheck -eq $true) -and ($clientsecretcheck -eq $true)) {
##AAD Secret passed, use to login
$aadlogin = "yes"

}


if ($idcheck -eq $true) {
    $inputid = $id
}

}
############################################################
############################################################
#############         POLICY NAME CHANGES      #############
############################################################
############################################################

## Change the below to "yes" if you want to change the name of the policies when restoring to Name - restore - date
$changename = "yes"

####### First check if running automated and bypass parameters to set variables below

############################################################
############################################################
############# CHANGE THIS TO USE IN AUTOMATION #############
############################################################
############################################################
$automated = "no"
############################################################

############################################################
#############           AUTOMATION NOTES       #############
############################################################

## You need to add these modules to your Automation Account if using Azure Automation
## Don't use the V2 preview versions
## https://www.powershellgallery.com/packages/PackageManagement/1.4.8.1
## https://www.powershellgallery.com/packages/Microsoft.Graph.Authentication/1.19.0
## https://www.powershellgallery.com/packages/Microsoft.Graph.Devices.CorporateManagement/1.19.0
## https://www.powershellgallery.com/packages/Microsoft.Graph.Groups/1.19.0
## https://www.powershellgallery.com/packages/Microsoft.Graph.DeviceManagement/1.19.0
## https://www.powershellgallery.com/packages/Microsoft.Graph.Identity.SignIns/1.19.0

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


##Either github or azuredevops
$repotype = "REPO_TYPE"

##Only for Azure Devops
$project = "YOUR_AZURE_DEVOPS_PROJECT"

##Only use if not set in script parameters
$tenantcheck = $PSBoundParameters.ContainsKey('tenant')
if ($tenantcheck -ne $true) {
$tenant = "TENANT_ID"
}

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


write-output "Installing Microsoft Graph modules if required (current user scope)"

#Install MS Graph if not available
#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication) {
    write-output "Microsoft Graph Authentication Already Installed"
} 
else {
        Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser -Repository PSGallery -Force
        write-output "Microsoft Graph Authentication Installed"
}

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name microsoft.graph.devices.corporatemanagement ) {
    write-output "Microsoft Graph Corporate Management Already Installed"
} 
else {
        Install-Module -Name microsoft.graph.devices.corporatemanagement  -Scope CurrentUser -Repository PSGallery -Force  
        write-output "Microsoft Graph Corporate Management Installed"
    }

    if (Get-Module -ListAvailable -Name Microsoft.Graph.Groups) {
        write-output "Microsoft Graph Groups Already Installed "
    } 
    else {
            Install-Module -Name Microsoft.Graph.Groups -Scope CurrentUser -Repository PSGallery -Force
            write-output "Microsoft Graph Groups Installed"
    }
    
    #Install MS Graph if not available
    if (Get-Module -ListAvailable -Name Microsoft.Graph.DeviceManagement) {
        write-output "Microsoft Graph DeviceManagement Already Installed"
    } 
    else {
            Install-Module -Name Microsoft.Graph.DeviceManagement -Scope CurrentUser -Repository PSGallery -Force  
            write-output "Microsoft Graph DeviceManagement Installed"
    }

    #Install MS Graph if not available
    if (Get-Module -ListAvailable -Name Microsoft.Graph.identity.signins) {
        write-output "Microsoft Graph Identity SignIns Already Installed"
    } 
    else {
            Install-Module -Name Microsoft.Graph.Identity.SignIns -Scope CurrentUser -Repository PSGallery -Force
            write-output "Microsoft Graph Identity SignIns Installed"
    }


# Load the Graph module
Import-Module microsoft.graph.authentication
import-module Microsoft.Graph.Identity.SignIns
import-module Microsoft.Graph.DeviceManagement
import-module microsoft.Graph.Groups
import-module microsoft.graph.devices.corporatemanagement

if (($automated -eq "yes") -or ($aadlogin -eq "yes")) {
 
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
write-output "Graph Connection Established"
}
else {
##Connect to Graph
Select-MgProfile -Name Beta
Connect-MgGraph -Scopes Policy.ReadWrite.ConditionalAccess, CloudPC.ReadWrite.All, DeviceManagementServiceConfig.ReadWrite.All, RoleAssignmentSchedule.ReadWrite.Directory, Domain.Read.All, Domain.ReadWrite.All, Directory.Read.All, Policy.ReadWrite.ConditionalAccess, DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, openid, profile, email, offline_access, DeviceManagementRBAC.Read.All, DeviceManagementRBAC.ReadWrite.All
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
$contentheaderraw = (Invoke-WebRequest -Uri $liveuri -Method Get -UseBasicParsing)
$contentheader = $contentheaderraw.Content.Split([Environment]::NewLine)
$liveversion = (($contentheader | Select-String 'Version:') -replace '[^0-9.]','') | Select-Object -First 1
$currentversion = ((Get-Content -Path $PSCommandPath | Select-String -Pattern "Version: *") -replace '[^0-9.]','') | Select-Object -First 1
if ($liveversion -ne $currentversion) {
write-warning "Script has been updated, please download the latest version from $liveuri"
}
}

if (!$WebHookData){
Get-ScriptVersion -liveuri "https://raw.githubusercontent.com/andrew-s-taylor/public/main/Powershell%20Scripts/Intune/intune-backup-restore-withgui.ps1"
}

###############################################################################################################
######                                          Add Functions                                            ######
###############################################################################################################


Function Add-DevopsFile(){
    
    <#
    .SYNOPSIS
    This function is used to add a file to an Azure Devops Repository
    .DESCRIPTION
    The function connects to the Azure Devops API and adds a file to a repository
    .EXAMPLE
    add-devopsfile -repo reponame -project projectname -organization orgname -filename filename -filecontent filecontent -token token
    .NOTES
    NAME: add-devopsfile
    #>
    
    [cmdletbinding()]
    
    param
    (
        $repo,
        $project,
        $organization,
        $filename,
        $filecontent,
        $token,
        $comment
    )
    

    $base64AuthInfo= [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($token)"))
    $encryptedcontent= [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($filecontent)"))

    $repoUrl = "https://dev.azure.com/$organization/$project/_apis/git/repositories/$repo"

    $repo = Invoke-RestMethod -Uri $repoUrl -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method Get
    $repoId = $repo.id

    ##Check for commits
    $pushiduri = "https://dev.azure.com/$organization/$project/_apis/git/repositories/$repoId/pushes?&`$top=1&searchCriteria.refName=refs/heads/master&api-version=6.0"
    $pushid = ((Invoke-RestMethod -Uri $pushiduri -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method Get).value).pushId
    $commituri = "https://dev.azure.com/$organization/$project/_apis/git/repositories/$repoID/pushes/$pushid`?api-version=6.0"
    $commit = ((Invoke-RestMethod -Uri $commituri -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method Get).commits).commitId

    if ($commit) {
        $oldid = $commit
    } else {
        $oldid = "0000000000000000000000000000000000000000"
    }


    # Push the commit
$pushUrl = "https://dev.azure.com/$organization/$project/_apis/git/repositories/$repoId/pushes?api-version=6.0"
$json = @"
{
    "refUpdates": [
      {
        "name": "refs/heads/master",
        "oldObjectId": "$oldid"
      }
    ],
    "commits": [
      {
        "comment": "$comment",
        "changes": [
          {
            "changeType": "add",
            "item": {
              "path": "/$filename"
            },
            "newContent": {
              "content": "$encryptedcontent",
              "contentType": "base64encoded"
            }
          }
        ]
      }
    ]
  }
"@
Invoke-RestMethod -Uri $pushUrl -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method Post -Body $json -ContentType "application/json"   
}

Function Get-DevOpsCommits(){
    
    <#
    .SYNOPSIS
    This function is used to get commits from an Azure Devops Repository
    .DESCRIPTION
    The function connects to the Azure Devops API and gets commits from a repository
    .EXAMPLE
    Get-DevOpsCommits -repo reponame -project projectname -organization orgname -token token
    .NOTES
    NAME: Get-DevOpsCommits
    #>
    
    [cmdletbinding()]
    
    param
    (
        $repo,
        $project,
        $organization,
        $token
    )
    

    $base64AuthInfo= [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($token)"))
    $repoUrl = "https://dev.azure.com/$organization/$project/_apis/git/repositories/$repo"
    $repo = Invoke-RestMethod -Uri $repoUrl -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method Get
    $repoId = $repo.id

    # Get the commits
$ProjectUrl = "https://dev.azure.com/$organization/$project/_apis/git/repositories/$repoId/commits?api-version=7.0"
$CommitInfo = (Invoke-RestMethod -Uri $ProjectUrl -Method Get -UseDefaultCredential -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)}).value

return $CommitInfo
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
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
    
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
        $response = (Invoke-MgGraphRequest -uri $uri -Method Get -OutputType PSObject)
        $allscsettings = $response.value
        
        $allscsettingsNextLink = $response."@odata.nextLink"
        
        while ($null -ne $allscsettingsNextLink) {
            $allscsettingsResponse = (Invoke-MGGraphRequest -Uri $allscsettingsNextLink -Method Get -outputType PSObject)
            $allscsettingsNextLink = $allscsettingsResponse."@odata.nextLink"
            $allscsettings += $allscsettingsResponse.value
        }
                $allscsettings  
        
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


Function Get-DeviceCompliancePolicyScripts(){
    
    <#
    .SYNOPSIS
    This function is used to get device custom compliance policy scripts from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device compliance policies
    .EXAMPLE
    Get-DeviceCompliancePolicyScripts
    Returns any device compliance policy scripts configured in Intune
    .NOTES
    NAME: Get-DeviceCompliancePolicyScripts
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/deviceComplianceScripts"
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

Function Get-Win365ProvisioningPolicies(){
    
    <#
    .SYNOPSIS
    This function is used to get Windows 365 Provisioning Policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Windows 365 Provisioning Policies
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

Function Get-IntunePolicySets(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune policy sets from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune policy sets
    .EXAMPLE
    Get-IntunePolicySets
    Returns any policy sets configured in Intune
    .NOTES
    NAME: Get-IntunePolicySets
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceAppManagement/policySets"
    try {
            if($id){
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$($id)?`$expand=items"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    
            }
    
            else {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
            }
        }
        catch {}
    
   
}

Function Get-EnrollmentConfigurations(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune enrollment configurations from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune enrollment configurations
    .EXAMPLE
    Get-EnrollmentConfigurations
    Returns any enrollment configurations configured in Intune
    .NOTES
    NAME: Get-EnrollmentConfigurations
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
    

Function Get-DeviceCategories(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune device categories from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune device categories
    .EXAMPLE
    Get-DeviceCategories
    Returns any device categories configured in Intune
    .NOTES
    NAME: Get-DeviceCategories
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/deviceCategories"
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


Function Get-DeviceFilters(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune device filters from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune device filters
    .EXAMPLE
    Get-DeviceFilters
    Returns any device filters configured in Intune
    .NOTES
    NAME: Get-DeviceFilters
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/assignmentFilters"
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


Function Get-BrandingProfiles(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune Branding Profiles from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune Branding Profiles
    .EXAMPLE
    Get-BrandingProfiles
    Returns any Branding Profiles configured in Intune
    .NOTES
    NAME: Get-BrandingProfiles
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/intuneBrandingProfiles"
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


Function Get-AdminApprovals(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune admin approvals from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune admin approvals
    .EXAMPLE
    Get-AdminApprovals
    Returns any admin approvals configured in Intune
    .NOTES
    NAME: Get-AdminApprovals
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/operationApprovalPolicies"
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

Function Get-OrgMessages(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune organizational messages from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune organizational messages
    .EXAMPLE
    Get-OrgMessages
    Returns any organizational messages configured in Intune
    .NOTES
    NAME: Get-OrgMessages
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/organizationalMessageDetails"
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


Function Get-IntuneTerms(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune terms and conditions from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune terms and conditions
    .EXAMPLE
    Get-IntuneTerms
    Returns any terms and conditions configured in Intune
    .NOTES
    NAME: Get-IntuneTerms
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/termsAndConditions"
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

Function Get-IntuneRoles(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune custom roles from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune custom roles
    .EXAMPLE
    Get-IntuneRoles
    Returns any custom roles configured in Intune
    .NOTES
    NAME: Get-IntuneRoles
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/roleDefinitions"
    try {
            if($id){
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    
            }
    
            else {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value | where-object isBuiltIn -eq $False
    
            }
        }
        catch {}
    
   
}
################################################################################################


Function Get-WHfBPolicies(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune Windows Hello for Business policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune WHfB Policies
    .EXAMPLE
    Get-WHfBPolicies
    Returns any WHfB Policies configured in Intune
    .NOTES
    NAME: Get-WHfBPolicies
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
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    
            }
    
            else {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value | where-object deviceEnrollmentConfigurationType -eq "WindowsHelloForBusiness"
    
            }
        }
        catch {}
    
   
}

Function Get-WHfBPoliciesbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune Windows Hello for Business policies from the Graph API REST interface by name
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune WHfB Policies
    .EXAMPLE
    Get-WHfBPoliciesbyName
    Returns any WHfB Policies configured in Intune
    .NOTES
    NAME: Get-WHfBPoliciesbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/deviceEnrollmentConfigurations"
    try {
    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$($DCP_resource)"
        $allpolicies = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value | where-object deviceEnrollmentConfigurationType -eq "WindowsHelloForBusiness"
        $app = $allpolicies | Where-Object DisplayName -eq $name


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
$check = Get-WHfBPoliciesbyName -name $name
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
    $id = $policyid
    $graphApiVersion = "beta"
    switch ($resource) {
    "deviceManagement/deviceConfigurations" {
     $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
     $policy = Get-DecryptedDeviceConfigurationPolicy -dcpid $id
     $oldname = $policy.displayName
     $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
     if ($changename -eq "yes") {
        $newname = $oldname + "-restore-" + $restoredate
    }
    else {
        $newname = $oldname
    }
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
        if ($changename -eq "yes") {
            $newname = $oldname + "-restore-" + $restoredate
        }
        else {
            $newname = $oldname
        }        $policy.displayName = $newname
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
        if ($changename -eq "yes") {
            $newname = $oldname + "-restore-" + $restoredate
        }
        else {
            $newname = $oldname
        }        $policy.displayName = $newname
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
        if ($changename -eq "yes") {
            $newname = $oldname + "-restore-" + $restoredate
        }
        else {
            $newname = $oldname
        }        $policy.displayName = $newname
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

       "deviceManagement/deviceComplianceScripts" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $policy = Get-DeviceCompliancePolicyScripts -id $id
        $oldname = $policy.DisplayName
        $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
        if ($changename -eq "yes") {
            $newname = $oldname + "-restore-" + $restoredate
        }
        else {
            $newname = $oldname
        }        $policy.displayName = $newname
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
        $firstsettings = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$id/settings" -OutputType PSObject
        $settings = $firstsettings.value
        $policynextlink = $firstsettings."@odata.nextlink"
        #$policynextlink = $policynextlink -replace '\S', ''
        while (($policynextlink -ne "") -and ($null -ne $policynextlink))
        {
            $nextsettings = (Invoke-MgGraphRequest -Uri $policynextlink -Method Get -OutputType PSObject)
            $policynextlink = $nextsettings."@odata.nextLink"
            #$policynextlink = $policynextlink -replace '\S', ''
            $settings += $nextsettings.value
        }

        $settings =  $settings | select-object * -ExcludeProperty '@odata.count'
        if ($settings -isnot [System.Array]) {
            $policy.Settings = @($settings)
        } else {
            $policy.Settings = $settings
        }
        
        #
        $oldname = $policy.Name
        $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
        if ($changename -eq "yes") {
            $newname = $oldname + "-restore-" + $restoredate
        }
        else {
            $newname = $oldname
        }        $policy.Name = $newname

    }
    
    "deviceManagement/deviceCompliancePolicies" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $policy = Get-DeviceCompliancePolicy -id $id
        $oldname = $policy.DisplayName
        $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
        if ($changename -eq "yes") {
            $newname = $oldname + "-restore-" + $restoredate
        }
        else {
            $newname = $oldname
        }        $policy.displayName = $newname
        
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
        if ($changename -eq "yes") {
            $newname = $oldname + "-restore-" + $restoredate
        }
        else {
            $newname = $oldname
        }           $policy = @{
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
        if ($changename -eq "yes") {
            $newname = $oldname + "-restore-" + $restoredate
        }
        else {
            $newname = $oldname
        }           $policy.displayName = $newname
    }
    "groups" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $policy = Get-GraphAADGroups -id $id
        $oldname = $policy.displayName
        $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
        if ($changename -eq "yes") {
            $newname = $oldname + "-restore-" + $restoredate
        }
        else {
            $newname = $oldname
        }           $policy.displayName = $newname
        $policy = $policy | Select-Object description, DisplayName, groupTypes, mailEnabled, mailNickname, securityEnabled, isAssignabletoRole, membershiprule, MembershipRuleProcessingState
    }
    "deviceManagement/deviceEnrollmentConfigurationsESP" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/deviceManagement/deviceEnrollmentConfigurations"
        $policy = Get-AutoPilotESP -id $id
        $oldname = $policy.displayName
        $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
        if ($changename -eq "yes") {
            $newname = $oldname + "-restore-" + $restoredate
        }
        else {
            $newname = $oldname
        }           $policy.displayName = $newname
    }
    "deviceManagement/virtualEndpoint/userSettings" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $policy = Get-Win365UserSettings -id $id
        $oldname = $policy.displayName
        $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
        if ($changename -eq "yes") {
            $newname = $oldname + "-restore-" + $restoredate
        }
        else {
            $newname = $oldname
        }        $policy.displayName = $newname
    }
    "deviceManagement/virtualEndpoint/provisioningPolicies" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $policy = Get-Win365ProvisioningPolicies -id $id
        $oldname = $policy.displayName
        $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
        if ($changename -eq "yes") {
            $newname = $oldname + "-restore-" + $restoredate
        }
        else {
            $newname = $oldname
        }        $policy.displayName = $newname
    }
    "deviceAppManagement/managedAppPoliciesandroid" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/managedAppPolicies"
        #$policy = Invoke-RestMethod -Uri "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/managedAppPolicies('$id')" -Headers $authToken -Method Get
        $policy = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/managedAppPolicies('$id')" -OutputType PSObject
        $oldname = $policy.displayName
        $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
        if ($changename -eq "yes") {
            $newname = $oldname + "-restore-" + $restoredate
        }
        else {
            $newname = $oldname
        }           $policy.displayName = $newname
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
        if ($changename -eq "yes") {
            $newname = $oldname + "-restore-" + $restoredate
        }
        else {
            $newname = $oldname
        }           $policy.displayName = $newname
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
        if ($changename -eq "yes") {
            $newname = $oldname + "-restore-" + $restoredate
        }
        else {
            $newname = $oldname
        }           $policy.displayName = $newname
        $policy = $policy | Select-Object * -ExcludeProperty uploadState, publishingState, isAssigned, dependentAppCount, supersedingAppCount, supersededAppCount
    }
    "deviceAppManagement/policySets" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $policy = Get-IntunePolicySets -id $id
        $oldname = $policy.displayName
        $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
        if ($changename -eq "yes") {
            $newname = $oldname + "-restore-" + $restoredate
        }
        else {
            $newname = $oldname
        }        $policy.displayName = $newname
        $policyitems = $policy.items | select-object * -ExcludeProperty createdDateTime, lastModifiedDateTime, id, itemType, displayName, status, errorcode, priority, targetedAppManagementLevels
        $policy.items = $policyitems
        $policy = $policy | Select-Object * -ExcludeProperty '@odata.context', status, errorcode, 'items@odata.context'
    }
    "deviceManagement/deviceEnrollmentConfigurations" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $policy = Get-EnrollmentConfigurations -id $id
        $oldname = $policy.displayName
        $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
        if ($changename -eq "yes") {
            $newname = $oldname + "-restore-" + $restoredate
        }
        else {
            $newname = $oldname
        }        $policy.displayName = $newname
    }
    "deviceManagement/deviceEnrollmentConfigurationswhfb" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/deviceManagement/deviceEnrollmentConfigurations"
        $policy = Get-WHfBPolicies -id $id
        $oldname = $policy.displayName
        $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
        if ($changename -eq "yes") {
            $newname = $oldname + "-restore-" + $restoredate
        }
        else {
            $newname = $oldname
        }        $policy.displayName = $newname
    }
    "deviceManagement/deviceCategories" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $policy = Get-DeviceCategories -id $id
        $oldname = $policy.displayName
        $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
        if ($changename -eq "yes") {
            $newname = $oldname + "-restore-" + $restoredate
        }
        else {
            $newname = $oldname
        }        $policy.displayName = $newname
    }
    "deviceManagement/assignmentFilters" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $policy = Get-DeviceFilters -id $id
        $oldname = $policy.displayName
        $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
        if ($changename -eq "yes") {
            $newname = $oldname + "-restore-" + $restoredate
        }
        else {
            $newname = $oldname
        }        $policy.displayName = $newname
        $policy = $policy | Select-Object * -ExcludeProperty Payloads
    }
    "deviceManagement/intuneBrandingProfiles" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $policy = Get-BrandingProfiles -id $id
        $oldname = $policy.profileName
        $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
        if ($changename -eq "yes") {
            $newname = $oldname + "-restore-" + $restoredate
        }
        else {
            $newname = $oldname
        }        $policy.profileName = $newname
    }
    "deviceManagement/operationApprovalPolicies" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $policy = Get-AdminApprovals -id $id
        $oldname = $policy.displayName
        $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
        if ($changename -eq "yes") {
            $newname = $oldname + "-restore-" + $restoredate
        }
        else {
            $newname = $oldname
        }        $policy.displayName = $newname
    }
    "deviceManagement/organizationalMessageDetails" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $policy = Get-OrgMessages -id $id
        $oldname = $policy.displayName
        $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
        if ($changename -eq "yes") {
            $newname = $oldname + "-restore-" + $restoredate
        }
        else {
            $newname = $oldname
        }        $policy.displayName = $newname
    }
    "deviceManagement/termsAndConditions" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $policy = Get-IntuneTerms -id $id
        $oldname = $policy.displayName
        $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
        if ($changename -eq "yes") {
            $newname = $oldname + "-restore-" + $restoredate
        }
        else {
            $newname = $oldname
        }        $policy.displayName = $newname
        $policy = $policy | Select-Object * -ExcludeProperty modifiedDateTime
    }
    "deviceManagement/roleDefinitions" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $policy = Get-IntuneRoles -id $id
        $oldname = $policy.displayName
        $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
        if ($changename -eq "yes") {
            $newname = $oldname + "-restore-" + $restoredate
        }
        else {
            $newname = $oldname
        }        $policy.displayName = $newname
    }
    }

    ##We don't want to convert CA policy to JSON
    if (($resource -eq "conditionalaccess")) {
        $policy = $policy
            ##If Authentication strength is included, we need to make some tweaks
    if ($policy.grantControls.authenticationStrength) {
        $policy.grantControls = $policy.grantControls | Select-Object * -ExcludeProperty authenticationStrength@odata.context
        $policy.grantControls.authenticationStrength = $policy.grantControls.authenticationStrength | Select-Object id
        write-host "set"
        }
    
    }
    else {
    # Remove any GUIDs or dates/times to allow Intune to regenerate
    if ($resource -eq "deviceManagement/termsAndConditions") {
        ##We need the version number for T&Cs
        $policy = $policy | Select-Object * -ExcludeProperty id, createdDateTime, LastmodifieddateTime, creationSource, '@odata.count' | ConvertTo-Json -Depth 100
    
        }
        else {
        $policy = $policy | Select-Object * -ExcludeProperty id, createdDateTime, LastmodifieddateTime, version, creationSource, '@odata.count' | ConvertTo-Json -Depth 100
        }
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

##Check if any parameters have been passed
if (($namecheck -ne $true) -and ($idcheck -ne $true)) {

##Get Config Policies
$configuration += Get-DeviceConfigurationPolicy | Select-Object ID, DisplayName, Description, @{N='Type';E={"Config Policy"}}

##Get Admin Template Policies
$configuration += Get-DeviceConfigurationPolicyGP | Select-Object ID, DisplayName, Description, @{N='Type';E={"Admin Template"}}


##Get Settings Catalog Policies
$configuration += Get-DeviceConfigurationPolicySC | Select-Object @{N='ID';E={$_.id}}, @{N='DisplayName';E={$_.Name}}, @{N='Description';E={$_.Description}} , @{N='Type';E={"Settings Catalog"}}

##Get Compliance Policies
$configuration += Get-DeviceCompliancePolicy | Select-Object ID, DisplayName, Description, @{N='Type';E={"Compliance Policy"}}

##Get Proactive Remediations
$configuration += Get-DeviceProactiveRemediations | Select-Object ID, DisplayName, Description, @{N='Type';E={"Proactive Remediation"}}

##Get Device Scripts
$configuration += Get-DeviceManagementScripts | Select-Object ID, DisplayName, Description, @{N='Type';E={"PowerShell Script"}}

##Get Compliance Scripts
$configuration += Get-DeviceCompliancePolicyScripts | Select-Object ID, DisplayName, Description, @{N='Type';E={"Compliance Script"}}


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

##Get Intune Policy Sets
$configuration += Get-IntunePolicySets | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Policy Set"}}

##Get Enrollment Configurations
$configuration += Get-EnrollmentConfigurations | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Enrollment Configuration"}}

##Get WHfBPolicies
$configuration += Get-WHfBPolicies | Select-Object ID, DisplayName, Description,  @{N='Type';E={"WHfB Policy"}}

##Get Device Categories
$configuration += Get-DeviceCategories | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Device Categories"}}

##Get Device Filters
$configuration += Get-DeviceFilters | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Device Filter"}}

##Get Branding Profiles
$configuration += Get-BrandingProfiles | Select-Object ID, @{N='DisplayName';E={$_.profileName}}, Description,  @{N='Type';E={"Branding Profile"}}

##Get Admin Approvals
$configuration += Get-AdminApprovals | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Admin Approval"}}

##Get Org Messages
##NOTE: API NOT LIVE YET
#$configuration += Get-OrgMessages | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Organization Message"}}

##Get Intune Terms
$configuration += Get-IntuneTerms | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Intune Terms"}}

##Get Intune Roles
$configuration += Get-IntuneRoles | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Intune Role"}}



if (($automated -eq "yes") -or ($WebHookData)) {
    $configuration2 = $configuration
    }
else {
    $configuration2 = $configuration | Out-GridView -PassThru -Title "Select policies to backup"

}

}
else {
$configuration2 = @()
    ##Parameters passed, check what they are
    if ($namecheck -eq $true) {
        ##Name(s) sent, convert to ID and pass-through
        foreach ($item in $name) {
            write-output "Getting ID for $name"
            $policyid = (Get-DetailsbyName -name $item)
            $id = $policyid.ID
            write-output "ID is $id"
            $configuration2 += $policyid
        }
    }
    if ($idcheck -eq $true) {
        ##ID(s) sent, pass-through
        foreach ($item in $inputid) {
            write-output "Copying policy $id"
            $object = "" | select-object id
            $object.id = $item
            $configuration2 += $object
        }

    }
}

$configuration2 | foreach-object {

##Find out what it is
$id = $_.ID
write-output $id
##Performance improvement, use existing array instead of additional graph calls

if (($namecheck -ne $true) -and ($idcheck -ne $true)) {
    $policy = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Config Policy")}
    $catalog = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Settings Catalog")}
    $compliance = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Compliance Policy")}
    $security = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Security Policy")}
    $autopilot = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Autopilot Profile")}
    $esp = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Autopilot ESP")}
    $android = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Android App Protection")}
    $ios = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "iOS App Protection")}
    $gp = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Admin Template")}
    $ca = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Conditional Access Policy")}
    $proac = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Proactive Remediation")}
    $aad = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "AAD Group")}
    $wingetapp = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Winget Application")}
    $scripts = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "PowerShell Script")}
    $compliancescripts = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Compliance Script")}
    $win365usersettings = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Win365 User Settings")}
    $win365provisioning = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Win365 Provisioning Policy")}
    $policysets = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Policy Set")}
    $enrollmentconfigs = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Enrollment Configuration")}
    $devicecategories = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Device Categories")}
    $devicefilters = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Device Filter")}
    $brandingprofiles = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Branding Profile")}
    $adminapprovals = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Admin Approval")}
    $intuneterms = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Intune Terms")}
    $intunerole = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Intune Role")}
    $whfb = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "WHfB Policy")}

    }
    else {
        
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
    $compliancescripts = Get-DeviceCompliancePolicyScripts -id $id
    $win365usersettings = Get-Win365UserSettings -id $id
    $win365provisioning = Get-Win365ProvisioningPolicies -id $id
    $policysets = Get-IntunePolicySets -id $id
    $enrollmentconfigs = Get-EnrollmentConfigurations -id $id
    $devicecategories = Get-DeviceCategories -id $id
    $devicefilters = Get-DeviceFilters -id $id
    $brandingprofiles = Get-BrandingProfiles -id $id
    $adminapprovals = Get-AdminApprovals -id $id
    #$orgmessages = Get-OrgMessages -id $id
    $intuneterms = Get-IntuneTerms -id $id
    $intunerole = Get-IntuneRoles -id $id
    $whfb = get-whfbpolicy -id $id
    }





# Copy it
if ($null -ne $policy) {
    # Standard Device Configuratio Policy
write-output "It's a policy"
$id = $policy.id
$Resource = "deviceManagement/deviceConfigurations"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))

}
if ($null -ne $gp) {
    # Standard Device Configuration Policy
write-output "It's an Admin Template"
$id = $gp.id
$Resource = "deviceManagement/groupPolicyConfigurations"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}
if ($null -ne $catalog) {
    # Settings Catalog Policy
write-output "It's a Settings Catalog"
$id = $catalog.id
$Resource = "deviceManagement/configurationPolicies"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))

}
if ($null -ne $compliance) {
    # Compliance Policy
write-output "It's a Compliance Policy"
$id = $compliance.id
$Resource = "deviceManagement/deviceCompliancePolicies"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}
if ($null -ne $proac) {
    # Proactive Remediations
write-output "It's a Proactive Remediation"
$id = $proac.id
$Resource = "deviceManagement/devicehealthscripts"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}
if ($null -ne $scripts) {
    # Device Scripts
    write-output "It's a PowerShell Script"
$id = $scripts.id
$Resource = "deviceManagement/devicemanagementscripts"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}

if ($null -ne $compliancescripts) {
    # Compliance Scripts
    write-output "It's a Compliance Script"
$id = $compliancescripts.id
$Resource = "deviceManagement/deviceComplianceScripts"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}

if ($null -ne $security) {
    # Security Policy
write-output "It's a Security Policy"
$id = $security.id
$Resource = "deviceManagement/intents"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}
if ($null -ne $autopilot) {
    # Autopilot Profile
write-output "It's an Autopilot Profile"
$id = $autopilot.id
$Resource = "deviceManagement/windowsAutopilotDeploymentProfiles"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}
if ($null -ne $esp) {
    # Autopilot ESP
write-output "It's an AutoPilot ESP"
$id = $esp.id
$Resource = "deviceManagement/deviceEnrollmentConfigurationsESP"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}
if ($null -ne $whfb) {
    # Windows Hello for Business
write-output "It's a WHfB Policy"
$id = $esp.id
$Resource = "deviceManagement/deviceEnrollmentConfigurationswhfb"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}
if ($null -ne $android) {
    # Android App Protection
write-output "It's an Android App Protection Policy"
$id = $android.id
$Resource = "deviceAppManagement/managedAppPoliciesandroid"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}
if ($null -ne $ios) {
    # iOS App Protection
write-output "It's an iOS App Protection Policy"
$id = $ios.id
$Resource = "deviceAppManagement/managedAppPoliciesios"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}
if ($null -ne $aad) {
    # AAD Groups
write-output "It's an AAD Group"
$id = $aad.id
$Resource = "groups"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}
if ($null -ne $ca) {
    # Conditional Access
write-output "It's a Conditional Access Policy"
$id = $ca.id
$Resource = "ConditionalAccess"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}
if ($null -ne $wingetapp) {
    # Winget App
write-output "It's a Windows Application"
$id = $wingetapp.id
$Resource = "deviceAppManagement/mobileApps"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}
if ($null -ne $win365usersettings) {
    # W365 User Settings
write-output "It's a W365 User Setting"
$id = $win365usersettings.id
$Resource = "deviceManagement/virtualEndpoint/userSettings"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}
if ($null -ne $win365provisioning) {
    # W365 Provisioning Policy
write-output "It's a W365 Provisioning Policy"
$id = $win365provisioning.id
$Resource = "deviceManagement/virtualEndpoint/provisioningPolicies"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}
if ($null -ne $policysets) {
    # Policy Set
write-output "It's a Policy Set"
$id = $policysets.id
$Resource = "deviceAppManagement/policySets"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}
if ($null -ne $enrollmentconfigs) {
    # Enrollment Config
write-output "It's an enrollment configuration"
$id = $enrollmentconfigs.id
$Resource = "deviceManagement/deviceEnrollmentConfigurations"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}
if ($null -ne $devicecategories) {
    # Device Categories
write-output "It's a device category"
$id = $devicecategories.id
$Resource = "deviceManagement/deviceCategories"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}
if ($null -ne $devicefilters) {
    # Device Filter
write-output "It's a device filter"
$id = $devicefilters.id
$Resource = "deviceManagement/assignmentFilters"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}
if ($null -ne $brandingprofiles) {
    # Branding Profile
write-output "It's a branding profile"
$id = $brandingprofiles.id
$Resource = "deviceManagement/intuneBrandingProfiles"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}
if ($null -ne $adminapprovals) {
    # Multi-admin approval
write-output "It's a multi-admin approval"
$id = $adminapprovals.id
$Resource = "deviceManagement/operationApprovalPolicies"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}
#if ($null -ne $orgmessages) {
    # Organizational Message
#write-output "It's an organizational message"
#$id = $orgmessages.id
#$Resource = "deviceManagement/organizationalMessageDetails"
#$copypolicy = getpolicyjson -resource $Resource -policyid $id
#$profiles+= ,(@($copypolicy[0],$copypolicy[1], $id))
#}
if ($null -ne $intuneterms) {
    # Intune Terms
write-output "It's a T&C"
$id = $intuneterms.id
$Resource = "deviceManagement/termsAndConditions"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}
if ($null -ne $intunerole) {
    # Intune Role
write-output "It's a role"
$id = $intunerole.id
$Resource = "deviceManagement/roleDefinitions"
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
    if (($namecheck -ne $true) -and ($idcheck -ne $true)) {
        $backupreason = "Automated Backup on $id"
    } else {
##Prompt for Message
[void][Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic')

$title = 'Reason'
$msg   = 'Enter your backup reason:'

$backupreason = [Microsoft.VisualBasic.Interaction]::InputBox($msg, $title)
    }
}

if ($repotype -eq "github") {
    write-output "Uploading to Github"
##Upload to GitHub
$date =get-date -format yyMMddHHmmss
$date = $date.ToString()
$readabledate = get-date -format dd-MM-yyyy-HH-mm-ss
$filename = $tenant+"-intunebackup-"+$date+".json"
$uri = "https://api.github.com/repos/$ownername/$reponame/contents/$filename"
$message = "$backupreason - $readabledate"
$body = '{{"message": "{0}", "content": "{1}" }}' -f $message, $profilesencoded
(Invoke-RestMethod -Uri $uri -Method put -Headers @{'Authorization'='bearer '+$token; 'Accept'='Accept: application/vnd.github+json'} -Body $body -ContentType "application/json")
}
if ($repotype -eq "azuredevops") {
    $date =get-date -format yyMMddHHmmss
$date = $date.ToString()

    $filename = $tenant+"-intunebackup-"+$date+".json"
    write-output "Uploading to Azure DevOps"
    Add-DevopsFile -repo $reponame -project $project -organization $ownername -filename $filename -filecontent $profilesjson -token $token -comment $backupreason

}


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

if ($repotype -eq "github") {

    if ($WebHookData){
        $filename = $postedfilename
    }
    else {

    
    write-output "Finding Latest Backup Commit from Repo $reponame in $ownername GitHub"
    $uri = "https://api.github.com/repos/$ownername/$reponame/commits"
    $events = (Invoke-RestMethod -Uri $uri -Method Get -Headers @{'Authorization'='bearer '+$token; 'Accept'='Accept: application/vnd.github+json'}).commit
    $events2 = $events | Select-object message, url| Out-GridView -PassThru -Title "Select Backup to View"
        ForEach ($event in $events2) 
        {
    $eventsuri = $event.url
    $commitid = Split-Path $eventsuri -Leaf
    $commituri = "https://api.github.com/repos/$ownername/$reponame/commits/$commitid"
    $commitfilename = ((Invoke-RestMethod -Uri $commituri -Method Get -Headers @{'Authorization'='token '+$token; 'Accept'='application/json'}).Files).raw_url
    write-output "$commitfilename Found"
    }
    
    
    $filename = $commitfilename.Substring($commitfilename.LastIndexOf("/") + 1)
}
    $commitfilename2 = " https://api.github.com/repos/$ownername/$reponame/contents/$filename"
    
    
    $decodedbackup = (Invoke-RestMethod -Uri $commitfilename2 -Method Get -Headers @{'Authorization'='bearer '+$token; 'Accept'='Accept: application/vnd.github.v3.raw';'Cache-Control'='no-cache'})
    
    }
    
    if ($repotype -eq "azuredevops") {

        $base64AuthInfo= [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($token)"))

        if ($WebHookData){
            $commitfilename2 = $postedfilename
        }
        else {
        write-output "Finding Latest Backup Commit from Repo $reponame in $ownername DevOps"
        $events = Get-DevOpsCommits -repo $reponame -project $project -organization $ownername -token $token
        $events2 = $events | Select-object comment, url| Out-GridView -PassThru -Title "Select Backup to View" 
        ForEach ($event in $events2) 
        {
            $eventsuri = $event.url
            $commitid = Split-Path $eventsuri -Leaf
            $commituri = "https://dev.azure.com/$ownername/$project/_apis/git/repositories/$reponame/commits/$commitid/changes"
            $commitfilename2 = (((Invoke-RestMethod -Uri $commituri -Method Get -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)}).changes))[0].item.path
        }
    }
            $repoUrl = "https://dev.azure.com/$ownername/$project/_apis/git/repositories/$reponame"
            $repo = Invoke-RestMethod -Uri $repoUrl -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method Get
            $repoId = $repo.id
            $jsonuri = " https://dev.azure.com/$ownername/$project/_apis/git/repositories/$reponame/items?scopepath=$commitfilename2&api-version=7.0&version=master"
            $decodedbackup2 = (Invoke-RestMethod -Uri $jsonuri -Method Get -UseDefaultCredential -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)})
            $decodedbackup = $decodedbackup2.Substring(1)
            
    
    
    
    }
    
    
###############################################################################################################
######                                         GridView Policies within Backup                           ######
###############################################################################################################

if ($repotype -eq "azuredevops") {
$profilelist2 = $decodedbackup | ConvertFrom-Json
}
if ($repotype -eq "github") {
$profilelist2 = $decodedbackup
}
$oneormore = $profilelist2.Count
write-host $oneormore
if ($oneormore -gt 4) {

$fullist = $profilelist2
$profilelist3 = $profilelist2
$looplist = $profilelist3
$profilelist = @()
$idtoname = @()
foreach ($profiletemp in $fullist) {
    $value1 =  ($profiletemp.value)[2]
    $prid = ($profiletemp.value)[3]
    $profilelist += $value1
    $idtoname += [pscustomobject]@{
        id = $prid
        name = $value1
    }
}
}
else {
$fulllist = $profilelist2.value
$profilelist3 = $fulllist
$looplist = $profilelist3 | Select-Object -First 1
$profilelist = @()
$idtoname = @()
    $value1 =  ($profilelist3)[2]
    $prid = ($profilelist3)[3]
    $profilelist += $value1
    $idtoname += [pscustomobject]@{
        id = $prid
        name = $value1
    }
}


if (($namecheck -ne $true) -and ($idcheck -ne $true)) {


if ($selected -eq "all") {
    $temp = $profilelist
    }
else {
    $temp = $profilelist | Out-GridView -Title "Select Object to Restore" -PassThru

}
}
else {
    $temp = @()

    if ($namecheck -eq $true) {
        foreach ($item in $name) {
            $temp += $profilelist | Where-Object { $_ -like "*$item*"}
        }
    }
    if ($idcheck -eq $true) {
        foreach ($item in $inputid) {
            $temp += ($idtoname | Where-Object { $_.id -eq $item} | Select-Object Name).Name
        }    
    }

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
            write-output $profilevalue[1]
            $policy = $policyjson
            ##If policy is conditional access, we need special config
            if ($policyuri -eq "conditionalaccess") {
                write-output "Creating Conditional Access Policy"
                $uri = "https://graph.microsoft.com/beta/identity/conditionalAccess/policies"
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
                
                ##Check if ID is a string and if not convert it
                if ($id -is [string]) {
                    $id = $id
                }
                else {
                    $id = $id.tostring()
                }

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
            if ($policyuri -like "https://graph.microsoft.com/beta/deviceManagement/templates*") {
                write-host "It's a security intent, add the settings"
                $policyid = $copypolicy.id
                $uri = "https://graph.microsoft.com/beta/deviceManagement/intents/$policyid/updateSettings"
                $values = ($policyjson | convertfrom-json).values[1]
                $settingjson = @"
                {
      "settings": [
"@
    $countarray = $values.Count
    $start = 0
    foreach ($value in $values) {
    $settingjson += $value | convertto-json
    $start++
    if ($start -ne $countarray) {
    $settingjson += ","
    }
    }
                $settingjson += @"
      ]
    }
"@
                $body = ([System.Text.Encoding]::UTF8.GetBytes($settingjson.tostring()))
    
    Invoke-MgGraphRequest -Uri $uri -Method POST -Body $body -ContentType "application/json; charset=utf-8" 
    
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
        if (!$WebHookData){
            Stop-Transcript        
        }
