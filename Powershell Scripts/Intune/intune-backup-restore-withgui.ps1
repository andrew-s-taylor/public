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
  Version:        7.0.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  24/11/2022
  Updated: 10/05/2024
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
  Change: Added support for Mobile App Config policies
  Change: Repaired pagination issue with Settings Catalog
  Change: Added support for assignments
  Change: Added support for GitLab
  Change: Added logging during runbook
  Change: Added support for template creation
  Change: Set connection to use basic parsing for runbooks
  Change: Fix for Boolean custom policies
  Change: Added feature and quality updates
  Change: Added support for Git pagination
  Change: Added Driver Update profiles
  Change: Group creation fix
  Change: Switched array so groups deploy first
  Change: Added live migration support for a tenant to tenant migration


  .EXAMPLE
N/A
#>

<#PSScriptInfo
.VERSION 7.0.0
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
    [ValidateSet("backup", "restore", "livemigration")]
    [string]$type #Type can be "backup", "restore" or "livemigration"
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
    [string]$project #Project is the project when using Azure Devops or Project ID when using GitLab
    , 
    [string]$repotype #Repotype is the type of repo, github, gitlab or azuredevops, defaults to github
    , 
    [string]$tenant #Tenant ID (optional) for when automating and you want to use across tenants instead of hard-coded
    ,
    [string]$secondtenant #Tenant ID for destination tenant(optional) for when automating and you want to use across tenants instead of hard-coded
    ,
    [string]$clientid #ClientID is the type of Azure AD App Reg ID
    ,
    [string]$clientsecret #ClientSecret is the type of Azure AD App Reg Secret
    ,
    [string]$assignments #Assignments triggers restoration of polciy assignments
    ,
    [string]$groupcreate #Create groups if they don't exist, works with assignments
    ,
    [string]$template #Used with backup, adds "template" to the filename, can be "yes" or "no"
    ,
    [string]$templatename #Used with backup, adds a name to the template
    ,
    [string]$rename #Adds "restored" to restored policies
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
$assignments = ((($bodyData.assignments) | out-string).trim())
$groupcreate = ((($bodyData.groupcreate) | out-string).trim())
$templatecheck  = ((($bodyData.template) | out-string).trim())
$templatename  = ((($bodyData.templatename) | out-string).trim())
$rename = ((($bodyData.rename) | out-string).trim())
$secondtenant = ((($bodyData.secondtenant) | out-string).trim())


$keycheck = ((($bodyData.webhooksecret) | out-string).trim())

##Lets add some security, check if a password has been sent in the header

##Set my password
$webhooksecret = ""

##Check if the password is correct
if ($keycheck -ne $webhooksecret) {
    #write-output "Webhook password incorrect, exiting"
    #exit
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
$templatetest1 = $PSBoundParameters.ContainsKey('template')

if ($templatetest1 -eq $true) {
    $templatecheck = $template
}


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
if ($rename -eq "yes") {
    $changename -eq "yes"
}
else {
$changename = "no"
}

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

##Only for Azure Devops or GitLab
$project = "YOUR_AZURE_DEVOPS_PROJECT_OR_GITLAB_ID"


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

##Add custom logging for runbook
$Logfile = "$env:TEMP\intuneauto-$date.log"
function WriteLog
{
Param ([string]$LogString)
$Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
$LogMessage = "$Stamp $LogString \n"
Add-content $LogFile -value $LogMessage
}

#Install MS Graph if not available


write-output "Installing Microsoft Graph modules if required (current user scope)"
writelog "Installing Microsoft Graph modules if required (current user scope)"


#Install MS Graph if not available
#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication) {
    write-output "Microsoft Graph Authentication Already Installed"
    writelog "Microsoft Graph Authentication Already Installed"
} 
else {
        Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser -Repository PSGallery -Force
        write-output "Microsoft Graph Authentication Installed"
        writelog "Microsoft Graph Authentication Installed"
}

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name microsoft.graph.devices.corporatemanagement ) {
    write-output "Microsoft Graph Corporate Management Already Installed"
    writelog "Microsoft Graph Corporate Management Already Installed"

} 
else {
        Install-Module -Name microsoft.graph.devices.corporatemanagement  -Scope CurrentUser -Repository PSGallery -Force  
        write-output "Microsoft Graph Corporate Management Installed"
        writelog "Microsoft Graph Corporate Management Installed"

    }

    if (Get-Module -ListAvailable -Name Microsoft.Graph.Groups) {
        write-output "Microsoft Graph Groups Already Installed "
        writelog "Microsoft Graph Groups Already Installed "

    } 
    else {
            Install-Module -Name Microsoft.Graph.Groups -Scope CurrentUser -Repository PSGallery -Force
            write-output "Microsoft Graph Groups Installed"
            writelog "Microsoft Graph Groups Installed"

    }
    
    #Install MS Graph if not available
    if (Get-Module -ListAvailable -Name Microsoft.Graph.DeviceManagement) {
        write-output "Microsoft Graph DeviceManagement Already Installed"
        writelog "Microsoft Graph DeviceManagement Already Installed"

    } 
    else {
            Install-Module -Name Microsoft.Graph.DeviceManagement -Scope CurrentUser -Repository PSGallery -Force  
            write-output "Microsoft Graph DeviceManagement Installed"
            writelog "Microsoft Graph DeviceManagement Installed"

        }

    #Install MS Graph if not available
    if (Get-Module -ListAvailable -Name Microsoft.Graph.identity.signins) {
        write-output "Microsoft Graph Identity SignIns Already Installed"
        writelog "Microsoft Graph Identity SignIns Already Installed"

    } 
    else {
            Install-Module -Name Microsoft.Graph.Identity.SignIns -Scope CurrentUser -Repository PSGallery -Force
            write-output "Microsoft Graph Identity SignIns Installed"
            writelog "Microsoft Graph Identity SignIns Installed"

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
         
                $response = Invoke-RestMethod -Method Post -Uri https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token -Body $body -UseBasicParsing
                $accessToken = $response.access_token
         
                $accessToken
                if ($version -eq 2) {
                    write-output "Version 2 module detected"
                    $accesstokenfinal = ConvertTo-SecureString -String $accessToken -AsPlainText -Force
                }
                else {
                    write-output "Version 1 Module Detected"
                    Select-MgProfile -Name Beta
                    $accesstokenfinal = $accessToken
                }
                $graph = Connect-MgGraph  -AccessToken $accesstokenfinal 
                write-output "Connected to Intune tenant $TenantId using app-based authentication (Azure AD authentication not supported)"
            }
            else {
                if ($version -eq 2) {
                    write-output "Version 2 module detected"
                }
                else {
                    write-output "Version 1 Module Detected"
                    Select-MgProfile -Name Beta
                }
                $graph = Connect-MgGraph -scopes $scopes
                write-output "Connected to Intune tenant $($graph.TenantId)"
            }
        }
    }    

# Load the Graph module
Import-Module microsoft.graph.authentication
import-module Microsoft.Graph.Identity.SignIns
import-module Microsoft.Graph.DeviceManagement
import-module microsoft.Graph.Groups
import-module microsoft.graph.devices.corporatemanagement

if (($automated -eq "yes") -or ($aadlogin -eq "yes")) {
 
Connect-ToGraph -Tenant $tenant -AppId $clientId -AppSecret $clientSecret
write-output "Graph Connection Established"
writelog "Graph Connection Established"

}
else {
##Connect to Graph
#Select-MgProfile -Name Beta
Connect-ToGraph -Scopes "Policy.ReadWrite.ConditionalAccess, CloudPC.ReadWrite.All, DeviceManagementServiceConfig.ReadWrite.All, RoleAssignmentSchedule.ReadWrite.Directory, Domain.Read.All, Domain.ReadWrite.All, Directory.Read.All, Policy.ReadWrite.ConditionalAccess, DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, openid, profile, email, offline_access, DeviceManagementRBAC.Read.All, DeviceManagementRBAC.ReadWrite.All"
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
            
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id"
                    (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
            
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
Function Get-MobileAppConfigurations(){
    
    <#
    .SYNOPSIS
    This function is used to get Mobile App Configurations from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Mobile App Configurations
    .EXAMPLE
    Get-mobileAppConfigurations
    Returns any Mobile App Configurations configured in Intune
    .NOTES
    NAME: Get-mobileAppConfigurations
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceAppManagement/mobileAppConfigurations"
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


Function Get-FeatureUpdatePolicies(){
    
    <#
    .SYNOPSIS
    This function is used to get Feature Update Policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Feature Update Policies
    .EXAMPLE
    Get-FeatureUpdatePolicies
    Returns any Feature Update Policies configured in Intune
    .NOTES
    NAME: Get-FeatureUpdatePolicies
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/windowsFeatureUpdateProfiles"
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

Function Get-DriverUpdatePolicies(){
    
    <#
    .SYNOPSIS
    This function is used to get Driver Update Policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Driver Update Policies
    .EXAMPLE
    Get-DriverUpdatePolicies
    Returns any Driver Update Policies configured in Intune
    .NOTES
    NAME: Get-DriverUpdatePolicies
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/windowsDriverUpdateProfiles"
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

Function Get-QualityUpdatePolicies(){
    
    <#
    .SYNOPSIS
    This function is used to get Quality Update Policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Quality Update Policies
    .EXAMPLE
    Get-QualityUpdatePolicies
    Returns any Quality Update Policies configured in Intune
    .NOTES
    NAME: Get-QualityUpdatePolicies
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/windowsQualityUpdateProfiles"
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

Function Get-MobileAppConfigurationsbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get Mobile App Configurations from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Mobile App Configurations
    .EXAMPLE
    Get-MobileAppConfigurationsbyName
    Returns any Mobile App Configurations configured in Intune
    .NOTES
    NAME: Get-MobileAppConfigurationsbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceAppManagement/mobileAppConfigurations"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $PR = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $PR.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "App Config"
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

Function Get-QualityUpdatePoliciesbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get Quality Update Policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Quality Update Policies
    .EXAMPLE
    Get-QualityUpdatePoliciesbyName
    Returns any Quality Update Policies configured in Intune
    .NOTES
    NAME: Get-QualityUpdatePoliciesbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/windowsQualityUpdateProfiles"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $W365User = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $W365User.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Quality Update"
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

Function GetFeatureUpdatePoliciesbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get Feature Update Policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Feature Update Policies
    .EXAMPLE
    Get-FeatureUpdatePolicies
    Returns any Feature Update Policies configured in Intune
    .NOTES
    NAME: Get-FeatureUpdatePolicies
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/windowsFeatureUpdateProfiles"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $W365User = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $W365User.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Feature Update"
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


Function GetDriverUpdatePoliciesbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get Driver Update Policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Driver Update Policies
    .EXAMPLE
    Get-DriverUpdatePoliciesbyName
    Returns any Driver Update Policies configured in Intune
    .NOTES
    NAME: Get-DriverUpdatePoliciesbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/windowsDriverUpdateProfiles"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $W365User = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $W365User.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Driver Update"
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
$check = Get-MobileAppConfigurationsbyName -name $name
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
$check = Get-FeatureUpdatePoliciesbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-QualityUpdatePoliciesbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-DriverUpdatePoliciesbyName -name $name
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
### ASSIGNMENT FUNCTIONS
#################################################################################################
Function Get-IntuneApplicationAssignments() {
    
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
        [Parameter(Position = 0, mandatory = $true)]
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

Function Get-DeviceConfigurationPolicyGPAssignments() {
    
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
        [Parameter(Position = 0, mandatory = $true)]
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


Function Get-DeviceConfigurationPolicyAssignments() {
    
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
        [Parameter(Position = 0, mandatory = $true)]
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

Function Get-DeviceConfigurationPolicySCAssignments() {
    
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
        [Parameter(Position = 0, mandatory = $true)]
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
Function Get-DeviceProactiveRemediationsAssignments() {
    
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
        [Parameter(Position = 0, mandatory = $true)]
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


Function Get-MobileAppConfigurationsAssignments() {
    
    <#
                    .SYNOPSIS
                    This function is used to get Mobile App Configuration assignments from the Graph API REST interface
                    .DESCRIPTION
                    The function connects to the Graph API Interface and gets any Mobile App Configuration assignments
                    .EXAMPLE
                    Get-MobileAppConfigurationsAssignments
                    Returns any Mobile App Configuration assignments configured in Intune
                    .NOTES
                    NAME: Get-MobileAppConfigurationsAssignments
                    #>
                    
    [cmdletbinding()]
                    
    param
    (
        [Parameter(Position = 0, mandatory = $true)]
        $id
    )
                    
    $graphApiVersion = "Beta"
    $Resource = "deviceAppManagement/mobileAppConfigurations"
                    
    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id/assignments"
                            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    }
                    
    catch {
                    
    }
                    
}
Function Get-DeviceCompliancePolicyAssignments() {
    
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
        [Parameter(Position = 0, mandatory = $true)]
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
Function Get-DeviceSecurityPolicyAssignments() {
    
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
        [Parameter(Position = 0, mandatory = $true)]
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
                                  

Function Get-AutoPilotProfileAssignments() {
    
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
        [Parameter(Position = 0, mandatory = $true)]
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
                                        
Function Get-AutoPilotESPAssignments() {
    
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
        [Parameter(Position = 0, mandatory = $true)]
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
                                            
Function Get-DeviceManagementScriptsAssignments() {
    
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
        [Parameter(Position = 0, mandatory = $true)]
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

Function Get-Win365UserSettingsAssignments() {
    
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
        [Parameter(Position = 0, mandatory = $true)]
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

Function Get-FeatureUpdatePoliciesAssignments() {
    
    <#
    .SYNOPSIS
    This function is used to get Feature Update Policies assignments from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Feature Update Policies assignments
    .EXAMPLE
    Get-FeatureUpdatePoliciesAssignments
    Returns any Feature Update Policies assignments configured in Intune
    .NOTES
    NAME: Get-FeatureUpdatePoliciesAssignments
    #>
    [cmdletbinding()]
    param
    (
        [Parameter(Position = 0, mandatory = $true)]
        $id
    )
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/windowsFeatureUpdateProfiles"
    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id/assignments"
        (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    }

    catch {
    }
}


Function Get-QualityUpdatePoliciesAssignments() {
    
    <#
    .SYNOPSIS
    This function is used to get Quality Update Policies assignments from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Quality Update Policies assignments
    .EXAMPLE
    Get-QualityUpdatePoliciesAssignments
    Returns any Quality Update Policies assignments configured in Intune
    .NOTES
    NAME: Get-QualityUpdatePoliciesAssignments
    #>
    [cmdletbinding()]
    param
    (
        [Parameter(Position = 0, mandatory = $true)]
        $id
    )
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/windowsQualityUpdateProfiles"
    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id/assignments"
        (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    }

    catch {
    }
}


Function Get-DriverUpdatePoliciesAssignments() {
    
    <#
    .SYNOPSIS
    This function is used to get Driver Update Policies assignments from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Driver Update Policies assignments
    .EXAMPLE
    Get-DriverUpdatePoliciesAssignments
    Returns any Driver Update Policies assignments configured in Intune
    .NOTES
    NAME: Get-DriverUpdatePoliciesAssignments
    #>
    [cmdletbinding()]
    param
    (
        [Parameter(Position = 0, mandatory = $true)]
        $id
    )
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/windowsDriverUpdateProfiles"
    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id/assignments"
        (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    }

    catch {
    }
}

Function Get-Win365ProvisioningPoliciesAssignments() {
    
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
        [Parameter(Position = 0, mandatory = $true)]
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

Function Get-EnrollmentConfigurationsAssignments(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune enrollment configurations from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune enrollment configurations
    .EXAMPLE
    Get-EnrollmentConfigurationsAssignments -id xx
    Returns any enrollment configurations configured in Intune
    .NOTES
    NAME: Get-EnrollmentConfigurationsAssignments
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/deviceEnrollmentConfigurations"
    try {
 
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id/assignments"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)

        }
        catch {}
    
   
}


Function Get-BrandingProfilesAssignments(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune Branding Profiles assignments from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune Branding Profiles assignments
    .EXAMPLE
    Get-BrandingProfilesAssignments
    Returns any Branding Profiles assignments configured in Intune
    .NOTES
    NAME: Get-BrandingProfilesAssignments
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/intuneBrandingProfiles"
    try {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id/assignments"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)

        }
        catch {}
    
   
}


Function Get-AdminApprovalsAssignments(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune admin approvals assignments from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune admin approvals assignments
    .EXAMPLE
    Get-AdminApprovalsAssignments
    Returns any admin approvals assignments configured in Intune
    .NOTES
    NAME: Get-AdminApprovalsAssignments
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/operationApprovalPolicies"
    try {
   
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id/assignments"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
  
    }
        catch {}
    
   
}

Function Get-DeviceCompliancePolicyScriptsAssignments(){
    
    <#
    .SYNOPSIS
    This function is used to get device custom compliance policy scripts Assignments from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device compliance policies assignments
    .EXAMPLE
    Get-DeviceCompliancePolicyScriptsAssignments
    Returns any device compliance policy scripts assignments configured in Intune
    .NOTES
    NAME: Get-DeviceCompliancePolicyScriptsAssignments
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/deviceComplianceScripts"
    try {
      
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id/assignments"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    
        }
        catch {}
    
}

Function Get-IntuneTermsAssignments(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune terms and conditions assignments from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune terms and conditions assignments
    .EXAMPLE
    Get-IntuneTermsAssignments
    Returns any terms and conditions assignments configured in Intune
    .NOTES
    NAME: Get-IntuneTermsAssignments
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/termsAndConditions"
    try {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id/assignments"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)

        }
        catch {}
    
   
}
function getallgroups () {
<#
.SYNOPSIS
This function is used to grab all groups in Azure AD
.DESCRIPTION
The function connects to the Graph API Interface and gets all groups
.EXAMPLE
getallgroups
 Returns all groups
.NOTES
 NAME: getallgroups
#>
    $response = (Invoke-MgGraphRequest -uri "https://graph.microsoft.com/beta/groups" -Method Get -OutputType PSObject)
    $allgroups = $response.value
    
    $allgroupsNextLink = $response."@odata.nextLink"
    
    while ($null -ne $allgroupsNextLink) {
        $allgroupsResponse = (Invoke-MGGraphRequest -Uri $allgroupsNextLink -Method Get -outputType PSObject)
        $allgroupsNextLink = $allgroupsResponse."@odata.nextLink"
        $allgroups += $allgroupsResponse.value
    }
    
    return $allgroups
}
function getallfilters () {
    $response = (Invoke-MgGraphRequest -uri "https://graph.microsoft.com/beta/deviceManagement/assignmentFilters" -Method Get -OutputType PSObject)
    $allfilters = $response.value
    
    $allfiltersNextLink = $response."@odata.nextLink"
    
    while ($null -ne $allfiltersNextLink) {
        $allfiltersResponse = (Invoke-MGGraphRequest -Uri $allfiltersNextLink -Method Get -outputType PSObject)
        $allfiltersNextLink = $allfiltersResponse."@odata.nextLink"
        $allfilters += $allfiltersResponse.value
    }
    
    return $allfilters
    }
function convertidtoname() {
    [cmdletbinding()]
    
    param
    (
        [Parameter(Position = 0, mandatory = $true)]
        $json,
        $allgroups,
        $allfilters
    )
    
foreach ($assignment in $json) {
    $groupid = $assignment.target.groupid
    if ($groupid) {
    $groupname = $allgroups | where-object {$_.id -eq $groupid} | select-object -expandproperty displayname
    $assignment.target.groupId = $groupname
    }
    $filterid = $assignment.target.deviceAndAppManagementAssignmentFilterId
    if ($filterid) {
    $filtername = $allfilters | where-object {$_.id -eq $filterid} | select-object -expandproperty displayname
    $assignment.target.deviceAndAppManagementAssignmentFilterId = $filtername
    }
}
return $json
}

function convertnametoid() {
    [cmdletbinding()]
    
    param
    (
        [Parameter(Position = 0, mandatory = $true)]
        $json,
        $allgroups,
        $allfilters,
        $create
    )
foreach ($assignment in $json) {
    $groupid = $assignment.target.groupid
    if ($groupid) {
        $allgroups = getallgroups
    $groupname = $allgroups | where-object {$_.displayName -eq $groupid} | select-object -expandproperty ID
    ##If group can't be found and create is yes, create it
    if (!$groupname -and $create -eq "yes") {
                ##Remove all spaces and special characters for the nickname
                $groupidnick = $groupid -replace " ",""
                $groupidnick = $groupid -replace "[^a-zA-Z0-9]",""
    $groupjson = @"
        {
            "description": "$groupid Automatically Created",
            "displayName": "$groupid",
            "groupTypes": [
            ],
            "mailEnabled": false,
            "mailNickname": "$groupidnick",
            "securityEnabled": true,
          }
"@
        $group = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/groups" -Method Post -Body $groupjson -OutputType PSObject
        $groupname = $group.id
    }
    $assignment.target.groupId = $groupname
    }
    $filterid = $assignment.target.deviceAndAppManagementAssignmentFilterId
    if ($filterid) {
    $filtername = $allfilters | where-object {$_.displayName -eq $filterid} | select-object -expandproperty ID
    $assignment.target.deviceAndAppManagementAssignmentFilterId = $filtername
    }
}
return $json
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
             $policyconvert = $policyconvert | Select-Object -Property * -ExcludeProperty secretReferenceValueId
             foreach ($pvalue in $policyconvert) {
             $unencoded = $pvalue.value
             ##Check if $unencoded is boolean
             if ($unencoded -is [bool] -or $unencoded -is [int] -or $unencoded -is [int32] -or $unencoded -is [int64]) {
                $unencoded = $unencoded.ToString().ToLower()
            }
            $EncodedText =[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($unencoded))
            
$pvalue.value = $EncodedText
             }
             $policy.omaSettings = @($policyconvert)
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

        $assignments = Get-DeviceConfigurationPolicyAssignments -id $id
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

              $assignments = Get-DeviceConfigurationPolicyGPAssignments -id $id
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

                $assignments = Get-DeviceProactiveRemediationsAssignments -id $id
       }
       "deviceAppManagement/mobileAppConfigurations" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $policy = Get-MobileAppConfigurations -id $id
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

                $assignments = Get-MobileAppConfigurationsAssignments -id $id
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

                $assignments = Get-DeviceManagementScriptsAssignments -id $id
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
            
                    $assignments = Get-DeviceCompliancePolicyScriptsAssignments -id $id
       }
    

       "deviceManagement/configurationPolicies" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $policy = Get-DeviceConfigurationPolicysc -id $id
        $policy | Add-Member -MemberType NoteProperty -Name 'settings' -Value @() -Force
        #$settings = Invoke-MSGraphRequest -HttpMethod GET -Url "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$id/settings" | Get-MSGraphAllPages
        $uri2 = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$id/settings"
        $response = (Invoke-MgGraphRequest -uri $uri2 -Method Get -OutputType PSObject)
        $allsettings = $response.value
        
        $allsettingsNextLink = $response."@odata.nextLink"
        
        while ($null -ne $allsettingsNextLink) {
            $allsettingsResponse = (Invoke-MGGraphRequest -Uri $allsettingsNextLink -Method Get -outputType PSObject)
            $allsettingsNextLink = $allsettingsResponse."@odata.nextLink"
            $allsettings += $allsettingsResponse.value
        }

        $settings =  $allsettings | select-object * -ExcludeProperty '@odata.count'
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
            $assignments = Get-DeviceConfigurationPolicySCAssignments -id $id

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
            
            $assignments = Get-DeviceCompliancePolicyAssignments -id $id
            
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

        $assignments = Get-DeviceSecurityPolicyAssignments -id $id

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

        $assignments = Get-AutoPilotProfileAssignments -id $id
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

        $assignments = "none"
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

        $assignments = Get-AutoPilotESPAssignments -id $id
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

        $assignments = Get-Win365UserSettingsAssignments -id $id
    }
    "deviceManagement/windowsFeatureUpdateProfiles" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $policy = Get-FeatureUpdatePolicies -id $id
        $oldname = $policy.displayName
        $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
        if ($changename -eq "yes") {
            $newname = $oldname + "-restore-" + $restoredate
        }
        else {
            $newname = $oldname
        }        $policy.displayName = $newname

        $assignments = Get-FeatureUpdatePoliciesAssignments -id $id
    }

    "deviceManagement/windowsQualityUpdateProfiles" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $policy = Get-QualityUpdatePolicies -id $id
        $oldname = $policy.displayName
        $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
        if ($changename -eq "yes") {
            $newname = $oldname + "-restore-" + $restoredate
        }
        else {
            $newname = $oldname
        }        $policy.displayName = $newname

        $assignments = Get-QualityUpdatePoliciesAssignments -id $id
    }
    "deviceManagement/windowsDriverUpdateProfiles" {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $policy = Get-DriverUpdatePolicies -id $id
        $oldname = $policy.displayName
        $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
        if ($changename -eq "yes") {
            $newname = $oldname + "-restore-" + $restoredate
        }
        else {
            $newname = $oldname
        }        $policy.displayName = $newname

        $assignments = Get-DriverUpdatePoliciesAssignments -id $id
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

        $assignments = Get-Win365ProvisioningPoliciesAssignments -id $id
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

        $assignments = "none"

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


        $assignments = "none"
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

        $assignments = Get-IntuneApplicationAssignments -id $id
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

        $assignments = "none"
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

        $assignments = Get-EnrollmentConfigurationsAssignments -id $id
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

        $assignments = Get-EnrollmentConfigurationsAssignments -id $id

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

        $assignments = "none"
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

        $assignments = "none"
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

        $assignments = Get-BrandingProfilesAssignments -id $id
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

        $assignments = get-adminapprovalassignments -id $id
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

        $assignments = "none"
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

        $assignments = Get-IntuneTermsAssignments -id $id
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

        $assignments = "none"
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
        $assignments = "none"
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

    return $policy, $uri, $oldname, $assignments

}


###############################################################################################################
#################################                   BACKUP             #######################################
###############################################################################################################

if (($type -eq "backup") -or ($type -eq "livemigration")) {



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

##Get App Config
$configuration += Get-MobileAppConfigurations | Select-Object ID, DisplayName, Description, @{N='Type';E={"App Config"}}


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

##Get Feature Updates
$configuration += Get-FeatureUpdatePolicies | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Feature Update"}}

##Get Quality Updates
$configuration += Get-QualityUpdatePolicies | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Quality Update"}}

##Get Driver Updates
$configuration += Get-DriverUpdatePolicies | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Driver Update"}}

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
            writelog "Getting ID for $name"
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
            writelog "Copying policy $id"
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
writelog $id
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
    $appconfig = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "App Config")}
    $aad = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "AAD Group")}
    $wingetapp = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Winget Application")}
    $scripts = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "PowerShell Script")}
    $compliancescripts = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Compliance Script")}
    $win365usersettings = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Win365 User Settings")}
    $featureupdates = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Feature Update")}
    $qualityupdates = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Quality Update")}
    $driverupdates = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Driver Update")}
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
    $appconfig = Get-MobileAppConfigurations -id $id
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
    $whfb = get-whfbpolicies -id $id
    $featureupdates = get-FeatureUpdatePolicies -id $id
    $qualityupdates = get-qualityUpdatePolicies -id $id
    $driverupdates = get-driverUpdatePolicies -id $id
    }


##Grab the groups
$allgroups = getallgroups

##Grab the filters
$allfilters = getallfilters



# Copy it
if ($null -ne $policy) {
    # Standard Device Configuratio Policy
write-output "It's a policy"
writelog "It's a policy"

$id = $policy.id
$Resource = "deviceManagement/deviceConfigurations"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))

}
if ($null -ne $gp) {
    # Standard Device Configuration Policy
write-output "It's an Admin Template"
writelog "It's an Admin Template"

$id = $gp.id
$Resource = "deviceManagement/groupPolicyConfigurations"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))}
if ($null -ne $catalog) {
    # Settings Catalog Policy
write-output "It's a Settings Catalog"
writelog "It's a Settings Catalog"

$id = $catalog.id
$Resource = "deviceManagement/configurationPolicies"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($null -ne $compliance) {
    # Compliance Policy
write-output "It's a Compliance Policy"
writelog "It's a Compliance Policy"

$id = $compliance.id
$Resource = "deviceManagement/deviceCompliancePolicies"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))}
if ($null -ne $proac) {
    # Proactive Remediations
write-output "It's a Proactive Remediation"
writelog "It's a Proactive Remediation"

$id = $proac.id
$Resource = "deviceManagement/devicehealthscripts"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))}
if ($null -ne $appconfig) {
    # App Config
write-output "It's an App Config"
writelog "It's an App Config"

$id = $appconfig.id
$Resource = "deviceAppManagement/mobileAppConfigurations"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($null -ne $scripts) {
    # Device Scripts
    write-output "It's a PowerShell Script"
    writelog "It's a PowerShell Script"

$id = $scripts.id
$Resource = "deviceManagement/devicemanagementscripts"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))}

if ($null -ne $compliancescripts) {
    # Compliance Scripts
    write-output "It's a Compliance Script"
    writelog "It's a Compliance Script"

$id = $compliancescripts.id
$Resource = "deviceManagement/deviceComplianceScripts"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))}

if ($null -ne $security) {
    # Security Policy
write-output "It's a Security Policy"
writelog "It's a Security Policy"

$id = $security.id
$Resource = "deviceManagement/intents"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))}
if ($null -ne $autopilot) {
    # Autopilot Profile
write-output "It's an Autopilot Profile"
writelog "It's an Autopilot Profile"

$id = $autopilot.id
$Resource = "deviceManagement/windowsAutopilotDeploymentProfiles"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))}
if ($null -ne $esp) {
    # Autopilot ESP
write-output "It's an AutoPilot ESP"
writelog "It's an AutoPilot ESP"

$id = $esp.id
$Resource = "deviceManagement/deviceEnrollmentConfigurationsESP"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))}
if ($null -ne $whfb) {
    # Windows Hello for Business
write-output "It's a WHfB Policy"
writelog "It's a WHfB Policy"

$id = $esp.id
$Resource = "deviceManagement/deviceEnrollmentConfigurationswhfb"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))}
if ($null -ne $android) {
    # Android App Protection
write-output "It's an Android App Protection Policy"
writelog "It's an Android App Protection Policy"

$id = $android.id
$Resource = "deviceAppManagement/managedAppPoliciesandroid"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))}
if ($null -ne $ios) {
    # iOS App Protection
write-output "It's an iOS App Protection Policy"
writelog "It's an iOS App Protection Policy"

$id = $ios.id
$Resource = "deviceAppManagement/managedAppPoliciesios"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($null -ne $aad) {
    # AAD Groups
write-output "It's an AAD Group"
writelog "It's an AAD Group"

$id = $aad.id
$Resource = "groups"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($null -ne $ca) {
    # Conditional Access
write-output "It's a Conditional Access Policy"
writelog "It's a Conditional Access Policy"

$id = $ca.id
$Resource = "ConditionalAccess"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($null -ne $wingetapp) {
    # Winget App
write-output "It's a Windows Application"
writelog "It's a Windows Application"

$id = $wingetapp.id
$Resource = "deviceAppManagement/mobileApps"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($null -ne $win365usersettings) {
    # W365 User Settings
write-output "It's a W365 User Setting"
writelog "It's a W365 User Setting"

$id = $win365usersettings.id
$Resource = "deviceManagement/virtualEndpoint/userSettings"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($null -ne $featureupdates) {
    # Feature Updates
write-output "It's a Feature Update"
writelog "It's a Feature Update"

$id = $featureupdates.id
$Resource = "deviceManagement/windowsFeatureUpdateProfiles"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}

if ($null -ne $qualityupdates) {
    # Quality Updates
write-output "It's a Quality Update"
writelog "It's a Quality Update"

$id = $qualityupdates.id
$Resource = "deviceManagement/windowsQualityUpdateProfiles"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}

if ($null -ne $driverupdates) {
    # Quality Updates
write-output "It's a Driver Update"
writelog "It's a Driver Update"

$id = $driverupdates.id
$Resource = "deviceManagement/windowsDriverUpdateProfiles"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}

if ($null -ne $win365provisioning) {
    # W365 Provisioning Policy
write-output "It's a W365 Provisioning Policy"
writelog "It's a W365 Provisioning Policy"

$id = $win365provisioning.id
$Resource = "deviceManagement/virtualEndpoint/provisioningPolicies"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($null -ne $policysets) {
    # Policy Set
write-output "It's a Policy Set"
writelog "It's a Policy Set"

$id = $policysets.id
$Resource = "deviceAppManagement/policySets"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($null -ne $enrollmentconfigs) {
    # Enrollment Config
write-output "It's an enrollment configuration"
writelog "It's an enrollment configuration"

$id = $enrollmentconfigs.id
$Resource = "deviceManagement/deviceEnrollmentConfigurations"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($null -ne $devicecategories) {
    # Device Categories
write-output "It's a device category"
writelog "It's a device category"

$id = $devicecategories.id
$Resource = "deviceManagement/deviceCategories"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($null -ne $devicefilters) {
    # Device Filter
write-output "It's a device filter"
writelog "It's a device filter"

$id = $devicefilters.id
$Resource = "deviceManagement/assignmentFilters"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($null -ne $brandingprofiles) {
    # Branding Profile
write-output "It's a branding profile"
writelog "It's a branding profile"

$id = $brandingprofiles.id
$Resource = "deviceManagement/intuneBrandingProfiles"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($null -ne $adminapprovals) {
    # Multi-admin approval
write-output "It's a multi-admin approval"
writelog "It's a multi-admin approval"

$id = $adminapprovals.id
$Resource = "deviceManagement/operationApprovalPolicies"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
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
writelog "It's a T&C"

$id = $intuneterms.id
$Resource = "deviceManagement/termsAndConditions"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($null -ne $intunerole) {
    # Intune Role
write-output "It's a role"
writelog "It's a role"

$id = $intunerole.id
$Resource = "deviceManagement/roleDefinitions"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
}

##Convert profiles to JSON
$profilesjson = $profiles | convertto-json -Depth 50 

##Encode profiles to base64
$profilesencoded =[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($profilesjson))

if ($type -ne "livemigration") {

if ($selected -eq "all") {
$backupreason = "Automated Backup"
}
if ($templatecheck -eq "yes") {
    $backupreason = "Automated Template"
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


$date =get-date -format yyMMddHHmmss
$date = $date.ToString()

if ($templatecheck -eq "yes") {
    $filename = $tenant + "-intunebackup-" + $date + "-Template-" + $templatename + ".json"
}
else {
    $filename = $tenant + "-intunebackup-" + $date + ".json"
}

if ($repotype -eq "github") {
    write-output "Uploading to Github"
    writelog "Uploading to Github"

##Upload to GitHub
$readabledate = get-date -format dd-MM-yyyy-HH-mm-ss
$uri = "https://api.github.com/repos/$ownername/$reponame/contents/$filename"
$message = "$backupreason - $readabledate"
$body = '{{"message": "{0}", "content": "{1}" }}' -f $message, $profilesencoded
(Invoke-RestMethod -Uri $uri -Method put -Headers @{'Authorization'='bearer '+$token;} -Body $body -ContentType "application/json")
}
if ($repotype -eq "gitlab") {
    write-output "Uploading to GitLab"
    writelog "Uploading to GitLab"

##Upload to GitLab
$readabledate = Get-Date -Format dd-MM-yyyy-HH-mm-ss
$GitLabUrl = "https://gitlab.com/api/v4"

# Create a new file in the repository
$CommitMessage = $backupreason
$BranchName = "main"
$FileContent = @{
    "branch" = $BranchName
    "commit_message" = $CommitMessage
    "actions" = @(
        @{
            "action" = "create"
            "file_path" = $filename
            "content" = $profilesencoded
        }
    )
}
$FileContentJson = $FileContent | ConvertTo-Json -Depth 10
$CreateFileUrl = "$GitLabUrl/projects/$project/repository/commits"
$Headers = @{
    "PRIVATE-TOKEN" = $token
}
Invoke-RestMethod -Uri $CreateFileUrl -Method Post -Headers $Headers -Body $FileContentJson -ContentType "application/json"
}
if ($repotype -eq "azuredevops") {

    write-output "Uploading to Azure DevOps"
    writelog "Uploading to Azure DevOps"

    Add-DevopsFile -repo $reponame -project $project -organization $ownername -filename $filename -filecontent $profilesjson -token $token -comment $backupreason

}
}

}

#######################################################################################################################################
#########                                                   END BACKUP                         ########################################
#######################################################################################################################################




#######################################################################################################################################
#########                                                   RESTORE                            ########################################
#######################################################################################################################################

if (($type -eq "backup") -or ($type -eq "livemigration")) {

if ($type -eq "livemigration") {
    Disconnect-MgGraph
    if ($secondtenant -and $clientsecret) {
 
        Connect-ToGraph -Tenant $secondtenant -AppId $clientId -AppSecret $clientSecret
        write-output "Graph Connection Established"
        writelog "Graph Connection Established"
        
        }
        else {
        ##Connect to Graph
        #Select-MgProfile -Name Beta
        Connect-ToGraph -Scopes "Policy.ReadWrite.ConditionalAccess, CloudPC.ReadWrite.All, DeviceManagementServiceConfig.ReadWrite.All, RoleAssignmentSchedule.ReadWrite.Directory, Domain.Read.All, Domain.ReadWrite.All, Directory.Read.All, Policy.ReadWrite.ConditionalAccess, DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, openid, profile, email, offline_access, DeviceManagementRBAC.Read.All, DeviceManagementRBAC.ReadWrite.All"
        }
        

}
    ##Grab the groups
write-output "Grabbing Groups"
writelog "Grabbing Groups"

$allgroups = getallgroups

##Grab the filters
write-output "Grabbing Filters"
writelog "Grabbing Filters"

$allfilters = getallfilters
        
###############################################################################################################
######                                          Get Commits                                              ######
###############################################################################################################
if ($type -ne "livemigration") {
if ($repotype -eq "github") {

    if ($WebHookData){
        $filename = $postedfilename
    }
    else {

    
    write-output "Finding Latest Backup Commit from Repo $reponame in $ownername GitHub"
    writelog "Finding Latest Backup Commit from Repo $reponame in $ownername GitHub"


    $uri = "https://api.github.com/repos/$ownername/$reponame/commits?per_page=100"
    $events = @()
    $page = 1

Do
{
    $response = Invoke-RestMethod -Headers @{'Authorization'='bearer '+$token;} -Uri "$uri&page=$page"
    
    foreach ($obj in $response)
    {
        $events += $obj.commit
    }
    
    $page = $page + 1
}
While ($response.Count -gt 0)

    ##$events = (Invoke-RestMethod -Uri $uri -Method Get -Headers @{'Authorization'='bearer '+$token;}).commit
    $events2 = $events | Select-Object message, url | Where-Object {($_.message -notmatch "\blog\b") -and ($_.message -notmatch "\bdelete\b") -and ($_.message -notmatch "\bdaily\b") -and ($_.message -notmatch "\bdrift\b") -and ($_.message -notmatch "\btemplate\b")} | Out-GridView -PassThru -Title "Select Backup to View"
    ForEach ($event in $events2) 
        {
    $eventsuri = $event.url
    $commitid = Split-Path $eventsuri -Leaf
    $commituri = "https://api.github.com/repos/$ownername/$reponame/commits/$commitid"
    $commitfilename = ((Invoke-RestMethod -Uri $commituri -Method Get -Headers @{'Authorization'='token '+$token; 'Accept'='application/json'}).Files).raw_url
    write-output "$commitfilename Found"
    writelog "$commitfilename Found"

    }
    
    
    $filename = $commitfilename.Substring($commitfilename.LastIndexOf("/") + 1)
}
    $commitfilename2 = " https://api.github.com/repos/$ownername/$reponame/contents/$filename"
    
    
    $decodedbackupdownload = (Invoke-RestMethod -Uri $commitfilename2 -Method Get -Headers @{'Authorization'='bearer '+$token; 'Accept'='Accept: application/json';'Cache-Control'='no-cache'}).download_url
    $decodedbackup = (Invoke-RestMethod -Uri $decodedbackupdownload -Method Get)
    
    }

    if ($repotype -eq "gitlab") {

        $GitLabUrl = "https://gitlab.com/api/v4"
        $Headers = @{
            "PRIVATE-TOKEN" = $token
        }
        if ($WebHookData){
            $filename = $postedfilename
        }
        else {
    
        
        write-output "Finding Latest Backup Commit from Project $project in GitLab"
        writelog "Finding Latest Backup Commit from Project $project in GitLab"

        $uri = "$GitLabUrl/projects/$project/repository/commits?per_page=100"
        $events = @()
        $page = 1
    
    Do
    {
        $response = Invoke-RestMethod -Headers @{'Authorization'='bearer '+$token;} -Uri "$uri&page=$page"
        
        foreach ($obj in $response)
        {
            $events += $obj.commit
        }
        
        $page = $page + 1
    }
    While ($response.Count -gt 0)
    
        ##$events = (Invoke-RestMethod -Uri $uri -Method Get -Headers @{'Authorization'='bearer '+$token;}).commit
        $events2 = $events | Select-Object message, web_url | Where-Object {($_.message -notmatch "\blog\b") -and ($_.message -notmatch "\bdelete\b") -and ($_.message -notmatch "\bdaily\b") -and ($_.message -notmatch "\bdrift\b") -and ($_.message -notmatch "\btemplate\b")} | Out-GridView -PassThru -Title "Select Backup to View"
            ForEach ($event in $events2) 
            {
        $eventsuri = $event.web_url
        $commitid = Split-Path $eventsuri -Leaf
        $commituri = "$GitLabUrl/projects/$project/repository/commits/$commitid/diff"
        $commit = Invoke-RestMethod -Uri $commitUri -Method Get -Headers $Headers
        $commitFilename = $commit.new_path
        write-output "$commitfilename Found"
        writelog "$commitfilename Found"

        }
        
        
        $filename = $commitfilename.Substring($commitfilename.LastIndexOf("/") + 1)
    }
        $commitfilename2 = "$GitLabUrl/projects/$project/repository/files/$filename"+"/raw?ref=main"
        
        $decodedbackupdownload = (Invoke-RestMethod -Uri $commitfilename2 -Method Get -Headers $Headers)
        ##Decode

        $decodedbackup = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($decodedbackupdownload))

        
        }
    
    if ($repotype -eq "azuredevops") {

        $base64AuthInfo= [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($token)"))

        if ($WebHookData){
            $commitfilename2 = $postedfilename
        }
        else {
        write-output "Finding Latest Backup Commit from Repo $reponame in $ownername DevOps"
        writelog "Finding Latest Backup Commit from Repo $reponame in $ownername DevOps"

        $events = Get-DevOpsCommits -repo $reponame -project $project -organization $ownername -token $token
        $events2 = $events | Select-object comment, url| Where-Object {($_.comment -notmatch "\blog\b") -and ($_.comment -notmatch "\bdelete\b") -and ($_.comment -notmatch "\bdaily\b") -and ($_.comment -notmatch "\bdrift\b") -and ($_.comment -notmatch "\btemplate\b")} | Out-GridView -PassThru -Title "Select Backup to View"
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
    
    }
    
    
###############################################################################################################
######                                         GridView Policies within Backup                           ######
###############################################################################################################
if ($type -eq "livemigration") {
    $profilelist2 = $profilesjson | ConvertFrom-Json
}
else {
if ($repotype -eq "azuredevops") {
$profilelist2 = $decodedbackup | ConvertFrom-Json
}
if ($repotype -eq "gitlab") {
    $profilelist2 = $decodedbackup | ConvertFrom-Json
    }
if ($repotype -eq "github") {
$profilelist2 = $decodedbackup
}
}
$oneormore = $profilelist2.Count
write-host $oneormore
if ($oneormore -gt 4) {
        $firstarray = @()
        $secondarray = @()
        foreach ($loop in $profilelist2) {
            $type = $loop.value[1]
            if ($type -eq "https://graph.microsoft.com/beta/groups") {
                $firstarray += $loop
            }
            else {
                $secondarray += $loop
            }
        }

        $joined = $firstarray + $secondarray

        $fullist = $joined
        $profilelist3 = $joined
        $looplist = $profilelist3
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
if (($automated -eq "yes") -or ($WebHookData) -or ($assignments -eq "yes")) {

    ##Do nothing
    }
    else {
        ##Popup prompt to ask about assignments
        Add-Type -AssemblyName System.Windows.Forms

$caption = "Confirmation"
$message = "Do you want to restore assignments?"
$buttons = [System.Windows.Forms.MessageBoxButtons]::YesNo
$result = [System.Windows.Forms.MessageBox]::Show($message, $caption, $buttons)

if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
    # User clicked "Yes"
    $assignments = "yes"
} 
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
            $assignmentjson = $profilevalue[4]
            $policy = $policyjson
            ##If policy is conditional access, we need special config
            if ($policyuri -eq "conditionalaccess") {
                write-output "Creating Conditional Access Policy"
                writelog "Creating Conditional Access Policy"
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
                write-output "Restoring Policy $tname"
                writelog "Restoring Policy $tname"

            $copypolicy = Invoke-MgGraphRequest -Uri $policyuri -Method Post -Body $body  -ContentType "application/json; charset=utf-8"
            ##Assign if selected
            if ($assignments -eq "yes") {
                write-output "Assignment Selected, assigning policy"
                writelog "Assignment Selected, assigning policy"

                if ($assignmentjson -ne "No Available Assignment") {
                $copypolicyid = $copypolicy.id
                $assignmenturi = $policyuri + "/" + $copypolicyid + "/assign"
                    ##Check if group creation
                    if ($groupcreate -eq "yes") {
                        $assignmenttoid = convertnametoid -json $assignmentjson -allgroups $allgroups -allfilters $allfilters -create "yes"
                    }
                    else {
                        $assignmenttoid = convertnametoid -json $assignmentjson -allgroups $allgroups -allfilters $allfilters -create "no"
                    }
                $assignments2a = @"
                {
                    "assignments": [
                
"@
                $assignmentjson2b = ($assignmenttoid | select-object * -excludeproperty id, source, sourceId, intent | ConvertTo-Json).replace("[","").replace("]","")
                $assignmentjson2c = @"
            ]
            }
"@
                $assignmentjson2 = $assignments2a + $assignmentjson2b + $assignmentjson2c
                Invoke-MgGraphRequest -Uri $assignmenturi -Method Post -Body $assignmentjson2  -ContentType "application/json"
                }
            }
        }
            catch {

            }



            ##If policy is an admin template, we need to loop through and add the settings
            if ($policyuri -eq "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations") {
                write-output "Policy is admin template, restoring values"
                writelog "Policy is admin template, restoring values"

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
        if (!$WebHookData) {
            Stop-Transcript  
        }
                  

            if (($automated -eq "yes") -or ($WebHookData)) {
                $backupreason = "Log on $tenant"

                ##Ingest it
                $logcontent = Get-Content -Path $Logfile      
                ##Encode profiles to base64
                $logencoded =[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($logcontent))
                ##Upload Logs
                writelog "Uploading log to Git Repo"
                if ($repotype -eq "github") {
                    writelog "Uploading to Github"
                ##Upload to GitHub
                $date =get-date -format yyMMddHHmmss
                $date = $date.ToString()
                $readabledate = get-date -format dd-MM-yyyy-HH-mm-ss
                $filename = $tenant+"-log-"+$date+".json"
                $uri = "https://api.github.com/repos/$ownername/$reponame/contents/$filename"
                $message = "$backupreason - $readabledate"
                $body = '{{"message": "{0}", "content": "{1}" }}' -f $message, $logencoded
                (Invoke-RestMethod -Uri $uri -Method put -Headers @{'Authorization'='bearer '+$token;} -Body $body -ContentType "application/json")
                }
                if ($repotype -eq "gitlab") {
                    writelog "Uploading to GitLab"
                ##Upload to GitLab
                $date = Get-Date -Format yyMMddHHmmss
                $date = $date.ToString()
                $readabledate = Get-Date -Format dd-MM-yyyy-HH-mm-ss
                $filename = $tenant + "-log-" + $date + ".json"
                $GitLabUrl = "https://gitlab.com/api/v4"
                
                # Create a new file in the repository
                $CommitMessage = $backupreason
                $BranchName = "main"
                $FileContent = @{
                    "branch" = $BranchName
                    "commit_message" = $CommitMessage
                    "actions" = @(
                        @{
                            "action" = "create"
                            "file_path" = $filename
                            "content" = $logencoded
                        }
                    )
                }
                $FileContentJson = $FileContent | ConvertTo-Json -Depth 10
                $CreateFileUrl = "$GitLabUrl/projects/$project/repository/commits"
                $Headers = @{
                    "PRIVATE-TOKEN" = $token
                }
                Invoke-RestMethod -Uri $CreateFileUrl -Method Post -Headers $Headers -Body $FileContentJson -ContentType "application/json"
                }
                if ($repotype -eq "azuredevops") {
                    $date =get-date -format yyMMddHHmmss
                $date = $date.ToString()
                
                    $filename = $tenant+"-log-"+$date+".json"
                    writelog "Uploading to Azure DevOps"
                    Add-DevopsFile -repo $reponame -project $project -organization $ownername -filename $filename -filecontent $logcontent -token $token -comment $backupreason
                
                }
                }

# SIG # Begin signature block
# MIIoGQYJKoZIhvcNAQcCoIIoCjCCKAYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBAfEgjFfONkeXR
# 1ymB762EJYGLK82aLY//Pcs60hddl6CCIRwwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# gjcCARUwLwYJKoZIhvcNAQkEMSIEIO7ACaTudBFM8/LY3sNwChU7eGAxN838hnrb
# sVI8BVbWMA0GCSqGSIb3DQEBAQUABIICAB0a5ISGhVDdybL4cmHnIirKcPTkCLUB
# vQIT1AQUEB3teTcQfdUPHCb3ibhrcTj9kfyqw7S7EzsNyZxPnAzwbLbazrLzN8mg
# UPRKz+KRIKHxJTo6ML1MG/QG1zy0WjPYE/22uQw+S2FLTIX48Ps5zwjSCQO4aQx9
# mZbOAFZkkgLCLt3kGZjObOGai10LhqwKpKsf0pHcDLF7pPjyqfPaAVF81Lsg0VDz
# p258wdl0iK57WIhEnvi016Yj4uFpfsJKykdduixDYnUEhnGikLy22O6O/nbIpTjK
# 9eFI+C1zGwe1z3rK7G1gL7+O2M70dSzAEkRci9Mz/6f+p6kLScwl5YBMhqUsepl6
# WVqMZcwzvfEvhBeM7/QYX2+ALCYrcOSLNl4N0ovbP+adUT4qbPyrynICBuU3nvkl
# mVYaYgtkp+1ZC0rtUG7gkONPAX0ZSyHPUIIvnS2UohoG8aHSEAQjQ79F6BhSi765
# zAxp4zNsbFyg2i4wcHULEd6v7lP9sjv/XNr3oAqtKC3811LJ03zsDUwHL539vQSI
# vGwZ9vF82n3JJDgl5fPuOV5Gt1tJtQLTTWifDrhdQV6y2Lk04BfX1m/DpPREDIah
# 6IUOM3dziDvj+zJIMVZHUgjN/7vugOYdLzuO5CwVXOrbaHe7ZKNAyTCnx2wg5T8n
# R+P1KNaKKGDwoYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkG
# A1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdp
# Q2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQ
# BUSv85SdCDmmv9s/X+VhFjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzEL
# BgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI0MDUxMDEwMzA0M1owLwYJKoZI
# hvcNAQkEMSIEIDok8awnuyKJNFTfAlYEOr4eC/rAHQ7L4fmYQyS0LlgrMA0GCSqG
# SIb3DQEBAQUABIICABMUmILcfGIoEXmGnvAmb1beRCMce+WgTlgi3YvTzXiyS05e
# 9Re3jUK8wURix1/+ZPx6zaSZDwjBozloZzbt+TnvHsxU0cwvhGODBSnmokVX1N7L
# l0s7U/6/5IVd/uexwnheuUQroB5Z507fDmgRkU0bSZ4Dw9wrBOH2ZCLFJ0sdaOO/
# QgFcMc0jiqJWkBqADjg2vbKd72GfZwX1EwHi5o4CaGN0FleeSkWdiE3cHbKsFLGB
# SVlhT30y0ONbol6T5eKy1wOJ6PXH+fWqLVnMWDauTU2SG0Tc3FQazy86/f4lXSEs
# RCk92GpY6PT8JkXgeYRKe8PmUdmhlkgKDsX/8hZPYpody2EH25OHg1zVMOKUW71Y
# GEyE2nSmcS+pnefH7j7dVYCQgybIrt+mOuPNizE7FpX6dEafXQeUjr918D4bhzAZ
# boZJlFY2Td0VuqimhjBp25PN8jPSzohosu1itiswRty439m0+nQIkyWAbfUwxaAW
# 5hhkgmpVzAy/n9TNES7kjw0i3ln/G7IfDEJiNKKbhOQxB9lxrf0DCM2VndNdI+4F
# z6TG9LVYDB2olYJEV6OucPO+Cl19Ws2xM2YBm99Zn+761qHV4zmdEd+AGnvVK8I7
# 2fTK1kg3ZPelpLb+t/K/dC7Y539DkKxq8HzRR4Gk3jbILqGTZUpfyvxOQfDH
# SIG # End signature block
