<#PSScriptInfo
.VERSION 1.0.2
.GUID 90ccb2c9-a75c-4d6b-a92a-a12866166b84
.AUTHOR AndrewTaylor
.DESCRIPTION Creates Windows 365 for all purchased SKUs and then nests them within master groups
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
Creates Windows 365 groups for each SKU
.DESCRIPTION
Creates Windows 365 for all purchased SKUs and then nests them within master groups

.INPUTS
None
.OUTPUTS
Creates a log file in %Temp%
.NOTES
  Version:        1.0.2
  Author:         Andrew Taylor
  WWW:            andrewstaylor.com
  Creation Date:  25/07/2022
  Purpose/Change: Initial script development
  
.EXAMPLE
N/A
#>


##################################################################################################################################
#################                                                  INITIALIZATION                                #################
##################################################################################################################################
$ErrorActionPreference = "Continue"
##Start Logging to %TEMP%\intune.log
$date = get-date -format yyyyMMddTHHmmssffff
Start-Transcript -Path $env:TEMP\intune-$date.log

#Install MS Graph if not available
Write-Host "Installing Microsoft Graph modules if required (current user scope)"

#Install MS Graph if not available
#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication) {
    Write-Host "Microsoft Graph Authentication Already Installed"
} 
else {
        Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser -Repository PSGallery -Force -RequiredVersion 1.19.0 
        Write-Host "Microsoft Graph Authentication Installed"
}

if (Get-Module -ListAvailable -Name Microsoft.Graph.Groups) {
    Write-Host "Microsoft Graph Groups Already Installed "
} 
else {
        Install-Module -Name Microsoft.Graph.Groups -Scope CurrentUser -Repository PSGallery -Force -RequiredVersion 1.19.0  
        Write-Host "Microsoft Graph Groups Installed"
}
# Load the Graph module
Import-Module microsoft.graph.authentication
import-module microsoft.Graph.Groups

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
## https://www.powershellgallery.com/packages/Microsoft.Graph.Authentication/1.19.0
## https://www.powershellgallery.com/packages/Microsoft.Graph.Groups/1.19.0


if ($automated -eq "yes") {
    ##################################################################################################################################
    #################                                                  VARIABLES                                     #################
    ##################################################################################################################################
    

    $clientid = "YOUR_AAD_REG_ID"

    $clientsecret = "YOUR_CLIENT_SECRET"

    $sourcetenant = "TENANT_ID"
    
    
    ##################################################################################################################################
    #################                                             END  VARIABLES                                     #################
    ##################################################################################################################################
    }

###############################################################################################################
######                                          MS Graph Implementations                                 ######
###############################################################################################################
if ($automated -eq "yes") {
 

Connect-ToGraph -Tenant $sourcetenant -AppId $clientid -AppSecret $clientsecret
write-host "Graph Connection Established"
}
else {
##Connect to Graph
    Connect-ToGraph -Scopes "Domain.Read.All, Domain.ReadWrite.All, Directory.Read.All openid, profile, email, offline_access, Group.ReadWrite.All"

}



###############################################################################################################
######                                                     ENGAGE                                        ######
###############################################################################################################


##Create AAD Group
write-host "Creating Azure AD Groups"
##Create W365 Groups for W365 users, manually assigned

##Check if group exists first
$w365users = Get-MgGroup -Filter "DisplayName eq 'W365-Users'"
if ($null -eq $w365users) {
    write-host "Creating W365 Users Group"
    $w365users = New-MGGroup -DisplayName "W365-Users" -Description "Windows 365 Users" -MailEnabled:$False -MailNickName "W365Users" -SecurityEnabled -IsAssignableToRole:$false
    write-host "W365 Users Group Created"
}
else {
    write-host "W365 Users Group Already Exists"
}

##Check if device group exists
$w365devices = Get-MgGroup -Filter "DisplayName eq 'W365 Devices'"
if ($null -eq $w365devices) {
##Create Devices Group with dynamic membership based on Cloud PC model type
write-host "Creating W365 Devices Group - Dynamically Assigned"
$w365devices = New-MGGroup -DisplayName "W365 Devices" -Description "Dynamic group for all Windows 365 Single User devices" -MailEnabled:$False -MailNickName "w365devices" -SecurityEnabled -GroupTypes "DynamicMembership" -MembershipRule "(device.deviceModel -startsWith ""Cloud"")" -MembershipRuleProcessingState "On" -IsAssignableToRole:$false
write-host "W365 Devices Group Created"
}
else {
    write-host "W365 Devices Group Already Exists"
}



## Get the Group ID for our Win365 devices
$groupid = $w365users.Id

##Grab all SKUs and create groups accordingly

##Assign Licenses to Group
write-host "Creating groups and assigning licenses"

##Get Assigned SKUs
##Get All skus in the tenant
write-host "Getting SKUs"
$sku2 = ((Invoke-MgGraphRequest -uri "https://graph.microsoft.com/v1.0/subscribedSkus" -method get -OutputType PSObject).value)
##Loop through looking for W365 enterprise non-frontline SKUs (currently start with either CPC_E)
$skuids = @()
foreach ($sku in $sku2) {
    $part = $sku.skuPartNumber
    if ($part -like "*CPC_E*") {
        $skuidsobject = [pscustomobject]@{
            sid = $sku.skuid
            part = $part
        }
        $skuids += $skuidsobject
        write-host "SKU Found - $part"
    }
}
$i = 1
foreach ($skuiditem in $skuids) {

    $skuid = $skuiditem.sid
    $skupart = $skuiditem.part
##Check if this group already exists
$w365userssku = Get-MgGroup -Filter "DisplayName eq 'W365-Users-$skupart'"
if ($null -eq $w365userssku) {

##Create W365 Groups for W365 users of each sku, manually assigned
write-host "Creating W365 Users Group for SKU $skupart"
$w365userssku = New-MGGroup -DisplayName "W365-Users-$skupart" -Description "Windows 365 Users $skupart" -MailEnabled:$False -MailNickName "W365Users_$i" -SecurityEnabled -IsAssignableToRole:$false
write-host "W365 Users Group Created for SKU $skupart"

$skugroupid = $w365userssku.Id
##Assign the license to the group
write-host "Assigning License to Group - W365 Users $skupart"
$uri = "https://graph.microsoft.com/v1.0/groups/$skugroupid/assignLicense"
$body = @"
{
	"addLicenses": [{
		"disabledPlans": [],
		"skuId": "$skuid"
	}],
	"removeLicenses": []
}
"@
Invoke-MgGraphRequest -Uri $uri -Method POST -Body $body -ContentType "application/json"
write-host "License Assigned to Group W365 Users $skupart"

##Add to main group
write-host "Nesting Group $skugroupid in $groupid"
New-MgGroupMember -GroupId "$groupid" -DirectoryObjectId "$skugroupid"
write-host "Group $skugroupid nested in $groupid"

$i++
}
else {
    write-host "Group W365-Users-$skupart already exists, skipping"
}
}


###############Front Line Users

##Create AAD Group

##Check if group exists first
$w365frontlineusers = Get-MgGroup -Filter "DisplayName eq 'W365-Frontline-Users'"

if ($null -eq $w365users) {


##Create W365 Groups for W365 Frontline users, manually assigned
write-host "Creating W365 Frontline Users Group"
$w365frontlineusers = New-MGGroup -DisplayName "W365-Frontline-Users" -Description "Windows 365 Frontline Users" -MailEnabled:$False -MailNickName "W365FrontlineUsers" -SecurityEnabled -IsAssignableToRole:$false
write-host "W365 Frontline Users Group Created"
}
else {
    write-host "W365 Frontline Users Group already exists"
}


##Assign Licenses to Group
write-host "Assigning Licenses to Group"
$frontlinegroupid = $w365frontlineusers.Id

##Get Assigned SKUs
##Get All skus in the tenant
write-host "Getting SKUs"
$skuf2 = ((Invoke-MgGraphRequest -uri "https://graph.microsoft.com/v1.0/subscribedSkus" -method get -OutputType PSObject).value)
##Loop through looking for W365 SKUs (currently start with Windows_365_S)
$skuidfs = @()

foreach ($skuf in $skuf2) {
    $partf = $skuf.skuPartNumber
    if (($partf -like "*Windows_365_S*")) {
        $skuidsobjectf = [pscustomobject]@{
            sid = $skuf.skuid
            part = $partf
        }
        $skuidfs += $skuidsobjectf
        write-host "SKU Found - $partf"
    }
}

$i = 1
foreach ($skuidfitem in $skuidfs) {

    
    $skuidf = $skuidfitem.sid
    $skupartf = $skuidfitem.part
##Check if group exists

$w365usersskuf = Get-MgGroup -Filter "DisplayName eq 'W365-Frontline-Users-$skupartf'"
if ($null -eq $w365usersskuf) {


##Create W365 Groups for W365 users of each sku, manually assigned
write-host "Creating W365 Users Group for SKU $skupartf"
$w365usersskuf = New-MGGroup -DisplayName "W365-Frontline-Users-$skupartf" -Description "Windows 365 Frontline Users $skupartf" -MailEnabled:$False -MailNickName "W365Usersfront_$i" -SecurityEnabled -IsAssignableToRole:$false
write-host "W365 Frontline Users Group Created for SKU $skuidf"

$skugroupidf = $w365usersskuf.Id
##Assign the license to the group
write-host "Assigning License to Group - W365 Users $skupartf"
$uri = "https://graph.microsoft.com/v1.0/groups/$skugroupidf/assignLicense"
$body = @"
{
	"addLicenses": [{
		"disabledPlans": [],
		"skuId": "$skuidf"
	}],
	"removeLicenses": []
}
"@
Invoke-MgGraphRequest -Uri $uri -Method POST -Body $body -ContentType "application/json"
write-host "License Assigned to Group W365 Users $skupartf"

##Add to main group
write-host "Nesting Group $skugroupidf in $frontlinegroupid"
New-MgGroupMember -GroupId "$frontlinegroupid" -DirectoryObjectId "$skugroupidf"
write-host "Group $skugroupidf nested in $frontlinegroupid"

$i++
}
else {
    write-host "Group W365-Users-$skupartf already exists, skipping"
}

}
