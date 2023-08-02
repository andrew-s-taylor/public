<#
.SYNOPSIS
Switches Intune Apps to allow Company Portal Uninstall
.DESCRIPTION
Switches Intune Apps to allow Company Portal Uninstall
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
  Version:        1.0.1
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  01/08/2023
  Purpose/Change: Initial script development


  .EXAMPLE
N/A
#>

<#PSScriptInfo
.VERSION 1.0.1
.GUID 95df78d9-209b-434e-bc56-2bee6f9dae8b
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
    [string]$selected #Selected can be "all" or literally anything else
    ,  
    [string]$tenant #Tenant ID (optional) for when automating and you want to use across tenants instead of hard-coded
    ,
    [string]$clientid #ClientID is the type of Azure AD App Reg ID
    ,
    [string]$clientsecret #ClientSecret is the type of Azure AD App Reg Secret
    )


##################################################################################################################################
#################                                                  FUNCTIONS                                     #################
##################################################################################################################################

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


function getallpagination () {
    <#
.SYNOPSIS
This function is used to grab all items from Graph API that are paginated
.DESCRIPTION
The function connects to the Graph API Interface and gets all items from the API that are paginated
.EXAMPLE
getallpagination -url "https://graph.microsoft.com/v1.0/groups"
 Returns all items
.NOTES
 NAME: getallpagination
#>
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

function set-appuninstall() {
    [cmdletbinding()]
    
    param
    (
        $appid
    )
    $app = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$appid" -Method Get -OutputType PSObject
    $app.allowAvailableUninstall = $true
    $appid = $app.id
    $app = $app | Select-Object * -ExcludeProperty createdDateTime, id, lastModifiedDateTime, uploadState, publishingState, isAssigned, dependentAppCount, supersedingAppCount, supersededAppCount, committedContentVersion, size, minimumSupportedOperatingSystem
        $appjson = $app | ConvertTo-Json -Depth 10
        $appuri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$appid"
        Invoke-MgGraphRequest -Uri $appuri -Method Patch -Body $appjson
}



##################################################################################################################################
#################                                              Connection                                        #################
##################################################################################################################################
#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication) {
    write-output "Microsoft Graph Authentication Already Installed"
} 
else {
        Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser -Repository PSGallery -Force
        write-output "Microsoft Graph Authentication Installed"
}

Import-Module microsoft.graph.authentication


if (($automated -eq "yes") -or ($aadlogin -eq "yes")) {
 
    Connect-ToGraph -Tenant $tenant -AppId $clientId -AppSecret $clientSecret
    write-output "Graph Connection Established"
    }
    else {
    ##Connect to Graph
    Select-MgProfile -Name Beta
    Connect-ToGraph -Scopes "Policy.ReadWrite.ConditionalAccess, CloudPC.ReadWrite.All, DeviceManagementServiceConfig.ReadWrite.All, RoleAssignmentSchedule.ReadWrite.Directory, Domain.Read.All, Domain.ReadWrite.All, Directory.Read.All, Policy.ReadWrite.ConditionalAccess, DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, openid, profile, email, offline_access, DeviceManagementRBAC.Read.All, DeviceManagementRBAC.ReadWrite.All"
    }



##################################################################################################################################
#################                                                ENGAGE                                          #################
##################################################################################################################################
##Get all apps
Write-Host "Getting all Windows Intune Apps"
$appsurl = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=isof('microsoft.graph.win32LobApp') or isof('microsoft.graph.microsoftStoreForBusinessApp')"

$allapps = getallpagination -url $appsurl
write-host "Apps Retrieved"


##Check if parameter set
if ($selected) {
    write-host "Parameter Set, checking value"
    if ($selected -eq "All") {
        $selected = "All"
    }
    else {
        $selected = "Some"
    }
    write-host "Parameter Value set to $selected"
}
else {
    write-host "No parameter set, prompting"
    Add-Type -AssemblyName System.Windows.Forms

$form = New-Object System.Windows.Forms.Form
$form.Text = "All Apps or Select"
$form.Width = 300
$form.Height = 150
$form.StartPosition = "CenterScreen"

$label = New-Object System.Windows.Forms.Label
$label.Text = "Select an option:"
$label.Location = New-Object System.Drawing.Point(10, 20)
$label.AutoSize = $true
$form.Controls.Add($label)

$exportButton = New-Object System.Windows.Forms.Button
$exportButton.Text = "All"
$exportButton.Location = New-Object System.Drawing.Point(100, 60)
$exportButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
$form.AcceptButton = $exportButton
$form.Controls.Add($exportButton)

$viewButton = New-Object System.Windows.Forms.Button
$viewButton.Text = "Select"
$viewButton.Location = New-Object System.Drawing.Point(180, 60)
$viewButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.CancelButton = $viewButton
$form.Controls.Add($viewButton)

$result = $form.ShowDialog()

if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    # Export code here
    $selected = "All"
} elseif ($result -eq [System.Windows.Forms.DialogResult]::Cancel) {
    # View code here
    $selected = "Some"
}
write-host "$selected Chosen"
}

if ($selected -eq "All") {
write-host "Changing for all apps"
$counter = 0
foreach ($app in $allapps) {
$counter++
Write-Progress -Activity 'Processing Application' -CurrentOperation $app.displayName -PercentComplete (($counter / $allapps.count) * 100)
set-appuninstall $app.id
}
}
else {
    $selectedapp = $allapps | select-object ID, DisplayName | Out-GridView -Title "Select Applications" -PassThru
    $counter = 0
foreach ($app in $selectedapp) {
$counter++
Write-Progress -Activity 'Processing Application' -CurrentOperation $app.displayName -PercentComplete (($counter / $selectedapp.count) * 100)
set-appuninstall $app.id
}
}