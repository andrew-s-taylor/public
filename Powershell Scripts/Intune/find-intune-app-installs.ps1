<#PSScriptInfo
.VERSION 3.0.2
.GUID 71d4d716-70bb-468a-9322-a0441468919b
.AUTHOR AndrewTaylor
.DESCRIPTION Lists Intune apps and shows which machines have it installed
.COMPANYNAME 
.COPYRIGHT GPL
.TAGS Intune App
.LICENSEURI https://github.com/andrew-s-taylor/public/blob/main/LICENSE
.PROJECTURI https://github.com/andrew-s-taylor/public
.ICONURI 
.EXTERNALMODULEDEPENDENCIES azureAD
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
#>
<#
.SYNOPSIS
  Displays List of apps from Intune with drill down to show where installed
.DESCRIPTION
Lists Intune apps and shows which machines have it installed

.INPUTS
None required
.OUTPUTS
GridView
.NOTES
  Version:        3.0.2
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  24/07/2022
  Last Change:    28/10/2022    
  Purpose/Change: Initial script development
  Change: Added CSV output
  Change: Amended to only show Installed devices
  Change: Added logic to bypass 1000 device limit
  Change: Switched authentication to MG Graph
  
.EXAMPLE
N/A
#>

####################################################

##Install Module

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

import-module microsoft.graph
##Authenticate
Connect-ToGraph -Scopes "DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, openid, profile, email, offline_access"
    

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
Get-ScriptVersion -liveuri "https://raw.githubusercontent.com/andrew-s-taylor/public/main/Powershell%20Scripts/Intune/find-intune-app-installs.ps1"


    ####################################################
    
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
        $Name
    )
    
    $graphApiVersion = "Beta"
    $Resource = "deviceAppManagement/mobileApps"
    
        try {
    
            if($Name){
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value | Where-Object { ($_.'displayName').contains("$Name") -and (!($_.'@odata.type').Contains("managed")) -and (!($_.'@odata.type').Contains("#microsoft.graph.iosVppApp")) }
    
            }
    
            else {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value | Where-Object { (!($_.'@odata.type').Contains("managed")) -and (!($_.'@odata.type').Contains("#microsoft.graph.iosVppApp")) }
    
            }
    
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
    
    
    ####################################################

    ####################################################
    
    $Intune_Apps = Get-IntuneApplication | Select-Object displayName,id | Out-GridView -Title "Intune Applications" -passthru | ForEach-Object {
    
    $thisapp = $_.displayName
    $thisappid = $_.id
    
    ##Loop through devices
    $devicesuri = "https://graph.microsoft.com/beta/devicemanagement/manageddevices"
    $devicelist = (Invoke-MgGraphRequest -Uri $devicesuri -Method Get -OutputType PSObject)
    $Results = @()
    $Results += $devicelist.value

    $Pages = $devicelist.'@odata.nextLink'
    while($null -ne $Pages) {

    Write-Warning "Checking Next page"
    $Addtional = Invoke-MgGraphRequest -Uri $Pages -Method Get

    if ($Pages){
    $Pages = $Addtional."@odata.nextLink"
    }
    $Results += $Addtional.value
    }
    $appinstalls = @()
    $appinstallsgui = @()
    ##Foreach device
    $output = 0
    foreach ($device in $Results) {
    ##Find Device ID
    $deviceid = $device.id
    $devicename = $device.devicename
    ##Find primary user
    $primaryuser = $device.userid
    ##Find installed apps
    $appsuri = "https://graph.microsoft.com/beta/users('$primaryuser')/mobileAppIntentAndStates('$deviceid')"
    $fullapplist = Invoke-MgGraphRequest -Uri $appsuri -Method Get -OutputType PSObject
    $appstocheck = $fullapplist.mobileapplist
    foreach ($app in $appstocheck) {
        ##Query and add hostname to list if found (only if installed successfully)
        if (($app.applicationid -eq $thisappid) -and ($app.installstate -eq "installed")) {

            ##Get Install Date/Time
            $troubleshootingguid = $deviceid+"_"+$thisappid
            $eventsuri = "https://graph.microsoft.com/beta/users('$primaryuser')/mobileAppTroubleshootingEvents('$troubleshootingguid')?`$select=history"
            $events = (Invoke-MgGraphRequest -Uri $eventsuri -Method Get -OutputType PSObject).history
            foreach ($event in $events) {                
            $actiontype = $event.actiontype
            $datatype = $event.'@odata.type'
                if ($actiontype -eq "installed") {
                    $installdate = $event.occurrenceDateTime
                    $output++
                }
                else {  
                    if ($datatype -eq "#microsoft.graph.mobileAppTroubleshootingAppUpdateHistory") { 
                    $installdate = $event.occurrenceDateTime
                    $output++
                     
                }
            }
            }
            if ($output -gt 0) {
            $appinstallsgui += $devicename + " - " + $installdate
            $appinstalls += New-Object PsObject -property @{
            "Device" = $devicename
            "Install Date" = $installdate
            }
        }
        }
    
    }
    }
    $filename = $env:temp + "\" + $thisapp + "-installs.csv"
        Write-Host
   $split = $appinstallsgui  -join "`n" 
    $Appoutput = @"
    Also in your clipboard
    Exported to $filename
    Name: $thisapp
    Installed Devices: 
    $split
"@
set-clipboard $Appoutput
$appinstalls | export-csv $filename -NoTypeInformation
    
    
        [System.Windows.MessageBox]::Show($Appoutput)
    
    }
    