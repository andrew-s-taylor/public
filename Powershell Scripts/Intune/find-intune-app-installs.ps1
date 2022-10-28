<#PSScriptInfo
.VERSION 2.2.0
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
  Version:        2.2.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  24/07/2022
  Last Change:    28/10/2022    
  Purpose/Change: Initial script development
  Change: Added CSV output
  Change: Amended to only show Installed devices
  Change: Added logic to bypass 1000 device limit
  
.EXAMPLE
N/A
#>

####################################################

function Get-AuthToken {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthToken
    Authenticates you with the Graph API interface
    .NOTES
    NAME: Get-AuthToken
    #>
    
    [cmdletbinding()]
    
    param
    (
        [Parameter(Mandatory=$true)]
        $User
    )
    
    $userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User
    
    $tenant = $userUpn.Host
    
    Write-Host "Checking for AzureAD module..."
    
        $AadModule = Get-Module -Name "AzureAD" -ListAvailable
    
        if ($AadModule -eq $null) {
    
            install-module AzureAD -Scope CurrentUser -AllowClobber -Force
    
        }
    
    
    # Getting path to ActiveDirectory Assemblies
    # If the module count is greater than 1 find the latest version
    
        if($AadModule.count -gt 1){
    
            $Latest_Version = ($AadModule | select version | Sort-Object)[-1]
    
            $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }
    
                # Checking if there are multiple versions of the same module found
    
                if($AadModule.count -gt 1){
    
                $aadModule = $AadModule | select -Unique
    
                }
    
            $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
            $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    
        }
    
        else {
    
            $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
            $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    
        }
    
    [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
    
    [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null
    
    $clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
    
    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
    
    $resourceAppIdURI = "https://graph.microsoft.com"
    
    $authority = "https://login.microsoftonline.com/$Tenant"
    
        try {
    
        $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
    
        # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
        # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession
    
        $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"
    
        $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")
    
        $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId).Result
    
            # If the accesstoken is valid then create the authentication header
    
            if($authResult.AccessToken){
    
            # Creating header for Authorization token
    
            $authHeader = @{
                'Content-Type'='application/json'
                'Authorization'="Bearer " + $authResult.AccessToken
                'ExpiresOn'=$authResult.ExpiresOn
                }
    
            return $authHeader
    
            }
    
            else {
    
            Write-Host
            Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
            Write-Host
            break
    
            }
    
        }
    
        catch {
    
        write-host $_.Exception.Message -f Red
        write-host $_.Exception.ItemName -f Red
        write-host
        break
    
        }
    
    }
    
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
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'displayName').contains("$Name") -and (!($_.'@odata.type').Contains("managed")) -and (!($_.'@odata.type').Contains("#microsoft.graph.iosVppApp")) }
    
            }
    
            else {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { (!($_.'@odata.type').Contains("managed")) -and (!($_.'@odata.type').Contains("#microsoft.graph.iosVppApp")) }
    
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
    
    #region Authentication
    
    write-host
    
    # Checking if authToken exists before running authentication
    if($global:authToken){
    
        # Setting DateTime to Universal time to work in all timezones
        $DateTime = (Get-Date).ToUniversalTime()
    
        # If the authToken exists checking when it expires
        $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes
    
            if($TokenExpires -le 0){
    
            write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
            write-host
    
                # Defining User Principal Name if not present
    
                if($User -eq $null -or $User -eq ""){
    
                $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
                Write-Host
    
                }
    
            $global:authToken = Get-AuthToken -User $User
    
            }
    }
    
    # Authentication doesn't exist, calling Get-AuthToken function
    
    else {
    
        if($User -eq $null -or $User -eq ""){
    
        $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
        Write-Host
    
        }
    
    # Getting the authorization token
    $global:authToken = Get-AuthToken -User $User
    
    }
    
    #endregion
    
    ####################################################
    
    $Intune_Apps = Get-IntuneApplication | Select-Object displayName,id | Out-GridView -Title "Intune Applications" -passthru | ForEach-Object {
    
    $thisapp = $_.displayName
    $thisappid = $_.id
    
    ##Loop through devices
    $devicesuri = "https://graph.microsoft.com/beta/devicemanagement/manageddevices"
    $devicelist = (Invoke-RestMethod -Uri $devicesuri -Headers $authToken -Method Get)
    $Results = @()
    $Results += $devicelist.value

    $Pages = $devicelist.'@odata.nextLink'
    while($null -ne $Pages) {

    Write-Warning "Checking Next page"
    $Addtional = Invoke-RestMethod -Headers $authToken -Uri $Pages -Method Get

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
    $fullapplist = Invoke-RestMethod -Uri $appsuri -Headers $authToken -Method Get
    $appstocheck = $fullapplist.mobileapplist
    foreach ($app in $appstocheck) {
        ##Query and add hostname to list if found (only if installed successfully)
        if (($app.applicationid -eq $thisappid) -and ($app.installstate -eq "installed")) {

            ##Get Install Date/Time
            $troubleshootingguid = $deviceid+"_"+$thisappid
            $eventsuri = "https://graph.microsoft.com/beta/users('$primaryuser')/mobileAppTroubleshootingEvents('$troubleshootingguid')?`$select=history"
            $events = (Invoke-RestMethod -Uri $eventsuri -Headers $authToken -Method Get).history
            foreach ($event in $events) {                
            $actiontype = $event.actiontype
            $datatype = $event.'@odata.type'
                if ($actiontype -eq "installed") {
                    $installdate = $event.occurrenceDateTime
                    $installdate2 = $installdate.Split(".")[0]
                    $output++
                }
                else {  
                    if ($datatype -eq "#microsoft.graph.mobileAppTroubleshootingAppUpdateHistory") { 
                    $installdate = $event.occurrenceDateTime
                    $installdate2 = $installdate.Split(".")[0]
                    $output++
                     
                }
            }
            }
            if ($output -gt 0) {
            $appinstallsgui += $devicename + " - " + $installdate2
            $appinstalls += New-Object PsObject -property @{
            "Device" = $devicename
            "Install Date" = $installdate2
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
    