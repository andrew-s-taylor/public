<#PSScriptInfo
.VERSION 2.1
.GUID 729ebf90-26fe-4795-92dc-ca8f570cdd22
.AUTHOR AndrewTaylor
.DESCRIPTION Display a list of devices for a user in Intune with drill-down for more information
.COMPANYNAME 
.COPYRIGHT GPL
.TAGS intune devicemanagement graph apps devices
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
  Displays List of machines assigned to a user with drill-down
.DESCRIPTION
Display an Intune list of machines assigned to a user in a grid to find more details

.INPUTS
None required
.OUTPUTS
GridView
.NOTES
  Version:        2.1
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  21/12/2021
  Modified Date:  30/10/2022
  Purpose/Change: Initial script development
  Change: Switched to Graph Authentication
  
.EXAMPLE
N/A
#>

####################################################


Write-Host "Installing Microsoft Graph modules if required (current user scope)"

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


# Load the Graph module
Import-Module microsoft.graph

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
#Connect to Graph
Connect-ToGraph -Scopes RoleAssignmentSchedule.ReadWrite.Directory, Domain.Read.All, Domain.ReadWrite.All, Directory.Read.All, Policy.ReadWrite.ConditionalAccess, DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, openid, profile, email, offline_access

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
Get-ScriptVersion -liveuri "https://raw.githubusercontent.com/andrew-s-taylor/public/main/Powershell%20Scripts/Intune/get-intune-details-from-user.ps1"



Function Get-IntuneDeviceByUser(){

<#
.SYNOPSIS
This function is used to get devices per user from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any device assigned to a user
.EXAMPLE
Get-IntuneDeviceByUser
Returns any devices configured to a user in Intune
.NOTES
NAME: Get-IntuneDeviceByUser
#>

[cmdletbinding()]

param
(
    $userPrincipalName
)

$graphApiVersion = "Beta"
$Resource = "deviceAppManagement/mobileApps"

    try {


        $uri = "https://graph.microsoft.com/$graphApiVersion/DeviceManagement/managedDevices?filter=userPrincipalName eq '$userPrincipalName'"
        (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value 

    

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

Function Get-IntuneDeviceByName(){

    <#
    .SYNOPSIS
    This function is used to get devices by PC name from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets a device by PC name
    .EXAMPLE
    Get-IntuneDeviceByUser
    Returns a devices in Intune
    .NOTES
    NAME: Get-IntuneDeviceByName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $Name
    )
    
    $graphApiVersion = "Beta"
    $Resource = "deviceAppManagement/mobileApps"
    
        try {
    
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/DeviceManagement/managedDevices?filter=deviceName eq '$Name'"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value 
    
        
    
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




    Function Get-IntuneDeviceConfig(){

        <#
        .SYNOPSIS
        This function is used to get device configuration from the Graph API REST interface
        .DESCRIPTION
        The function connects to the Graph API Interface and gets device configuration by name
        .EXAMPLE
        Get-IntuneDeviceConfig
        Returns a devices in Intune
        .NOTES
        NAME: Get-IntuneDeviceConfig
        #>
        
        [cmdletbinding()]
        
        param
        (
            $Name
        )
        
        $graphApiVersion = "Beta"
        
            try {
        
        
                $uri = "https://graph.microsoft.com/Beta/DeviceManagement/managedDevices/$Name/deviceconfigurationstates"
                (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value 
        
            
        
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



        Function Get-IntuneDeviceCompliance(){

            <#
            .SYNOPSIS
            This function is used to get device compliance from the Graph API REST interface
            .DESCRIPTION
            The function connects to the Graph API Interface and gets device compliance by name
            .EXAMPLE
            Get-IntuneDeviceCompliance
            Returns a devices in Intune
            .NOTES
            NAME: Get-IntuneDeviceCompliance
            #>
            
            [cmdletbinding()]
            
            param
            (
                $Name
            )
            
            $graphApiVersion = "Beta"
            
                try {
            
            
                    $uri = "https://graph.microsoft.com/Beta/DeviceManagement/managedDevices/$Name/devicecompliancepolicystates"
                    (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value 
            
                
            
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


Function Get-IntuneDeviceApps(){

                <#
                .SYNOPSIS
                This function is used to get device apps from the Graph API REST interface
                .DESCRIPTION
                The function connects to the Graph API Interface and gets device apps by name
                .EXAMPLE
                Get-IntuneDeviceApps
                Returns a devices in Intune
                .NOTES
                NAME: Get-IntuneDeviceApps
                #>
                
                [cmdletbinding()]
                
                param
                (
                    $Name
                )
                
                $graphApiVersion = "Beta"
                
                    try {
                
                        
                        $uri = "https://graph.microsoft.com/beta/deviceManagement/manageddevices/$Name/?`$expand=detectedApps"
                        (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject) 
                
                    
                
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


[void][Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic')
$userPrincipalName = [Microsoft.VisualBasic.Interaction]::InputBox("Please enter the user principal name of the user you want to get the devices for:","Name?")
$devices = Get-IntuneDeviceByUser -userPrincipalName $userPrincipalName | Select-Object userPrincipalName,deviceName,id | Out-GridView -Title "Devices by User" -passthru | ForEach-Object {

    $Menu = [ordered]@{

        1 = 'Device Info'
      
        2 = 'Configuration Policies'
      
        3 = 'Compliance Policies'

        4 = 'Discovered Apps'

      
        }
      
        
      $deviceid = $_.id
      $devicename = $_.devicename
        $Result = $Menu | Out-GridView -PassThru  -Title 'Make a  selection'
      
        Switch ($Result)  {
      
        {$Result.Name -eq 1} {Get-IntuneDeviceByName -Name $devicename | Out-GridView -Title "Device Details"}
      
        {$Result.Name -eq 2} {Get-IntuneDeviceConfig -Name $deviceid | Out-GridView -Title "Device Configuration Profiles"}
      
        {$Result.Name -eq 3} {Get-IntuneDeviceCompliance -Name $deviceid | Out-GridView -Title "Device Compliance Policies"}   

        {$Result.Name -eq 4} {
            $apps = get-intuneDeviceApps -Name $deviceid | select-object DetectedApps
            $applist = @()
            $apps1 = $apps.detectedApps
            foreach ($app in $apps1) {
                $applist += $app.displayName + "-" + $app.version

            }
            $applist | Out-GridView -Title "Discovered Apps"}  
      
      

  
}
  } 


