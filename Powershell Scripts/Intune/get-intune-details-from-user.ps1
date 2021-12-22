<#PSScriptInfo
.VERSION 1.0
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
  Version:        1.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  21/12/2021
  Purpose/Change: Initial script development
  
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
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value 

    

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
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value 
    
        
    
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
                (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value 
        
            
        
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
                    (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value 
            
                
            
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
                        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get) 
                
                    
                
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


