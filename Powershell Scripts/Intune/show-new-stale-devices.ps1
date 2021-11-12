<#PSScriptInfo
.VERSION 1.0
.GUID 729ebf90-26fe-4795-92dc-ca8f570cdd22
.AUTHOR AndrewTaylor
.DESCRIPTION Display stale and new Intune devices
.COMPANYNAME 
.COPYRIGHT GPL
.TAGS intune aad
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
  Display stale and new Intune devices
.DESCRIPTION
Displays new and stale devices in a grid to find more details

.INPUTS
None required
.OUTPUTS
GridView
.NOTES
  Version:        1.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  12/11/2021
  Purpose/Change: Initial script development
  
.EXAMPLE
N/A
#>

####################################################


<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

#>

####################################################



######################################################################################## MICROSOFT FUNCTIONS #########################################################################################
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
    
            Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"
            $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable
    
        }
    
        if ($AadModule -eq $null) {
            write-host
            write-host "AzureAD Powershell module not installed..." -f Red
            write-host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
            write-host "Script can't continue..." -f Red
            write-host
            exit
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
    
    Function Get-AADUser(){
    
    <#
    .SYNOPSIS
    This function is used to get AAD Users from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any users registered with AAD
    .EXAMPLE
    Get-AADUser
    Returns all users registered with Azure AD
    .EXAMPLE
    Get-AADUser -userPrincipleName user@domain.com
    Returns specific user by UserPrincipalName registered with Azure AD
    .NOTES
    NAME: Get-AADUser
    #>
    
    [cmdletbinding()]
    
    param
    (
        $userPrincipalName,
        $Property
    )
    
    # Defining Variables
    $graphApiVersion = "v1.0"
    $User_resource = "users"
        
        try {
            
            if($userPrincipalName -eq "" -or $userPrincipalName -eq $null){
            
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($User_resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
            
            }
    
            else {
                
                if($Property -eq "" -or $Property -eq $null){
    
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($User_resource)/$userPrincipalName"
                Write-Verbose $uri
                Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
    
                }
    
                else {
    
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($User_resource)/$userPrincipalName/$Property"
                Write-Verbose $uri
                (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
    
                }
    
            }
        
        }
    
        catch {
    
        $ex = $_.Exception
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
    
    ################################################################################## END MICROSOFT FUNCTIONS ##################################################################################



    ################################################################################## CREATE FORM ##################################################################################


    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.Application]::EnableVisualStyles()
    
    $NewStale                        = New-Object system.Windows.Forms.Form
    $NewStale.ClientSize             = New-Object System.Drawing.Point(367,436)
    $NewStale.text                   = "Find New and Stale Devices"
    $NewStale.TopMost                = $false
    $NewStale.BackColor              = [System.Drawing.ColorTranslator]::FromHtml("#ffffff")
    
    $Label1                          = New-Object system.Windows.Forms.Label
    $Label1.text                     = "Find New Devices"
    $Label1.AutoSize                 = $true
    $Label1.width                    = 25
    $Label1.height                   = 10
    $Label1.location                 = New-Object System.Drawing.Point(99,83)
    $Label1.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',20)
    
    $Label2                          = New-Object system.Windows.Forms.Label
    $Label2.text                     = "In the last"
    $Label2.AutoSize                 = $true
    $Label2.width                    = 25
    $Label2.height                   = 10
    $Label2.location                 = New-Object System.Drawing.Point(42,126)
    $Label2.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',13)
    
    $hours                           = New-Object system.Windows.Forms.TextBox
    $hours.multiline                 = $false
    $hours.width                     = 100
    $hours.height                    = 20
    $hours.location                  = New-Object System.Drawing.Point(136,123)
    $hours.Font                      = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    
    $newdevices                      = New-Object system.Windows.Forms.Button
    $newdevices.text                 = "Find"
    $newdevices.width                = 89
    $newdevices.height               = 46
    $newdevices.location             = New-Object System.Drawing.Point(148,156)
    $newdevices.Font                 = New-Object System.Drawing.Font('Microsoft Sans Serif',17)
    
    $Label3                          = New-Object system.Windows.Forms.Label
    $Label3.text                     = "Find Stale Devices"
    $Label3.AutoSize                 = $true
    $Label3.width                    = 25
    $Label3.height                   = 10
    $Label3.location                 = New-Object System.Drawing.Point(84,269)
    $Label3.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',20)
    
    $Label4                          = New-Object system.Windows.Forms.Label
    $Label4.text                     = "In the last"
    $Label4.AutoSize                 = $true
    $Label4.width                    = 25
    $Label4.height                   = 10
    $Label4.location                 = New-Object System.Drawing.Point(42,312)
    $Label4.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',13)
    
    $Label5                          = New-Object system.Windows.Forms.Label
    $Label5.text                     = "hours"
    $Label5.AutoSize                 = $true
    $Label5.width                    = 25
    $Label5.height                   = 10
    $Label5.location                 = New-Object System.Drawing.Point(256,125)
    $Label5.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    
    $days                            = New-Object system.Windows.Forms.TextBox
    $days.multiline                  = $false
    $days.width                      = 100
    $days.height                     = 20
    $days.location                   = New-Object System.Drawing.Point(136,309)
    $days.Font                       = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    
    $Label6                          = New-Object system.Windows.Forms.Label
    $Label6.text                     = "days"
    $Label6.AutoSize                 = $true
    $Label6.width                    = 25
    $Label6.height                   = 10
    $Label6.location                 = New-Object System.Drawing.Point(255,313)
    $Label6.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    
    $olddevices                      = New-Object system.Windows.Forms.Button
    $olddevices.text                 = "Find"
    $olddevices.width                = 89
    $olddevices.height               = 46
    $olddevices.location             = New-Object System.Drawing.Point(148,340)
    $olddevices.Font                 = New-Object System.Drawing.Font('Microsoft Sans Serif',17)
    
    $Label7                          = New-Object system.Windows.Forms.Label
    $Label7.text                     = "Created by Andrew Taylor (andrewstaylor.com)"
    $Label7.AutoSize                 = $true
    $Label7.width                    = 25
    $Label7.height                   = 10
    $Label7.location                 = New-Object System.Drawing.Point(13,408)
    $Label7.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',8)
    
    $Panel1                          = New-Object system.Windows.Forms.Panel
    $Panel1.height                   = 141
    $Panel1.width                    = 350
    $Panel1.location                 = New-Object System.Drawing.Point(10,78)
    
    $Panel2                          = New-Object system.Windows.Forms.Panel
    $Panel2.height                   = 134
    $Panel2.width                    = 343
    $Panel2.location                 = New-Object System.Drawing.Point(13,255)
    
    $Label8                          = New-Object system.Windows.Forms.Label
    $Label8.text                     = "AAD Username"
    $Label8.AutoSize                 = $true
    $Label8.width                    = 25
    $Label8.height                   = 10
    $Label8.location                 = New-Object System.Drawing.Point(18,27)
    $Label8.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    
    $username                            = New-Object system.Windows.Forms.TextBox
    $username.multiline                  = $false
    $username.width                      = 196
    $username.height                     = 20
    $username.location                   = New-Object System.Drawing.Point(136,25)
    $username.Font                       = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    
    $NewStale.controls.AddRange(@($Label1,$Label2,$hours,$newdevices,$Label3,$Label4,$Label5,$days,$Label6,$olddevices,$Label7,$Panel1,$Panel2,$Label8,$username))
    


################################################################################ END CREATE FORM ##########################################################################################
 


    
    ######################################################################################   NEW DEVICES  ######################################################################################


    $newdevices.Add_Click({


        $user = $username.Text
        $hourstocheck = [int]$hours.Text
        $minutestocheck = $hourstocheck * 60
    # Filter for the minimum number of minutes when the device enrolled into the Intune Service
    ######################## AUTHENTICATE ########################
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
    
                # Defining Azure AD tenant name, this is the name of your Azure Active Directory (do not use the verified domain name)
    
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

    ####################################### END AUTHENTICATE ######################################






    
    $minutesago = "{0:s}" -f (get-date).addminutes(0-$minutestocheck) + "Z"
    
    $CurrentTime = [System.DateTimeOffset]::Now
    
    write-host "Checking if any Intune Managed Device Enrolled Date is within or equal to $minutestocheck minutes..." -f Yellow
    Write-Host
    write-host "Minutes Ago:" $minutesago -f Magenta
    Write-Host
    
        try {
    
        $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=enrolledDateTime ge $minutesago"
    
        $Devices = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | sort deviceName
    
        $Devices = $Devices | ? { $_.managementAgent -ne "eas" }
    
            # If there are devices not synced in the past 30 days script continues
            
            if($Devices){
    
            $DeviceCount = @($Devices).count
    
    
            $Devices | Select-Object deviceName | Out-GridView -Title "New Devices" -passthru | ForEach-Object {
            
    
                # Looping through all the devices returned
                $devicenametofind = $_.deviceName.ToString()
                $uri2 = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=deviceName eq '$devicenametofind'"
    
                $Device = (Invoke-RestMethod -Uri $uri2 -Headers $authToken -Method Get).Value
                $DeviceID = $device.id
                $LSD = $device.lastSyncDateTime
                $EDT = $device.enrolledDateTime    
                $EnrolledTime = [datetimeoffset]::Parse($EDT)
    
                $TimeDifference = $CurrentTime - $EnrolledTime
    
                $TotalMinutes = ($TimeDifference.TotalMinutes).tostring().split(".")[0]
                #Set Variables
                $devicename = $Device.deviceName
                $managementstate =$Device.managementState
                $operatingsystem = $Device.operatingSystem
                $enrolleddatetime = $Device.enrolledDateTime
                $lastsyncdatetime = $Device.lastSyncDateTime
                $devicetype = $Device.deviceType
                $jailbroken = $Device.jailBroken
                $compliance = $Device.complianceState
                $enrollmenttype = $Device.enrollmentType
                $AADreg = $Device.aadRegistered
                $managementagent = $Device.managementAgent
                $Appoutput = @"
                Device Name: $devicename
                Management State: $managementstate
                Operating System: $operatingsystem
                Device Type: $devicetype
                Last Sync Date Time: $lastsyncdatetime
                Enrolled Date Time: $enrolleddatetime
                Jail Broken: $jailbroken
                Compliance State: $compliance
                Enrollment Type: $enrollmenttype
                AAD Registered: $AADreg
                Management Agent: $managementagent
                Date Time difference is $TotalMinutes minutes from current date time...
    
"@
    
    [System.Windows.MessageBox]::Show($Appoutput)
    
                }
    
            }
    
            else {
    
            write-host "No Devices not checked in the last $minutestocheck minutes found..." -f green
            Write-Host
    
            }
    
        }
    
        catch {
    
        Write-Host
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        Write-Host
    
        break
    
        }
    
    })
        ############################################################################################################# END NEW DEVICES ##############################################################################################################






        ######################################################################################   OLD DEVICES  ######################################################################################

        $olddevices.Add_Click({


            $user = $username.Text
        $daystocheck = [int]$days.Text
        
    ######################## AUTHENTICATE ########################
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
    
                # Defining Azure AD tenant name, this is the name of your Azure Active Directory (do not use the verified domain name)
    
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

    ####################################### END AUTHENTICATE ######################################
    
        $daysago = "{0:s}" -f (get-date).AddDays(-$daystocheck) + "Z"
        
        $CurrentTime = [System.DateTimeOffset]::Now
        
        Write-Host
        Write-Host "Checking to see if there are devices that haven't synced in the last $daystocheck days..." -f Yellow
        Write-Host
        
            try {
        
            $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=lastSyncDateTime le $daysago"
        
            $Devices = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | sort deviceName
        
                # If there are devices not synced in the past 30 days script continues
                
                if($Devices){
        
                    $Devices | Select-Object deviceName | Out-GridView -Title "Old Devices" -passthru | ForEach-Object {
                
        
                        # Looping through all the devices returned
                        $devicenametofind = $_.deviceName.ToString()
                        $uri2 = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=deviceName eq '$devicenametofind'"
            
                        $Device = (Invoke-RestMethod -Uri $uri2 -Headers $authToken -Method Get).Value
                        $DeviceID = $device.id
                        $LSD = $device.lastSyncDateTime
                        $EDT = $device.enrolledDateTime    
                        $EnrolledTime = [datetimeoffset]::Parse($EDT)
            
                        $TimeDifference = $CurrentTime - $EnrolledTime
            
                        $TotalMinutes = ($TimeDifference.TotalMinutes).tostring().split(".")[0]
                        $LastSyncTime = [datetimeoffset]::Parse($LSD)
        
                    $TimeDifference = $CurrentTime - $LastSyncTime
                        #Set Variables
                        $devicename = $Device.deviceName
                        $managementstate =$Device.managementState
                        $operatingsystem = $Device.operatingSystem
                        $enrolleddatetime = $Device.enrolledDateTime
                        $lastsyncdatetime = $Device.lastSyncDateTime
                        $devicetype = $Device.deviceType
                        $jailbroken = $Device.jailBroken
                        $compliance = $Device.complianceState
                        $enrollmenttype = $Device.enrollmentType
                        $AADreg = $Device.aadRegistered
                        $managementagent = $Device.managementAgent
                        $userPrincipalName = $Device.userPrincipalName
                        $TD = $TimeDifference.days
                        $Appoutput = @"
                        Device Name: $devicename
                        Management State: $managementstate
                        Operating System: $operatingsystem
                        Device Type: $devicetype
                        Last Sync Date Time: $lastsyncdatetime
                        Enrolled Date Time: $enrolleddatetime
                        Jail Broken: $jailbroken
                        Compliance State: $compliance
                        Enrollment Type: $enrollmenttype
                        AAD Registered: $AADreg
                        Management Agent: $managementagent
                        User Principal Name: $userPrincipalName
                        Device last synced: $TD days ago
            
"@
            
            [System.Windows.MessageBox]::Show($Appoutput)
        
        
                }
            }
                else {
        
                write-host "No Devices not checked in the last $days days found..." -f green
                Write-Host
        
                }
        
            }
        
            catch {
        
            Write-Host
            $ex = $_.Exception
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            Write-Host "Response content:`n$responseBody" -f Red
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
            Write-Host
        
            break
        
            }



        })
        ############################################################################################################# END OLD DEVICES ##############################################################################################################

## SHOW FORM

[void]$NewStale.ShowDialog()