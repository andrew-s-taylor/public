<#PSScriptInfo
.VERSION 2.0
.GUID 729ebf90-26fe-4795-92dc-ca8f570cdd22
.AUTHOR AndrewTaylor
.DESCRIPTION Lists all intune apps with install counts
.COMPANYNAME 
.COPYRIGHT GPL
.TAGS intune app endpoint
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
  Displays Intune app installs
.DESCRIPTION
Lists all intune apps with install counts

.INPUTS
None required
.OUTPUTS
GridView
.NOTES
  Version:        2.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  29/09/2021
  Modified Date:  30/10/2022
  Purpose/Change: Initial script development
  Change:         Switched to Graph Auth
  
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
Import-Module microsoft.graph.authentication


#Connect to Graph
Select-MgProfile -Name Beta
Connect-MgGraph -Scopes  	RoleAssignmentSchedule.ReadWrite.Directory, Domain.Read.All, Domain.ReadWrite.All, Directory.Read.All, Policy.ReadWrite.ConditionalAccess, DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, openid, profile, email, offline_access

    
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
    
    Function Get-InstallStatusForApp {
    
    <#
    .SYNOPSIS
    This function will get the installation status of an application given the application's ID.
    .DESCRIPTION
    If you want to track your managed intune application installation stats as you roll them out in your environment, use this commandlet to get the insights.
    .EXAMPLE
    Get-InstallStatusForApp -AppId a1a2a-b1b2b3b4-c1c2c3c4
    This will return the installation status of the application with the ID of a1a2a-b1b2b3b4-c1c2c3c4
    .NOTES
    NAME: Get-InstallStatusForApp
    #>
        
    [cmdletbinding()]
    
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$AppId
    )
        
        $graphApiVersion = "Beta"
        $Resource = "deviceAppManagement/mobileApps/$AppId/installSummary"
        
        try
        {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject
    
        }
        
        catch
        {
            
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
    
    ####################################################
    
    Function Get-DeviceStatusForApp {
    
    <#
    .SYNOPSIS
    This function will get the devices installation status of an application given the application's ID.
    .DESCRIPTION
    If you want to track your managed intune application installation stats as you roll them out in your environment, use this commandlet to get the insights.
    .EXAMPLE
    Get-DeviceStatusForApp -AppId a1a2a-b1b2b3b4-c1c2c3c4
    This will return devices and their installation status of the application with the ID of a1a2a-b1b2b3b4-c1c2c3c4
    .NOTES
    NAME: Get-DeviceStatusForApp
    #>
        
    [cmdletbinding()]
    
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$AppId
    )
        
        $graphApiVersion = "Beta"
        $Resource = "deviceAppManagement/mobileApps/$AppId/deviceStatuses"
        
        try
        {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        
        catch
        {
            
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
    
    ####################################################
    
    ####################################################
    $List = New-Object System.Collections.ArrayList   
    $Applications = Get-IntuneApplication
    
foreach ($application in $Applications) {
    $appdetails = Get-InstallStatusForApp -AppId $application.ID | Select-Object installedDeviceCount, failedDeviceCount, installedUserCount, failedUserCount
    $appname = $application.displayName
    $installdevice = $appdetails.installedDeviceCount
    $faileddevice = $appdetails.failedDeviceCount
    $installuser = $appdetails.installedUserCount
    $faileduser = $appdetails.failedUserCount
    $appid = $application.ID
    $Hash = [ordered]@{
        Name = $appname
        ID = $appid
        DeviceInstalls = $installdevice
        UserInstalls = $installuser
        FailedDeviceInstalls = $faileddevice
        FailedUserInstalls = $faileduser
    }
    [void]$List.Add((

        [pscustomobject]$Hash
      
        ))
}
    
$List | Out-GridView -Title 'App Installs' 
    