<#
.SYNOPSIS
    Install an application to devices via InTune utilising powershell to incorporate customisations and registry confirmation.

.DESCRIPTION
    This script configures and installs applications to end user devices via InTune.  It includes all app customisations.  Also included is a registry key to record the version of the app installed, when and how.


.NOTES
  Version:        1.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  13/01/2020
  Purpose/Change: Initial script development
    
    Version history:
    1.0.0 - (13/01/2020) Script created

    Required modules:
  
#>

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
Get-ScriptVersion -liveuri "https://raw.githubusercontent.com/andrew-s-taylor/public/main/Powershell%20Scripts/powershell-wrapper-template.ps1"

#Add Application to Registry
#Populate the app details here
$registryPath = "HKLM:\Software\CustomInstalls\Build\Apps"
$apppath = "HKLM:\Software\CustomInstalls\Build\Apps\7zip"
$appname = "7-Zip"
$appversion = "19.00"
$installdate = get-date
$installtype = "InTune"
$filename = "7z1900-x64.exe"
IF(!(Test-Path $registryPath))

  {

    New-Item -Path $registryPath -Force | Out-Null
    New-Item -Path $apppath -Force | Out-Null
    New-ItemProperty -Path $apppath -Name "AppName" -Value $appname -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $apppath -Name "AppVersion" -Value $appversion -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $apppath -Name "InstallDate" -Value $installdate -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $apppath -Name "InstallType" -Value $installtype -PropertyType String -Force | Out-Null
    }

 ELSE {
    New-Item -Path $apppath -Force | Out-Null
    New-ItemProperty -Path $apppath -Name "AppName" -Value $appname -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $apppath -Name "AppVersion" -Value $appversion -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $apppath -Name "InstallDate" -Value $installdate -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $apppath -Name "InstallType" -Value $installtype -PropertyType String -Force | Out-Null
    }


#INSTALL THE APPLICATION

#Set Path
if ($psISE)
{
    $location = Split-Path -Path $psISE.CurrentFile.FullPath        
}
else
{
    $location = $global:PSScriptRoot
}
  
$filelocation = $location + "\" + $filename

#Check extension and install silently accordingly
$extension = (get-item $filelocation).Extension
if ($extension -eq ".exe")
{
    $EXEArguments = @(
    "/S"
)
Start-Process $filelocation -ArgumentList $EXEArguments -Wait
}
elseif ($extension -eq ".msi")
{
    $MSIArguments = @(
    "/i"
    ('"{0}"' -f $filelocation)
    "/qn"
    "/norestart"
    "/L*v"
)
Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -NoNewWindow 
}