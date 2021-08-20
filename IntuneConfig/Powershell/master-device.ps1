#requires -version 2
<#
.SYNOPSIS
  Sets all config for a new build

.DESCRIPTION
  Sets the following:
  Chrome Homepage
  Configured MS OneDrive
  Allows Printer installs
  Disable FastBoot
  Set Desktop Background
  Set OneDrive Known Folder Move


.INPUTS
 $regpath - The full registry path
 $regname - The name of the key
 $regvalue - The value of the key
 $regtype - either STRING or DWORD

.OUTPUTS
  Log file stored in C:\Windows\Temp\build-device.log>

.NOTES
  Version:        1.0
  Author:         Andrew Taylor
  Creation Date:  13/01/2020
  Purpose/Change: Initial script development
  
.EXAMPLE
  addregkey($path, "Test", "1", "DWORD")
#>

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

#Set Error Action to Silently Continue
$ErrorActionPreference = "SilentlyContinue"


#----------------------------------------------------------[Declarations]----------------------------------------------------------

#Script Version
$sScriptVersion = "1.0"

#Log File Info
$sLogPath = "C:\Windows\Temp\build-device.log"

#----------------------------------------------------------[Configurables]----------------------------------------------------------
################################################## SET THESE FOR EACH CLIENT ###############################################


##No special characters
$clientname = ""

$o365tenant = ""

$homepage = ""

##Include File Extension:
$backgroundname = ""

#Azure Blob SAS for background image
$backgroundpath = ""



####################### DO NOT EDIT BELOW HERE WITHOUT COMMENTING AND GIT CHANGE################################################
#-----------------------------------------------------------[Functions]------------------------------------------------------------

start-transcript -path $LogPath

Function addregkey($regpath, $regname, $regvalue, $regtype){
   
  Begin{
    write-host "Adding keys"
  }
  
  Process{
    Try{
        IF(!(Test-Path $regpath))
        {
        New-Item -Path $regpath -Force | Out-Null
        New-ItemProperty -Path $regpath -Name $regname -Value $regvalue `
        -PropertyType $regtype -Force | Out-Null}
        ELSE {
        New-ItemProperty -Path $regpath -Name $regname -Value $regvalue `
        -PropertyType $regtype -Force | Out-Null}
    }
    
    Catch{
      write-host $_.Exception
      Break
    }
  }
  
  End{
    If($?){
      write-host "Completed Successfully."
    }
  }
}



#-----------------------------------------------------------[Execution]------------------------------------------------------------

## Set Chrome Homepage
write-host "Setting Chrome Homepage"
$registryPath = "HKLM:\SOFTWARE\Policies\Google\Chrome\Recommended"
$Name = "HomepageLocation"
$value = $homepage
$Type = "String"
addregkey($registryPath, $Name, $value, $Type)

#-----------------------------------------------------------------------------------------------------------------------------------

## Configure OneDrive
write-host "Configuring OneDrive"
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
$Name = "SilentAccountConfig"
$value = "1"
$Type = "DWORD"
addregkey($registryPath, $Name, $value, $Type)

$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
$Name = "FilesOnDemandEnabled"
$value = "1"
$Type = "DWORD"
addregkey($registryPath, $Name, $value, $Type)

#-----------------------------------------------------------------------------------------------------------------------------------


## Allow Printer Installs

write-host "Configuring Printers"
$registryPath = "HKLM:\Software\Policies\Microsoft\Windows\DriverInstall\Restrictions"
$Name = "AllowUserDeviceClasses"
$value = "1"
$Type = "DWORD"
addregkey($registryPath, $Name, $value, $Type)

$registryPath = "HKLM:\Software\Policies\Microsoft\Windows\DriverInstall\Restrictions\AllowUserDeviceClasses"
$Name = "{4658ee7e-f050-11d1-b6bd-00c04fa372a7}"
$value = ""
$Type = "String"
addregkey($registryPath, $Name, $value, $Type)

$registryPath = "HKLM:\Software\Policies\Microsoft\Windows\DriverInstall\Restrictions\AllowUserDeviceClasses"
$Name = "{4d36e979-e325-11ce-bfc1-08002be10318}"
$value = ""
$Type = "String"
addregkey($registryPath, $Name, $value, $Type)
#-----------------------------------------------------------------------------------------------------------------------------------


## Disable FastBoot
write-host "Disable FastBoot"
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
$Name = "HiberbootEnabled"
$value = "0"
$Type = "DWORD"
addregkey($registryPath, $Name, $value, $Type)


#-----------------------------------------------------------------------------------------------------------------------------------

##Set Background

$urlbase = $backgroundpath
$urltemp = $url+$Background
write-host "Download Desktop Images"
#Open the folder en Windows Explorer under C:\Users\USERNAME\AppData\Roaming\CustomerXXXX
########################################################################################
$path = [Environment]::GetFolderPath('ApplicationData') + "\" + $clientname

If(!(test-path $path))
{
      New-Item -ItemType Directory -Force -Path $path
}
########################################################################################

$newpath = "c:\Windows\Web\Wallpaper"

#Download the image from ImGur to user profile WALLPAPER
########################################################################################
$url = $urltemp
$output = $newpath + "\" + $Background
Start-BitsTransfer -Source $url -Destination $output

########################################################################################

#Download the image from ImGur to user profile WALLPAPER
########################################################################################
$url3 = $urltemp
$output3 = $newpath + "\" + $Background
Start-BitsTransfer -Source $url3 -Destination $output3

########################################################################################


#Download the image from ImGur to user profile LOCKSCREEN
########################################################################################
$url2 = $urltemp
$output2 = $newpath + "\" + $Background
Start-BitsTransfer -Source $url2 -Destination $output2

########################################################################################

write-host "Set Lockscreen"

$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
$img =  "C:\Windows\Web\Wallpaper\"+$Background
$Name = "LockScreenImage"
$value = "1"
$Type = "String"
addregkey($registryPath, $Name, $value, $Type)
#-----------------------------------------------------------------------------------------------------------------------------------


##OneDrive KFM
write-host "Setting Known Folder Move"
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
$Name = "KFMBlockOptIn"
$value = "1"
$Type = "DWORD"
addregkey($registryPath, $Name, $value, $Type)


$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
$Name = "KFMSilentOptIn"
$value = $o365tenant
$Type = "String"
addregkey($registryPath, $Name, $value, $Type)

$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
$Name = "KFMSilentOptInWithNotification"
$value = "0"
$Type = "DWORD"
addregkey($registryPath, $Name, $value, $Type)


$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
$Name = "KFMBlockOptOut"
$value = "1"
$Type = "DWORD"
addregkey($registryPath, $Name, $value, $Type)

#-----------------------------------------------------------------------------------------------------------------------------------

##Remove Unwanted Settings
write-host "Removing Settings"
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$Name = "SettingsPageVisibility"
$value = "hide:gaming-broadcasting;gaming-gamebar;gaming-gamedvr;gaming-gamemode;quietmomentsgame;gaming-xboxnetworking;cortana-notifications;cortana;cortana-moredetails;cortana-permissions;cortana-windowssearch;cortana-language;cortana-talktocortana"
$Type = "String"
addregkey($registryPath, $Name, $value, $Type)
#-----------------------------------------------------------------------------------------------------------------------------------

##Add Build Reg Keys
write-host "Adding Reg Keys"
$registryPath = "HKLM:\Software\BuildDetails"

$Name1 = "BuildNumber"
$value1 = "1.0"
$Name2 = "OS"
$value2 = "Windows 10 Enterprise"
$Name3 = "Imaged By"
$value3 = "AndrewSTaylor.com"
$Name4 = "Client"
$value4 = $clientname
$Name6 = "DatePCBuilt"
$value6 = get-date
$Name7 = "Serial"
$serial = gwmi win32_bios
$value7 = $serial.SerialNumber


IF(!(Test-Path $registryPath))

  {

    New-Item -Path $registryPath -Force | Out-Null

    New-ItemProperty -Path $registryPath -Name $Name1 -Value $value1 -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name $Name2 -Value $value2 -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name $Name3 -Value $value3 -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name $Name4 -Value $value4 -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name $Name6 -Value $value6 -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name $Name7 -Value $value7 -PropertyType String -Force | Out-Null
    }

 ELSE {

    New-ItemProperty -Path $registryPath -Name $Name1 -Value $value1 -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name $Name2 -Value $value2 -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name $Name3 -Value $value3 -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name $Name4 -Value $value4 -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name $Name6 -Value $value6 -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name $Name7 -Value $value7 -PropertyType String -Force | Out-Null
    }

## Stop Logging
stop-transcript