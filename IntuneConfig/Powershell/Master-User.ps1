#requires -version 2
<#
.SYNOPSIS
  Configures User Settings

.DESCRIPTION
  Configures:
  ADAL for OneDrive
  Sets Background
  Unpins MS Store



.INPUTS
 $regpath - The full registry path
 $regname - The name of the key
 $regvalue - The value of the key
 $regtype - either STRING or DWORD

.OUTPUTS
  Log file stored in C:\Windows\Temp\build-user.log>

.NOTES
  Version:        1.0
  Author:         Andrew S Taylor
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
$sLogPath = "C:\Windows\Temp\build-user.log"

#----------------------------------------------------------[Configurables]----------------------------------------------------------
################################################## SET THESE FOR EACH CLIENT ###############################################


##Include File Extension:
$backgroundname = "BACKGROUNDFILENAME"



####################### DO NOT EDIT BELOW HERE WITHOUT COMMENTING AND GIT CHANGE################################################

#-----------------------------------------------------------[Functions]------------------------------------------------------------

Start-Transcript -Path $LogPath

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


## Enable OneDrive ADAL
write-host "Enable ADAL"
$registryPath = "HKCU:\SOFTWARE\Microsoft\OneDrive"
$Name = "EnableADAL"
$value = "1"
$Type = "DWORD"
addregkey($registryPath, $Name, $value, $Type)


#----------------------------------------------------------------------------------------------------------------------------------

##Set Desktop Background
write-host "Setting Background"
Set-ItemProperty -path 'HKCU:\Control Panel\Desktop\' -name wallpaper -value "c:\Windows\Web\Wallpaper\"+$Background

rundll32.exe user32.dll, UpdatePerUserSystemParameters

#----------------------------------------------------------------------------------------------------------------------------------

##Unpin Store

$apps = ((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items())
foreach ($app in $apps) {
$appname = $app.Name
if ($appname -like "*store*") {
$finalname = $app.Name
}
}

((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() | ?{$_.Name -eq $finalname}).Verbs() | ?{$_.Name.replace('&','') -match 'Unpin from taskbar'} | %{$_.DoIt(); $exec = $true}

#----------------------------------------------------------------------------------------------------------------------------------

Stop-Transcript
