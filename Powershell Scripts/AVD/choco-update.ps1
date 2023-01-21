<#
.SYNOPSIS
  Updates/adds packages using chocolatey

.DESCRIPTION
  Grabs list of apps from a text file stored somewhere online, parses and installs/updates apps

.INPUTS
TxtURL

.OUTPUTS
Logged by Intune

.NOTES
  Version:        1.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  13/01/2020
  Purpose/Change: Initial script development
  
.EXAMPLE
choco-update.ps1 -URL "https://your-site.com/apps.txt"
#>

param (
    [Parameter(Mandatory=$true)]
    [String] $URL = ''
)


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
write-warning "Script has been updated, please download the latest version from $liveuri"
}
}
Get-ScriptVersion -liveuri "https://raw.githubusercontent.com/andrew-s-taylor/public/main/Powershell%20Scripts/AVD/choco-update.ps1"



########################################
##         Grab package list          ##
########################################

if((Test-Path -Path "c:\temp" )){
    New-Item -ItemType directory -Path "c:\temp"
}

Invoke-WebRequest -Uri $URL -OutFile "c:\temp\chocoapps.txt"

########################################
##         Install Packages           ##
########################################


$packages = get-content "c:\temp\chocoapps.txt"
foreach ($package in $packages) {
choco install $package -y
}

#######################################
##        Update All Packages        ##
#######################################
choco upgrade chocolatey
choco upgrade all