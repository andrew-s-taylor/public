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