<#
.SYNOPSIS
  Adds App-V Package to multiple servers

.DESCRIPTION
  Adds App-V package to multiple machines in an OU looking for a particular naming convention.  Useful for RDS etc.

.INPUTS
Params: OU, Name, Packagepath

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
add-appvpackage.ps1 -OU "YourOU" -Namingconvention "Names*" -packagepath "\\path"
#>

param (
    [Parameter(Mandatory=$true)] 
    [String]  $OU = '',
    
    [Parameter(Mandatory=$true)] 
    [String]  $NamingConvention = '',

    [Parameter(Mandatory=$true)]
    [String] $packagepath = ''
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
write-host "Script has been updated, please download the latest version from $liveuri" -ForegroundColor Red
}
}
Get-ScriptVersion -liveuri "https://raw.githubusercontent.com/andrew-s-taylor/public/main/Powershell%20Scripts/add-appvpackage.ps1"



$servers = Get-ADComputer -SearchBase $OU -Filter * | Where-Object Name -like $NamingConvention | select Name
foreach ($server in $servers) {
Invoke-Command -ComputerName $server.name -ScriptBlock {add-appvclientpackage $packagepath | publish-appvclientpackage -global}
}