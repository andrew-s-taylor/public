<#
.SYNOPSIS
  Adds registry keys to allow users to install printers

.DESCRIPTION
  Add 3 registry keys to allow users to install printers on Win10
Device Context 32-bit

.INPUTS
None required

.OUTPUTS
Logged by Intune

.NOTES
.NOTES
  Version:        1.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  13/01/2020
  Purpose/Change: Initial script development
  
.EXAMPLE
N/A
#>

#-----------------------------------------------------------[Execution]------------------------------------------------------------

$registryPath = "HKLM:\Software\Policies\Microsoft\Windows\DriverInstall\Restrictions"
$Name = "AllowUserDeviceClasses"
$value = "1"
IF(!(Test-Path $registryPath))
{
New-Item -Path $registryPath -Force | Out-Null
New-ItemProperty -Path $registryPath -Name $name -Value $value `
-PropertyType DWORD -Force | Out-Null}
ELSE {
New-ItemProperty -Path $registryPath -Name $name -Value $value `
-PropertyType DWORD -Force | Out-Null}

$registryPath = "HKLM:\Software\Policies\Microsoft\Windows\DriverInstall\Restrictions\AllowUserDeviceClasses"
$Name = "{4658ee7e-f050-11d1-b6bd-00c04fa372a7}"
$value = ""
IF(!(Test-Path $registryPath))
{
New-Item -Path $registryPath -Force | Out-Null
New-ItemProperty -Path $registryPath -Name $name -Value $value `
-PropertyType "String" -Force | Out-Null}
ELSE {
New-ItemProperty -Path $registryPath -Name $name -Value $value `
-PropertyType "String" -Force | Out-Null}

$registryPath = "HKLM:\Software\Policies\Microsoft\Windows\DriverInstall\Restrictions\AllowUserDeviceClasses"
$Name = "{4d36e979-e325-11ce-bfc1-08002be10318}"
$value = ""
IF(!(Test-Path $registryPath))
{
New-Item -Path $registryPath -Force | Out-Null
New-ItemProperty -Path $registryPath -Name $name -Value $value `
-PropertyType "String" -Force | Out-Null}
ELSE {
New-ItemProperty -Path $registryPath -Name $name -Value $value `
-PropertyType "String" -Force | Out-Null}