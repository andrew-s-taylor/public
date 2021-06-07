<#
.SYNOPSIS
  Configure OneDrive PC Settings

.DESCRIPTION
  Configures OneDrive for SilentConfig and Files on Demand
Device Context 32-bit

.INPUTS
None required

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
N/A
#>

#-----------------------------------------------------------[Execution]------------------------------------------------------------

$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
$Name = "SilentAccountConfig"
$value = "1"
IF(!(Test-Path $registryPath))
{
New-Item -Path $registryPath -Force | Out-Null
New-ItemProperty -Path $registryPath -Name $name -Value $value `
-PropertyType DWORD -Force | Out-Null}
ELSE {
New-ItemProperty -Path $registryPath -Name $name -Value $value `
-PropertyType DWORD -Force | Out-Null}
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
$Name = "FilesOnDemandEnabled"
$value = "1"
IF(!(Test-Path $registryPath))
{
New-Item -Path $registryPath -Force | Out-Null
New-ItemProperty -Path $registryPath -Name $name -Value $value `
-PropertyType DWORD -Force | Out-Null}
ELSE {
New-ItemProperty -Path $registryPath -Name $name -Value $value `
-PropertyType DWORD -Force | Out-Null}