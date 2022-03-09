<#
.SYNOPSIS
  Sets 7-Zip as default application
.DESCRIPTION
Sets all supported 7-zip formats to open in 7-zip (has to be installed in Program Files\7-Zip)

.INPUTS
None required
.OUTPUTS
Intune scripts output into reg key
.NOTES
  Version:        1.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  29/09/2021
  Purpose/Change: Initial script development
  
.EXAMPLE
N/A
#>
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\.7z") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\.7z" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\.gz") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\.gz" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\.gzip") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\.gzip" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\.rar") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\.rar" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\.tar") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\.tar" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\.tgz") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\.tgz" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\.z") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\.z" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\.zip") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\.zip" -force -ea SilentlyContinue };
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\.7z' -Name '(default)' -Value '7-Zip.7z' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\.gz' -Name '(default)' -Value '7-Zip.gz' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\.gzip' -Name '(default)' -Value '7-Zip.gzip' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\.rar' -Name '(default)' -Value '7-Zip.rar' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\.tar' -Name '(default)' -Value '7-Zip.tar' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\.tgz' -Name '(default)' -Value '7-Zip.tgz' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\.z' -Name '(default)' -Value '7-Zip.z' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\.zip' -Name '(default)' -Value '7-Zip.zip' -PropertyType String -Force -ea SilentlyContinue;
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.7z") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.7z" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.7z\DefaultIcon") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.7z\DefaultIcon" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.7z\shell") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.7z\shell" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.7z\shell\open") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.7z\shell\open" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.7z\shell\open\command") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.7z\shell\open\command" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.gz") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.gz" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.gz\DefaultIcon") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.gz\DefaultIcon" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.gz\shell") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.gz\shell" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.gz\shell\open") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.gz\shell\open" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.gz\shell\open\command") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.gz\shell\open\command" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.gzip") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.gzip" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.gzip\DefaultIcon") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.gzip\DefaultIcon" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.gzip\shell") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.gzip\shell" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.gzip\shell\open") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.gzip\shell\open" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.gzip\shell\open\command") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.gzip\shell\open\command" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.rar") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.rar" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.rar\DefaultIcon") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.rar\DefaultIcon" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.rar\shell") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.rar\shell" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.rar\shell\open") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.rar\shell\open" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.rar\shell\open\command") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.rar\shell\open\command" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.tar") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.tar" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.tar\DefaultIcon") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.tar\DefaultIcon" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.tar\shell") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.tar\shell" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.tar\shell\open") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.tar\shell\open" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.tar\shell\open\command") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.tar\shell\open\command" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.tgz") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.tgz" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.tgz\DefaultIcon") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.tgz\DefaultIcon" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.tgz\shell") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.tgz\shell" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.tgz\shell\open") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.tgz\shell\open" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.tgz\shell\open\command") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.tgz\shell\open\command" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.z") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.z" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.z\DefaultIcon") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.z\DefaultIcon" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.z\shell") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.z\shell" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.z\shell\open") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.z\shell\open" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.z\shell\open\command") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.z\shell\open\command" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.zip") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.zip" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.zip\DefaultIcon") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.zip\DefaultIcon" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.zip\shell") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.zip\shell" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.zip\shell\Open") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.zip\shell\Open" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\7-Zip.zip\shell\Open\Command") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\7-Zip.zip\shell\Open\Command" -force -ea SilentlyContinue };
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\7-Zip.7z' -Name '(default)' -Value '7z Archive' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\7-Zip.7z\DefaultIcon' -Name '(default)' -Value 'C:\Program Files\7-Zip\7z.dll,0' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\7-Zip.7z\shell' -Name '(default)' -Value ''
