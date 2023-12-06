<#PSScriptInfo
.VERSION 1.1.1
.GUID 600c7e1b-44a5-4aaa-9644-b2763b9ccc5e
.AUTHOR AndrewTaylor
.DESCRIPTION Downloads and deploys troubleshooting tools to display in Autopilot ESP
.COMPANYNAME 
.COPYRIGHT GPL
.TAGS Intune Autopilot
.LICENSEURI https://github.com/andrew-s-taylor/public/blob/main/LICENSE
.PROJECTURI https://github.com/andrew-s-taylor/public
.ICONURI 
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
#>
<#
.SYNOPSIS
  Downloads and deploys troubleshooting tools to display in Autopilot ESP
.DESCRIPTION
Downloads and deploys troubleshooting tools to display in Autopilot ESP

.INPUTS
None required
.OUTPUTS
None required
.NOTES
  Version:        1.1.2
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  03/08/2022
  Updated Date: 06/12/2023
  Purpose/Change: Initial script development
  Change: Added logic to stop running outside OOBE
  Change: Added command to auto-launch tools.  Thanks to Flo @ sunrise-it.fr
  Change: Fixed string output

  
.EXAMPLE
N/A
#>


##Create a folder to store everything
$toolsfolder = "C:\ProgramData\ServiceUI"
If (Test-Path $toolsfolder) {
    Write-Output "$toolsfolder exists. Skipping."
}
Else {
    Write-Output "The folder '$toolsfolder' doesn't exist. This folder will be used for storing logs created after the script runs. Creating now."
    Start-Sleep 1
    New-Item -Path "$toolsfolder" -ItemType Directory
    Write-Output "The folder $toolsfolder was successfully created."
}
##To install scripts
set-executionpolicy remotesigned -Force

##Set download locations
$templateFilePath = "C:\ProgramData\ServiceUI\serviceui.exe"
$cmtraceoutput = "C:\ProgramData\ServiceUI\cmtrace.exe"
$scriptoutput = "C:\ProgramData\ServiceUI\tools.ps1"

##Force install NuGet (no popups)
install-packageprovider -Name NuGet -MinimumVersion 2.8.5.201 -Force

##Force install Autopilot Diagnostics (no popups)
Install-Script -Name Get-AutopilotDiagnostics -Force


##Download ServiceUI
Invoke-WebRequest `
-Uri "https://github.com/andrew-s-taylor/public/raw/main/Troubleshooting/ServiceUI.exe" `
-OutFile $templateFilePath `
-UseBasicParsing `
-Headers @{"Cache-Control"="no-cache"}

##Download CMTrace
Invoke-WebRequest `
-Uri "https://github.com/andrew-s-taylor/public/raw/main/Troubleshooting/CMTrace.exe" `
-OutFile $cmtraceoutput `
-UseBasicParsing `
-Headers @{"Cache-Control"="no-cache"}


##Download tools.ps1
Invoke-WebRequest `
-Uri "https://github.com/andrew-s-taylor/public/raw/main/Troubleshooting/tools.ps1" `
-OutFile $scriptoutput `
-UseBasicParsing `
-Headers @{"Cache-Control"="no-cache"}

##Create powershell script we are launching
##$string = @"
##[void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
##[System.Windows.Forms.SendKeys]::SendWait("+{f10}") 
##start-process powershell.exe -argument '-nologo -noprofile -noexit -executionpolicy bypass -command C:\ProgramData\ServiceUI\tools.ps1 ' -Wait
##"@

##$file2="C:\ProgramData\ServiceUI\shiftf10.ps1"
##$string | out-file $file2

##Create powershell script we are launching
$string = @'
# Send Shift+F10 key to open a command prompt
$WscriptShell = New-Object -ComObject Wscript.Shell
$WscriptShell.SendKeys("%({TAB})")
Start-Sleep 1
$WscriptShell.SendKeys("+({F10})")
# Wait until cmd process is opened
Do {Start-Sleep 1} While (-not (Get-Process cmd -ErrorAction SilentlyContinue))
Start-Sleep 1
Get-Process cmd | Stop-Process -Force
start-process powershell.exe -argument '-nologo -noprofile -noexit -executionpolicy bypass -command C:\ProgramData\ServiceUI\tools.ps1 ' -Wait
'@
$file2="C:\ProgramData\ServiceUI\shiftf10.ps1"
$string | out-file $file2

##Check if we're during OOBE
$intunepath = "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps"
$intunecomplete = @(Get-ChildItem $intunepath).count
if ($intunecomplete -lt 2) {

##Launch script with UI interaction
start-process "C:\ProgramData\ServiceUI\serviceui.exe" -argumentlist ("-process:explorer.exe", 'c:\Windows\System32\WindowsPowershell\v1.0\powershell.exe -Executionpolicy bypass -file C:\ProgramData\ServiceUI\shiftf10.ps1 -windowstyle Hidden')
##Add script here
}