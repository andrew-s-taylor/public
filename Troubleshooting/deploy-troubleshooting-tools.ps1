<#PSScriptInfo
.VERSION 1.0.0
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
GridView
.NOTES
  Version:        1.0.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  03/08/2022
  Purpose/Change: Initial script development

  
.EXAMPLE
N/A
#>

$DebloatFolder = "C:\ProgramData\ServiceUI"
If (Test-Path $DebloatFolder) {
    Write-Output "$DebloatFolder exists. Skipping."
}
Else {
    Write-Output "The folder '$DebloatFolder' doesn't exist. This folder will be used for storing logs created after the script runs. Creating now."
    Start-Sleep 1
    New-Item -Path "$DebloatFolder" -ItemType Directory
    Write-Output "The folder $DebloatFolder was successfully created."
}
set-executionpolicy remotesigned -Force

$templateFilePath = "C:\ProgramData\ServiceUI\serviceui.exe"
$cmtraceoutput = "C:\ProgramData\ServiceUI\cmtrace.exe"
install-packageprovider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Script -Name Get-AutopilotDiagnostics -Force

Invoke-WebRequest `
-Uri "https://github.com/andrew-s-taylor/public/raw/main/Troubleshooting/ServiceUI.exe" `
-OutFile $templateFilePath `
-UseBasicParsing `
-Headers @{"Cache-Control"="no-cache"}

Invoke-WebRequest `
-Uri "https://github.com/andrew-s-taylor/public/raw/main/Troubleshooting/CMTrace.exe" `
-OutFile $cmtraceoutput `
-UseBasicParsing `
-Headers @{"Cache-Control"="no-cache"}



$string = @"
[void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
[System.Windows.Forms.SendKeys]::SendWait("+{f10}") 
set-executionpolicy unrestricted
start-process powershell.exe
"@

$file2="C:\ProgramData\ServiceUI\shiftf10.ps1"
$string | out-file $file2
start-process "C:\ProgramData\ServiceUI\serviceui.exe" -argumentlist ("-process:explorer.exe", 'c:\Windows\System32\WindowsPowershell\v1.0\powershell.exe -Executionpolicy bypass -file C:\ProgramData\ServiceUI\shiftf10.ps1 -windowstyle Hidden')