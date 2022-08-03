<#PSScriptInfo
.VERSION 1.0.0
.GUID d4bf7f0a-794e-4c16-bd3f-86ea7074cae9
.AUTHOR AndrewTaylor
.DESCRIPTION   Displays a GUI during ESP with a selection of troubleshooting tools
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
  Displays a GUI during ESP with a selection of troubleshooting tools
.DESCRIPTION
  Displays a GUI during ESP with a selection of troubleshooting tools

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

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

$AutopilotMenu             = New-Object system.Windows.Forms.Form
$AutopilotMenu.ClientSize  = New-Object System.Drawing.Point(396,431)
$AutopilotMenu.text        = "Autopilot Tools"
$AutopilotMenu.TopMost     = $false
$AutopilotMenu.BackColor   = [System.Drawing.ColorTranslator]::FromHtml("#ffffff")

$Label1                          = New-Object system.Windows.Forms.Label
$Label1.text                     = "Created by Andrew Taylor (andrewstaylor.com)"
$Label1.AutoSize                 = $true
$Label1.width                    = 25
$Label1.height                   = 10
$Label1.location                 = New-Object System.Drawing.Point(7,396)
$Label1.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',8)

$eventvwr                       = New-Object system.Windows.Forms.Button
$eventvwr.text                  = "Event Viewer"
$eventvwr.width                 = 157
$eventvwr.height                = 56
$eventvwr.location              = New-Object System.Drawing.Point(21,18)
$eventvwr.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$scriptrun                         = New-Object system.Windows.Forms.Button
$scriptrun.text                    = "Troubleshooting Script"
$scriptrun.width                   = 157
$scriptrun.height                  = 56
$scriptrun.location                = New-Object System.Drawing.Point(219,16)
$scriptrun.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$regedit                           = New-Object system.Windows.Forms.Button
$regedit.text                      = "Regedit"
$regedit.width                     = 157
$regedit.height                    = 56
$regedit.location                  = New-Object System.Drawing.Point(22,131)
$regedit.Font                      = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$explorer                          = New-Object system.Windows.Forms.Button
$explorer.text                     = "File Explorer"
$explorer.width                    = 157
$explorer.height                   = 56
$explorer.location                 = New-Object System.Drawing.Point(222,132)
$explorer.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$log1                           = New-Object system.Windows.Forms.Button
$log1.text                      = "SetupAct Log"
$log1.width                     = 157
$log1.height                    = 56
$log1.location                  = New-Object System.Drawing.Point(22,245)
$log1.Font                      = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$log2                          = New-Object system.Windows.Forms.Button
$log2.text                     = "Intune Mgmt Log"
$log2.width                    = 157
$log2.height                   = 56
$log2.location                 = New-Object System.Drawing.Point(222,245)
$log2.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',12)





$AutopilotMenu.controls.AddRange(@($Label1,$scriptrun,$eventvwr,$regedit,$explorer,$log1, $log2))

$scriptrun.Add_Click({ 
start-process powershell.exe -argument '-nologo -noprofile -noexit -executionpolicy bypass -command  Get-AutopilotDiagnostics ' -Wait
   
 })
$eventvwr.Add_Click({ 
    start-process -filepath "C:\Windows\System32\eventvwr.exe"
 })
$regedit.Add_Click({ 
    start-process -filepath "C:\Windows\regedit.exe"
 })
$explorer.Add_Click({ 
    start-process -filepath "C:\Windows\explorer.exe"
 })
$log1.Add_Click({ 
    start-process -filepath "C:\ProgramData\ServiceUI\cmtrace.exe" -argumentlist c:\windows\panther\setupact.log
 })
$log2.Add_Click({ 
    start-process -filepath "C:\ProgramData\ServiceUI\cmtrace.exe" -argumentlist C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\intunemanagementextension.log 
})


[void]$AutopilotMenu.ShowDialog()