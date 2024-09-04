<#
.SYNOPSIS
.Removes bloat from a fresh Windows build
.DESCRIPTION
.Removes AppX Packages
.Disables Cortana
.Removes McAfee
.Removes HP Bloat
.Removes Dell Bloat
.Removes Lenovo Bloat
.Windows 10 and Windows 11 Compatible
.Removes any unwanted installed applications
.Removes unwanted services and tasks
.Removes Edge Surf Game

.INPUTS
.OUTPUTS
C:\ProgramData\Debloat\Debloat.log
.NOTES
  Version:        5.0.24
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  08/03/2022
  Purpose/Change: Initial script development
  Change: 12/08/2022 - Added additional HP applications
  Change 23/09/2022 - Added Clipchamp (new in W11 22H2)
  Change 28/10/2022 - Fixed issue with Dell apps
  Change 23/11/2022 - Added Teams Machine wide to exceptions
  Change 27/11/2022 - Added Dell apps
  Change 07/12/2022 - Whitelisted Dell Audio and Firmware
  Change 19/12/2022 - Added Windows 11 start menu support
  Change 20/12/2022 - Removed Gaming Menu from Settings
  Change 18/01/2023 - Fixed Scheduled task error and cleared up $null posistioning
  Change 22/01/2023 - Re-enabled Telemetry for Endpoint Analytics
  Change 30/01/2023 - Added Microsoft Family to removal list
  Change 31/01/2023 - Fixed Dell loop
  Change 08/02/2023 - Fixed HP apps (thanks to http://gerryhampsoncm.blogspot.com/2023/02/remove-pre-installed-hp-software-during.html?m=1)
  Change 08/02/2023 - Removed reg keys for Teams Chat
  Change 14/02/2023 - Added HP Sure Apps
  Change 07/03/2023 - Enabled Location tracking (with commenting to disable)
  Change 08/03/2023 - Teams chat fix
  Change 10/03/2023 - Dell array fix
  Change 19/04/2023 - Added loop through all users for HKCU keys for post-OOBE deployments
  Change 29/04/2023 - Removes News Feed
  Change 26/05/2023 - Added Set-ACL
  Change 26/05/2023 - Added multi-language support for Set-ACL commands
  Change 30/05/2023 - Logic to check if gamepresencewriter exists before running Set-ACL to stop errors on re-run
  Change 25/07/2023 - Added Lenovo apps (Thanks to Simon Lilly and Philip Jorgensen)
  Change 31/07/2023 - Added LenovoAssist
  Change 21/09/2023 - Remove Windows backup for Win10
  Change 28/09/2023 - Enabled Diagnostic Tracking for Endpoint Analytics
  Change 02/10/2023 - Lenovo Fix
  Change 06/10/2023 - Teams chat fix
  Change 09/10/2023 - Dell Command Update change
  Change 11/10/2023 - Grab all uninstall strings and use native uninstaller instead of uninstall-package
  Change 14/10/2023 - Updated HP Audio package name
  Change 31/10/2023 - Added PowerAutomateDesktop and update Microsoft.Todos
  Change 01/11/2023 - Added fix for Windows backup removing Shell Components
  Change 06/11/2023 - Removes Windows CoPilot
  Change 07/11/2023 - HKU fix
  Change 13/11/2023 - Added CoPilot removal to .Default Users
  Change 14/11/2023 - Added logic to stop errors on HP machines without HP docs installed
  Change 14/11/2023 - Added logic to stop errors on Lenovo machines without some installers
  Change 15/11/2023 - Code Signed for additional security
  Change 02/12/2023 - Added extra logic before app uninstall to check if a user has logged in
  Change 04/01/2024 - Added Dropbox and DevHome to AppX removal
  Change 05/01/2024 - Added MSTSC to whitelist
  Change 25/01/2024 - Added logic for LenovoNow/LenovoWelcome
  Change 25/01/2024 - Updated Dell app list (thanks Hrvoje in comments)
  Change 29/01/2024 - Changed /I to /X in Dell command
  Change 30/01/2024 - Fix Lenovo Vantage version
  Change 31/01/2024 - McAfee fix and Dell changes
  Change 01/02/2024 - Dell fix
  Change 01/02/2024 - Added logic around appxremoval to stop failures in logging
  Change 05/02/2024 - Added whitelist parameters
  Change 16/02/2024 - Added wildcard to dropbox
  Change 23/02/2024 - Added Lenovo SmartMeetings
  Change 06/03/2024 - Added Lenovo View and Vantage
  Change 08/03/2024 - Added Lenovo Smart Noise Cancellation
  Change 13/03/2024 - Added updated McAfee
  Change 20/03/2024 - Dell app fixes
  Change 02/04/2024 - Stopped it removing Intune Management Extension!
  Change 03/04/2024 - Switched Win32 removal from whitelist to blacklist
  Change 10/04/2024 - Office uninstall string fix
  Change 11/04/2024 - Added Office support for multi-language
  Change 17/04/2024 - HP Apps update
  Change 19/04/2024 - HP Fix
  Change 24/04/2024 - Switched provisionedpackage and appxpackage arround
  Change 02/05/2024 - Fixed notlike to notin
  Change 03/05/2024 - Change $uninstallprograms
  Change 19/05/2024 - Disabled feeds on Win11
  Change 21/05/2024 - Added QuickAssist to removal after security issues
  Change 25/05/2024 - Whitelist array fix
  Change 29/05/2025 - Uninstall fix
  Change 31/05/2024 - Re-write for manufacturer bloat
  Change 03/06/2024 - Added function for removing Win32 apps
  Change 03/06/2024 - Added registry key to block "Tell me about this picture" icon
  Change 06/06/2024 - Added keys to block Windows Recall
  Change 07/06/2024 - New fixes for HP and McAfee (thanks to Keith Hay)
  Change 24/06/2024 - Added Microsoft.SecHealthUI to whitelist
  Change 26/06/2024 - Fix when run outside of ESP
  Change 04/07/2024 - Dell fix for "|"
  Change 08/07/2024 - Made whitelist more standard across platforms and removed bloat list to use only whitelisting
  Change 08/07/2024 - Added start.bin
  Change 12/07/2024 - Added logic around start.bin
  Change 15/07/2024 - Removed Lenovo bookmarks
  Change 18/07/2024 - Updated detection for removing Office Home
  Change 23/07/2024 - Lenovo camera fix for E14
  Change 25/07/2024 - Added MS Teams to whitelist
  Change 07/08/2024 - Lenovo fix
  Change 14/08/2024 - Whitelisted any language packs
  Change 19/08/2024 - Added version to log for troubleshooting
  Change 19/08/2024 - Added blacklist and whitelist for further protection
  Change 22/08/2024 - Added Poly Lens for HP
  Change 02/09/2024 - Added all possible languages to Office Home removal
  Change 03/09/2024 - OOBE Logic update for Win32 app removal
  Change 04/09/2024 - Lenovo updates
N/A
#>

############################################################################################################
#                                         Initial Setup                                                    #
#                                                                                                          #
############################################################################################################
param (
    [string[]]$customwhitelist
)

##Elevate if needed

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    write-output "You didn't run this script as an Administrator. This script will self elevate to run as an Administrator and continue."
    Start-Sleep 1
    write-output "                                               3"
    Start-Sleep 1
    write-output "                                               2"
    Start-Sleep 1
    write-output "                                               1"
    Start-Sleep 1
    Start-Process powershell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`" -WhitelistApps {1}" -f $PSCommandPath, ($WhitelistApps -join ',')) -Verb RunAs
    Exit
}

#no errors throughout
$ErrorActionPreference = 'silentlycontinue'


#Create Folder
$DebloatFolder = "C:\ProgramData\Debloat"
If (Test-Path $DebloatFolder) {
    Write-Output "$DebloatFolder exists. Skipping."
}
Else {
    Write-Output "The folder '$DebloatFolder' doesn't exist. This folder will be used for storing logs created after the script runs. Creating now."
    Start-Sleep 1
    New-Item -Path "$DebloatFolder" -ItemType Directory
    Write-Output "The folder $DebloatFolder was successfully created."
}

Start-Transcript -Path "C:\ProgramData\Debloat\Debloat.log"

$locale = Get-WinSystemLocale | Select-Object -expandproperty Name
write-output "Script version is 5.0.19 on locale $locale"
##Switch on locale to set variables
## Switch on locale to set variables
switch ($locale) {
    "ar-SA" {
        $everyone = "الجميع"
        $builtin = "مدمج"
    }
    "bg-BG" {
        $everyone = "Всички"
        $builtin = "Вграден"
    }
    "cs-CZ" {
        $everyone = "Všichni"
        $builtin = "Vestavěný"
    }
    "da-DK" {
        $everyone = "Alle"
        $builtin = "Indbygget"
    }
    "de-DE" {
        $everyone = "Jeder"
        $builtin = "Integriert"
    }
    "el-GR" {
        $everyone = "Όλοι"
        $builtin = "Ενσωματωμένο"
    }
    "en-US" {
        $everyone = "Everyone"
        $builtin = "Builtin"
    }
    "en-GB" {
        $everyone = "Everyone"
        $builtin = "Builtin"
    }
    "es-ES" {
        $everyone = "Todos"
        $builtin = "Incorporado"
    }
    "et-EE" {
        $everyone = "Kõik"
        $builtin = "Sisseehitatud"
    }
    "fi-FI" {
        $everyone = "Kaikki"
        $builtin = "Sisäänrakennettu"
    }
    "fr-FR" {
        $everyone = "Tout le monde"
        $builtin = "Intégré"
    }
    "he-IL" {
        $everyone = "כולם"
        $builtin = "מובנה"
    }
    "hr-HR" {
        $everyone = "Svi"
        $builtin = "Ugrađeni"
    }
    "hu-HU" {
        $everyone = "Mindenki"
        $builtin = "Beépített"
    }
    "it-IT" {
        $everyone = "Tutti"
        $builtin = "Incorporato"
    }
    "ja-JP" {
        $everyone = "すべてのユーザー"
        $builtin = "ビルトイン"
    }
    "ko-KR" {
        $everyone = "모든 사용자"
        $builtin = "기본 제공"
    }
    "lt-LT" {
        $everyone = "Visi"
        $builtin = "Įmontuotas"
    }
    "lv-LV" {
        $everyone = "Visi"
        $builtin = "Iebūvēts"
    }
    "nb-NO" {
        $everyone = "Alle"
        $builtin = "Innebygd"
    }
    "nl-NL" {
        $everyone = "Iedereen"
        $builtin = "Ingebouwd"
    }
    "pl-PL" {
        $everyone = "Wszyscy"
        $builtin = "Wbudowany"
    }
    "pt-BR" {
        $everyone = "Todos"
        $builtin = "Integrado"
    }
    "pt-PT" {
        $everyone = "Todos"
        $builtin = "Incorporado"
    }
    "ro-RO" {
        $everyone = "Toată lumea"
        $builtin = "Incorporat"
    }
    "ru-RU" {
        $everyone = "Все пользователи"
        $builtin = "Встроенный"
    }
    "sk-SK" {
        $everyone = "Všetci"
        $builtin = "Vstavaný"
    }
    "sl-SI" {
        $everyone = "Vsi"
        $builtin = "Vgrajen"
    }
    "sr-Latn-RS" {
        $everyone = "Svi"
        $builtin = "Ugrađeni"
    }
    "sv-SE" {
        $everyone = "Alla"
        $builtin = "Inbyggd"
    }
    "th-TH" {
        $everyone = "ทุกคน"
        $builtin = "ภายในเครื่อง"
    }
    "tr-TR" {
        $everyone = "Herkes"
        $builtin = "Yerleşik"
    }
    "uk-UA" {
        $everyone = "Всі"
        $builtin = "Вбудований"
    }
    "zh-CN" {
        $everyone = "所有人"
        $builtin = "内置"
    }
    "zh-TW" {
        $everyone = "所有人"
        $builtin = "內建"
    }
    default {
        $everyone = "Everyone"
        $builtin = "Builtin"
    }
}

############################################################################################################
#                                        Remove AppX Packages                                              #
#                                                                                                          #
############################################################################################################

#Removes AppxPackages
$WhitelistedApps = @(
    'Microsoft.WindowsNotepad',
    'Microsoft.CompanyPortal',
    'Microsoft.ScreenSketch',
    'Microsoft.Paint3D',
    'Microsoft.WindowsCalculator',
    'Microsoft.WindowsStore',
    'Microsoft.Windows.Photos',
    'CanonicalGroupLimited.UbuntuonWindows',
    'Microsoft.MicrosoftStickyNotes',
    'Microsoft.MSPaint',
    'Microsoft.WindowsCamera',
    '.NET Framework',
    'Microsoft.HEIFImageExtension',
    'Microsoft.ScreenSketch',
    'Microsoft.StorePurchaseApp',
    'Microsoft.VP9VideoExtensions',
    'Microsoft.WebMediaExtensions',
    'Microsoft.WebpImageExtension',
    'Microsoft.DesktopAppInstaller',
    'WindSynthBerry',
    'MIDIBerry',
    'Slack',
    'Microsoft.SecHealthUI',
    'WavesAudio.MaxxAudioProforDell2019',
    'Dell Optimizer Core',
    'Dell SupportAssist Remediation',
    'Dell SupportAssist OS Recovery Plugin for Dell Update',
    'Dell Pair',
    'Dell Display Manager 2.0',
    'Dell Display Manager 2.1',
    'Dell Display Manager 2.2',
    'Dell Peripheral Manager',
    'MSTeams',
    'Microsoft.Paint',
    'Microsoft.OutlookForWindows',
    'Microsoft.WindowsTerminal',
    'Microsoft.MicrosoftEdge.Stable'
)
##If $customwhitelist is set, split on the comma and add to whitelist
if ($customwhitelist) {
    $customWhitelistApps = $customwhitelist -split ","
    foreach ($whitelistapp in $customwhitelistapps) {
        ##Add to the array
        $WhitelistedApps += $whitelistapp
    }
}

#NonRemovable Apps that where getting attempted and the system would reject the uninstall, speeds up debloat and prevents 'initalizing' overlay when removing apps
$NonRemovable = @(
    '1527c705-839a-4832-9118-54d4Bd6a0c89',
    'c5e2524a-ea46-4f67-841f-6a9465d9d515',
    'E2A4F912-2574-4A75-9BB0-0D023378592B',
    'F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE',
    'InputApp',
    'Microsoft.AAD.BrokerPlugin',
    'Microsoft.AccountsControl',
    'Microsoft.BioEnrollment',
    'Microsoft.CredDialogHost',
    'Microsoft.ECApp',
    'Microsoft.LockApp',
    'Microsoft.MicrosoftEdgeDevToolsClient',
    'Microsoft.MicrosoftEdge',
    'Microsoft.PPIProjection',
    'Microsoft.Win32WebViewHost',
    'Microsoft.Windows.Apprep.ChxApp',
    'Microsoft.Windows.AssignedAccessLockApp',
    'Microsoft.Windows.CapturePicker',
    'Microsoft.Windows.CloudExperienceHost',
    'Microsoft.Windows.ContentDeliveryManager',
    'Microsoft.Windows.Cortana',
    'Microsoft.Windows.NarratorQuickStart',
    'Microsoft.Windows.ParentalControls',
    'Microsoft.Windows.PeopleExperienceHost',
    'Microsoft.Windows.PinningConfirmationDialog',
    'Microsoft.Windows.SecHealthUI',
    'Microsoft.Windows.SecureAssessmentBrowser',
    'Microsoft.Windows.ShellExperienceHost',
    'Microsoft.Windows.XGpuEjectDialog',
    'Microsoft.XboxGameCallableUI',
    'Windows.CBSPreview',
    'windows.immersivecontrolpanel',
    'Windows.PrintDialog',
    'Microsoft.VCLibs.140.00',
    'Microsoft.Services.Store.Engagement',
    'Microsoft.UI.Xaml.2.0',
    'Microsoft.AsyncTextService',
    'Microsoft.UI.Xaml.CBS',
    'Microsoft.Windows.CallingShellApp',
    'Microsoft.Windows.OOBENetworkConnectionFlow',
    'Microsoft.Windows.PrintQueueActionCenter',
    'Microsoft.Windows.StartMenuExperienceHost',
    'MicrosoftWindows.Client.CBS',
    'MicrosoftWindows.Client.Core',
    'MicrosoftWindows.UndockedDevKit',
    'NcsiUwpApp',
    'Microsoft.NET.Native.Runtime.2.2',
    'Microsoft.NET.Native.Framework.2.2',
    'Microsoft.UI.Xaml.2.8',
    'Microsoft.UI.Xaml.2.7',
    'Microsoft.UI.Xaml.2.3',
    'Microsoft.UI.Xaml.2.4',
    'Microsoft.UI.Xaml.2.1',
    'Microsoft.UI.Xaml.2.2',
    'Microsoft.UI.Xaml.2.5',
    'Microsoft.UI.Xaml.2.6',
    'Microsoft.VCLibs.140.00.UWPDesktop',
    'MicrosoftWindows.Client.LKG',
    'MicrosoftWindows.Client.FileExp',
    'Microsoft.WindowsAppRuntime.1.5',
    'Microsoft.WindowsAppRuntime.1.3',
    'Microsoft.WindowsAppRuntime.1.1',
    'Microsoft.WindowsAppRuntime.1.2',
    'Microsoft.WindowsAppRuntime.1.4',
    'Microsoft.Windows.OOBENetworkCaptivePortal',
    'Microsoft.Windows.Search'
)

##Combine the two arrays
$appstoignore = $WhitelistedApps += $NonRemovable

##Bloat list for future reference
$Bloatware = @(
#Unnecessary Windows 10/11 AppX Apps
"*ActiproSoftwareLLC*"
"*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
"*BubbleWitch3Saga*"
"*CandyCrush*"
"*DevHome*"
"*Disney*"
"*Dolby*"
"*Duolingo-LearnLanguagesforFree*"
"*EclipseManager*"
"*Facebook*"
"*Flipboard*"
"*gaming*"
"*Minecraft*"
"*Office*"
"*PandoraMediaInc*"
"*Royal Revolt*"
"*Speed Test*"
"*Spotify*"
"*Sway*"
"*Twitter*"
"*Wunderlist*"
"AD2F1837.HPPrinterControl"
"AppUp.IntelGraphicsExperience"
"C27EB4BA.DropboxOEM*"
"Disney.37853FC22B2CE"
"DolbyLaboratories.DolbyAccess"
"DolbyLaboratories.DolbyAudio"
"E0469640.SmartAppearance"
"Microsoft.549981C3F5F10"
"Microsoft.AV1VideoExtension"
"Microsoft.BingNews"
"Microsoft.BingSearch"
"Microsoft.BingWeather"
"Microsoft.GetHelp"
"Microsoft.Getstarted"
"Microsoft.GamingApp"
"Microsoft.HEVCVideoExtension"
"Microsoft.Messaging"
"Microsoft.Microsoft3DViewer"
"Microsoft.MicrosoftEdge.Stable"
"Microsoft.MicrosoftJournal"
"Microsoft.MicrosoftOfficeHub"
"Microsoft.MicrosoftSolitaireCollection"
"Microsoft.MixedReality.Portal"
"Microsoft.MPEG2VideoExtension"
"Microsoft.News"
"Microsoft.Office.Lens"
"Microsoft.Office.OneNote"
"Microsoft.Office.Sway"
"Microsoft.OneConnect"
"Microsoft.OneDriveSync"
"Microsoft.People"
"Microsoft.PowerAutomateDesktop"
"Microsoft.PowerAutomateDesktopCopilotPlugin"
"Microsoft.Print3D"
"Microsoft.RemoteDesktop"
"Microsoft.SkypeApp"
"Microsoft.StorePurchaseApp"
"Microsoft.SysinternalsSuite"
"Microsoft.Teams"
"Microsoft.Todos"
"Microsoft.Whiteboard"
"Microsoft.Windows.DevHome"
"Microsoft.WindowsAlarms"
"Microsoft.WindowsCamera"
"Microsoft.windowscommunicationsapps"
"Microsoft.WindowsFeedbackHub"
"Microsoft.WindowsMaps"
"Microsoft.WindowsSoundRecorder"
"Microsoft.WindowsStore"
"Microsoft.Xbox.TCUI"
"Microsoft.XboxApp"
"Microsoft.XboxGameOverlay"
"Microsoft.XboxGamingOverlay"
"Microsoft.XboxGamingOverlay_5.721.10202.0_neutral_~_8wekyb3d8bbwe"
"Microsoft.XboxIdentityProvider"
"Microsoft.XboxSpeechToTextOverlay"
"Microsoft.YourPhone"
"Microsoft.ZuneMusic"
"Microsoft.ZuneVideo"
"MicrosoftCorporationII.MicrosoftFamily"
"MicrosoftCorporationII.QuickAssist"
"MicrosoftWindows.Client.WebExperience"
"MicrosoftWindows.CrossDevice"
"MirametrixInc.GlancebyMirametrix"
"MSTeams"
"RealtimeboardInc.RealtimeBoard"
"SpotifyAB.SpotifyMusic"
#Optional: Typically not removed but you can if you need to for some reason
#"*Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe*"
#"*Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe*"
#"*Microsoft.BingWeather*"
#"*Microsoft.MSPaint*"
#"*Microsoft.MicrosoftStickyNotes*"
#"*Microsoft.Windows.Photos*"
#"*Microsoft.WindowsCalculator*"
#"*Microsoft.WindowsStore*"
#"Microsoft.Office.Todo.List"
#"Microsoft.Whiteboard"
#"Microsoft.WindowsCamera"
#"Microsoft.WindowsSoundRecorder"
#"Microsoft.YourPhone"
#"Microsoft.Todos"
#"Microsoft.PowerAutomateDesktop"
)


$provisioned = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -in $Bloatware -and $_.DisplayName -notin $appstoignore -and $_.DisplayName -notlike 'MicrosoftWindows.Voice*' -and $_.DisplayName -notlike 'Microsoft.LanguageExperiencePack*' -and $_.DisplayName -notlike 'MicrosoftWindows.Speech*' }
foreach ($appxprov in $provisioned) {
    $packagename = $appxprov.PackageName
    $displayname = $appxprov.DisplayName
    write-output "Removing $displayname AppX Provisioning Package"
    try {
        Remove-AppxProvisionedPackage -PackageName $packagename -Online -ErrorAction SilentlyContinue
        write-output "Removed $displayname AppX Provisioning Package"
    }
    catch {
        write-output "Unable to remove $displayname AppX Provisioning Package"
    }

}


$appxinstalled = Get-AppxPackage -AllUsers | Where-Object { $_.Name -in $Bloatware -and $_.Name -notin $appstoignore  -and $_.Name -notlike 'MicrosoftWindows.Voice*' -and $_.Name -notlike 'Microsoft.LanguageExperiencePack*' -and $_.Name -notlike 'MicrosoftWindows.Speech*'}
foreach ($appxapp in $appxinstalled) {
    $packagename = $appxapp.PackageFullName
    $displayname = $appxapp.Name
    write-output "$displayname AppX Package exists"
    write-output "Removing $displayname AppX Package"
    try {
        Remove-AppxPackage -Package $packagename -AllUsers -ErrorAction SilentlyContinue
        write-output "Removed $displayname AppX Package"
    }
    catch {
        write-output "$displayname AppX Package does not exist"
    }



}


############################################################################################################
#                                        Remove Registry Keys                                              #
#                                                                                                          #
############################################################################################################

##We need to grab all SIDs to remove at user level
$UserSIDs = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | Select-Object -ExpandProperty PSChildName


#These are the registry keys that it will delete.

$Keys = @(

    #Remove Background Tasks
    "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
    "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
    "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
    "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
    "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
    "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"

    #Windows File
    "HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"

    #Registry keys to delete if they aren't uninstalled by RemoveAppXPackage/RemoveAppXProvisionedPackage
    "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
    "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
    "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
    "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
    "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"

    #Scheduled Tasks to delete
    "HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"

    #Windows Protocol Keys
    "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
    "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
    "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
    "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"

    #Windows Share Target
    "HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
)

#This writes the output of each key it is removing and also removes the keys listed above.
ForEach ($Key in $Keys) {
    write-output "Removing $Key from registry"
    Remove-Item $Key -Recurse
}


#Disables Windows Feedback Experience
write-output "Disabling Windows Feedback Experience program"
$Advertising = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
If (!(Test-Path $Advertising)) {
    New-Item $Advertising
}
If (Test-Path $Advertising) {
    Set-ItemProperty $Advertising Enabled -Value 0
}

#Stops Cortana from being used as part of your Windows Search Function
write-output "Stopping Cortana from being used as part of your Windows Search Function"
$Search = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
If (!(Test-Path $Search)) {
    New-Item $Search
}
If (Test-Path $Search) {
    Set-ItemProperty $Search AllowCortana -Value 0
}

#Disables Web Search in Start Menu
write-output "Disabling Bing Search in Start Menu"
$WebSearch = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
If (!(Test-Path $WebSearch)) {
    New-Item $WebSearch
}
Set-ItemProperty $WebSearch DisableWebSearch -Value 1
##Loop through all user SIDs in the registry and disable Bing Search
foreach ($sid in $UserSIDs) {
    $WebSearch = "Registry::HKU\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"
    If (!(Test-Path $WebSearch)) {
        New-Item $WebSearch
    }
    Set-ItemProperty $WebSearch BingSearchEnabled -Value 0
}

Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" BingSearchEnabled -Value 0


#Stops the Windows Feedback Experience from sending anonymous data
write-output "Stopping the Windows Feedback Experience program"
$Period = "HKCU:\Software\Microsoft\Siuf\Rules"
If (!(Test-Path $Period)) {
    New-Item $Period
}
Set-ItemProperty $Period PeriodInNanoSeconds -Value 0

##Loop and do the same
foreach ($sid in $UserSIDs) {
    $Period = "Registry::HKU\$sid\Software\Microsoft\Siuf\Rules"
    If (!(Test-Path $Period)) {
        New-Item $Period
    }
    Set-ItemProperty $Period PeriodInNanoSeconds -Value 0
}

#Prevents bloatware applications from returning and removes Start Menu suggestions
write-output "Adding Registry key to prevent bloatware apps from returning"
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
$registryOEM = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
If (!(Test-Path $registryPath)) {
    New-Item $registryPath
}
Set-ItemProperty $registryPath DisableWindowsConsumerFeatures -Value 1

If (!(Test-Path $registryOEM)) {
    New-Item $registryOEM
}
Set-ItemProperty $registryOEM  ContentDeliveryAllowed -Value 0
Set-ItemProperty $registryOEM  OemPreInstalledAppsEnabled -Value 0
Set-ItemProperty $registryOEM  PreInstalledAppsEnabled -Value 0
Set-ItemProperty $registryOEM  PreInstalledAppsEverEnabled -Value 0
Set-ItemProperty $registryOEM  SilentInstalledAppsEnabled -Value 0
Set-ItemProperty $registryOEM  SystemPaneSuggestionsEnabled -Value 0

##Loop through users and do the same
foreach ($sid in $UserSIDs) {
    $registryOEM = "Registry::HKU\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    If (!(Test-Path $registryOEM)) {
        New-Item $registryOEM
    }
    Set-ItemProperty $registryOEM  ContentDeliveryAllowed -Value 0
    Set-ItemProperty $registryOEM  OemPreInstalledAppsEnabled -Value 0
    Set-ItemProperty $registryOEM  PreInstalledAppsEnabled -Value 0
    Set-ItemProperty $registryOEM  PreInstalledAppsEverEnabled -Value 0
    Set-ItemProperty $registryOEM  SilentInstalledAppsEnabled -Value 0
    Set-ItemProperty $registryOEM  SystemPaneSuggestionsEnabled -Value 0
}

#Preping mixed Reality Portal for removal
write-output "Setting Mixed Reality Portal value to 0 so that you can uninstall it in Settings"
$Holo = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic"
If (Test-Path $Holo) {
    Set-ItemProperty $Holo  FirstRunSucceeded -Value 0
}

##Loop through users and do the same
foreach ($sid in $UserSIDs) {
    $Holo = "Registry::HKU\$sid\Software\Microsoft\Windows\CurrentVersion\Holographic"
    If (Test-Path $Holo) {
        Set-ItemProperty $Holo  FirstRunSucceeded -Value 0
    }
}

#Disables Wi-fi Sense
write-output "Disabling Wi-Fi Sense"
$WifiSense1 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting"
$WifiSense2 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots"
$WifiSense3 = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
If (!(Test-Path $WifiSense1)) {
    New-Item $WifiSense1
}
Set-ItemProperty $WifiSense1  Value -Value 0
If (!(Test-Path $WifiSense2)) {
    New-Item $WifiSense2
}
Set-ItemProperty $WifiSense2  Value -Value 0
Set-ItemProperty $WifiSense3  AutoConnectAllowedOEM -Value 0

#Disables live tiles
write-output "Disabling live tiles"
$Live = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
If (!(Test-Path $Live)) {
    New-Item $Live
}
Set-ItemProperty $Live  NoTileApplicationNotification -Value 1

##Loop through users and do the same
foreach ($sid in $UserSIDs) {
    $Live = "Registry::HKU\$sid\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
    If (!(Test-Path $Live)) {
        New-Item $Live
    }
    Set-ItemProperty $Live  NoTileApplicationNotification -Value 1
}

#Turns off Data Collection via the AllowTelemtry key by changing it to 0
# This is needed for Intune reporting to work, uncomment if using via other method
#write-output "Turning off Data Collection"
#$DataCollection1 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
#$DataCollection2 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
#$DataCollection3 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
#If (Test-Path $DataCollection1) {
#    Set-ItemProperty $DataCollection1  AllowTelemetry -Value 0
#}
#If (Test-Path $DataCollection2) {
#    Set-ItemProperty $DataCollection2  AllowTelemetry -Value 0
#}
#If (Test-Path $DataCollection3) {
#    Set-ItemProperty $DataCollection3  AllowTelemetry -Value 0
#}


###Enable location tracking for "find my device", uncomment if you don't need it

#Disabling Location Tracking
#write-output "Disabling Location Tracking"
#$SensorState = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
#$LocationConfig = "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration"
#If (!(Test-Path $SensorState)) {
#    New-Item $SensorState
#}
#Set-ItemProperty $SensorState SensorPermissionState -Value 0
#If (!(Test-Path $LocationConfig)) {
#    New-Item $LocationConfig
#}
#Set-ItemProperty $LocationConfig Status -Value 0

#Disables People icon on Taskbar
write-output "Disabling People icon on Taskbar"
$People = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People'
If (Test-Path $People) {
    Set-ItemProperty $People -Name PeopleBand -Value 0
}

##Loop through users and do the same
foreach ($sid in $UserSIDs) {
    $People = "Registry::HKU\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People"
    If (Test-Path $People) {
        Set-ItemProperty $People -Name PeopleBand -Value 0
    }
}

write-output "Disabling Cortana"
$Cortana1 = "HKCU:\SOFTWARE\Microsoft\Personalization\Settings"
$Cortana2 = "HKCU:\SOFTWARE\Microsoft\InputPersonalization"
$Cortana3 = "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"
If (!(Test-Path $Cortana1)) {
    New-Item $Cortana1
}
Set-ItemProperty $Cortana1 AcceptedPrivacyPolicy -Value 0
If (!(Test-Path $Cortana2)) {
    New-Item $Cortana2
}
Set-ItemProperty $Cortana2 RestrictImplicitTextCollection -Value 1
Set-ItemProperty $Cortana2 RestrictImplicitInkCollection -Value 1
If (!(Test-Path $Cortana3)) {
    New-Item $Cortana3
}
Set-ItemProperty $Cortana3 HarvestContacts -Value 0

##Loop through users and do the same
foreach ($sid in $UserSIDs) {
    $Cortana1 = "Registry::HKU\$sid\SOFTWARE\Microsoft\Personalization\Settings"
    $Cortana2 = "Registry::HKU\$sid\SOFTWARE\Microsoft\InputPersonalization"
    $Cortana3 = "Registry::HKU\$sid\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"
    If (!(Test-Path $Cortana1)) {
        New-Item $Cortana1
    }
    Set-ItemProperty $Cortana1 AcceptedPrivacyPolicy -Value 0
    If (!(Test-Path $Cortana2)) {
        New-Item $Cortana2
    }
    Set-ItemProperty $Cortana2 RestrictImplicitTextCollection -Value 1
    Set-ItemProperty $Cortana2 RestrictImplicitInkCollection -Value 1
    If (!(Test-Path $Cortana3)) {
        New-Item $Cortana3
    }
    Set-ItemProperty $Cortana3 HarvestContacts -Value 0
}


#Removes 3D Objects from the 'My Computer' submenu in explorer
write-output "Removing 3D Objects from explorer 'My Computer' submenu"
$Objects32 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
$Objects64 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
If (Test-Path $Objects32) {
    Remove-Item $Objects32 -Recurse
}
If (Test-Path $Objects64) {
    Remove-Item $Objects64 -Recurse
}

##Removes the Microsoft Feeds from displaying
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds"
$Name = "EnableFeeds"
$value = "0"

if (!(Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
}

else {
    New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
}

##Kill Cortana again
Get-AppxPackage Microsoft.549981C3F5F10 -allusers | Remove-AppxPackage
############################################################################################################
#                                        Remove Learn about this picture                                   #
#                                                                                                          #
############################################################################################################

#Turn off Learn about this picture
write-output "Disabling Learn about this picture"
$picture = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel'
If (Test-Path $picture) {
    Set-ItemProperty $picture -Name "{2cc5ca98-6485-489a-920e-b3e88a6ccce3}" -Value 1
}

##Loop through users and do the same
foreach ($sid in $UserSIDs) {
    $picture = "Registry::HKU\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
    If (Test-Path $picture) {
        Set-ItemProperty $picture -Name "{2cc5ca98-6485-489a-920e-b3e88a6ccce3}" -Value 1
    }
}

############################################################################################################
#                                        Remove Scheduled Tasks                                            #
#                                                                                                          #
############################################################################################################

#Disables scheduled tasks that are considered unnecessary
write-output "Disabling scheduled tasks"
$task1 = Get-ScheduledTask -TaskName XblGameSaveTaskLogon -ErrorAction SilentlyContinue
if ($null -ne $task1) {
    Get-ScheduledTask  XblGameSaveTaskLogon | Disable-ScheduledTask -ErrorAction SilentlyContinue
}
$task2 = Get-ScheduledTask -TaskName XblGameSaveTask -ErrorAction SilentlyContinue
if ($null -ne $task2) {
    Get-ScheduledTask  XblGameSaveTask | Disable-ScheduledTask -ErrorAction SilentlyContinue
}
$task3 = Get-ScheduledTask -TaskName Consolidator -ErrorAction SilentlyContinue
if ($null -ne $task3) {
    Get-ScheduledTask  Consolidator | Disable-ScheduledTask -ErrorAction SilentlyContinue
}
$task4 = Get-ScheduledTask -TaskName UsbCeip -ErrorAction SilentlyContinue
if ($null -ne $task4) {
    Get-ScheduledTask  UsbCeip | Disable-ScheduledTask -ErrorAction SilentlyContinue
}
$task5 = Get-ScheduledTask -TaskName DmClient -ErrorAction SilentlyContinue
if ($null -ne $task5) {
    Get-ScheduledTask  DmClient | Disable-ScheduledTask -ErrorAction SilentlyContinue
}
$task6 = Get-ScheduledTask -TaskName DmClientOnScenarioDownload -ErrorAction SilentlyContinue
if ($null -ne $task6) {
    Get-ScheduledTask  DmClientOnScenarioDownload | Disable-ScheduledTask -ErrorAction SilentlyContinue
}


############################################################################################################
#                                             Disable Services                                             #
#                                                                                                          #
############################################################################################################
##write-output "Stopping and disabling Diagnostics Tracking Service"
#Disabling the Diagnostics Tracking Service
##Stop-Service "DiagTrack"
##Set-Service "DiagTrack" -StartupType Disabled


############################################################################################################
#                                        Windows 11 Specific                                               #
#                                                                                                          #
############################################################################################################
#Windows 11 Customisations
write-output "Removing Windows 11 Customisations"

#Remove Teams Chat
$MSTeams = "MicrosoftTeams"

$WinPackage = Get-AppxPackage -allusers | Where-Object { $_.Name -eq $MSTeams }
$ProvisionedPackage = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $WinPackage }
If ($null -ne $WinPackage) {
    Remove-AppxPackage  -Package $WinPackage.PackageFullName -AllUsers
}

If ($null -ne $ProvisionedPackage) {
    Remove-AppxProvisionedPackage -online -Packagename $ProvisionedPackage.Packagename -AllUsers
}

##Tweak reg permissions
invoke-webrequest -uri "https://github.com/andrew-s-taylor/public/raw/main/De-Bloat/SetACL.exe" -outfile "C:\Windows\Temp\SetACL.exe"
C:\Windows\Temp\SetACL.exe -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications" -ot reg -actn setowner -ownr "n:$everyone"
C:\Windows\Temp\SetACL.exe -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications" -ot reg -actn ace -ace "n:$everyone;p:full"


##Stop it coming back
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications"
If (!(Test-Path $registryPath)) {
    New-Item $registryPath
}
Set-ItemProperty $registryPath ConfigureChatAutoInstall -Value 0


##Unpin it
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Chat"
If (!(Test-Path $registryPath)) {
    New-Item $registryPath
}
Set-ItemProperty $registryPath "ChatIcon" -Value 2
write-output "Removed Teams Chat"


##Disable Feeds
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Dsh"
If (!(Test-Path $registryPath)) {
    New-Item $registryPath
}
Set-ItemProperty $registryPath "AllowNewsAndInterests" -Value 0
write-output "Disabled Feeds"

############################################################################################################
#                                           Windows Backup App                                             #
#                                                                                                          #
############################################################################################################
$version = Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Caption
if ($version -like "*Windows 10*") {
    write-output "Removing Windows Backup"
    $filepath = "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\WindowsBackup\Assets"
    if (Test-Path $filepath) {
        Remove-WindowsPackage -Online -PackageName "Microsoft-Windows-UserExperience-Desktop-Package~31bf3856ad364e35~amd64~~10.0.19041.3393"

        ##Add back snipping tool functionality
        write-output "Adding Windows Shell Components"
        DISM /Online /Add-Capability /CapabilityName:Windows.Client.ShellComponents~~~~0.0.1.0
        write-output "Components Added"
    }
    write-output "Removed"
}

############################################################################################################
#                                           Windows CoPilot                                                #
#                                                                                                          #
############################################################################################################
$version = Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Caption
if ($version -like "*Windows 11*") {
    write-output "Removing Windows Copilot"
    # Define the registry key and value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"
    $propertyName = "TurnOffWindowsCopilot"
    $propertyValue = 1

    # Check if the registry key exists
    if (!(Test-Path $registryPath)) {
        # If the registry key doesn't exist, create it
        New-Item -Path $registryPath -Force | Out-Null
    }

    # Get the property value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $propertyName -ErrorAction SilentlyContinue

    # Check if the property exists and if its value is different from the desired value
    if ($null -eq $currentValue -or $currentValue.$propertyName -ne $propertyValue) {
        # If the property doesn't exist or its value is different, set the property value
        Set-ItemProperty -Path $registryPath -Name $propertyName -Value $propertyValue
    }


    ##Grab the default user as well
    $registryPath = "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows\WindowsCopilot"
    $propertyName = "TurnOffWindowsCopilot"
    $propertyValue = 1

    # Check if the registry key exists
    if (!(Test-Path $registryPath)) {
        # If the registry key doesn't exist, create it
        New-Item -Path $registryPath -Force | Out-Null
    }

    # Get the property value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $propertyName -ErrorAction SilentlyContinue

    # Check if the property exists and if its value is different from the desired value
    if ($null -eq $currentValue -or $currentValue.$propertyName -ne $propertyValue) {
        # If the property doesn't exist or its value is different, set the property value
        Set-ItemProperty -Path $registryPath -Name $propertyName -Value $propertyValue
    }


    ##Load the default hive from c:\users\Default\NTUSER.dat
    reg load HKU\temphive "c:\users\default\ntuser.dat"
    $registryPath = "registry::hku\temphive\Software\Policies\Microsoft\Windows\WindowsCopilot"
    $propertyName = "TurnOffWindowsCopilot"
    $propertyValue = 1

    # Check if the registry key exists
    if (!(Test-Path $registryPath)) {
        # If the registry key doesn't exist, create it
        [Microsoft.Win32.RegistryKey]$HKUCoPilot = [Microsoft.Win32.Registry]::Users.CreateSubKey("temphive\Software\Policies\Microsoft\Windows\WindowsCopilot", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree)
        $HKUCoPilot.SetValue("TurnOffWindowsCopilot", 0x1, [Microsoft.Win32.RegistryValueKind]::DWord)
    }





    $HKUCoPilot.Flush()
    $HKUCoPilot.Close()
    [gc]::Collect()
    [gc]::WaitForPendingFinalizers()
    reg unload HKU\temphive


    write-output "Removed"


    foreach ($sid in $UserSIDs) {
        $registryPath = "Registry::HKU\$sid\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"
        $propertyName = "TurnOffWindowsCopilot"
        $propertyValue = 1

        # Check if the registry key exists
        if (!(Test-Path $registryPath)) {
            # If the registry key doesn't exist, create it
            New-Item -Path $registryPath -Force | Out-Null
        }

        # Get the property value
        $currentValue = Get-ItemProperty -Path $registryPath -Name $propertyName -ErrorAction SilentlyContinue

        # Check if the property exists and if its value is different from the desired value
        if ($null -eq $currentValue -or $currentValue.$propertyName -ne $propertyValue) {
            # If the property doesn't exist or its value is different, set the property value
            Set-ItemProperty -Path $registryPath -Name $propertyName -Value $propertyValue
        }
    }
}
############################################################################################################
#                                              Remove Recall                                               #
#                                                                                                          #
############################################################################################################

#Turn off Recall
write-output "Disabling Recall"
$recall = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
If (!(Test-Path $recall)) {
    New-Item $recall
}
Set-ItemProperty $recall DisableAIDataAnalysis -Value 1


$recalluser = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
If (!(Test-Path $recalluser)) {
    New-Item $recalluser
}
Set-ItemProperty $recalluser DisableAIDataAnalysis -Value 1

##Loop through users and do the same
foreach ($sid in $UserSIDs) {
    $recallusers = "Registry::HKU\$sid\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
    If (!(Test-Path $recallusers)) {
        New-Item $recallusers
    }
    Set-ItemProperty $recallusers DisableAIDataAnalysis -Value 1
}


############################################################################################################
#                                             Clear Start Menu                                             #
#                                                                                                          #
############################################################################################################
write-output "Clearing Start Menu"
#Delete layout file if it already exists

##Check windows version
$version = Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Caption
if ($version -like "*Windows 10*") {
    write-output "Windows 10 Detected"
    write-output "Removing Current Layout"
    If (Test-Path C:\Windows\StartLayout.xml)
    {

        Remove-Item C:\Windows\StartLayout.xml

    }
    write-output "Creating Default Layout"
    #Creates the blank layout file

    Write-Output "<LayoutModificationTemplate xmlns:defaultlayout=""http://schemas.microsoft.com/Start/2014/FullDefaultLayout"" xmlns:start=""http://schemas.microsoft.com/Start/2014/StartLayout"" Version=""1"" xmlns=""http://schemas.microsoft.com/Start/2014/LayoutModification"">" >> C:\Windows\StartLayout.xml

    Write-Output " <LayoutOptions StartTileGroupCellWidth=""6"" />" >> C:\Windows\StartLayout.xml

    Write-Output " <DefaultLayoutOverride>" >> C:\Windows\StartLayout.xml

    Write-Output " <StartLayoutCollection>" >> C:\Windows\StartLayout.xml

    Write-Output " <defaultlayout:StartLayout GroupCellWidth=""6"" />" >> C:\Windows\StartLayout.xml

    Write-Output " </StartLayoutCollection>" >> C:\Windows\StartLayout.xml

    Write-Output " </DefaultLayoutOverride>" >> C:\Windows\StartLayout.xml

    Write-Output "</LayoutModificationTemplate>" >> C:\Windows\StartLayout.xml
}
if ($version -like "*Windows 11*") {
    write-output "Windows 11 Detected"
    write-output "Removing Current Layout"
    If (Test-Path "C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml")
    {

        Remove-Item "C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml"

    }

    $blankjson = @'
{
    "pinnedList": [
{ "desktopAppId": "MSEdge" },
{ "packagedAppId": "Microsoft.WindowsStore_8wekyb3d8bbwe!App" },
{ "packagedAppId": "desktopAppId":"Microsoft.Windows.Explorer" }
    ]
}
'@

    $blankjson | Out-File "C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml" -Encoding utf8 -Force
    $intunepath = "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps"
    $intunecomplete = @(Get-ChildItem $intunepath).count
    $userpath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    $userprofiles = Get-ChildItem $userpath | ForEach-Object { Get-ItemProperty $_.PSPath }

    $nonAdminLoggedOn = $false
    foreach ($user in $userprofiles) {
        if ($user.PSChildName -ne '.DEFAULT' -and $user.PSChildName -ne 'S-1-5-18' -and $user.PSChildName -ne 'S-1-5-19' -and $user.PSChildName -ne 'S-1-5-20' -and $user.PSChildName -notmatch 'S-1-5-21-\d+-\d+-\d+-500') {
            $nonAdminLoggedOn = $true
            break
        }
    }

    if ($nonAdminLoggedOn -eq $false) {
        MkDir -Path "C:\Users\Default\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState" -Force -ErrorAction SilentlyContinue | Out-Null
        $starturl = "https://github.com/andrew-s-taylor/public/raw/main/De-Bloat/start2.bin"
        invoke-webrequest -uri $starturl -outfile "C:\Users\Default\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState\Start2.bin"
    }
}


############################################################################################################
#                                              Remove Xbox Gaming                                          #
#                                                                                                          #
############################################################################################################

New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\xbgm" -Name "Start" -PropertyType DWORD -Value 4 -Force
Set-Service -Name XblAuthManager -StartupType Disabled
Set-Service -Name XblGameSave -StartupType Disabled
Set-Service -Name XboxGipSvc -StartupType Disabled
Set-Service -Name XboxNetApiSvc -StartupType Disabled
$task = Get-ScheduledTask -TaskName "Microsoft\XblGameSave\XblGameSaveTask" -ErrorAction SilentlyContinue
if ($null -ne $task) {
    Set-ScheduledTask -TaskPath $task.TaskPath -Enabled $false
}

##Check if GamePresenceWriter.exe exists
if (Test-Path "$env:WinDir\System32\GameBarPresenceWriter.exe") {
    write-output "GamePresenceWriter.exe exists"
    C:\Windows\Temp\SetACL.exe -on  "$env:WinDir\System32\GameBarPresenceWriter.exe" -ot file -actn setowner -ownr "n:$everyone"
    C:\Windows\Temp\SetACL.exe -on  "$env:WinDir\System32\GameBarPresenceWriter.exe" -ot file -actn ace -ace "n:$everyone;p:full"

    #Take-Ownership -Path "$env:WinDir\System32\GameBarPresenceWriter.exe"
    $NewAcl = Get-Acl -Path "$env:WinDir\System32\GameBarPresenceWriter.exe"
    # Set properties
    $identity = "$builtin\Administrators"
    $fileSystemRights = "FullControl"
    $type = "Allow"
    # Create new rule
    $fileSystemAccessRuleArgumentList = $identity, $fileSystemRights, $type
    $fileSystemAccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $fileSystemAccessRuleArgumentList
    # Apply new rule
    $NewAcl.SetAccessRule($fileSystemAccessRule)
    Set-Acl -Path "$env:WinDir\System32\GameBarPresenceWriter.exe" -AclObject $NewAcl
    Stop-Process -Name "GameBarPresenceWriter.exe" -Force
    Remove-Item "$env:WinDir\System32\GameBarPresenceWriter.exe" -Force -Confirm:$false

}
else {
    write-output "GamePresenceWriter.exe does not exist"
}

New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\GameDVR" -Name "AllowgameDVR" -PropertyType DWORD -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "SettingsPageVisibility" -PropertyType String -Value "hide:gaming-gamebar;gaming-gamedvr;gaming-broadcasting;gaming-gamemode;gaming-xboxnetworking" -Force
Remove-Item C:\Windows\Temp\SetACL.exe -recurse

############################################################################################################
#                                        Disable Edge Surf Game                                            #
#                                                                                                          #
############################################################################################################
$surf = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
If (!(Test-Path $surf)) {
    New-Item $surf
}
New-ItemProperty -Path $surf -Name 'AllowSurfGame' -Value 0 -PropertyType DWord

############################################################################################################
#                                       Grab all Uninstall Strings                                         #
#                                                                                                          #
############################################################################################################


write-output "Checking 32-bit System Registry"
##Search for 32-bit versions and list them
$allstring = @()
$path1 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
#Loop Through the apps if name has Adobe and NOT reader
$32apps = Get-ChildItem -Path $path1 | Get-ItemProperty | Select-Object -Property DisplayName, UninstallString

foreach ($32app in $32apps) {
    #Get uninstall string
    $string1 = $32app.uninstallstring
    #Check if it's an MSI install
    if ($string1 -match "^msiexec*") {
        #MSI install, replace the I with an X and make it quiet
        $string2 = $string1 + " /quiet /norestart"
        $string2 = $string2 -replace "/I", "/X "
        #Create custom object with name and string
        $allstring += New-Object -TypeName PSObject -Property @{
            Name   = $32app.DisplayName
            String = $string2
        }
    }
    else {
        #Exe installer, run straight path
        $string2 = $string1
        $allstring += New-Object -TypeName PSObject -Property @{
            Name   = $32app.DisplayName
            String = $string2
        }
    }

}
write-output "32-bit check complete"
write-output "Checking 64-bit System registry"
##Search for 64-bit versions and list them

$path2 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
#Loop Through the apps if name has Adobe and NOT reader
$64apps = Get-ChildItem -Path $path2 | Get-ItemProperty | Select-Object -Property DisplayName, UninstallString

foreach ($64app in $64apps) {
    #Get uninstall string
    $string1 = $64app.uninstallstring
    #Check if it's an MSI install
    if ($string1 -match "^msiexec*") {
        #MSI install, replace the I with an X and make it quiet
        $string2 = $string1 + " /quiet /norestart"
        $string2 = $string2 -replace "/I", "/X "
        #Uninstall with string2 params
        $allstring += New-Object -TypeName PSObject -Property @{
            Name   = $64app.DisplayName
            String = $string2
        }
    }
    else {
        #Exe installer, run straight path
        $string2 = $string1
        $allstring += New-Object -TypeName PSObject -Property @{
            Name   = $64app.DisplayName
            String = $string2
        }
    }

}

write-output "64-bit checks complete"

##USER
write-output "Checking 32-bit User Registry"
##Search for 32-bit versions and list them
$path1 = "HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
##Check if path exists
if (Test-Path $path1) {
    #Loop Through the apps if name has Adobe and NOT reader
    $32apps = Get-ChildItem -Path $path1 | Get-ItemProperty | Select-Object -Property DisplayName, UninstallString

    foreach ($32app in $32apps) {
        #Get uninstall string
        $string1 = $32app.uninstallstring
        #Check if it's an MSI install
        if ($string1 -match "^msiexec*") {
            #MSI install, replace the I with an X and make it quiet
            $string2 = $string1 + " /quiet /norestart"
            $string2 = $string2 -replace "/I", "/X "
            #Create custom object with name and string
            $allstring += New-Object -TypeName PSObject -Property @{
                Name   = $32app.DisplayName
                String = $string2
            }
        }
        else {
            #Exe installer, run straight path
            $string2 = $string1
            $allstring += New-Object -TypeName PSObject -Property @{
                Name   = $32app.DisplayName
                String = $string2
            }
        }
    }
}
write-output "32-bit check complete"
write-output "Checking 64-bit Use registry"
##Search for 64-bit versions and list them

$path2 = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
#Loop Through the apps if name has Adobe and NOT reader
$64apps = Get-ChildItem -Path $path2 | Get-ItemProperty | Select-Object -Property DisplayName, UninstallString

foreach ($64app in $64apps) {
    #Get uninstall string
    $string1 = $64app.uninstallstring
    #Check if it's an MSI install
    if ($string1 -match "^msiexec*") {
        #MSI install, replace the I with an X and make it quiet
        $string2 = $string1 + " /quiet /norestart"
        $string2 = $string2 -replace "/I", "/X "
        #Uninstall with string2 params
        $allstring += New-Object -TypeName PSObject -Property @{
            Name   = $64app.DisplayName
            String = $string2
        }
    }
    else {
        #Exe installer, run straight path
        $string2 = $string1
        $allstring += New-Object -TypeName PSObject -Property @{
            Name   = $64app.DisplayName
            String = $string2
        }
    }

}


function UninstallAppFull {

    param (
        [string]$appName
    )

    # Get a list of installed applications from Programs and Features
    $installedApps = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
    HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
    Where-Object { $null -ne $_.DisplayName } |
    Select-Object DisplayName, UninstallString

    $userInstalledApps = Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
    Where-Object { $null -ne $_.DisplayName } |
    Select-Object DisplayName, UninstallString

    $allInstalledApps = $installedApps + $userInstalledApps | Where-Object { $_.DisplayName -eq "$appName" }

    # Loop through the list of installed applications and uninstall them

    foreach ($app in $allInstalledApps) {
        $uninstallString = $app.UninstallString
        $displayName = $app.DisplayName
        if ($uninstallString -match "^msiexec*") {
            #MSI install, replace the I with an X and make it quiet
            $string2 = $uninstallString + " /quiet /norestart"
            $string2 = $string2 -replace "/I", "/X "
        }
        else {
            #Exe installer, run straight path
            $string2 = $uninstallString
        }
        write-output "Uninstalling: $displayName"
        Start-Process $string2
        write-output "Uninstalled: $displayName" -ForegroundColor Green
    }
}


############################################################################################################
#                                        Remove Manufacturer Bloat                                         #
#                                                                                                          #
############################################################################################################
##Check Manufacturer
write-output "Detecting Manufacturer"
$details = Get-CimInstance -ClassName Win32_ComputerSystem
$manufacturer = $details.Manufacturer

if ($manufacturer -like "*HP*") {
    write-output "HP detected"
    #Remove HP bloat


    ##HP Specific
    $UninstallPrograms = @(
        "Poly Lens"
        "HP Client Security Manager"
        "HP Notifications"
        "HP Security Update Service"
        "HP System Default Settings"
        "HP Wolf Security"
        "HP Wolf Security Application Support for Sure Sense"
        "HP Wolf Security Application Support for Windows"
        "AD2F1837.HPPCHardwareDiagnosticsWindows"
        "AD2F1837.HPPowerManager"
        "AD2F1837.HPPrivacySettings"
        "AD2F1837.HPQuickDrop"
        "AD2F1837.HPSupportAssistant"
        "AD2F1837.HPSystemInformation"
        "AD2F1837.myHP"
        "RealtekSemiconductorCorp.HPAudioControl",
        "HP Sure Recover",
        "HP Sure Run Module"
        "RealtekSemiconductorCorp.HPAudioControl_2.39.280.0_x64__dt26b99r8h8gj"
        "HP Wolf Security - Console"
        "HP Wolf Security Application Support for Chrome 122.0.6261.139"
        "Windows Driver Package - HP Inc. sselam_4_4_2_453 AntiVirus  (11/01/2022 4.4.2.453)"

    )



    $UninstallPrograms = $UninstallPrograms | Where-Object { $appstoignore -notcontains $_ }

    #$HPidentifier = "AD2F1837"

    #$ProvisionedPackages = Get-AppxProvisionedPackage -Online | Where-Object {(($UninstallPrograms -contains $_.DisplayName) -or (($_.DisplayName -like "*$HPidentifier"))-and ($_.DisplayName -notin $WhitelistedApps))}

    #$InstalledPackages = Get-AppxPackage -AllUsers | Where-Object {(($UninstallPrograms -contains $_.Name) -or (($_.Name -like "^$HPidentifier"))-and ($_.Name -notin $WhitelistedApps))}

    $InstalledPrograms = $allstring | Where-Object { $UninstallPrograms -contains $_.Name }
    foreach ($app in $UninstallPrograms) {

        if (Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $app -ErrorAction SilentlyContinue) {
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $app | Remove-AppxProvisionedPackage -Online
            write-output "Removed provisioned package for $app."
        }
        else {
            write-output "Provisioned package for $app not found."
        }

        if (Get-AppxPackage -Name $app -ErrorAction SilentlyContinue) {
            Get-AppxPackage -allusers -Name $app | Remove-AppxPackage -AllUsers
            write-output "Removed $app."
        }
        else {
            write-output "$app not found."
        }

        UninstallAppFull -appName $app


    }





    ##Belt and braces, remove via CIM too
    foreach ($program in $UninstallPrograms) {
        Get-CimInstance -Classname Win32_Product | Where-Object Name -Match $program | Invoke-CimMethod -MethodName UnInstall
    }


    #Remove HP Documentation if it exists
    if (test-path -Path "C:\Program Files\HP\Documentation\Doc_uninstall.cmd") {
        Start-Process -FilePath "C:\Program Files\HP\Documentation\Doc_uninstall.cmd" -Wait -passthru -NoNewWindow
    }

    ##Remove HP Connect Optimizer if setup.exe exists
    if (test-path -Path 'C:\Program Files (x86)\InstallShield Installation Information\{6468C4A5-E47E-405F-B675-A70A70983EA6}\setup.exe') {
        invoke-webrequest -uri "https://raw.githubusercontent.com/andrew-s-taylor/public/main/De-Bloat/HPConnOpt.iss" -outfile "C:\Windows\Temp\HPConnOpt.iss"

        &'C:\Program Files (x86)\InstallShield Installation Information\{6468C4A5-E47E-405F-B675-A70A70983EA6}\setup.exe' @('-s', '-f1C:\Windows\Temp\HPConnOpt.iss')
    }

    ##Remove other crap
    if (Test-Path -Path "C:\Program Files (x86)\HP\Shared" -PathType Container) { Remove-Item -Path "C:\Program Files (x86)\HP\Shared" -Recurse -Force }
    if (Test-Path -Path "C:\Program Files (x86)\Online Services" -PathType Container) { Remove-Item -Path "C:\Program Files (x86)\Online Services" -Recurse -Force }
    if (Test-Path -Path "C:\ProgramData\HP\TCO" -PathType Container) { Remove-Item -Path "C:\ProgramData\HP\TCO" -Recurse -Force }
    if (Test-Path -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Amazon.com.lnk" -PathType Leaf) { Remove-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Amazon.com.lnk" -Force }
    if (Test-Path -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Angebote.lnk" -PathType Leaf) { Remove-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Angebote.lnk" -Force }
    if (Test-Path -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\TCO Certified.lnk" -PathType Leaf) { Remove-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\TCO Certified.lnk" -Force }
    if (Test-Path -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Booking.com.lnk" -PathType Leaf) { Remove-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Booking.com.lnk" -Force }
    if (Test-Path -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Adobe offers.lnk" -PathType Leaf) { Remove-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Adobe offers.lnk" -Force }

    write-output "Removed HP bloat"
}



if ($manufacturer -like "*Dell*") {
    write-output "Dell detected"
    #Remove Dell bloat

    ##Dell

    $UninstallPrograms = @(
        "Dell Optimizer"
        "Dell Power Manager"
        "DellOptimizerUI"
        "Dell SupportAssist OS Recovery"
        "Dell SupportAssist"
        "Dell Optimizer Service"
        "Dell Optimizer Core"
        "DellInc.PartnerPromo"
        "DellInc.DellOptimizer"
        "DellInc.DellCommandUpdate"
        "DellInc.DellPowerManager"
        "DellInc.DellDigitalDelivery"
        "DellInc.DellSupportAssistforPCs"
        "DellInc.PartnerPromo"
        "Dell Command | Update"
        "Dell Command | Update for Windows Universal"
        "Dell Command | Update for Windows 10"
        "Dell Command | Power Manager"
        "Dell Digital Delivery Service"
        "Dell Digital Delivery"
        "Dell Peripheral Manager"
        "Dell Power Manager Service"
        "Dell SupportAssist Remediation"
        "SupportAssist Recovery Assistant"
        "Dell SupportAssist OS Recovery Plugin for Dell Update"
        "Dell SupportAssistAgent"
        "Dell Update - SupportAssist Update Plugin"
        "Dell Core Services"
        "Dell Pair"
        "Dell Display Manager 2.0"
        "Dell Display Manager 2.1"
        "Dell Display Manager 2.2"
        "Dell SupportAssist Remediation"
        "Dell Update - SupportAssist Update Plugin"
        "DellInc.PartnerPromo"
    )



    $UninstallPrograms = $UninstallPrograms | Where-Object { $appstoignore -notcontains $_ }


    foreach ($app in $UninstallPrograms) {

        if (Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $app -ErrorAction SilentlyContinue) {
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $app | Remove-AppxProvisionedPackage -Online
            write-output "Removed provisioned package for $app."
        }
        else {
            write-output "Provisioned package for $app not found."
        }

        if (Get-AppxPackage -Name $app -ErrorAction SilentlyContinue) {
            Get-AppxPackage -allusers -Name $app | Remove-AppxPackage -AllUsers
            write-output "Removed $app."
        }
        else {
            write-output "$app not found."
        }

        UninstallAppFull -appName $app



    }

    ##Belt and braces, remove via CIM too
    foreach ($program in $UninstallPrograms) {
        write-output "Removing $program"
        Get-CimInstance -Query "SELECT * FROM Win32_Product WHERE name = '$program'" | Invoke-CimMethod -MethodName Uninstall
    }

    ##Manual Removals

    ##Dell Optimizer
    $dellSA = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object { $_.DisplayName -like "Dell*Optimizer*Core" } | Select-Object -Property UninstallString

    ForEach ($sa in $dellSA) {
        If ($sa.UninstallString) {
            try {
                cmd.exe /c $sa.UninstallString -silent
            }
            catch {
                Write-Warning "Failed to uninstall Dell Optimizer"
            }
        }
    }


    ##Dell Dell SupportAssist Remediation
    $dellSA = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object { $_.DisplayName -match "Dell SupportAssist Remediation" } | Select-Object -Property QuietUninstallString

    ForEach ($sa in $dellSA) {
        If ($sa.QuietUninstallString) {
            try {
                cmd.exe /c $sa.QuietUninstallString
            }
            catch {
                Write-Warning "Failed to uninstall Dell Support Assist Remediation"
            }
        }
    }

    ##Dell Dell SupportAssist OS Recovery Plugin for Dell Update
    $dellSA = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object { $_.DisplayName -match "Dell SupportAssist OS Recovery Plugin for Dell Update" } | Select-Object -Property QuietUninstallString

    ForEach ($sa in $dellSA) {
        If ($sa.QuietUninstallString) {
            try {
                cmd.exe /c $sa.QuietUninstallString
            }
            catch {
                Write-Warning "Failed to uninstall Dell Support Assist Remediation"
            }
        }
    }



    ##Dell Display Manager
    $dellSA = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object { $_.DisplayName -like "Dell*Display*Manager*" } | Select-Object -Property UninstallString

    ForEach ($sa in $dellSA) {
        If ($sa.UninstallString) {
            try {
                cmd.exe /c $sa.UninstallString /S
            }
            catch {
                Write-Warning "Failed to uninstall Dell Optimizer"
            }
        }
    }

    ##Dell Peripheral Manager

    try {
        start-process c:\windows\system32\cmd.exe '/c "C:\Program Files\Dell\Dell Peripheral Manager\Uninstall.exe" /S'
    }
    catch {
        Write-Warning "Failed to uninstall Dell Optimizer"
    }


    ##Dell Pair

    try {
        start-process c:\windows\system32\cmd.exe '/c "C:\Program Files\Dell\Dell Pair\Uninstall.exe" /S'
    }
    catch {
        Write-Warning "Failed to uninstall Dell Optimizer"
    }

}


if ($manufacturer -like "Lenovo") {
    write-output "Lenovo detected"

    #Remove HP bloat

    ##Lenovo Specific
    # Function to uninstall applications with .exe uninstall strings

    function UninstallApp {

        param (
            [string]$appName
        )

        # Get a list of installed applications from Programs and Features
        $installedApps = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
        HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
        Where-Object { $_.DisplayName -like "*$appName*" }

        # Loop through the list of installed applications and uninstall them

        foreach ($app in $installedApps) {
            $uninstallString = $app.UninstallString
            $displayName = $app.DisplayName
            write-output "Uninstalling: $displayName"
            Start-Process $uninstallString -ArgumentList "/VERYSILENT" -Wait
            write-output "Uninstalled: $displayName" -ForegroundColor Green
        }
    }

    ##Stop Running Processes

    $processnames = @(
        "SmartAppearanceSVC.exe"
        "UDClientService.exe"
        "ModuleCoreService.exe"
        "ProtectedModuleHost.exe"
        "*lenovo*"
        "FaceBeautify.exe"
        "McCSPServiceHost.exe"
        "mcapexe.exe"
        "MfeAVSvc.exe"
        "mcshield.exe"
        "Ammbkproc.exe"
        "AIMeetingManager.exe"
        "DADUpdater.exe"
        "CommercialVantage.exe"
    )

    foreach ($process in $processnames) {
        write-output "Stopping Process $process"
        Get-Process -Name $process | Stop-Process -Force
        write-output "Process $process Stopped"
    }

    $UninstallPrograms = @(
        "E046963F.AIMeetingManager"
        "E0469640.SmartAppearance"
        "MirametrixInc.GlancebyMirametrix"
        "E046963F.LenovoCompanion"
        "E0469640.LenovoUtility"
        "E0469640.LenovoSmartCommunication"
        "E046963F.LenovoSettingsforEnterprise"
        "E046963F.cameraSettings"
        "4505Fortemedia.FMAPOControl2_2.1.37.0_x64__4pejv7q2gmsnr"
        "ElevocTechnologyCo.Ltd.SmartMicrophoneSettings_1.1.49.0_x64__ttaqwwhyt5s6t"
        "Lenovo User Guide"
    )


    $UninstallPrograms = $UninstallPrograms | Where-Object { $appstoignore -notcontains $_ }



    $InstalledPrograms = $allstring | Where-Object { (($_.Name -in $UninstallPrograms)) }


    foreach ($app in $UninstallPrograms) {

        if (Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $app -ErrorAction SilentlyContinue) {
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $app | Remove-AppxProvisionedPackage -Online
            write-output "Removed provisioned package for $app."
        }
        else {
            write-output "Provisioned package for $app not found."
        }

        if (Get-AppxPackage -Name $app -ErrorAction SilentlyContinue) {
            Get-AppxPackage -allusers -Name $app | Remove-AppxPackage -AllUsers
            write-output "Removed $app."
        }
        else {
            write-output "$app not found."
        }

        UninstallAppFull -appName $app


    }


    ##Belt and braces, remove via CIM too
    foreach ($program in $UninstallPrograms) {
        Get-CimInstance -Classname Win32_Product | Where-Object Name -Match $program | Invoke-CimMethod -MethodName UnInstall
    }

    # Get Lenovo Vantage service uninstall string to uninstall service
    $lvs = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object DisplayName -eq "Lenovo Vantage Service"
    if (!([string]::IsNullOrEmpty($lvs.QuietUninstallString))) {
        $uninstall = "cmd /c " + $lvs.QuietUninstallString
        write-output $uninstall
        Invoke-Expression $uninstall
    }

    # Uninstall Lenovo Smart
    UninstallApp -appName "Lenovo Smart"

    # Uninstall Ai Meeting Manager Service
    UninstallApp -appName "Ai Meeting Manager"

    # Uninstall ImController service
    ##Check if exists
    $path = "c:\windows\system32\ImController.InfInstaller.exe"
    if (Test-Path $path) {
        write-output "ImController.InfInstaller.exe exists"
        $uninstall = "cmd /c " + $path + " -uninstall"
        write-output $uninstall
        Invoke-Expression $uninstall
    }
    else {
        write-output "ImController.InfInstaller.exe does not exist"
    }
    ##Invoke-Expression -Command 'cmd.exe /c "c:\windows\system32\ImController.InfInstaller.exe" -uninstall'

    # Remove vantage associated registry keys
    Remove-Item 'HKLM:\SOFTWARE\Policies\Lenovo\E046963F.LenovoCompanion_k1h2ywk1493x8' -Recurse -ErrorAction SilentlyContinue
    Remove-Item 'HKLM:\SOFTWARE\Policies\Lenovo\ImController' -Recurse -ErrorAction SilentlyContinue
    Remove-Item 'HKLM:\SOFTWARE\Policies\Lenovo\Lenovo Vantage' -Recurse -ErrorAction SilentlyContinue
    #Remove-Item 'HKLM:\SOFTWARE\Policies\Lenovo\Commercial Vantage' -Recurse -ErrorAction SilentlyContinue

    # Uninstall AI Meeting Manager Service
    $path = 'C:\Program Files\Lenovo\Ai Meeting Manager Service\unins000.exe'
    $params = "/SILENT"
    if (test-path -Path $path) {
        Start-Process -FilePath $path -ArgumentList $params -Wait
    }
    # Uninstall Lenovo Vantage
    $pathname = (Get-ChildItem -Path "C:\Program Files (x86)\Lenovo\VantageService").name
    $path = "C:\Program Files (x86)\Lenovo\VantageService\$pathname\Uninstall.exe"
    $params = '/SILENT'
    if (test-path -Path $path) {
        Start-Process -FilePath $path -ArgumentList $params -Wait
    }

    ##Uninstall Smart Appearance
    $path = 'C:\Program Files\Lenovo\Lenovo Smart Appearance Components\unins000.exe'
    $params = '/SILENT'
    if (test-path -Path $path) {
        try {
            Start-Process -FilePath $path -ArgumentList $params -Wait
        }
        catch {
            Write-Warning "Failed to start the process"
        }
    }
    $lenovowelcome = "c:\program files (x86)\lenovo\lenovowelcome\x86"
    if (Test-Path $lenovowelcome) {
        # Remove Lenovo Now
        Set-Location "c:\program files (x86)\lenovo\lenovowelcome\x86"

        # Update $PSScriptRoot with the new working directory
        $PSScriptRoot = (Get-Item -Path ".\").FullName
        try {
            invoke-expression -command .\uninstall.ps1 -ErrorAction SilentlyContinue
        }
        catch {
            write-output "Failed to execute uninstall.ps1"
        }

        write-output "All applications and associated Lenovo components have been uninstalled." -ForegroundColor Green
    }

    $lenovonow = "c:\program files (x86)\lenovo\LenovoNow\x86"
    if (Test-Path $lenovonow) {
        # Remove Lenovo Now
        Set-Location "c:\program files (x86)\lenovo\LenovoNow\x86"

        # Update $PSScriptRoot with the new working directory
        $PSScriptRoot = (Get-Item -Path ".\").FullName
        try {
            invoke-expression -command .\uninstall.ps1 -ErrorAction SilentlyContinue
        }
        catch {
            write-output "Failed to execute uninstall.ps1"
        }

        write-output "All applications and associated Lenovo components have been uninstalled." -ForegroundColor Green
    }


    $filename = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\User Guide.lnk"

    if (Test-Path $filename) {
        Remove-Item -Path $filename -Force
    }

    ##Camera fix for Lenovo E14
    $model = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Model
    if ($model -eq "21E30001MY") {
        $keypath = "HKLM:\SOFTWARE\\Microsoft\Windows Media Foundation\Platform"
        $keyname = "EnableFrameServerMode"
        $value = 0
        if (!(Test-Path $keypath)) {
            New-Item -Path $keypath -Force
        }
        Set-ItemProperty -Path $keypath -Name $keyname -Value $value -Type DWord -Force

        $keypath2 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Media Foundation\Platform"
        if (!(Test-Path $keypath2)) {
            New-Item -Path $keypath2 -Force
        }
        Set-ItemProperty -Path $keypath2 -Name $keyname -Value $value -Type DWord -Force
    }


        ##Remove Lenovo theme and background image
        $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes"

        # Check and remove ThemeName if it exists
        if (Get-ItemProperty -Path $registryPath -Name "ThemeName" -ErrorAction SilentlyContinue) {
            Remove-ItemProperty -Path $registryPath -Name "ThemeName"
        }
    
        # Check and remove DesktopBackground if it exists
        if (Get-ItemProperty -Path $registryPath -Name "DesktopBackground" -ErrorAction SilentlyContinue) {
            Remove-ItemProperty -Path $registryPath -Name "DesktopBackground"
        }

}


##Remove bookmarks

##Enumerate all users
$users = Get-ChildItem -Path "C:\Users" -Directory
foreach ($user in $users) {
    $userpath = $user.FullName
    $bookmarks = "C:\Users\$userpath\AppData\Local\Microsoft\Edge\User Data\Default\Bookmarks"
    ##Remove any files if they exist
    foreach ($bookmark in $bookmarks) {
        if (Test-Path -Path $bookmark) {
            Remove-Item -Path $bookmark -Force
        }
    }
}


############################################################################################################
#                                        Remove Any other installed crap                                   #
#                                                                                                          #
############################################################################################################

#McAfee

write-output "Detecting McAfee"
$mcafeeinstalled = "false"
$InstalledSoftware = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
foreach ($obj in $InstalledSoftware) {
    $name = $obj.GetValue('DisplayName')
    if ($name -like "*McAfee*") {
        $mcafeeinstalled = "true"
    }
}

$InstalledSoftware32 = Get-ChildItem "HKLM:\Software\WOW6432NODE\Microsoft\Windows\CurrentVersion\Uninstall"
foreach ($obj32 in $InstalledSoftware32) {
    $name32 = $obj32.GetValue('DisplayName')
    if ($name32 -like "*McAfee*") {
        $mcafeeinstalled = "true"
    }
}

if ($mcafeeinstalled -eq "true") {
    write-output "McAfee detected"
    #Remove McAfee bloat
    ##McAfee
    ### Download McAfee Consumer Product Removal Tool ###
    write-output "Downloading McAfee Removal Tool"
    # Download Source
    $URL = 'https://github.com/andrew-s-taylor/public/raw/main/De-Bloat/mcafeeclean.zip'

    # Set Save Directory
    $destination = 'C:\ProgramData\Debloat\mcafee.zip'

    #Download the file
    Invoke-WebRequest -Uri $URL -OutFile $destination -Method Get

    Expand-Archive $destination -DestinationPath "C:\ProgramData\Debloat" -Force

    write-output "Removing McAfee"
    # Automate Removal and kill services
    start-process "C:\ProgramData\Debloat\Mccleanup.exe" -ArgumentList "-p StopServices,MFSY,PEF,MXD,CSP,Sustainability,MOCP,MFP,APPSTATS,Auth,EMproxy,FWdiver,HW,MAS,MAT,MBK,MCPR,McProxy,McSvcHost,VUL,MHN,MNA,MOBK,MPFP,MPFPCU,MPS,SHRED,MPSCU,MQC,MQCCU,MSAD,MSHR,MSK,MSKCU,MWL,NMC,RedirSvc,VS,REMEDIATION,MSC,YAP,TRUEKEY,LAM,PCB,Symlink,SafeConnect,MGS,WMIRemover,RESIDUE -v -s"
    write-output "McAfee Removal Tool has been run"

    ###New MCCleanup
    ### Download McAfee Consumer Product Removal Tool ###
    write-output "Downloading McAfee Removal Tool"
    # Download Source
    $URL = 'https://github.com/andrew-s-taylor/public/raw/main/De-Bloat/mccleanup.zip'

    # Set Save Directory
    $destination = 'C:\ProgramData\Debloat\mcafeenew.zip'

    #Download the file
    Invoke-WebRequest -Uri $URL -OutFile $destination -Method Get

    New-Item -Path "C:\ProgramData\Debloat\mcnew" -ItemType Directory
    Expand-Archive $destination -DestinationPath "C:\ProgramData\Debloat\mcnew" -Force

    write-output "Removing McAfee"
    # Automate Removal and kill services
    start-process "C:\ProgramData\Debloat\mcnew\Mccleanup.exe" -ArgumentList "-p StopServices,MFSY,PEF,MXD,CSP,Sustainability,MOCP,MFP,APPSTATS,Auth,EMproxy,FWdiver,HW,MAS,MAT,MBK,MCPR,McProxy,McSvcHost,VUL,MHN,MNA,MOBK,MPFP,MPFPCU,MPS,SHRED,MPSCU,MQC,MQCCU,MSAD,MSHR,MSK,MSKCU,MWL,NMC,RedirSvc,VS,REMEDIATION,MSC,YAP,TRUEKEY,LAM,PCB,Symlink,SafeConnect,MGS,WMIRemover,RESIDUE -v -s"
    write-output "McAfee Removal Tool has been run"

    $InstalledPrograms = $allstring | Where-Object { ($_.Name -like "*McAfee*") }
    $InstalledPrograms | ForEach-Object {

        write-output "Attempting to uninstall: [$($_.Name)]..."
        $uninstallcommand = $_.String

        Try {
            if ($uninstallcommand -match "^msiexec*") {
                #Remove msiexec as we need to split for the uninstall
                $uninstallcommand = $uninstallcommand -replace "msiexec.exe", ""
                $uninstallcommand = $uninstallcommand + " /quiet /norestart"
                $uninstallcommand = $uninstallcommand -replace "/I", "/X "
                #Uninstall with string2 params
                Start-Process 'msiexec.exe' -ArgumentList $uninstallcommand -NoNewWindow -Wait
            }
            else {
                #Exe installer, run straight path
                $string2 = $uninstallcommand
                start-process $string2
            }
            #$A = Start-Process -FilePath $uninstallcommand -Wait -passthru -NoNewWindow;$a.ExitCode
            #$Null = $_ | Uninstall-Package -AllVersions -Force -ErrorAction Stop
            write-output "Successfully uninstalled: [$($_.Name)]"
        }
        Catch { Write-Warning -Message "Failed to uninstall: [$($_.Name)]" }
    }

    ##Remove Safeconnect
    $safeconnects = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object { $_.DisplayName -match "McAfee Safe Connect" } | Select-Object -Property UninstallString

    ForEach ($sc in $safeconnects) {
        If ($sc.UninstallString) {
            cmd.exe /c $sc.UninstallString /quiet /norestart
        }
    }

    ##
    ##remove some extra leftover Mcafee items from StartMenu-AllApps and uninstall registry keys
    ##
    if (Test-Path -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\McAfee") {
        Remove-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\McAfee" -Recurse -Force
    }
    if (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\McAfee.WPS") {
        Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\McAfee.WPS" -Recurse -Force
    }
    #Interesting emough, this producese an error, but still deletes the package anyway
    get-appxprovisionedpackage -online | sort-object displayname | format-table displayname, packagename
    get-appxpackage -allusers | sort-object name | format-table name, packagefullname
    Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "McAfeeWPSSparsePackage" | Remove-AppxProvisionedPackage -Online -AllUsers
}


##Look for anything else

##Make sure Intune hasn't installed anything so we don't remove installed apps

$intunepath = "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps"
$intunecomplete = @(Get-ChildItem $intunepath).count
$userpath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
$userprofiles = Get-ChildItem $userpath | Get-ItemProperty

$nonAdminLoggedOn = $false
foreach ($user in $userprofiles) {
    # Exclude default, system, and network service profiles, and the Administrator profile
    if ($user.PSChildName -notin '.DEFAULT', 'S-1-5-18', 'S-1-5-19', 'S-1-5-20' -and $user.PSChildName -notmatch 'S-1-5-21-\d+-\d+-\d+-500') {
        $nonAdminLoggedOn = $true
        break
    }
}
$TypeDef = @"
 
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
 
namespace Api
{
 public class Kernel32
 {
   [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
   public static extern int OOBEComplete(ref int bIsOOBEComplete);
 }
}
"@
 
Add-Type -TypeDefinition $TypeDef -Language CSharp
 
$IsOOBEComplete = $false
$hr = [Api.Kernel32]::OOBEComplete([ref] $IsOOBEComplete)
 

if ($IsOOBEComplete -eq 0) {

    write-output "Still in OOBE, continue"
    ##Apps to remove - NOTE: Chrome has an unusual uninstall so sort on it's own
    $blacklistapps = @(

    )


    foreach ($blacklist in $blacklistapps) {

        UninstallAppFull -appName $blacklist

    }


    ##Remove Chrome
    $chrome32path = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome"

    if ($null -ne $chrome32path) {

        $versions = (Get-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome').version
        ForEach ($version in $versions) {
            write-output "Found Chrome version $version"
            $directory = ${env:ProgramFiles(x86)}
            write-output "Removing Chrome"
            Start-Process "$directory\Google\Chrome\Application\$version\Installer\setup.exe" -argumentlist  "--uninstall --multi-install --chrome --system-level --force-uninstall"
        }

    }

    $chromepath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome"

    if ($null -ne $chromepath) {

        $versions = (Get-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome').version
        ForEach ($version in $versions) {
            write-output "Found Chrome version $version"
            $directory = ${env:ProgramFiles}
            write-output "Removing Chrome"
            Start-Process "$directory\Google\Chrome\Application\$version\Installer\setup.exe" -argumentlist  "--uninstall --multi-install --chrome --system-level --force-uninstall"
        }


    }

    ##Remove home versions of Office
    $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $AllLanguages = $OSInfo.MUILanguages


    $ClickToRunPath = "C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeClickToRun.exe"
    foreach ($Language in $AllLanguages) {
        Start-Process $ClickToRunPath -ArgumentList "scenario=install scenariosubtype=ARP sourcetype=None productstoremove=O365HomePremRetail.16_$($Language)_x-none culture=$($Language) version.16=16.0 DisplayLevel=False" -Wait
        Start-Sleep -Seconds 5
    }

    $ClickToRunPath = "C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeClickToRun.exe"
    foreach ($Language in $AllLanguages) {
        Start-Process $ClickToRunPath -ArgumentList "scenario=install scenariosubtype=ARP sourcetype=None productstoremove=OneNoteFreeRetail.16_$($Language)_x-none culture=$($Language) version.16=16.0 DisplayLevel=False" -Wait
        Start-Sleep -Seconds 5
    }

}
else {
    write-output "Intune detected, skipping removal of apps"
    write-output "$intunecomplete number of apps detected"

}

write-output "Completed"

Stop-Transcript

# SIG # Begin signature block
# MIIoGQYJKoZIhvcNAQcCoIIoCjCCKAYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAYtZNJhLjnK1qi
# rj0/5/tx4xzFpK/ltpo9y29gptg9faCCIRwwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggauMIIElqADAgECAhAHNje3JFR82Ees/ShmKl5bMA0GCSqG
# SIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDAeFw0yMjAzMjMwMDAwMDBaFw0zNzAzMjIyMzU5NTlaMGMx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMy
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcg
# Q0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDGhjUGSbPBPXJJUVXH
# JQPE8pE3qZdRodbSg9GeTKJtoLDMg/la9hGhRBVCX6SI82j6ffOciQt/nR+eDzMf
# UBMLJnOWbfhXqAJ9/UO0hNoR8XOxs+4rgISKIhjf69o9xBd/qxkrPkLcZ47qUT3w
# 1lbU5ygt69OxtXXnHwZljZQp09nsad/ZkIdGAHvbREGJ3HxqV3rwN3mfXazL6IRk
# tFLydkf3YYMZ3V+0VAshaG43IbtArF+y3kp9zvU5EmfvDqVjbOSmxR3NNg1c1eYb
# qMFkdECnwHLFuk4fsbVYTXn+149zk6wsOeKlSNbwsDETqVcplicu9Yemj052FVUm
# cJgmf6AaRyBD40NjgHt1biclkJg6OBGz9vae5jtb7IHeIhTZgirHkr+g3uM+onP6
# 5x9abJTyUpURK1h0QCirc0PO30qhHGs4xSnzyqqWc0Jon7ZGs506o9UD4L/wojzK
# QtwYSH8UNM/STKvvmz3+DrhkKvp1KCRB7UK/BZxmSVJQ9FHzNklNiyDSLFc1eSuo
# 80VgvCONWPfcYd6T/jnA+bIwpUzX6ZhKWD7TA4j+s4/TXkt2ElGTyYwMO1uKIqjB
# Jgj5FBASA31fI7tk42PgpuE+9sJ0sj8eCXbsq11GdeJgo1gJASgADoRU7s7pXche
# MBK9Rp6103a50g5rmQzSM7TNsQIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB
# /wIBADAdBgNVHQ4EFgQUuhbZbU2FL3MpdpovdYxqII+eyG8wHwYDVR0jBBgwFoAU
# 7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoG
# CCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29j
# c3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDig
# NqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZI
# hvcNAQELBQADggIBAH1ZjsCTtm+YqUQiAX5m1tghQuGwGC4QTRPPMFPOvxj7x1Bd
# 4ksp+3CKDaopafxpwc8dB+k+YMjYC+VcW9dth/qEICU0MWfNthKWb8RQTGIdDAiC
# qBa9qVbPFXONASIlzpVpP0d3+3J0FNf/q0+KLHqrhc1DX+1gtqpPkWaeLJ7giqzl
# /Yy8ZCaHbJK9nXzQcAp876i8dU+6WvepELJd6f8oVInw1YpxdmXazPByoyP6wCeC
# RK6ZJxurJB4mwbfeKuv2nrF5mYGjVoarCkXJ38SNoOeY+/umnXKvxMfBwWpx2cYT
# gAnEtp/Nh4cku0+jSbl3ZpHxcpzpSwJSpzd+k1OsOx0ISQ+UzTl63f8lY5knLD0/
# a6fxZsNBzU+2QJshIUDQtxMkzdwdeDrknq3lNHGS1yZr5Dhzq6YBT70/O3itTK37
# xJV77QpfMzmHQXh6OOmc4d0j/R0o08f56PGYX/sr2H7yRp11LB4nLCbbbxV7HhmL
# NriT1ObyF5lZynDwN7+YAN8gFk8n+2BnFqFmut1VwDophrCYoCvtlUG3OtUVmDG0
# YgkPCr2B2RP+v6TR81fZvAT6gt4y3wSJ8ADNXcL50CN/AAvkdgIm2fBldkKmKYcJ
# RyvmfxqkhQ/8mJb2VVQrH4D6wPIOK+XW+6kvRBVK5xMOHds3OBqhK/bt1nz8MIIG
# sDCCBJigAwIBAgIQCK1AsmDSnEyfXs2pvZOu2TANBgkqhkiG9w0BAQwFADBiMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQw
# HhcNMjEwNDI5MDAwMDAwWhcNMzYwNDI4MjM1OTU5WjBpMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0
# ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExMIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1bQvQtAorXi3XdU5WRuxiEL1M4zr
# PYGXcMW7xIUmMJ+kjmjYXPXrNCQH4UtP03hD9BfXHtr50tVnGlJPDqFX/IiZwZHM
# gQM+TXAkZLON4gh9NH1MgFcSa0OamfLFOx/y78tHWhOmTLMBICXzENOLsvsI8Irg
# nQnAZaf6mIBJNYc9URnokCF4RS6hnyzhGMIazMXuk0lwQjKP+8bqHPNlaJGiTUyC
# EUhSaN4QvRRXXegYE2XFf7JPhSxIpFaENdb5LpyqABXRN/4aBpTCfMjqGzLmysL0
# p6MDDnSlrzm2q2AS4+jWufcx4dyt5Big2MEjR0ezoQ9uo6ttmAaDG7dqZy3SvUQa
# khCBj7A7CdfHmzJawv9qYFSLScGT7eG0XOBv6yb5jNWy+TgQ5urOkfW+0/tvk2E0
# XLyTRSiDNipmKF+wc86LJiUGsoPUXPYVGUztYuBeM/Lo6OwKp7ADK5GyNnm+960I
# HnWmZcy740hQ83eRGv7bUKJGyGFYmPV8AhY8gyitOYbs1LcNU9D4R+Z1MI3sMJN2
# FKZbS110YU0/EpF23r9Yy3IQKUHw1cVtJnZoEUETWJrcJisB9IlNWdt4z4FKPkBH
# X8mBUHOFECMhWWCKZFTBzCEa6DgZfGYczXg4RTCZT/9jT0y7qg0IU0F8WD1Hs/q2
# 7IwyCQLMbDwMVhECAwEAAaOCAVkwggFVMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYD
# VR0OBBYEFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB8GA1UdIwQYMBaAFOzX44LScV1k
# TN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcD
# AzB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2lj
# ZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0
# cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmww
# HAYDVR0gBBUwEzAHBgVngQwBAzAIBgZngQwBBAEwDQYJKoZIhvcNAQEMBQADggIB
# ADojRD2NCHbuj7w6mdNW4AIapfhINPMstuZ0ZveUcrEAyq9sMCcTEp6QRJ9L/Z6j
# fCbVN7w6XUhtldU/SfQnuxaBRVD9nL22heB2fjdxyyL3WqqQz/WTauPrINHVUHmI
# moqKwba9oUgYftzYgBoRGRjNYZmBVvbJ43bnxOQbX0P4PpT/djk9ntSZz0rdKOtf
# JqGVWEjVGv7XJz/9kNF2ht0csGBc8w2o7uCJob054ThO2m67Np375SFTWsPK6Wrx
# oj7bQ7gzyE84FJKZ9d3OVG3ZXQIUH0AzfAPilbLCIXVzUstG2MQ0HKKlS43Nb3Y3
# LIU/Gs4m6Ri+kAewQ3+ViCCCcPDMyu/9KTVcH4k4Vfc3iosJocsL6TEa/y4ZXDlx
# 4b6cpwoG1iZnt5LmTl/eeqxJzy6kdJKt2zyknIYf48FWGysj/4+16oh7cGvmoLr9
# Oj9FpsToFpFSi0HASIRLlk2rREDjjfAVKM7t8RhWByovEMQMCGQ8M4+uKIw8y4+I
# Cw2/O/TOHnuO77Xry7fwdxPm5yg/rBKupS8ibEH5glwVZsxsDsrFhsP2JjMMB0ug
# 0wcCampAMEhLNKhRILutG4UI4lkNbcoFUCvqShyepf2gpx8GdOfy1lKQ/a+FSCH5
# Vzu0nAPthkX0tGFuv2jiJmCG6sivqf6UHedjGzqGVnhOMIIGwjCCBKqgAwIBAgIQ
# BUSv85SdCDmmv9s/X+VhFjANBgkqhkiG9w0BAQsFADBjMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0
# ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMB4XDTIzMDcxNDAw
# MDAwMFoXDTM0MTAxMzIzNTk1OVowSDELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMSAwHgYDVQQDExdEaWdpQ2VydCBUaW1lc3RhbXAgMjAyMzCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKNTRYcdg45brD5UsyPgz5/X
# 5dLnXaEOCdwvSKOXejsqnGfcYhVYwamTEafNqrJq3RApih5iY2nTWJw1cb86l+uU
# UI8cIOrHmjsvlmbjaedp/lvD1isgHMGXlLSlUIHyz8sHpjBoyoNC2vx/CSSUpIIa
# 2mq62DvKXd4ZGIX7ReoNYWyd/nFexAaaPPDFLnkPG2ZS48jWPl/aQ9OE9dDH9kgt
# XkV1lnX+3RChG4PBuOZSlbVH13gpOWvgeFmX40QrStWVzu8IF+qCZE3/I+PKhu60
# pCFkcOvV5aDaY7Mu6QXuqvYk9R28mxyyt1/f8O52fTGZZUdVnUokL6wrl76f5P17
# cz4y7lI0+9S769SgLDSb495uZBkHNwGRDxy1Uc2qTGaDiGhiu7xBG3gZbeTZD+BY
# QfvYsSzhUa+0rRUGFOpiCBPTaR58ZE2dD9/O0V6MqqtQFcmzyrzXxDtoRKOlO0L9
# c33u3Qr/eTQQfqZcClhMAD6FaXXHg2TWdc2PEnZWpST618RrIbroHzSYLzrqawGw
# 9/sqhux7UjipmAmhcbJsca8+uG+W1eEQE/5hRwqM/vC2x9XH3mwk8L9CgsqgcT2c
# kpMEtGlwJw1Pt7U20clfCKRwo+wK8REuZODLIivK8SgTIUlRfgZm0zu++uuRONhR
# B8qUt+JQofM604qDy0B7AgMBAAGjggGLMIIBhzAOBgNVHQ8BAf8EBAMCB4AwDAYD
# VR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAgBgNVHSAEGTAXMAgG
# BmeBDAEEAjALBglghkgBhv1sBwEwHwYDVR0jBBgwFoAUuhbZbU2FL3MpdpovdYxq
# II+eyG8wHQYDVR0OBBYEFKW27xPn783QZKHVVqllMaPe1eNJMFoGA1UdHwRTMFEw
# T6BNoEuGSWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRH
# NFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcmwwgZAGCCsGAQUFBwEBBIGD
# MIGAMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wWAYIKwYB
# BQUHMAKGTGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0
# ZWRHNFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcnQwDQYJKoZIhvcNAQEL
# BQADggIBAIEa1t6gqbWYF7xwjU+KPGic2CX/yyzkzepdIpLsjCICqbjPgKjZ5+PF
# 7SaCinEvGN1Ott5s1+FgnCvt7T1IjrhrunxdvcJhN2hJd6PrkKoS1yeF844ektrC
# QDifXcigLiV4JZ0qBXqEKZi2V3mP2yZWK7Dzp703DNiYdk9WuVLCtp04qYHnbUFc
# jGnRuSvExnvPnPp44pMadqJpddNQ5EQSviANnqlE0PjlSXcIWiHFtM+YlRpUurm8
# wWkZus8W8oM3NG6wQSbd3lqXTzON1I13fXVFoaVYJmoDRd7ZULVQjK9WvUzF4UbF
# KNOt50MAcN7MmJ4ZiQPq1JE3701S88lgIcRWR+3aEUuMMsOI5ljitts++V+wQtaP
# 4xeR0arAVeOGv6wnLEHQmjNKqDbUuXKWfpd5OEhfysLcPTLfddY2Z1qJ+Panx+VP
# NTwAvb6cKmx5AdzaROY63jg7B145WPR8czFVoIARyxQMfq68/qTreWWqaNYiyjvr
# moI1VygWy2nyMpqy0tg6uLFGhmu6F/3Ed2wVbK6rr3M66ElGt9V/zLY4wNjsHPW2
# obhDLN9OTH0eaHDAdwrUAuBcYLso/zjlUlrWrBciI0707NMX+1Br/wd3H3GXREHJ
# uEbTbDJ8WC9nR2XlG3O2mflrLAZG70Ee8PBf4NvZrZCARK+AEEGKMIIHWzCCBUOg
# AwIBAgIQCLGfzbPa87AxVVgIAS8A6TANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQG
# EwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0
# IFRydXN0ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0Ex
# MB4XDTIzMTExNTAwMDAwMFoXDTI2MTExNzIzNTk1OVowYzELMAkGA1UEBhMCR0Ix
# FDASBgNVBAcTC1doaXRsZXkgQmF5MR4wHAYDVQQKExVBTkRSRVdTVEFZTE9SLkNP
# TSBMVEQxHjAcBgNVBAMTFUFORFJFV1NUQVlMT1IuQ09NIExURDCCAiIwDQYJKoZI
# hvcNAQEBBQADggIPADCCAgoCggIBAMOkYkLpzNH4Y1gUXF799uF0CrwW/Lme676+
# C9aZOJYzpq3/DIa81oWv9b4b0WwLpJVu0fOkAmxI6ocu4uf613jDMW0GfV4dRodu
# tryfuDuit4rndvJA6DIs0YG5xNlKTkY8AIvBP3IwEzUD1f57J5GiAprHGeoc4Utt
# zEuGA3ySqlsGEg0gCehWJznUkh3yM8XbksC0LuBmnY/dZJ/8ktCwCd38gfZEO9UD
# DSkie4VTY3T7VFbTiaH0bw+AvfcQVy2CSwkwfnkfYagSFkKar+MYwu7gqVXxrh3V
# /Gjval6PdM0A7EcTqmzrCRtvkWIR6bpz+3AIH6Fr6yTuG3XiLIL6sK/iF/9d4U2P
# iH1vJ/xfdhGj0rQ3/NBRsUBC3l1w41L5q9UX1Oh1lT1OuJ6hV/uank6JY3jpm+Of
# Z7YCTF2Hkz5y6h9T7sY0LTi68Vmtxa/EgEtG6JVNVsqP7WwEkQRxu/30qtjyoX8n
# zSuF7TmsRgmZ1SB+ISclejuqTNdhcycDhi3/IISgVJNRS/F6Z+VQGf3fh6ObdQLV
# woT0JnJjbD8PzJ12OoKgViTQhndaZbkfpiVifJ1uzWJrTW5wErH+qvutHVt4/sEZ
# AVS4PNfOcJXR0s0/L5JHkjtM4aGl62fAHjHj9JsClusj47cT6jROIqQI4ejz1slO
# oclOetCNAgMBAAGjggIDMIIB/zAfBgNVHSMEGDAWgBRoN+Drtjv4XxGG+/5hewiI
# ZfROQjAdBgNVHQ4EFgQU0HdOFfPxa9Yeb5O5J9UEiJkrK98wPgYDVR0gBDcwNTAz
# BgZngQwBBAEwKTAnBggrBgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20v
# Q1BTMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzCBtQYDVR0f
# BIGtMIGqMFOgUaBPhk1odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEzODQyMDIxQ0ExLmNybDBToFGg
# T4ZNaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29k
# ZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAyMUNBMS5jcmwwgZQGCCsGAQUFBwEBBIGH
# MIGEMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXAYIKwYB
# BQUHMAKGUGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0
# ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3J0MAkGA1UdEwQC
# MAAwDQYJKoZIhvcNAQELBQADggIBAEkRh2PwMiyravr66Zww6Pjl24KzDcGYMSxU
# KOEU4bykcOKgvS6V2zeZIs0D/oqct3hBKTGESSQWSA/Jkr1EMC04qJHO/Twr/sBD
# CDBMtJ9XAtO75J+oqDccM+g8Po+jjhqYJzKvbisVUvdsPqFll55vSzRvHGAA6hjy
# DyakGLROcNaSFZGdgOK2AMhQ8EULrE8Riri3D1ROuqGmUWKqcO9aqPHBf5wUwia8
# g980sTXquO5g4TWkZqSvwt1BHMmu69MR6loRAK17HvFcSicK6Pm0zid1KS2z4ntG
# B4Cfcg88aFLog3ciP2tfMi2xTnqN1K+YmU894Pl1lCp1xFvT6prm10Bs6BViKXfD
# fVFxXTB0mHoDNqGi/B8+rxf2z7u5foXPCzBYT+Q3cxtopvZtk29MpTY88GHDVJsF
# MBjX7zM6aCNKsTKC2jb92F+jlkc8clCQQnl3U4jqwbj4ur1JBP5QxQprWhwde0+M
# ifDVp0vHZsVZ0pnYMCKSG5bUr3wOU7EP321DwvvEsTjCy/XDgvy8ipU6w3GjcQQF
# mgp/BX/0JCHX+04QJ0JkR9TTFZR1B+zh3CcK1ZEtTtvuZfjQ3viXwlwtNLy43vbe
# 1J5WNTs0HjJXsfdbhY5kE5RhyfaxFBr21KYx+b+evYyolIS0wR6New6FqLgcc4Ge
# 94yaYVTqMYIGUzCCBk8CAQEwfTBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGln
# aUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgQ29kZSBT
# aWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExAhAIsZ/Ns9rzsDFVWAgBLwDp
# MA0GCWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJ
# KoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQB
# gjcCARUwLwYJKoZIhvcNAQkEMSIEILVQMBUGgHGxY17m/eRgDLEr+Eh4jNSbJlkc
# 0plEc2lcMA0GCSqGSIb3DQEBAQUABIICALy/bZ7jo4aSwaEHOhy/6gBw8pGs4NxL
# nclDsPYLbOw0sDt5aUAn4UKu06WNpKGRvoxobAEhpkAjZ6fW9TZGIWkRhAl1+vPm
# 8BLk6D8jCwb+V+XC0pa2WDF0XMVtS1lB0xVwCjut+yi5TuotVREHJdDNlmfz5bvt
# ThmQNsKtsBvN8GtKpWSQGckySCXwEPd75sW7vU3Lwy5P+hzuAORi41O5CYfXy4i4
# VsL6YK3mFS+1NgA0qfVsit+UWVzLTS2uPjpZFW1IQtU0M2HsEMbY2yW0+1elyOfa
# n2UrOPqyQC9H997EC1hBkEvIkmenq7uwgzahIN87H4UDP1CmiHe2sXi4w+lPex2C
# sSqFe7EkEsvLukZgXMyRE8KcAUNMRWn99hsjvKL6OS+NG0Hms8hbG5Vo60D5yR+9
# rTDBJQAqUfT2r8j51mbLuY4CGboB8g/tNjnxEOKYt+uDjFRpm2AuUShhWrc/0FTG
# E/SQOP8br9AFHmHulGVSbI3f3B4rwK3FSTONIuzmSmwvllypVoLkllI49+GiEo9d
# skts5BgBJMtrWVeHCax/dVYTUik34gk2RfRMgfref4VA52DI73Me/iopFBoNQJBd
# qcVAxtrOnC5syh4m5TNRx/n5IwSrZt9dJq/uSjYSZMa6eI6AgDb5hVyC3v7exvZW
# ZfSumyfXfPFIoYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkG
# A1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdp
# Q2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQ
# BUSv85SdCDmmv9s/X+VhFjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzEL
# BgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI0MDkwNDA5MzMwMVowLwYJKoZI
# hvcNAQkEMSIEIOQyA47kj/EzXnJiNwPlOnL+9jsVaqCWeYZq/4KsN0A3MA0GCSqG
# SIb3DQEBAQUABIICABeHK5HVS+LNJT46PNwD/WO0ygSfb81TkB/9NbIwysstyDCQ
# 6GDD8qgmp4cl91aM68wN9SqGMYnOL/sLiK5Ptr4WCeIlfBGHa0n3PtA4EKh2XwyM
# 1lwf9bg3rQ8HcP2pwJ1AvFY3+iclP4l3jxct612VhQLUK9S9q8G166w+D1aJypVT
# 0kwdNoxK4+mR4rZWEfqzlfII0wKyCVh7EY9bMsm/c6eYntQCh/Nduvv+50pD5YhT
# +6PSlBjnX0pLWk8/uEbCNLTF6JY5X1gZF40hvrACRcMsu496/WwSu3EUC3+K5T8a
# aC5j+gkQ6uCHVpXAx4vOel00+Lr7J9Dc+ByCBLFpR7ia42uSIPweTna74dIG9Iac
# fVXpKXcg9tOHsZ1Qgkp5LYYgZkMD7nU2DlhZY4weMkU0XNLLAABVOSWJt91v8lNU
# f7Ht0B71BTbkwXPg9nc71D3vMT+fdt8wA6xRYC0BUfhC3O2ccR1aEwRNM7h4OiuV
# Deya7uuzXHoC8sFFWmzK94hL7aQkrae+gNpaItqqdSqnDaV+3MFrfk9lo0ayaEqq
# utwTT+quB9muV49H55WeiLdBfZcuLuvwND7YEJ0/YdPwQ5tcoWAQoS1xLgi2T2U0
# 0/fnveWj1hRjNLdic7trxwqGIXB3wymNgpel8w4nC1SbNK6TMfUHkv0/WVVy
# SIG # End signature block
