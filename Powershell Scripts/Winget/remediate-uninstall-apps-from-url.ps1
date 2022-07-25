<#PSScriptInfo
.VERSION 1.0.0
.GUID f2b08def-87cf-45e8-95fb-aeec4ab7a23e
.AUTHOR AndrewTaylor
.DESCRIPTION Removes applications via Winget from internet list
.COMPANYNAME 
.COPYRIGHT GPL
.TAGS intune endpoint MEM winget
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
Removes applications via Winget from internet list
.DESCRIPTION
Removes applications via Winget from internet list

.INPUTS
None
.OUTPUTS
None
.NOTES
  Version:        1.0.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  25/07/2022
  Purpose/Change: Initial script development

  
.EXAMPLE
N/A
#>

#####################################################################################################################################
#                            LIST URL                                                                                               #
#                                                                                                                               #
#####################################################################################################################################

$uninstalluri = "https://github.com/andrew-s-taylor/winget/raw/main/uninstall-apps.txt"


##Create a folder to store the lists
$AppList = "C:\ProgramData\AppList"
If (Test-Path $AppList) {
    Write-Output "$AppList exists. Skipping."
}
Else {
    Write-Output "The folder '$AppList' doesn't exist. This folder will be used for storing logs created after the script runs. Creating now."
    Start-Sleep 1
    New-Item -Path "$AppList" -ItemType Directory
    Write-Output "The folder $AppList was successfully created."
}

$templateFilePath = "C:\ProgramData\AppList\uninstall-apps.txt"


##Download the list
Invoke-WebRequest `
-Uri $uninstalluri `
-OutFile $templateFilePath `
-UseBasicParsing `
-Headers @{"Cache-Control"="no-cache"}


##Find Winget Path

$ResolveWingetPath = Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe"
    if ($ResolveWingetPath){
           $WingetPath = $ResolveWingetPath[-1].Path
    }

$config

##Navigate to the Winget Path
cd $wingetpath

##Loop through app list
$apps = get-content $templateFilePath | select-object -skip 1

##Uninstall each app
foreach ($app in $apps) {

write-host "Uninstalling $app"
.\winget.exe uninstall --exact --id $app --silent --accept-source-agreements
}

##Delete the .old file to replace it with the new one
$oldpath = "C:\ProgramData\AppList\uninstall-apps-old.txt"
If (Test-Path $oldpath) {
    remove-item $oldpath -Force
}

##Rename new to old
rename-item $templateFilePath $oldpath