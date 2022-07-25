<#PSScriptInfo
.VERSION 1.0.0
.GUID f2b08def-87cf-45e8-95fb-aeec4ab7a23e
.AUTHOR AndrewTaylor
.DESCRIPTION Detects changes to URL to trigger app install
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
Detects changes to URL to trigger app install
.DESCRIPTION
Detects changes to URL to trigger app install
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

$installuri = "https://github.com/andrew-s-taylor/winget/raw/main/install-apps.txt"


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

$templateFilePath = "C:\ProgramData\AppList\install-apps.txt"


##Download the list
Invoke-WebRequest `
-Uri $installuri `
-OutFile $templateFilePath `
-UseBasicParsing `
-Headers @{"Cache-Control"="no-cache"}



$oldpath = "C:\ProgramData\AppList\install-apps-old.txt"
If (Test-Path $oldpath) {
$newcontent = get-content $templateFilePath | select-object -first 1
$oldcontent = get-content $oldpath | select-object -first 1
If ($newcontent -eq $oldcontent) {
    remove-item -path $templateFilePath -force
    Write-Output "Compliant"
    exit 0
}
else {
    remove-item -path $templateFilePath -force
    Write-Warning "Not Compliant"
    Exit 1

}


}
else {
    remove-item -path $templateFilePath -force
    Write-Warning "Not Compliant"
    Exit 1
}
