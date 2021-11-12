<#PSScriptInfo
.VERSION 1.1
.AUTHOR AndrewTaylor
.DESCRIPTION Creates an Intune application from a Winget Manifest
.COMPANYNAME 
.COPYRIGHT GPL
.TAGS intune aad
.LICENSEURI https://github.com/andrew-s-taylor/public/blob/main/LICENSE
.PROJECTURI https://github.com/andrew-s-taylor/public
.ICONURI 
.EXTERNALMODULEDEPENDENCIES powershell-yaml AzureADPreview IntuneWin32App
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
#>
<#
.SYNOPSIS
  Creates an Intune application from a Winget Manifest
.DESCRIPTION
Complete end-end creation of application in Intune.
Creates AzureAD group for Install and Uninstall
Extracts information from Winget custom manifest

.INPUTS
Winget YAML URL
.OUTPUTS
None
.NOTES
  Version:        1.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  12/11/2021
  Purpose/Change: Initial script development
  
.EXAMPLE
N/A
#>

####################################################


[CmdletBinding()]
param (
    [Parameter()]
    [String]
    $yamlFile
)


###############################################################################################################
######                                         Install Modules                                           ######
###############################################################################################################
Write-Host "Installing Intune modules if required (current user scope)"

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name powershell-yaml) {
    Write-Host "PowerShell YAML Already Installed"
} 
else {
    try {
        Install-Module -Name powershell-yaml -Scope CurrentUser -Repository PSGallery -Force 
    }
    catch [Exception] {
        $_.message 
        exit
    }
}

#Install AZ Module if not available
if (Get-Module -ListAvailable -Name AzureADPreview) {
    Write-Host "AZ Ad Preview Module Already Installed"
} 
else {
    try {
        Install-Module -Name AzureADPreview -Scope CurrentUser -Repository PSGallery -Force -AllowClobber 
    }
    catch [Exception] {
        $_.message 
        exit
    }
}

#Install IntuneWin32App  if not available
if (Get-Module -ListAvailable -Name IntuneWin32App ) {
    Write-Host "IntuneWin32App Module Already Installed"
} 
else {
    try {
        Install-Module -Name IntuneWin32App  -Scope CurrentUser -Repository PSGallery -Force -AllowClobber -AcceptLicense
    }
    catch [Exception] {
        $_.message 
        exit
    }
}



#Importing Modules
Import-Module powershell-yaml
import-module IntuneWin32App 
#Group creation needs preview module so we need to remove non-preview first
# Unload the AzureAD module (or continue if it's already unloaded)
Remove-Module AzureAD -ErrorAction SilentlyContinue
# Load the AzureADPreview module
Import-Module AzureADPreview

#Get Creds and connect
write-host "Connect to Azure"
Connect-AzureAD

#Get Tenant ID
$tenantId = (Get-AzureADTenantDetail | Select-Object -ExpandProperty ObjectID)
Connect-MSIntuneGraph -TenantID $tenantId

##Set Download Directory

$directory = $env:TEMP
#Create Temp location
$random = Get-Random -Maximum 1000 
$random = $random.ToString()
$date =get-date -format yyMMddmmss
$date = $date.ToString()
$path2 = $random + "-"  + $date
$path = $directory + "\" + $path2 + "\"
new-item -ItemType Directory -Path $path

$filename = $yamlFile.Substring($yamlFile.LastIndexOf("/") + 1)

##File Name
$templateFilePath = $path + $filename

###############################################################################################################
######                                          Download YAML                                            ######
###############################################################################################################

Invoke-WebRequest `
   -Uri $yamlFile `
   -OutFile $templateFilePath `
   -UseBasicParsing `
   -Headers @{"Cache-Control"="no-cache"}

[string[]]$fileContent = Get-Content $templateFilePath
$content = ''
foreach ($line in $fileContent) { $content = $content + "`n" + $line }
$obj = ConvertFrom-Yaml $content
$tags = $obj.Tags
foreach ($tag in $tags) {
    if ($tag -like '*ICON*') {
        $icon = $tag
    }
    if ($tag -like '*DETECTION*') {
        $detection = $tag
    }
    if ($tag -like 'UNINSTALLCOMMAND*') {
        $uninstall = $tag
    }
    if ($tag -like '*ADGROUPI*') {
        $adgroupi = $tag
    }
    if ($tag -like '*ADGROUPU*') {
        $adgroupu = $tag
    }
}

$icon2 = $icon -split '='
$iconpath = $icon2[1]
$iconname = $iconpath.Substring($iconpath.LastIndexOf("/") + 1)
$icondownload = $path + $iconname


##Download Icon
Invoke-WebRequest `
   -Uri $iconpath `
   -OutFile $icondownload `
   -UseBasicParsing `
   -Headers @{"Cache-Control"="no-cache"}

$detection2 = $detection -split '='
$detectionrule = $detection2[1]

$uninstall2 = $uninstall -split '='
$uninstallcommand = $uninstall2[1]

$adgroupi2 = $adgroupi -split '='
$adgroupinstall = $adgroupi2[1]

$adgroupu2 = $adgroupu -split '='
$adgroupuninstall = $adgroupu2[1]

$publisher = $obj.publisher
$name = $obj.packagename
$description = $obj.shortdescription
$appversion = $obj.PackageVersion
$infourl = $obj.PackageUrl


$groupname1 = $name + "-INSTALL"
#Create Install Group
$installgroup = New-AzureADMSGroup -DisplayName $adgroupinstall -Description "Install group for $name" -MailEnabled $False -MailNickName "group" -SecurityEnabled $True

$groupname2 = $name + "-UNINSTALL"
#Create Uninstall Group
$uninstallgroup = New-AzureADMSGroup -DisplayName $adgroupuninstall -Description "Uninstall group for $name" -MailEnabled $False -MailNickName "group" -SecurityEnabled $True

$setupfile = "$path$name-Install.ps1"
$setupfilename = "$name-Install.ps1"
##Create Install File
Set-Content $setupfile @'

$URL = 
'@ -NoNewline
add-Content $setupfile @"
"$yamlFile"
"@
add-Content $setupfile @'
$directory = $env:TEMP
#Create Temp location
$random = Get-Random -Maximum 1000 
$random = $random.ToString()
$date =get-date -format yyMMddmmss
$date = $date.ToString()
$path2 = $random + "-"  + $date
$path = $directory + "\" + $path2 + "\"
new-item -ItemType Directory -Path $path
$filename = $URL.Substring($URL.LastIndexOf("/") + 1)

##File Name
$templateFilePath = $path + $filename
Invoke-WebRequest `
   -Uri $url `
   -OutFile $templateFilePath `
   -UseBasicParsing `
   -Headers @{"Cache-Control"="no-cache"}

   $Winget = Get-ChildItem -Path (Join-Path -Path (Join-Path -Path $env:ProgramFiles -ChildPath "WindowsApps") -ChildPath "Microsoft.DesktopAppInstaller*_x64*\AppInstallerCLI.exe")

   &$winget install --silent  --manifest $templateFilePath

'@

$detectionfile = "$path$name-Detection.ps1"
    ## Create Detection Powershell File
    Set-Content $detectionfile $detectionrule


    # Package as .intunewin file
    $SourceFolder = $path
    $OutputFolder = $path
    New-IntuneWin32AppPackage -SourceFolder $SourceFolder -SetupFile $setupfilename -OutputFolder $OutputFolder -Verbose

    $IntuneWinFile = Get-ChildItem -Path  $path | Where-Object Name -Like "*.intunewin"
    $IntuneWinFile.Name

    # Create custom display name like 'Name' and 'Version'
    $DisplayName = $name

    # Create PowerShell script detection rule
    $DetectionScriptFile = Get-ChildItem -Path $path | Where-Object Name -Like "*-Detection.ps1"
    $DetectionRule = New-IntuneWin32AppDetectionRuleScript -ScriptFile $DetectionScriptFile.FullName -EnforceSignatureCheck $false -RunAs32Bit $false

    # Add new EXE Win32 app
    $InstallationScriptFile = Get-ChildItem -Path $path | Where-Object Name -Like "*-Install.ps1"
    $InstallCommandLine = "powershell.exe -ExecutionPolicy Bypass -File .\$($InstallationScriptFile.Name)"
    $UninstallCommandLine = $uninstallcommand
    $ImageFile = $icondownload
    $Icon = New-IntuneWin32AppIcon -FilePath $ImageFile
    Add-IntuneWin32App -FilePath $IntuneWinFile.FullName -DisplayName $DisplayName -Description $description -Publisher $publisher -AppVersion $appversion -InformationURL $infourl -Icon $Icon -InstallExperience "system" -RestartBehavior "suppress" -DetectionRule $DetectionRule -InstallCommandLine $InstallCommandLine -UninstallCommandLine $UninstallCommandLine -Verbose


    ##Assignments
    $Win32App = Get-IntuneWin32App -DisplayName $DisplayName -Verbose

    #Install
$installid = $installgroup.Id
Add-IntuneWin32AppAssignmentGroup -Include -ID $Win32App.id -GroupID $installid -Intent "available" -Notification "showAll" -Verbose


#Uninstall
$uninstallid = $uninstallgroup.Id
Add-IntuneWin32AppAssignmentGroup -Include -ID $Win32App.id -GroupID $uninstallid -Intent "uninstall" -Notification "showAll" -Verbose
    
