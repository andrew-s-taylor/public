<#
.SYNOPSIS
  Builds an Intune Environment
.DESCRIPTION
Builds an Intune environment using intunebackupandrestore

.INPUTS
None required
.OUTPUTS
Within Azure
.NOTES
  Version:        1.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  21/08/2021
  Purpose/Change: Initial script development
  
.EXAMPLE
N/A
#>


###############################################################################################################
######                                         Install Modules                                           ######
###############################################################################################################
Write-Host "Installing Intune modules if required (current user scope)"

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph.Intune) {
    Write-Host "Microsoft Graph Already Installed"
} 
else {
    try {
        Install-Module -Name Microsoft.Graph.Intune -Scope CurrentUser -Repository PSGallery -Force 
    }
    catch [Exception] {
        $_.message 
        exit
    }
}


#Install MS Intune Backup and Restore if not available
if (Get-Module -ListAvailable -Name IntuneBackupAndRestore) {
    Write-Host "Intune Backup and Restore Already Installed"
} 
else {
    try {
        Install-Module -Name IntuneBackupAndRestore -Scope CurrentUser -Repository PSGallery -Force 
    }
    catch [Exception] {
        $_.message 
        exit
    }
}


#Importing Modules
Import-Module IntuneBackupAndRestore
Import-Module Microsoft.Graph.Intune


###############################################################################################################
######                                          Launch Form                                              ######
###############################################################################################################








###############################################################################################################
######                                          Deploy                                                   ######
###############################################################################################################


##Connect to Intune
Connect-MSGraph

#Create path for files
$DirectoryToCreate = "c:\temp"
if (-not (Test-Path -LiteralPath $DirectoryToCreate)) {
    
    try {
        New-Item -Path $DirectoryToCreate -ItemType Directory -ErrorAction Stop | Out-Null #-Force
    }
    catch {
        Write-Error -Message "Unable to create directory '$DirectoryToCreate'. Error was: $_" -ErrorAction Stop
    }
    "Successfully created directory '$DirectoryToCreate'."

}
else {
    "Directory already existed"
}


$random = Get-Random -Maximum 1000 
$random = $random.ToString()
$date =get-date -format yyMMddmmss
$date = $date.ToString()
$path2 = $random + "-"  + $date
$path = "c:\temp\" + $path2 + "\"

New-Item -ItemType Directory -Path $path


$pathvar = [PSCustomObject]@{value=$path}

Write-Host "Directory Created"

#Set Paths
    $url = "https://github.com/andrew-s-taylor/Intune-Config/archive/main.zip"
    $pathaz = "c:\temp\" + $path2 + "\Intune-Config"
    $output = "c:\temp\" + $path2 + "\main.zip"

#Download Files
Invoke-WebRequest -Uri $url -OutFile $output -Method Get

Expand-Archive $output -DestinationPath $path -Force

#Remove Zip file downloaded
remove-item $output -Force


Add-Type -AssemblyName PresentationCore,PresentationFramework
$msgBody = "Files saves to $path"
[System.Windows.MessageBox]::Show($msgBody)


##Edit details in ps scripts


##Device Script
$devicescript = $path + "\Device Management Scripts\Script Content\Device Config.ps1"

#Update Client Name
(Get-Content -path $devicescript -Raw ) `
-replace '<CLIENTREPLACENAME>',$clientname | Set-Content -Path $devicescript


#Update O365 Tenant
(Get-Content -path $devicescript -Raw ) `
-replace '<CLIENTTENANT>',$tenantid | Set-Content -Path $devicescript


#Update Client Homepage
(Get-Content -path $devicescript -Raw ) `
-replace '<CLIENTHOMEPAGE>',$homepage | Set-Content -Path $devicescript

#Update Background location
(Get-Content -path $devicescript -Raw ) `
-replace '<BACKGROUNDBLOBURL>',$bloburl | Set-Content -Path $devicescript


#Update Background Name
(Get-Content -path $devicescript -Raw ) `
-replace '<BACKGROUNDFILENAME>',$backgroundfilename | Set-Content -Path $devicescript


##User Script
$userscript = $path + "\Device Management Scripts\Script Content\User-Config.ps1"
(Get-Content -path $userscript -Raw ) `
-replace '<BACKGROUNDFILENAME>',$backgroundfilename | Set-Content -Path $userscript

##Restore
Start-IntuneRestoreConfig -Path $path


Add-Type -AssemblyName PresentationCore,PresentationFramework
$msgBody = "Environment Built"
[System.Windows.MessageBox]::Show($msgBody)
