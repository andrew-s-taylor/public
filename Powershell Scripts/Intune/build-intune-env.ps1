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


##Connect to Intune
Connect-MSGraph

#Create path for files
#Ask for something to keep files individual
$random = Get-Random -Maximum 1000 
$random = $random.ToString()
$date =get-date -format yyMMddmmss
$date = $date.ToString()
$path2 = $random + "-"  + $date
$path = "c:\temp\" + $path2 + "\"

New-Item -ItemType Directory -Path $path

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

##Restore
Start-IntuneRestoreConfig -Path $path


Add-Type -AssemblyName PresentationCore,PresentationFramework
$msgBody = "Environment Built"
[System.Windows.MessageBox]::Show($msgBody)