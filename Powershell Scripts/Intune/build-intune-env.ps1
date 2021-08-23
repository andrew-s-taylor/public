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


<# This form was created using POSHGUI.com  a free online gui designer for PowerShell
.NAME
    Intune
#>

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

$CreateIntuneEnv                 = New-Object system.Windows.Forms.Form
$CreateIntuneEnv.ClientSize      = New-Object System.Drawing.Point(397,379)
$CreateIntuneEnv.text            = "Create Intune Environment"
$CreateIntuneEnv.TopMost         = $false
$CreateIntuneEnv.BackColor       = [System.Drawing.ColorTranslator]::FromHtml("#ffffff")

$Label1                          = New-Object system.Windows.Forms.Label
$Label1.text                     = "Created by Andrew Taylor (andrewstaylor.com)"
$Label1.AutoSize                 = $true
$Label1.width                    = 25
$Label1.height                   = 10
$Label1.location                 = New-Object System.Drawing.Point(4,348)
$Label1.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label2                          = New-Object system.Windows.Forms.Label
$Label2.text                     = "Client Name"
$Label2.AutoSize                 = $true
$Label2.width                    = 25
$Label2.height                   = 10
$Label2.location                 = New-Object System.Drawing.Point(10,22)
$Label2.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label3                          = New-Object system.Windows.Forms.Label
$Label3.text                     = "Tenant ID"
$Label3.AutoSize                 = $true
$Label3.width                    = 25
$Label3.height                   = 10
$Label3.location                 = New-Object System.Drawing.Point(10,66)
$Label3.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label4                          = New-Object system.Windows.Forms.Label
$Label4.text                     = "HomePage"
$Label4.AutoSize                 = $true
$Label4.width                    = 25
$Label4.height                   = 10
$Label4.location                 = New-Object System.Drawing.Point(10,109)
$Label4.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label5                          = New-Object system.Windows.Forms.Label
$Label5.text                     = "Background URL"
$Label5.AutoSize                 = $true
$Label5.width                    = 25
$Label5.height                   = 10
$Label5.location                 = New-Object System.Drawing.Point(10,156)
$Label5.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label6                          = New-Object system.Windows.Forms.Label
$Label6.text                     = "Background Filename"
$Label6.AutoSize                 = $true
$Label6.width                    = 25
$Label6.height                   = 40
$Label6.location                 = New-Object System.Drawing.Point(10,215)
$Label6.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$clientname                      = New-Object system.Windows.Forms.TextBox
$clientname.multiline            = $false
$clientname.width                = 200
$clientname.height               = 20
$clientname.location             = New-Object System.Drawing.Point(151,22)
$clientname.Font                 = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$tenantid                        = New-Object system.Windows.Forms.TextBox
$tenantid.multiline              = $false
$tenantid.width                  = 200
$tenantid.height                 = 20
$tenantid.location               = New-Object System.Drawing.Point(151,66)
$tenantid.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$homepage                        = New-Object system.Windows.Forms.TextBox
$homepage.multiline              = $false
$homepage.width                  = 200
$homepage.height                 = 20
$homepage.location               = New-Object System.Drawing.Point(151,109)
$homepage.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$bgurl                           = New-Object system.Windows.Forms.TextBox
$bgurl.multiline                 = $false
$bgurl.width                     = 200
$bgurl.height                    = 20
$bgurl.location                  = New-Object System.Drawing.Point(151,156)
$bgurl.Font                      = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$bgname                          = New-Object system.Windows.Forms.TextBox
$bgname.multiline                = $false
$bgname.width                    = 200
$bgname.height                   = 20
$bgname.location                 = New-Object System.Drawing.Point(151,215)
$bgname.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$build                           = New-Object system.Windows.Forms.Button
$build.text                      = "Build"
$build.width                     = 153
$build.height                    = 72
$build.location                  = New-Object System.Drawing.Point(113,257)
$build.Font                      = New-Object System.Drawing.Font('Microsoft Sans Serif',19)

$Label7                          = New-Object system.Windows.Forms.Label
$Label7.text                     = " (inc extension)"
$Label7.AutoSize                 = $true
$Label7.width                    = 25
$Label7.height                   = 10
$Label7.location                 = New-Object System.Drawing.Point(29,231)
$Label7.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$CreateIntuneEnv.controls.AddRange(@($Label1,$Label2,$Label3,$Label4,$Label5,$Label6,$clientname,$tenantid,$homepage,$bgurl,$bgname,$build,$Label7))

$build.Add_Click({ 

    $clientnameout = $clientname.Text
    $tenantidout = $tenantid.Text
    $homepageout = $homepage.Text
    $bloburl = $bgurl.Text
    $backgroundfilename = $bgname.Text

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
$devicescript = $path + "\Intune-Config-main\Device Management Scripts\Script Content\Device Config.ps1"

#Update Client Name
(Get-Content -path $devicescript -Raw ) `
-replace '<CLIENTREPLACENAME>',$clientnameout | Set-Content -Path $devicescript


#Update O365 Tenant
(Get-Content -path $devicescript -Raw ) `
-replace '<CLIENTTENANT>',$tenantidout | Set-Content -Path $devicescript


#Update Client Homepage
(Get-Content -path $devicescript -Raw ) `
-replace '<CLIENTHOMEPAGE>',$homepageout | Set-Content -Path $devicescript

#Update Background location
(Get-Content -path $devicescript -Raw ) `
-replace '<BACKGROUNDBLOBURL>',$bloburl | Set-Content -Path $devicescript


#Update Background Name
(Get-Content -path $devicescript -Raw ) `
-replace '<BACKGROUNDFILENAME>',$backgroundfilename | Set-Content -Path $devicescript


##User Script
$userscript = $path + "\Intune-Config-main\Device Management Scripts\Script Content\User-Config.ps1"
(Get-Content -path $userscript -Raw ) `
-replace '<BACKGROUNDFILENAME>',$backgroundfilename | Set-Content -Path $userscript

##Restore
##Start-IntuneRestoreConfig -Path $path


Add-Type -AssemblyName PresentationCore,PresentationFramework
$msgBody = "Environment Built"
[System.Windows.MessageBox]::Show($msgBody)



 })



#Write your logic code here

[void]$CreateIntuneEnv.ShowDialog()