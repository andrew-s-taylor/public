<#
.SYNOPSIS
  Builds an Azure Landing Zone
.DESCRIPTION
Builds an Azure Landing Zone using Bicep

.INPUTS
None required
.OUTPUTS
Within Azure
.NOTES
  Version:        1.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  02/06/2021
  Purpose/Change: Initial script development
  
.EXAMPLE
N/A
#>

Write-Host "Checking if Bicep is installed and installing if required"

#Install Bicep
if((Test-Path "$env:USERPROFILE\.bicep") -eq $false) {
# Create the install folder
$installPath = "$env:USERPROFILE\.bicep"
$installDir = New-Item -ItemType Directory -Path $installPath -Force
$installDir.Attributes += 'Hidden'
# Fetch the latest Bicep CLI binary
(New-Object Net.WebClient).DownloadFile("https://github.com/Azure/bicep/releases/latest/download/bicep-win-x64.exe", "$installPath\bicep.exe")
# Add bicep to your PATH
$currentPath = (Get-Item -path "HKCU:\Environment" ).GetValue('Path', '', 'DoNotExpandEnvironmentNames')
if (-not $currentPath.Contains("%USERPROFILE%\.bicep")) { setx PATH ($currentPath + ";%USERPROFILE%\.bicep") }
if (-not $env:path.Contains($installPath)) { $env:path += ";$installPath" }
}


Write-Host "Checking if Git is installed and installing if required"

#Install Git 

$git = git --version
if ($git = "") {
# get latest download url for git-for-windows 64-bit exe
$git_url = "https://api.github.com/repos/git-for-windows/git/releases/latest"
$asset = Invoke-RestMethod -Method Get -Uri $git_url | % assets | where name -like "*64-bit.exe"
# download installer
$installer = "$env:temp\$($asset.name)"
Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $installer
# run installer
$install_args = "/SP- /VERYSILENT /SUPPRESSMSGBOXES /NOCANCEL /NORESTART /CLOSEAPPLICATIONS /RESTARTAPPLICATIONS"
Start-Process -FilePath $installer -ArgumentList $install_args -Wait
}


Write-Host "Installing AZ modules if required (current user scope)"

#Install AZ Module if not available
if (Get-Module -ListAvailable -Name Az) {
    Write-Host "AZ Module Already Installed"
} 
else {
    try {
        Install-Module -Name Az -Scope CurrentUser -Repository PSGallery -Force 
    }
    catch [Exception] {
        $_.message 
        exit
    }
}




write-host "Importing Modules"
#Import AZ Module
import-module -Name Az



#Get Creds and connect
write-host "Connect to Azure"
Connect-AzAccount 

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

###############################################################################################################################################
#####                                                  Environment Build                                                                        ##
###############################################################################################################################################


#Find out which files to clone

write-host "Grabbing files from Git"


#Grab Files from Git
git clone https://github.com/andrew-s-taylor/az-landing.git $path


write-host "Files Downloaded"

#Update Parameters File
$jsonfile = $path+"parameters.json"
$json = Get-Content $jsonfile | ConvertFrom-Json 
$json.parameters.orggroup.value = Read-Host "Organisation Management Group"
$json.parameters.devgroup.value = Read-Host "Dev Management Group"
$json.parameters.testgroup.value = Read-Host "Test Management Group"
$json.parameters.prodgroup.value = Read-Host "Prod Management Group"
$json.parameters.excgroup.value = Read-Host "Exclusions Management Group"
$json.parameters.SubscriptionID.value = Read-Host "Subscription ID"
$json.parameters.tagname.value = Read-Host "Resource Tag name"
$json.parameters.tagvalue.value = Read-Host "Resource Tag Value"
$json.parameters.region.value = Read-Host "Region"
$json.parameters.hubrgname.value = Read-Host "Hub Network RG Name"
$json.parameters.spokergname.value = Read-Host "Spoke Resource Group Name"
$json.parameters.hubname.value = Read-Host "Hub Network Name"
$json.parameters.hubspace.value = Read-Host "Hub Network Address Space"
$json.parameters.hubfwsubnet.value = Read-Host "Hub Firewall Subnet Space"
$json.parameters.spokename.value = Read-Host "Spoke Network Name"
$json.parameters.spokespace.value = Read-Host "Spoke Network Space"
$json.parameters.spokesnname.value = Read-Host "Spoke Subnet Name"
$json.parameters.spokesnspace.value = "Spoke Subnet Space"
$json.parameters.logAnalyticsWorkspaceName.value = Read-Host "Log Analytics Workspace Name"
$json.parameters.logAnalyticslocation.value = "Log Analytics Location"
$json.parameters.monitoringrg.value = Read-Host "Monitoring RG Name"
$json.parameters.serverrg.value = Read-Host "Server Resource Group"
$json.parameters.adminUserName.value = Read-Host "Admin UserName"
$json.parameters.adminPassword.value = Read-Host "Admin Password"
$json.parameters.dnsLabelPrefix.value = Read-Host "DNS Label Prefix"
$json.parameters.storageAccountName.value = Read-Host "Monitoring RG Name"
$json.parameters.vmName.value = Read-Host "VM Name"
$json.parameters.networkSecurityGroupName.value = Read-Host "Network Security Group Name"
$json.parameters.vpnsubnet.value = Read-Host "VPN Subnet Address Space"
$json.parameters.vpngwpipname.value = Read-Host "VPN Gateway Public IP Name"
$json.parameters.vpngwname.value = Read-Host "VPN Gateway Name"
$json.parameters.localnetworkgwname.value = Read-Host "Local Network Gateway Name"
$json.parameters.addressprefixes.value = Read-Host "Local Network Address Prefix"
$json.parameters.gwipaddress.value = Read-Host "Local Network Gateway IP"
$json.parameters.bgppeeringpddress.value = Read-Host "BPG Peering Address"
$json.parameters.devicesubnet.value = Read-Host "Subnet for Devices"
$json | ConvertTo-Json | Out-File $jsonfile

write-host "Parameters Updated"

#Set Location for Deployment
$location = Read-Host "Which location are you deploying to?"
Set-Location $path

write-host "Deploying Environment using Bicep"

#Deploy WVD
New-AzSubscriptionDeployment -Location $location -TemplateFile ./main.bicep -TemplateParameterFile ./parameters.json