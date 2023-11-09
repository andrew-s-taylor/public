<#PSScriptInfo
.VERSION 1.0
.GUID fb5c2309-971c-4736-b7f3-2adcee3d3dff
.AUTHOR AndrewTaylor
.DESCRIPTION Creates a new Winget repo
.COMPANYNAME 
.COPYRIGHT GPL
.TAGS intune endpoint MEM environment
.LICENSEURI https://github.com/andrew-s-taylor/public/blob/main/LICENSE
.PROJECTURI https://github.com/andrew-s-taylor/public
.ICONURI 
.EXTERNALMODULEDEPENDENCIES Az
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
#>
<#
.SYNOPSIS
Creates a Winget Repository in Azure
.DESCRIPTION
Creates a Winget Repository in Azure

.INPUTS
Tenant ID, Subscription, Name, Region, Implementation Type
.OUTPUTS
Within Azure
.NOTES
  Version:        1.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  09/11/2023
  Purpose/Change: Initial script development
 
.EXAMPLE
N/A
#>

write-host "Creating folder to store files"
#Create Folder
$wingetfolder = $env:temp + "\winget"
If (Test-Path $wingetfolder) {
    Write-Output "$wingetfolder exists. Skipping."
}
Else {
    Write-Output "The folder '$wingetfolder' doesn't exist. This folder will be used for storing logs created after the script runs. Creating now."
    Start-Sleep 1
    New-Item -Path "$wingetfolder" -ItemType Directory
    Write-Output "The folder $wingetfolder was successfully created."
}
write-host "Folder created at $wingetfolder"
$transcript = "$wingetfolder\wingetrepo.log"
Start-Transcript -Path $transcript

##Download the zip file from GitHub
write-host "Downloading the zip file from GitHub"
$downloadlink = "https://github.com/microsoft/winget-cli-restsource/releases/latest/download/WinGet.RestSource-Winget.PowerShell.Source.zip"
$downloadlocation = "$wingetfolder\WinGet.RestSource-Winget.PowerShell.Source.zip"
$download = Invoke-WebRequest -Uri $downloadlink -OutFile $downloadlocation
write-host "Downloaded the zip file from GitHub"

##Unzip the file
write-host "Unzipping the file"
$unziplocation = "$wingetfolder\WinGet.RestSource-Winget.PowerShell.Source"
Expand-Archive -Path $downloadlocation -DestinationPath $unziplocation -Force
write-host "Unzipped the file"

##Unlock files within the folder
write-host "Unlocking files within the folder"
Get-ChildItem -Path $unziplocation -Recurse | Unblock-File
write-host "Unlocked files within the folder"

##Install AZ Module
write-host "Installing AZ Module"
if (Get-Module -ListAvailable -Name Az) {
    Write-Host "AZ Module Already Installed"
} 
else {
    try {
        Install-Module -Name Az -Scope CurrentUser -Repository PSGallery -Force 
        Write-Host "Az"
    }
    catch [Exception] {
        $_.message 
    }
}

##Prompt for tenant ID
$tenantid = Read-Host -Prompt "Enter the Tenant ID"

##Connect to Azure
write-host "Connecting to Azure"
Connect-AzAccount -Tenant $tenantid
write-host "Connected to Azure"

##Prompt for subscription
$subscriptionid = Read-Host -Prompt "Enter the Subscription ID"

##Set the subscription
write-host "Setting the subscription"
Set-AzContext -SubscriptionId $subscriptionid
write-host "Set the subscription"


##Import the module
write-host "Importing the module"
Import-Module -Name $unziplocation\WinGet.RestSource-Winget.PowerShell.Source\Microsoft.WinGet.Source.psd1
write-host "Imported the module"

##Prompt for resource group
$resourcegroup = Read-Host -Prompt "Enter the Resource Group Name"

##Prompt for Winget Item Names
$wingetitemname = Read-Host -Prompt "Enter the Winget Item Name"

##Select Region from array of Azure regions
$regions = @(
    "eastus",
    "eastus2",
    "southcentralus",
    "westus2",
    "westus3",
    "australiaeast",
    "southeastasia",
    "northeurope",
    "swedencentral",
    "uksouth",
    "westeurope",
    "centralus",
    "southafricanorth",
    "centralindia",
    "eastasia",
    "japaneast",
    "koreacentral",
    "canadacentral",
    "francecentral",
    "germanywestcentral",
    "norwayeast",
    "switzerlandnorth",
    "uaenorth",
    "brazilsouth",
    "centraluseuap",
    "eastus2euap",
    "qatarcentral",
    "centralusstage",
    "eastusstage",
    "eastus2stage",
    "northcentralusstage",
    "southcentralusstage",
    "westusstage",
    "westus2stage",
    "asia",
    "asiapacific",
    "australia",
    "brazil",
    "canada",
    "europe",
    "france",
    "germany",
    "global",
    "india",
    "japan",
    "korea",
    "norway",
    "singapore",
    "southafrica",
    "switzerland",
    "uae",
    "uk",
    "unitedstates",
    "unitedstateseuap",
    "eastasiastage",
    "southeastasiastage",
    "brazilus",
    "eastusstg",
    "northcentralus",
    "westus",
    "jioindiawest",
    "devfabric",
    "westcentralus",
    "southafricawest",
    "australiacentral",
    "australiacentral2",
    "australiasoutheast",
    "japanwest",
    "jioindiacentral",
    "koreasouth",
    "southindia",
    "westindia",
    "canadaeast",
    "francesouth",
    "germanynorth",
    "norwaywest",
    "switzerlandwest",
    "ukwest",
    "uaecentral",
    "brazilsoutheast"
)

$region = $regions | Out-GridView -Title "Select a region" -PassThru

$installtype = Read-Host -Prompt "Enter the Install Type (Basic, Enhanced, Demo)"

##Create the Winget Repo
write-host "Creating the Winget Repo"
new-wingetsource -Name $wingetitemname -ResourceGroup $resourcegroup -Region $region -ImplementationPerformance $installtype -ShowConnectionInstructions
write-host "Created the Winget Repo"

##Web app keeps failing so manually publish
##Check if needed
$webapptest = get-azwebapp -Name $wingetitemname

##Check if empty
if ($webapptest -eq $null) {
    write-host "Web App doesn't exist"
    $RestSourcePath = "$unziplocation\WinGet.RestSource-Winget.PowerShell.Source\Library\RestAPI\WinGet.RestSource.Functions.zip"
$webapp = Publish-AzWebApp -ArchivePath $RestSourcePath -ResourceGroupName $resourcegroup -Name $wingetitemname -Force
write-host "web app created"
}
else {
    write-host "Web App exists"
}


##Get the URL
$webappurl = (get-azwebapp -Name $wingetitemname).HostNames[0]
write-host "Your Winget Repo is available at https://$webappurl/api"
Stop-Transcript