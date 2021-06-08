<#
.SYNOPSIS
  Builds an AVD environment
.DESCRIPTION
Builds AVD environment using Project Bicep and then builds an image using image builder

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

if (Get-Module -ListAvailable -Name Az.ImageBuilder) {
    Write-Host "AZ Module Already Installed"
} 
else {
    try {
        Install-Module -Name Az.ImageBuilder -Scope CurrentUser -Repository PSGallery -Force -AllowPrerelease
    }
    catch [Exception] {
        $_.message 
        exit
    }
}

if (Get-Module -ListAvailable -Name Az.ManagedServiceIdentity) {
    Write-Host "AZ Module Already Installed"
} 
else {
    try {
        Install-Module -Name Az.ManagedServiceIdentity -Scope CurrentUser -Repository PSGallery -Force -AllowPrerelease
    }
    catch [Exception] {
        $_.message 
        exit
    }
}


write-host "Importing Modules"
#Import AZ Module
import-module -Name Az
import-module -Name Az.ImageBuilder
import-module -Name Az.ManagedServiceIdentity



#Get Creds and connect
write-host "Connect to Azure"
Connect-AzAccount 

#Create path for files
#Ask for something to keep files individual
$clientname = Read-Host "Who is the client?"
$path = "c:\temp\" + $clientname + "\"

New-Item -ItemType Directory -Path $path

Write-Host "Directory Created"

###############################################################################################################################################
#####                                                  Environment Build                                                                        ##
###############################################################################################################################################

#Check if multi-subscription and set-azcontext
$multisubscription = Read-Host "Does this customer have multiple subscriptions? (Y/N)"

if ($multisubscription -eq "Y") {
    $subscriptionID = read-host "What is the subscription ID?"

    set-azcontext -SubscriptionId $subscriptionID

}



#Find out which files to clone
$multiregion = Read-Host "Do they require cross-region? (Y/N)"

write-host "Grabbing files from Git"

if ($multiregion -eq "Y") {
#Grab Multi-Region files from GitHub
git clone https://github.com/andrew-s-taylor/wvd-deploy-bicep-MR.git $path

}
else {
#Grab Single Region files from GitHub
git clone https://github.com/andrew-s-taylor/wvd-deploy-bicep-SR.git $path

}

write-host "Files Downloaded"

#Update Parameters File
$jsonfile = $path+"parameters.json"
$json = Get-Content $jsonfile | ConvertFrom-Json 
$json.parameters.resourceGroupPrefix.value = Read-Host "Resource Group Prefix"
$json.parameters.hostpoolName.value = Read-Host "Host Pool Name"
$json.parameters.hostpoolFriendlyName.value = Read-Host "Host Pool Friendly Name"
$json.parameters.appgroupName.value = Read-Host "App Group Name"
$json.parameters.appgroupFriendlyName.value = Read-Host "App Group Friendly Name"
$json.parameters.workspaceName.value = Read-Host "Workspace Name"
$json.parameters.workspaceNameFriendlyName.value = Read-Host "Workspace Friendly Name"
$json.parameters.preferredAppGroupType.value = Read-Host "App Group Type (Desktop or RailApplications)"
$json.parameters.wvdbackplanelocation.value = Read-Host "BackPlane Location (default eastus)"
$json.parameters.hostPoolType.value = Read-Host "Host Pool Type (pooled or personal)"
$json.parameters.loadBalancerType.value = Read-Host "Load Balancer Type (breadthfirst or depthfirst)"
$json.parameters.logAnalyticsWorkspaceName.value = Read-Host "Log Analytics Workspace Name (All lowercase, no special characters)"
$json.parameters.logAnalyticsLocation.value = Read-Host "Log Analytics Location"
$json.parameters.azureSubscriptionID.value = Read-Host "Azure Subscription ID"
$json.parameters.automationaccountname.value = Read-Host "Automation Account Name (All lowercase, no special characters)"
$json.parameters.sigName.value = Read-Host "Image Signature Name (All lowercase, no special characters)"
$json.parameters.sigLocation.value = Read-Host "Image Signature Location"
$json.parameters.imagePublisher.value = "microsoftwindowsdesktop"
$json.parameters.imageDefinitionName.value = Read-Host "Image Defintion Name"
$json.parameters.imageOffer.value = "office-365"
$json.parameters.imageSKU.value = Read-Host "Image SKU (office-36520h1-evd-o365pp)"
$json.parameters.imageLocation.value = Read-Host "Image Location"
$json.parameters.roleNameGalleryImage.value = Read-Host "Image Gallery Role Title"
$json.parameters.templateImageResourceGroup.value = Read-Host "Image Gallery Resource Group (prefix + IMG)"
$json.parameters.useridentity.value = Read-Host "User Identity Name (All lowercase, no special characters)"
$json.parameters.vnetName.value = Read-Host "VNET Name"
$json.parameters.vnetaddressPrefix.value = Read-Host "VNET Address Prefix (10.0.0.0/15)"
$json.parameters.subnetPrefix.value = Read-Host "Subnet Address Prefix (10.0.1.0/15)"
$json.parameters.vnetLocation.value = Read-Host "VNET Location"
$json.parameters.subnetName.value = Read-Host "Subnet Name"
$json.parameters.storageaccountlocation.value = Read-Host "Storage Account Location"
$json.parameters.storageaccountName.value = Read-Host "Storage Account Name (All lowercase, no special characters)"
$json.parameters.storageaccountkind.value = "FileStorage"
$json.parameters.storageaccountkindblob.value = "BlobStorage"
$json.parameters.storgeaccountglobalRedundancy.value = "Premium_LRS"
$json.parameters.fileshareFolderName.value = Read-Host "File Share Folder Name"

if ($multiregion -eq "Y") {
$json.parameters.logAnalyticsLocation2.value = Read-Host "Log Analytics Location (DR)"
$json.parameters.sigName2.value = Read-Host "Image Sig Name (DR)"
$json.parameters.sigLocation2.value = Read-Host "Image Gallery Location (DR)"
$json.parameters.vnetName2.value = Read-Host "VNET Name (DR)"
$json.parameters.vnetaddressPrefix2.value = Read-Host "VNET Address Prefix (DR)"
$json.parameters.subnetPrefix2.value = Read-Host "Subnet Prefix (DR)"
$json.parameters.vnetLocation2.value = Read-Host "VNET Location (DR)"
$json.parameters.subnetName2.value = Read-Host "Subnet Name (DR)"
$json.parameters.storageaccountlocation2.value = Read-Host "Storage Account Location (DR)"
$json.parameters.storageaccountName2.value = Read-Host "Storage Account Name (DR)"
$json.parameters.storageaccountkind2.value = "FileStorage"
$json.parameters.storgeaccountglobalRedundancy2.value = "Premium_LRS"
$json.parameters.fileshareFolderName2.value = Read-Host "File Share Name (DR)"
}
$json | ConvertTo-Json | Out-File $jsonfile

write-host "Parameters Updated"

#Set Location for Deployment
$location = Read-Host "Which location are you deploying to?"
$packages2 = read-host "Comma separated package name list (leave blank if no choco needed)"
Set-Location $path

write-host "Deploying Environment using Bicep"

#Deploy WVD
New-AzSubscriptionDeployment -Location $location -TemplateFile ./main.bicep -TemplateParameterFile ./parameters.json


###############################################################################################################################################
#####                                                  IMAGE BUILDER                                                                         ##
###############################################################################################################################################




write-host "Begin Image Build"
write-host "Registering AZ Provider"
#Register Image Builder
Register-AzProviderFeature -ProviderNamespace Microsoft.VirtualMachineImages -FeatureName VirtualMachineTemplatePreview

#While Loop to check for Registered here

Do {
    $state = Get-AzProviderFeature -ProviderNamespace Microsoft.VirtualMachineImages -FeatureName VirtualMachineTemplatePreview | select-object RegistrationState
    Write-Host "Unregistered"
    Start-Sleep 5
}
Until (
    
    $state = "Registered AZ Provider"
)
Write-Host "Registered AZ Provider"


#Register Other Components if required
write-host "Registering Other Components"
Get-AzResourceProvider -ProviderNamespace Microsoft.Compute, Microsoft.KeyVault, Microsoft.Storage, Microsoft.VirtualMachineImages, Microsoft.Network |
  Where-Object RegistrationState -ne Registered |
    Register-AzResourceProvider


#Define Variables using data above

write-host "Grabbing details from parameters json"
#Get Set variables
$jsonfile = $path+"parameters.json"
$json = Get-Content $jsonfile | ConvertFrom-Json 

# Destination image resource group name
$igr1 = $json.parameters.resourceGroupPrefix.value

$imageResourceGroup = $igr1 + "IMG"

# Azure region
if ($multiregion -eq "Y") {

$location2 = $json.parameters.sigLocation2.value
$location1 = $json.parameters.imageLocation.value
$location = $location1 + "," + $location2
}
else {
$location = $json.parameters.imageLocation.value
}

# Name of the image to be created
$imageTemplateName = $json.parameters.imageDefinitionName.value + "bld"

# Distribution properties of the managed image upon completion
$runOutputName = 'myDistResults'

# Your Azure Subscription ID
$subscriptionID = (Get-AzContext).Subscription.Id
Write-Output $subscriptionID


write-host "Creating Identity"
##CREATE A USER ASSIGNED IDENTITY, THIS WILL BE USED TO ADD THE IMAGE TO THE SIG
# setup role def names, these need to be unique
[int]$timeInt = $(Get-Date -UFormat '%s')
$imageRoleDefName="Azure Image Builder Image Def"+$timeInt
$identityName="aibidentity$timeInt"

## Add AZ PS module to support AzUserAssignedIdentity
Install-Module -Name Az.ManagedServiceIdentity -scope CurrentUser

# Create identity
# New-AzUserAssignedIdentity -ResourceGroupName $imageResourceGroup -Name $identityName
New-AzUserAssignedIdentity -ResourceGroupName $imageResourceGroup -Name $identityName
$identityNameResourceId=$(Get-AzUserAssignedIdentity -ResourceGroupName $imageResourceGroup -Name $identityName).Id
$identityNamePrincipalId=$(Get-AzUserAssignedIdentity -ResourceGroupName $imageResourceGroup -Name $identityName).PrincipalId
write-host "Identity Created"

write-host "Assigning Permissions"
## ASSIGN PERMISSIONS FOR THIS IDENTITY TO DISTRIBUTE IMAGES
$aibRoleImageCreationUrl="https://raw.githubusercontent.com/TomHickling/AzureImageBuilder/master/aibRoleImageCreation.json"
$aibRoleImageCreationPath = "aibRoleImageCreation.json"

# Download config
Invoke-WebRequest -Uri $aibRoleImageCreationUrl -OutFile $aibRoleImageCreationPath -UseBasicParsing
((Get-Content -path $aibRoleImageCreationPath -Raw) -replace '<subscriptionID>',$subscriptionID) | Set-Content -Path $aibRoleImageCreationPath
((Get-Content -path $aibRoleImageCreationPath -Raw) -replace '<rgName>', $imageResourceGroup) | Set-Content -Path $aibRoleImageCreationPath
((Get-Content -path $aibRoleImageCreationPath -Raw) -replace 'Azure Image Builder Service Image Creation Role', $imageRoleDefName) | Set-Content -Path $aibRoleImageCreationPath

# Create the  role definition
New-AzRoleDefinition -InputFile  ./aibRoleImageCreation.json

# Grant role definition to image builder service principal
New-AzRoleAssignment -ObjectId $identityNamePrincipalId -RoleDefinitionName $imageRoleDefName -Scope "/subscriptions/$subscriptionID/resourceGroups/$imageResourceGroup"
write-host "Permissions Assigned"

write-host "Creating Image"

  $myGalleryName = $json.parameters.sigName.value
  $imageDefName = $json.parameters.imageDefinitionName.value + "bld"

  New-AzGalleryImageDefinition `
   -GalleryName $myGalleryName `
   -ResourceGroupName $imageResourceGroup `
   -Location $location `
   -Name $imageDefName `
   -OsState generalized `
   -OsType Windows `
   -Publisher 'BytesSoftwareServices' `
   -Offer 'Windows-10-App-Teams' `
   -Sku '21h1-evd'



 #Create Image
 $SrcObjParams = @{
    SourceTypePlatformImage = $true
    Publisher = $json.parameters.imagePublisher.value
    Offer = $json.parameters.imageOffer.value
    Sku = $json.parameters.imageSKU.value
    Version = 'latest'
  }
  $srcPlatform = New-AzImageBuilderSourceObject @SrcObjParams

  #Distributor Object

    $disObjParams = @{
    SharedImageDistributor = $true
    ArtifactTag = @{tag='dis-share'}
    GalleryImageId = "/subscriptions/$subscriptionID/resourceGroups/$imageResourceGroup/providers/Microsoft.Compute/galleries/$myGalleryName/images/$imageDefName"
    ReplicationRegion = $location
    RunOutputName = $runOutputName
    ExcludeFromLatest = $false
  }
  $disSharedImg = New-AzImageBuilderDistributorObject @disObjParams

  #Let's get customizing

#Basic Script - For all deployments
$imgCustomParams = @{
    PowerShellCustomizer = $true
    CustomizerName       = 'MountAppShareAndRunInstaller'
    RunElevated          = $true
    scriptUri            = 'https://raw.githubusercontent.com/andrew-s-taylor/public/main/Powershell%20Scripts/WVD/wvd-box-config-generic.ps1'
}
$Customizer01 = New-AzImageBuilderCustomizerObject @imgCustomParams

if ($packages2 = "") {
    Write-Verbose "Skipping Choco Install"
}
else {
#Install Choco Apps
$ImgCustomParams03 = @{
    PowerShellCustomizer = $true
    CustomizerName = 'settingUpMgmtAgtPath'
    RunElevated = $false
    Inline = @('
    $packages = $packages2.split(“,”);
    foreach ($package in $packages) {
    choco install $package -y
    }')
  }
$Customizer03 = New-AzImageBuilderCustomizerObject @ImgCustomParams03
}
#Configure FSLogix

if ($multiregion -eq "Y") {

#Get Storage Account
$files1 = $json.parameters.resourceGroupPrefix.value

$fileresource = $files1 + "FILESERVICES"
$share = get-azstorageaccount -ResourceGroupName $fileresource -Name $json.parameters.storageaccountName.value

#Get Share Details
$store = get-azstorageshare -Context $share.Context | Select-Object Name
$files2 = "\\" + $share.StorageAccountName + ".file.core.windows.net\" + $store.Name


#Get Storage AccountDR
$files1dr = $json.parameters.resourceGroupPrefix.value

$fileresourcedr = $files1dr + "FILESERVICES-DR"
$sharedr = get-azstorageaccount -ResourceGroupName $fileresourcedr -Name $json.parameters.storageaccountName2.value

#Get Share Details
$storedr = get-azstorageshare -Context $sharedr.Context | Select-Object Name
$files2dr = "\\" + $sharedr.StorageAccountName + ".file.core.windows.net\" + $storedr.Name

$FSLogixCD = "type=smb,connectionString="+$files2+";type=smb,connectionString="+$files2DR


$ImgCustomParams02 = @{
    PowerShellCustomizer = $true
    CustomizerName = 'settingUpMgmtAgtPath'
    RunElevated = $false
    Inline = @('if((Test-Path -LiteralPath "HKLM:\SOFTWARE\FSLogix\Profiles") -ne $true) {  New-Item "HKLM:\SOFTWARE\FSLogix\Profiles" -force -ea SilentlyContinue };
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "Enabled" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "CCDLocations" -Value $FSLogixCD -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "ConcurrentUserSessions" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "IsDynamic" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "KeepLocalDir" -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "VolumeType" -Value "vhdx" -PropertyType String -Force -ea SilentlyContinue;
    
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\FSLogix\ODFC") -ne $true) {  New-Item "HKLM:\SOFTWARE\FSLogix\ODFC" -force -ea SilentlyContinue };
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\ODFC" -Name "Enabled" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\ODFC" -Name "CCDLocations" -Value $FSLogixCD -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\ODFC" -Name "IncludeOneDrive" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\ODFC" -Name "IncludeOneNote" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\ODFC" -Name "IncludeOneNote_UWP" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\ODFC" -Name "IncludeOutlook" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\ODFC" -Name "IncludeOutlookPersonalization" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\ODFC" -Name "IncludeSharepoint" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\ODFC" -Name "IncludeTeams" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    Restart-Computer -Force ')
  }
$Customizer02 = New-AzImageBuilderCustomizerObject @ImgCustomParams02


}

else {

#Get Storage Account
$files1 = $json.parameters.resourceGroupPrefix.value

$fileresource = $files1 + "FILESERVICES"
$share = get-azstorageaccount -ResourceGroupName $fileresource -Name $json.parameters.storageaccountName.value

#Get Share Details
$store = get-azstorageshare -Context $share.Context | Select-Object Name
$files2 = "\\" + $share.StorageAccountName + ".file.core.windows.net\" + $store.Name


$ImgCustomParams02 = @{
    PowerShellCustomizer = $true
    CustomizerName = 'settingUpMgmtAgtPath'
    RunElevated = $false
    Inline = @('if((Test-Path -LiteralPath "HKLM:\SOFTWARE\FSLogix\Profiles") -ne $true) {  New-Item "HKLM:\SOFTWARE\FSLogix\Profiles" -force -ea SilentlyContinue };
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "Enabled" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "VHDLocations" -Value $files2 -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "ConcurrentUserSessions" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "IsDynamic" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "KeepLocalDir" -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "VolumeType" -Value "vhdx" -PropertyType String -Force -ea SilentlyContinue;
    
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\FSLogix\ODFC") -ne $true) {  New-Item "HKLM:\SOFTWARE\FSLogix\ODFC" -force -ea SilentlyContinue };
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\ODFC" -Name "Enabled" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\ODFC" -Name "VHDLocations" -Value $files2 -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\ODFC" -Name "IncludeOneDrive" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\ODFC" -Name "IncludeOneNote" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\ODFC" -Name "IncludeOneNote_UWP" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\ODFC" -Name "IncludeOutlook" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\ODFC" -Name "IncludeOutlookPersonalization" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\ODFC" -Name "IncludeSharepoint" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\ODFC" -Name "IncludeTeams" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    Restart-Computer -Force ')
  }
$Customizer02 = New-AzImageBuilderCustomizerObject @ImgCustomParams02

}

#Build the image template
if ($packages2 = "") {
    $ImgTemplateParams = @{
        ImageTemplateName = $imageTemplateName
        ResourceGroupName = $imageResourceGroup
        Source = $srcPlatform
        Distribute = $disSharedImg
        Customize = $Customizer01, $Customizer02
        Location = $location
        UserAssignedIdentityId = $identityNameResourceId
      }
}
else {
    $ImgTemplateParams = @{
        ImageTemplateName = $imageTemplateName
        ResourceGroupName = $imageResourceGroup
        Source = $srcPlatform
        Distribute = $disSharedImg
        Customize = $Customizer01, $Customizer02, $Customizer03
        Location = $location
        UserAssignedIdentityId = $identityNameResourceId
      }

}

  New-AzImageBuilderTemplate @ImgTemplateParams
 write-host "Image Building"


  #Wait for it to complete

  Do {
    $state = Get-AzImageBuilderTemplate -ImageTemplateName $imageTemplateName -ResourceGroupName $imageResourceGroup | Select-Object -Property Name, LastRunStatusRunState, LastRunStatusMessage, ProvisioningState
    Write-Host "Running"
    Start-Sleep 5
}
Until (
    
    $state = "Succeeded"
)
Write-Host "Completed"


  #Build the Image
write-host "Starting Template Build"
  Start-AzImageBuilderTemplate -ResourceGroupName $imageResourceGroup -Name $imageTemplateName


  write-host "Build Completed"
