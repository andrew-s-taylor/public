<#
.SYNOPSIS
  Builds an AVD environment with GUI
.DESCRIPTION
Builds AVD environment using Project Bicep and then builds an image using image builder with GUI

.INPUTS
None required
.OUTPUTS
Within Azure
.NOTES
  Version:        1.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  11/06/2021
  Purpose/Change: Initial script development
  
.EXAMPLE
N/A
#>
#Check if Multi-Region
$wshell = New-Object -ComObject Wscript.Shell
$answer2 = $wshell.Popup("Is this multi-region??",0,"Alert",64+4)


#Create Temp location
$random = Get-Random -Maximum 1000 
$random = $random.ToString()
$date =get-date -format yyMMddmmss
$date = $date.ToString()
$path2 = $random + "-"  + $date
$path = "c:\temp\" + $path2 + "\"

#Params depending on region choice

if ($answer2 -eq 6) {
    #Mutli-Region
    $url2 = "https://github.com/andrew-s-taylor/avd-deploy-bicep-MR/archive/main.zip"
    $pathaz = "c:\temp\" + $path2 + "\avd-deploy-bicep-MR-main"
    $output3 = "c:\temp\" + $path2 + "\main.zip"

}
else {
    #Single Region
    $url2 = "https://github.com/andrew-s-taylor/avd-deploy-bicep-SR/archive/main.zip"
    $pathaz = "c:\temp\" + $path2 + "\avd-deploy-bicep-SR-main"
    $output3 = "c:\temp\" + $path2 + "\main.zip"

}

New-Item -ItemType Directory -Path $path


#Set Variables
Write-Host "Directory Created"
Set-Location $path
$jsonfile = [PSCustomObject]@{value=$pathaz+"\parameters.json"}
$path2 = [PSCustomObject]@{value=$path}
$pathaz2 = [PSCustomObject]@{value=$pathaz}
$output2 = [PSCustomObject]@{value=$output3}
$url = [PSCustomObject]@{value=$url2}
$answer = [PSCustomObject]@{value=$answer2}


#Create Form

###############################################################################################################################################
#####                                                  CREATE FORM                                                                           ##
###############################################################################################################################################

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

$AVDDeployment                   = New-Object system.Windows.Forms.Form
$AVDDeployment.ClientSize        = New-Object System.Drawing.Point(896,869)
$AVDDeployment.text              = "AVD Deployment Tool V1.0"
$AVDDeployment.TopMost           = $false

$OrgMgmtGrpName                  = New-Object system.Windows.Forms.Label
$OrgMgmtGrpName.text             = "Resource Group Prefix(add -)"
$OrgMgmtGrpName.AutoSize         = $true
$OrgMgmtGrpName.width            = 25
$OrgMgmtGrpName.height           = 10
$OrgMgmtGrpName.location         = New-Object System.Drawing.Point(31,73)
$OrgMgmtGrpName.Font             = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$resourceGroupPrefix             = New-Object system.Windows.Forms.TextBox
$resourceGroupPrefix.multiline   = $false
$resourceGroupPrefix.width       = 178
$resourceGroupPrefix.height      = 20
$resourceGroupPrefix.location    = New-Object System.Drawing.Point(253,72)
$resourceGroupPrefix.Font        = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label1                          = New-Object system.Windows.Forms.Label
$Label1.text                     = "Host Pool Name"
$Label1.AutoSize                 = $true
$Label1.width                    = 25
$Label1.height                   = 10
$Label1.location                 = New-Object System.Drawing.Point(31,108)
$Label1.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$hostpoolName                    = New-Object system.Windows.Forms.TextBox
$hostpoolName.multiline          = $false
$hostpoolName.width              = 178
$hostpoolName.height             = 20
$hostpoolName.location           = New-Object System.Drawing.Point(253,105)
$hostpoolName.Font               = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label2                          = New-Object system.Windows.Forms.Label
$Label2.text                     = "Host Pool Friendly Name"
$Label2.AutoSize                 = $true
$Label2.width                    = 25
$Label2.height                   = 10
$Label2.location                 = New-Object System.Drawing.Point(31,135)
$Label2.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$hostpoolFriendlyName            = New-Object system.Windows.Forms.TextBox
$hostpoolFriendlyName.multiline  = $false
$hostpoolFriendlyName.width      = 178
$hostpoolFriendlyName.height     = 20
$hostpoolFriendlyName.location   = New-Object System.Drawing.Point(253,132)
$hostpoolFriendlyName.Font       = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label3                          = New-Object system.Windows.Forms.Label
$Label3.text                     = "App Group Name"
$Label3.AutoSize                 = $true
$Label3.width                    = 25
$Label3.height                   = 10
$Label3.location                 = New-Object System.Drawing.Point(31,163)
$Label3.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$appgroupName                    = New-Object system.Windows.Forms.TextBox
$appgroupName.multiline          = $false
$appgroupName.width              = 178
$appgroupName.height             = 20
$appgroupName.location           = New-Object System.Drawing.Point(253,159)
$appgroupName.Font               = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label4                          = New-Object system.Windows.Forms.Label
$Label4.text                     = "App Group Friendly Name"
$Label4.AutoSize                 = $true
$Label4.width                    = 25
$Label4.height                   = 10
$Label4.location                 = New-Object System.Drawing.Point(31,187)
$Label4.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$appgroupFriendlyName            = New-Object system.Windows.Forms.TextBox
$appgroupFriendlyName.multiline  = $false
$appgroupFriendlyName.width      = 178
$appgroupFriendlyName.height     = 20
$appgroupFriendlyName.location   = New-Object System.Drawing.Point(253,184)
$appgroupFriendlyName.Font       = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label5                          = New-Object system.Windows.Forms.Label
$Label5.text                     = "Workspace Name"
$Label5.AutoSize                 = $true
$Label5.width                    = 25
$Label5.height                   = 10
$Label5.location                 = New-Object System.Drawing.Point(31,211)
$Label5.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$workspaceName                   = New-Object system.Windows.Forms.TextBox
$workspaceName.multiline         = $false
$workspaceName.width             = 178
$workspaceName.height            = 20
$workspaceName.location          = New-Object System.Drawing.Point(253,208)
$workspaceName.Font              = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label6                          = New-Object system.Windows.Forms.Label
$Label6.text                     = "Workspace Friendly Name"
$Label6.AutoSize                 = $true
$Label6.width                    = 25
$Label6.height                   = 10
$Label6.location                 = New-Object System.Drawing.Point(31,238)
$Label6.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$workspaceNameFriendlyName       = New-Object system.Windows.Forms.TextBox
$workspaceNameFriendlyName.multiline  = $false
$workspaceNameFriendlyName.width  = 178
$workspaceNameFriendlyName.height  = 20
$workspaceNameFriendlyName.location  = New-Object System.Drawing.Point(253,234)
$workspaceNameFriendlyName.Font  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label7                          = New-Object system.Windows.Forms.Label
$Label7.text                     = "App Group Type"
$Label7.AutoSize                 = $true
$Label7.width                    = 25
$Label7.height                   = 10
$Label7.location                 = New-Object System.Drawing.Point(31,265)
$Label7.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label8                          = New-Object system.Windows.Forms.Label
$Label8.text                     = "BackPlane Location"
$Label8.AutoSize                 = $true
$Label8.width                    = 25
$Label8.height                   = 10
$Label8.location                 = New-Object System.Drawing.Point(31,297)
$Label8.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$avdbackplanelocation            = New-Object system.Windows.Forms.ComboBox
$avdbackplanelocation.text       = "region"
$avdbackplanelocation.width      = 178
$avdbackplanelocation.height     = 20
@('centralus','eastus2','eastus2','northcentralus','northeurope','southcentralus','westcentralus','westeurope','westus','westus2') | ForEach-Object {[void] $avdbackplanelocation.Items.Add($_)}
$avdbackplanelocation.location   = New-Object System.Drawing.Point(253,286)
$avdbackplanelocation.Font       = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label9                          = New-Object system.Windows.Forms.Label
$Label9.text                     = "Host Pool Type"
$Label9.AutoSize                 = $true
$Label9.width                    = 25
$Label9.height                   = 10
$Label9.location                 = New-Object System.Drawing.Point(31,320)
$Label9.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label10                         = New-Object system.Windows.Forms.Label
$Label10.text                    = "Load Balancer Type"
$Label10.AutoSize                = $true
$Label10.width                   = 25
$Label10.height                  = 10
$Label10.location                = New-Object System.Drawing.Point(30,340)
$Label10.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label11                         = New-Object system.Windows.Forms.Label
$Label11.text                    = "Log Analytics Workspace Name"
$Label11.AutoSize                = $true
$Label11.width                   = 25
$Label11.height                  = 10
$Label11.location                = New-Object System.Drawing.Point(31,370)
$Label11.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$logAnalyticsWorkspaceName       = New-Object system.Windows.Forms.TextBox
$logAnalyticsWorkspaceName.multiline  = $false
$logAnalyticsWorkspaceName.text  = "All lowercase no special characters"
$logAnalyticsWorkspaceName.width  = 178
$logAnalyticsWorkspaceName.height  = 20
$logAnalyticsWorkspaceName.location  = New-Object System.Drawing.Point(253,368)
$logAnalyticsWorkspaceName.Font  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label12                         = New-Object system.Windows.Forms.Label
$Label12.text                    = "Log Analytics Location"
$Label12.AutoSize                = $true
$Label12.width                   = 25
$Label12.height                  = 10
$Label12.location                = New-Object System.Drawing.Point(30,398)
$Label12.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label13                         = New-Object system.Windows.Forms.Label
$Label13.text                    = "Azure Subscription ID"
$Label13.AutoSize                = $true
$Label13.width                   = 25
$Label13.height                  = 10
$Label13.location                = New-Object System.Drawing.Point(31,427)
$Label13.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$azureSubscriptionID             = New-Object system.Windows.Forms.TextBox
$azureSubscriptionID.multiline   = $false
$azureSubscriptionID.width       = 178
$azureSubscriptionID.height      = 20
$azureSubscriptionID.location    = New-Object System.Drawing.Point(252,424)
$azureSubscriptionID.Font        = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label14                         = New-Object system.Windows.Forms.Label
$Label14.text                    = "Automation Account Name"
$Label14.AutoSize                = $true
$Label14.width                   = 25
$Label14.height                  = 10
$Label14.location                = New-Object System.Drawing.Point(31,455)
$Label14.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$automationaccountname           = New-Object system.Windows.Forms.TextBox
$automationaccountname.multiline  = $false
$automationaccountname.text      = "All lowercase no special characters"
$automationaccountname.width     = 178
$automationaccountname.height    = 20
$automationaccountname.location  = New-Object System.Drawing.Point(253,452)
$automationaccountname.Font      = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label15                         = New-Object system.Windows.Forms.Label
$Label15.text                    = "Image Signature Name"
$Label15.AutoSize                = $true
$Label15.width                   = 25
$Label15.height                  = 10
$Label15.location                = New-Object System.Drawing.Point(31,480)
$Label15.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$sigName                         = New-Object system.Windows.Forms.TextBox
$sigName.multiline               = $false
$sigName.text                    = "All lowercase no special characters"
$sigName.width                   = 178
$sigName.height                  = 20
$sigName.location                = New-Object System.Drawing.Point(252,480)
$sigName.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label16                         = New-Object system.Windows.Forms.Label
$Label16.text                    = "Image Signature Location"
$Label16.AutoSize                = $true
$Label16.width                   = 25
$Label16.height                  = 10
$Label16.location                = New-Object System.Drawing.Point(31,510)
$Label16.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label17                         = New-Object system.Windows.Forms.Label
$Label17.text                    = "Image Defintion Name"
$Label17.AutoSize                = $true
$Label17.width                   = 25
$Label17.height                  = 10
$Label17.location                = New-Object System.Drawing.Point(33,546)
$Label17.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$imageDefinitionName             = New-Object system.Windows.Forms.TextBox
$imageDefinitionName.multiline   = $false
$imageDefinitionName.width       = 178
$imageDefinitionName.height      = 20
$imageDefinitionName.location    = New-Object System.Drawing.Point(253,542)
$imageDefinitionName.Font        = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label18                         = New-Object system.Windows.Forms.Label
$Label18.text                    = "Image SKU"
$Label18.AutoSize                = $true
$Label18.width                   = 25
$Label18.height                  = 10
$Label18.location                = New-Object System.Drawing.Point(31,580)
$Label18.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$imageSKU                        = New-Object system.Windows.Forms.TextBox
$imageSKU.multiline              = $false
$imageSKU.text                   = "21h1-evd-o365pp"
$imageSKU.width                  = 178
$imageSKU.height                 = 20
$imageSKU.location               = New-Object System.Drawing.Point(253,580)
$imageSKU.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label19                         = New-Object system.Windows.Forms.Label
$Label19.text                    = "Image Location"
$Label19.AutoSize                = $true
$Label19.width                   = 25
$Label19.height                  = 10
$Label19.location                = New-Object System.Drawing.Point(30,609)
$Label19.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$loganalyticslocation            = New-Object system.Windows.Forms.ComboBox
$loganalyticslocation.text       = "region"
$loganalyticslocation.width      = 178
$loganalyticslocation.height     = 20
@('uksouth','ukwest','northeurope','westeurope') | ForEach-Object {[void] $loganalyticslocation.Items.Add($_)}
$loganalyticslocation.location   = New-Object System.Drawing.Point(251,395)
$loganalyticslocation.Font       = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label20                         = New-Object system.Windows.Forms.Label
$Label20.text                    = "Image Gallery Role Title"
$Label20.AutoSize                = $true
$Label20.width                   = 25
$Label20.height                  = 10
$Label20.location                = New-Object System.Drawing.Point(470,73)
$Label20.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$roleNameGalleryImage            = New-Object system.Windows.Forms.TextBox
$roleNameGalleryImage.multiline  = $false
$roleNameGalleryImage.width      = 178
$roleNameGalleryImage.height     = 20
$roleNameGalleryImage.location   = New-Object System.Drawing.Point(694,72)
$roleNameGalleryImage.Font       = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

#$Label21                         = New-Object system.Windows.Forms.Label
#$Label21.text                    = "Image Gallery Resource Group"
#$Label21.AutoSize                = $true
#$Label21.width                   = 25
#$Label21.height                  = 10
#$Label21.location                = New-Object System.Drawing.Point(470,108)
#$Label21.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

#$templateImageResourceGroup      = New-Object system.Windows.Forms.TextBox
#$templateImageResourceGroup.multiline  = $false
#$templateImageResourceGroup.text  = "prefix + IMG"
#$templateImageResourceGroup.width  = 178
#$templateImageResourceGroup.height  = 20
#$templateImageResourceGroup.location  = New-Object System.Drawing.Point(694,98)
#$templateImageResourceGroup.Font  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label22                         = New-Object system.Windows.Forms.Label
$Label22.text                    = "User Identity Name"
$Label22.AutoSize                = $true
$Label22.width                   = 25
$Label22.height                  = 10
$Label22.location                = New-Object System.Drawing.Point(470,132)
$Label22.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$useridentity                    = New-Object system.Windows.Forms.TextBox
$useridentity.multiline          = $false
$useridentity.text               = "All lowercase no special characters"
$useridentity.width              = 178
$useridentity.height             = 20
$useridentity.location           = New-Object System.Drawing.Point(694,125)
$useridentity.Font               = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label23                         = New-Object system.Windows.Forms.Label
$Label23.text                    = "VNET Name"
$Label23.AutoSize                = $true
$Label23.width                   = 25
$Label23.height                  = 10
$Label23.location                = New-Object System.Drawing.Point(470,163)
$Label23.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$vnetName                        = New-Object system.Windows.Forms.TextBox
$vnetName.multiline              = $false
$vnetName.width                  = 178
$vnetName.height                 = 20
$vnetName.location               = New-Object System.Drawing.Point(694,159)
$vnetName.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label24                         = New-Object system.Windows.Forms.Label
$Label24.text                    = "VNET Address Prefix"
$Label24.AutoSize                = $true
$Label24.width                   = 25
$Label24.height                  = 10
$Label24.location                = New-Object System.Drawing.Point(470,187)
$Label24.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$vnetaddressPrefix               = New-Object system.Windows.Forms.TextBox
$vnetaddressPrefix.multiline     = $false
$vnetaddressPrefix.text          = "10.0.0.0/15"
$vnetaddressPrefix.width         = 178
$vnetaddressPrefix.height        = 20
$vnetaddressPrefix.location      = New-Object System.Drawing.Point(694,184)
$vnetaddressPrefix.Font          = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label25                         = New-Object system.Windows.Forms.Label
$Label25.text                    = "Subnet Address Prefix"
$Label25.AutoSize                = $true
$Label25.width                   = 25
$Label25.height                  = 10
$Label25.location                = New-Object System.Drawing.Point(470,211)
$Label25.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$subnetPrefix                    = New-Object system.Windows.Forms.TextBox
$subnetPrefix.multiline          = $false
$subnetPrefix.text               = "10.0.1.0/24"
$subnetPrefix.width              = 178
$subnetPrefix.height             = 20
$subnetPrefix.location           = New-Object System.Drawing.Point(694,208)
$subnetPrefix.Font               = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label26                         = New-Object system.Windows.Forms.Label
$Label26.text                    = "VNET Location"
$Label26.AutoSize                = $true
$Label26.width                   = 25
$Label26.height                  = 10
$Label26.location                = New-Object System.Drawing.Point(470,238)
$Label26.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label27                         = New-Object system.Windows.Forms.Label
$Label27.text                    = "Subnet Name"
$Label27.AutoSize                = $true
$Label27.width                   = 25
$Label27.height                  = 10
$Label27.location                = New-Object System.Drawing.Point(470,261)
$Label27.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$subnetName                      = New-Object system.Windows.Forms.TextBox
$subnetName.multiline            = $false
$subnetName.width                = 178
$subnetName.height               = 20
$subnetName.location             = New-Object System.Drawing.Point(694,261)
$subnetName.Font                 = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label28                         = New-Object system.Windows.Forms.Label
$Label28.text                    = "Storage Account Location"
$Label28.AutoSize                = $true
$Label28.width                   = 25
$Label28.height                  = 10
$Label28.location                = New-Object System.Drawing.Point(470,287)
$Label28.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label29                         = New-Object system.Windows.Forms.Label
$Label29.text                    = "Storage Account Name"
$Label29.AutoSize                = $true
$Label29.width                   = 25
$Label29.height                  = 10
$Label29.location                = New-Object System.Drawing.Point(470,320)
$Label29.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$storageaccountName              = New-Object system.Windows.Forms.TextBox
$storageaccountName.multiline    = $false
$storageaccountName.text         = "All lowercase no special characters"
$storageaccountName.width        = 178
$storageaccountName.height       = 20
$storageaccountName.location     = New-Object System.Drawing.Point(694,315)
$storageaccountName.Font         = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label30                         = New-Object system.Windows.Forms.Label
$Label30.text                    = "File Share Folder Name"
$Label30.AutoSize                = $true
$Label30.width                   = 25
$Label30.height                  = 10
$Label30.location                = New-Object System.Drawing.Point(470,340)
$Label30.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$fileshareFolderName             = New-Object system.Windows.Forms.TextBox
$fileshareFolderName.multiline   = $false
$fileshareFolderName.width       = 178
$fileshareFolderName.height      = 20
$fileshareFolderName.location    = New-Object System.Drawing.Point(694,339)
$fileshareFolderName.Font        = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label32                         = New-Object system.Windows.Forms.Label
$Label32.text                    = "Log Analytics Location (DR)"
$Label32.AutoSize                = $true
$Label32.width                   = 25
$Label32.height                  = 10
$Label32.location                = New-Object System.Drawing.Point(470,398)
$Label32.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label33                         = New-Object system.Windows.Forms.Label
$Label33.text                    = "Image Sig Name (DR)"
$Label33.AutoSize                = $true
$Label33.width                   = 25
$Label33.height                  = 10
$Label33.location                = New-Object System.Drawing.Point(470,427)
$Label33.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$sigName2                        = New-Object system.Windows.Forms.TextBox
$sigName2.multiline              = $false
$sigName2.width                  = 178
$sigName2.height                 = 20
$sigName2.location               = New-Object System.Drawing.Point(694,424)
$sigName2.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label34                         = New-Object system.Windows.Forms.Label
$Label34.text                    = "Image Gallery Location (DR)"
$Label34.AutoSize                = $true
$Label34.width                   = 25
$Label34.height                  = 10
$Label34.location                = New-Object System.Drawing.Point(470,455)
$Label34.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label35                         = New-Object system.Windows.Forms.Label
$Label35.text                    = "VNET Name (DR)"
$Label35.AutoSize                = $true
$Label35.width                   = 25
$Label35.height                  = 10
$Label35.location                = New-Object System.Drawing.Point(470,480)
$Label35.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$vnetName2                       = New-Object system.Windows.Forms.TextBox
$vnetName2.multiline             = $false
$vnetName2.width                 = 178
$vnetName2.height                = 20
$vnetName2.location              = New-Object System.Drawing.Point(694,480)
$vnetName2.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label36                         = New-Object system.Windows.Forms.Label
$Label36.text                    = "Create AVD Deployment"
$Label36.AutoSize                = $true
$Label36.width                   = 25
$Label36.height                  = 10
$Label36.location                = New-Object System.Drawing.Point(309,15)
$Label36.Font                    = New-Object System.Drawing.Font('Calibri',20)

$update                          = New-Object system.Windows.Forms.Button
$update.text                     = "1-Update Params"
$update.width                    = 160
$update.height                   = 65
$update.location                 = New-Object System.Drawing.Point(278,716)
$update.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',13)

$login                           = New-Object system.Windows.Forms.Button
$login.text                      = "2-Azure Login"
$login.width                     = 170
$login.height                    = 65
$login.location                  = New-Object System.Drawing.Point(464,716)
$login.Font                      = New-Object System.Drawing.Font('Microsoft Sans Serif',13)

$deploy                          = New-Object system.Windows.Forms.Button
$deploy.text                     = "3-Deploy"
$deploy.width                    = 160
$deploy.height                   = 64
$deploy.location                 = New-Object System.Drawing.Point(278,791)
$deploy.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',13)

$Build                           = New-Object system.Windows.Forms.Button
$Build.text                      = "4-Build Image"
$Build.width                     = 169
$Build.height                    = 63
$Build.location                  = New-Object System.Drawing.Point(465,791)
$Build.Font                      = New-Object System.Drawing.Font('Microsoft Sans Serif',13)

$exit                            = New-Object system.Windows.Forms.Button
$exit.text                       = "5-Exit"
$exit.width                      = 172
$exit.height                     = 64
$exit.location                   = New-Object System.Drawing.Point(644,791)
$exit.Font                       = New-Object System.Drawing.Font('Microsoft Sans Serif',13)

$preferredAppGroupType           = New-Object system.Windows.Forms.ComboBox
$preferredAppGroupType.text      = "App Group"
$preferredAppGroupType.width     = 178
$preferredAppGroupType.height    = 20
@('Desktop','RailApplications') | ForEach-Object {[void] $preferredAppGroupType.Items.Add($_)}
$preferredAppGroupType.location  = New-Object System.Drawing.Point(253,258)
$preferredAppGroupType.Font      = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$hostPoolType                    = New-Object system.Windows.Forms.ComboBox
$hostPoolType.text               = "Pool Type"
$hostPoolType.width              = 178
$hostPoolType.height             = 20
@('Pooled','Personal') | ForEach-Object {[void] $hostPoolType.Items.Add($_)}
$hostPoolType.location           = New-Object System.Drawing.Point(253,310)
$hostPoolType.Font               = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$loadBalancerType                       = New-Object system.Windows.Forms.ComboBox
$loadBalancerType.text                  = "Balance"
$loadBalancerType.width                 = 178
$loadBalancerType.height                = 20
@('breadthfirst','depthfirst') | ForEach-Object {[void] $loadBalancerType.Items.Add($_)}
$loadBalancerType.location              = New-Object System.Drawing.Point(253,335)
$loadBalancerType.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Lowercase                       = New-Object system.Windows.Forms.ToolTip
$Lowercase.ToolTipTitle          = "Lowercase, no special characters"
$Lowercase.isBalloon             = $true

$sigLocation                     = New-Object system.Windows.Forms.ComboBox
$sigLocation.text                = "region"
$sigLocation.width               = 178
$sigLocation.height              = 20
@('uksouth','ukwest','northeurope','westeurope') | ForEach-Object {[void] $sigLocation.Items.Add($_)}
$sigLocation.location            = New-Object System.Drawing.Point(251,510)
$sigLocation.Font                = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$imageLocation                   = New-Object system.Windows.Forms.ComboBox
$imageLocation.text              = "region"
$imageLocation.width             = 178
$imageLocation.height            = 20
@('uksouth','ukwest','northeurope','westeurope') | ForEach-Object {[void] $imageLocation.Items.Add($_)}
$imageLocation.location          = New-Object System.Drawing.Point(251,609)
$imageLocation.Font              = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$vnetLocation                    = New-Object system.Windows.Forms.ComboBox
$vnetLocation.text               = "region"
$vnetLocation.width              = 178
$vnetLocation.height             = 20
@('uksouth','ukwest','northeurope','westeurope') | ForEach-Object {[void] $vnetLocation.Items.Add($_)}
$vnetLocation.location           = New-Object System.Drawing.Point(693,234)
$vnetLocation.Font               = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$storageaccountlocation          = New-Object system.Windows.Forms.ComboBox
$storageaccountlocation.text     = "region"
$storageaccountlocation.width    = 178
$storageaccountlocation.height   = 20
@('uksouth','ukwest','northeurope','westeurope') | ForEach-Object {[void] $storageaccountlocation.Items.Add($_)}
$storageaccountlocation.location  = New-Object System.Drawing.Point(694,286)
$storageaccountlocation.Font     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$logAnalyticsLocation2           = New-Object system.Windows.Forms.ComboBox
$logAnalyticsLocation2.text      = "region"
$logAnalyticsLocation2.width     = 178
$logAnalyticsLocation2.height    = 20
@('uksouth','ukwest','northeurope','westeurope') | ForEach-Object {[void] $logAnalyticsLocation2.Items.Add($_)}
$logAnalyticsLocation2.location  = New-Object System.Drawing.Point(693,395)
$logAnalyticsLocation2.Font      = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$sigLocation2                    = New-Object system.Windows.Forms.ComboBox
$sigLocation2.text               = "region"
$sigLocation2.width              = 178
$sigLocation2.height             = 20
@('uksouth','ukwest','northeurope','westeurope') | ForEach-Object {[void] $sigLocation2.Items.Add($_)}
$sigLocation2.location           = New-Object System.Drawing.Point(693,452)
$sigLocation2.Font               = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$vnetaddressPrefix2              = New-Object system.Windows.Forms.TextBox
$vnetaddressPrefix2.multiline    = $false
$vnetaddressPrefix2.width        = 178
$vnetaddressPrefix2.height       = 20
$vnetaddressPrefix2.location     = New-Object System.Drawing.Point(694,510)
$vnetaddressPrefix2.Font         = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$subnetPrefix2                   = New-Object system.Windows.Forms.TextBox
$subnetPrefix2.multiline         = $false
$subnetPrefix2.width             = 178
$subnetPrefix2.height            = 20
$subnetPrefix2.location          = New-Object System.Drawing.Point(694,543)
$subnetPrefix2.Font              = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$subnetName2                     = New-Object system.Windows.Forms.TextBox
$subnetName2.multiline           = $false
$subnetName2.width               = 178
$subnetName2.height              = 20
$subnetName2.location            = New-Object System.Drawing.Point(694,602)
$subnetName2.Font                = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$storageaccountName2             = New-Object system.Windows.Forms.TextBox
$storageaccountName2.multiline   = $false
$storageaccountName2.width       = 178
$storageaccountName2.height      = 20
$storageaccountName2.location    = New-Object System.Drawing.Point(694,660)
$storageaccountName2.Font        = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$fileshareFolderName2            = New-Object system.Windows.Forms.TextBox
$fileshareFolderName2.multiline  = $false
$fileshareFolderName2.width      = 178
$fileshareFolderName2.height     = 20
$fileshareFolderName2.location   = New-Object System.Drawing.Point(694,691)
$fileshareFolderName2.Font       = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label37                         = New-Object system.Windows.Forms.Label
$Label37.text                    = "VNET Address Prefix (DR)"
$Label37.AutoSize                = $true
$Label37.width                   = 25
$Label37.height                  = 10
$Label37.location                = New-Object System.Drawing.Point(470,510)
$Label37.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label38                         = New-Object system.Windows.Forms.Label
$Label38.text                    = "Subnet Prefix (DR)"
$Label38.AutoSize                = $true
$Label38.width                   = 25
$Label38.height                  = 10
$Label38.location                = New-Object System.Drawing.Point(470,546)
$Label38.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label39                         = New-Object system.Windows.Forms.Label
$Label39.text                    = "VNET Location (DR)"
$Label39.AutoSize                = $true
$Label39.width                   = 25
$Label39.height                  = 10
$Label39.location                = New-Object System.Drawing.Point(470,576)
$Label39.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label40                         = New-Object system.Windows.Forms.Label
$Label40.text                    = "Subnet Name (DR)"
$Label40.AutoSize                = $true
$Label40.width                   = 25
$Label40.height                  = 10
$Label40.location                = New-Object System.Drawing.Point(470,609)
$Label40.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label41                         = New-Object system.Windows.Forms.Label
$Label41.text                    = "Storage Account Location (DR)"
$Label41.AutoSize                = $true
$Label41.width                   = 25
$Label41.height                  = 10
$Label41.location                = New-Object System.Drawing.Point(470,635)
$Label41.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label42                         = New-Object system.Windows.Forms.Label
$Label42.text                    = "Storage Account Name (DR)"
$Label42.AutoSize                = $true
$Label42.width                   = 25
$Label42.height                  = 10
$Label42.location                = New-Object System.Drawing.Point(470,660)
$Label42.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label43                         = New-Object system.Windows.Forms.Label
$Label43.text                    = "File Share Name (DR)"
$Label43.AutoSize                = $true
$Label43.width                   = 25
$Label43.height                  = 10
$Label43.location                = New-Object System.Drawing.Point(470,691)
$Label43.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$vnetLocation2                   = New-Object system.Windows.Forms.ComboBox
$vnetLocation2.text              = "region"
$vnetLocation2.width             = 178
$vnetLocation2.height            = 20
@('uksouth','ukwest','northeurope','westeurope') | ForEach-Object {[void] $vnetLocation2.Items.Add($_)}
$vnetLocation2.location          = New-Object System.Drawing.Point(694,570)
$vnetLocation2.Font              = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$storageaccountlocation2         = New-Object system.Windows.Forms.ComboBox
$storageaccountlocation2.text    = "region"
$storageaccountlocation2.width   = 178
$storageaccountlocation2.height  = 20
@('uksouth','ukwest','northeurope','westeurope') | ForEach-Object {[void] $storageaccountlocation2.Items.Add($_)}
$storageaccountlocation2.location  = New-Object System.Drawing.Point(694,632)
$storageaccountlocation2.Font    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label44                         = New-Object system.Windows.Forms.Label
$Label44.text                    = "Created by Andrew Taylor (andrewstaylor.com)"
$Label44.AutoSize                = $true
$Label44.width                   = 25
$Label44.height                  = 10
$Label44.location                = New-Object System.Drawing.Point(7,848)
$Label44.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',8)




if ($answer2 -eq 6) {
    #Display MR only
    $AVDDeployment.controls.AddRange(@($OrgMgmtGrpName,$resourceGroupPrefix,$Label1,$hostpoolName,$Label2,$hostpoolFriendlyName,$Label3,$appgroupName,$Label4,$appgroupFriendlyName,$Label5,$workspaceName,$Label6,$workspaceNameFriendlyName,$Label7,$Label8,$avdbackplanelocation,$Label9,$Label10,$Label11,$logAnalyticsWorkspaceName,$Label12,$Label13,$azureSubscriptionID,$Label14,$automationaccountname,$Label15,$sigName,$Label16,$Label17,$imageDefinitionName,$Label18,$imageSKU,$Label19,$loganalyticslocation,$Label20,$roleNameGalleryImage,$Label22,$useridentity,$Label23,$vnetName,$Label24,$vnetaddressPrefix,$Label25,$subnetPrefix,$Label26,$Label27,$subnetName,$Label28,$Label29,$storageaccountName,$Label30,$fileshareFolderName,$Label32,$Label33,$sigName2,$Label34,$Label35,$vnetName2,$Label36,$update,$login,$deploy,$exit,$preferredAppGroupType,$hostPoolType,$loadBalancerType,$sigLocation,$imageLocation,$vnetLocation,$storageaccountlocation,$logAnalyticsLocation2,$sigLocation2,$vnetaddressPrefix2,$subnetPrefix2,$subnetName2,$storageaccountName2,$fileshareFolderName2,$Label37,$Label38,$Label39,$Label40,$Label41,$Label42,$Label43,$vnetLocation2,$storageaccountlocation2,$Label44,$Build))

}

else {
    #Display SR
    $AVDDeployment.controls.AddRange(@($OrgMgmtGrpName,$resourceGroupPrefix,$Label1,$hostpoolName,$Label2,$hostpoolFriendlyName,$Label3,$appgroupName,$Label4,$appgroupFriendlyName,$Label5,$workspaceName,$Label6,$workspaceNameFriendlyName,$Label7,$Label8,$avdbackplanelocation,$Label9,$Label10,$Label11,$logAnalyticsWorkspaceName,$Label12,$Label13,$azureSubscriptionID,$Label14,$automationaccountname,$Label15,$sigName,$Label16,$Label17,$imageDefinitionName,$Label18,$imageSKU,$Label19,$loganalyticslocation,$Label20,$roleNameGalleryImage,$Label22,$useridentity,$Label23,$vnetName,$Label24,$vnetaddressPrefix,$Label25,$subnetPrefix,$Label26,$Label27,$subnetName,$Label28,$Label29,$storageaccountName,$Label30,$fileshareFolderName,$update,$login,$deploy,$exit,$preferredAppGroupType,$hostPoolType,$loadBalancerType,$sigLocation,$imageLocation,$vnetLocation,$storageaccountlocation,$Label44,$Build))


}




###############################################################################################################################################
#####                                                  UPDATE PARAMETERS                                                                     ##
###############################################################################################################################################
$update.Add_Click({ 

  #Download files and update parameters.json

  $output = $output2.value
  $expath = $path2.value

  $wc = New-Object System.Net.WebClient
  $wc.DownloadFile($url.value, $output)
  
  Expand-Archive $output -DestinationPath $expath -Force

  #Remove Zip file downloaded
  remove-item $output -Force

  #Open json file
  $json = Get-Content $jsonfile.value | ConvertFrom-Json 
  $json.parameters.resourceGroupPrefix.value = $resourceGroupPrefix.Text
$json.parameters.hostpoolName.value = $hostpoolName.Text
$json.parameters.hostpoolFriendlyName.value = $hostpoolFriendlyName.Text
$json.parameters.appgroupName.value = $appgroupName.Text
$json.parameters.appgroupNameFriendlyName.value = $appgroupFriendlyName.Text
$json.parameters.workspaceName.value = $workspaceName.Text
$json.parameters.workspaceNameFriendlyName.value = $workspaceNameFriendlyName.Text
$json.parameters.preferredAppGroupType.value = $preferredAppGroupType.Text
$json.parameters.avdbackplanelocation.value = $avdbackplanelocation.Text
$json.parameters.hostPoolType.value = $hostPoolType.Text
$json.parameters.loadBalancerType.value = $loadBalancerType.Text
$json.parameters.logAnalyticsWorkspaceName.value = $logAnalyticsWorkspaceName.Text
$json.parameters.logAnalyticsLocation.value = $logAnalyticsLocation.Text
$json.parameters.azureSubscriptionID.value = $azureSubscriptionID.Text
$json.parameters.automationaccountname.value = $automationaccountname.Text
$json.parameters.sigName.value = $sigName.Text
$json.parameters.sigLocation.value = $sigLocation.Text
$json.parameters.imagePublisher.value = "microsoftwindowsdesktop"
$json.parameters.imageDefinitionName.value = $imageDefinitionName.Text
$json.parameters.imageOffer.value = "office-365"
$json.parameters.imageSKU.value = $imageSKU.Text
$json.parameters.imageLocation.value = $imageLocation.Text
$json.parameters.roleNameGalleryImage.value = $roleNameGalleryImage.Text
$json.parameters.templateImageResourceGroup.value = $resourceGroupPrefix.Text + "-IMG"
$json.parameters.useridentity.value = $useridentity.Text
$json.parameters.vnetName.value = $vnetName.Text
$json.parameters.vnetaddressPrefix.value = $vnetaddressPrefix.Text
$json.parameters.subnetPrefix.value = $subnetPrefix.Text
$json.parameters.vnetLocation.value = $vnetLocation.Text
$json.parameters.subnetName.value = $subnetName.Text
$json.parameters.storageaccountlocation.value = $storageaccountlocation.Text
$json.parameters.storageaccountName.value = $storageaccountName.Text
$json.parameters.storageaccountkind.value = "FileStorage"
$json.parameters.storageaccountkindblob.value = "BlobStorage"
$json.parameters.storgeaccountglobalRedundancy.value = "Premium_LRS"
$json.parameters.fileshareFolderName.value = $fileshareFolderName.Text

if ($answer.value -eq 6) {
#Add values for MR
$json.parameters.logAnalyticsLocation2.value = $logAnalyticsLocation2.Text
$json.parameters.sigName2.value = $sigName2.Text
$json.parameters.sigLocation2.value = $sigLocation2.Text
$json.parameters.vnetName2.value = $vnetName2.Text
$json.parameters.vnetaddressPrefix2.value = $vnetaddressPrefix2.Text
$json.parameters.subnetPrefix2.value = $subnetPrefix2.Text
$json.parameters.vnetLocation2.value = $vnetLocation2.Text
$json.parameters.subnetName2.value = $subnetName2.Text
$json.parameters.storageaccountlocation2.value = $storageaccountlocation2.Text
$json.parameters.storageaccountName2.value = $storageaccountName2.Text
$json.parameters.storageaccountkind2.value = "FileStorage"
$json.parameters.storgeaccountglobalRedundancy2.value = "Premium_LRS"
$json.parameters.fileshareFolderName2.value = $fileshareFolderName2.Text
}
#Update Params
$json | ConvertTo-Json | Out-File $jsonfile.value

#Popup box to show completed
Add-Type -AssemblyName PresentationCore,PresentationFramework
$msgBody = "Parameters updated and saved to " + $jsonfile.value
[System.Windows.MessageBox]::Show($msgBody)

 })





###############################################################################################################################################
#####                                                  AZURE LOGIN                                                                           ##
###############################################################################################################################################
$login.Add_Click({ 

#Get Creds and connect
write-host "Connect to Azure"
Connect-AzAccount 
Add-Type -AssemblyName PresentationCore,PresentationFramework
$msgBody = "Azure Connected"
[System.Windows.MessageBox]::Show($msgBody)

 })



###############################################################################################################################################
#####                                                  DEPLOY                                                                                ##
###############################################################################################################################################
$deploy.Add_Click({  
    Set-Location $pathaz
    $Location =  $loganalyticslocation.text

    write-host "Deploying Environment using Bicep"
    Set-AzContext $azureSubscriptionID.Text

#Deploy AVD
New-AzSubscriptionDeployment -Location $location -TemplateFile ./main.bicep -TemplateParameterFile ./parameters.json

Add-Type -AssemblyName PresentationCore,PresentationFramework
$msgBody = "Environment Built"
[System.Windows.MessageBox]::Show($msgBody)


})





###############################################################################################################################################
#####                                                  PRE-LOAD ITEMS                                                                        ##
###############################################################################################################################################

$AVDDeployment.Add_Load({

#Load Bits

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


Write-Host "Installing AZ modules if required (current user scope)"

#Install AZ Module if not available
if (Get-Module -ListAvailable -Name Az*) {
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


Write-Host "Installing AZ modules if required (current user scope)"

if (Get-Module -ListAvailable -Name Az.ImageBuilder) {
    Write-Host "AZ Module Already Installed"
} 
else {
    try {
        Install-Module -Name Az.ImageBuilder -Scope CurrentUser -Repository PSGallery -Force
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
        Install-Module -Name Az.ManagedServiceIdentity -Scope CurrentUser -Repository PSGallery -Force
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

  })





###############################################################################################################################################
#####                                                  QUIT AND CLEANUP                                                                      ##
###############################################################################################################################################
$exit.Add_Click({ 
#Close Form and del dir
Set-Location "c:\windows"
Get-ChildItem -Path $pathaz2.value -Exclude 'parameters.json' | ForEach-Object {Remove-Item $_ -Recurse }
$AVDDeployment.Close()

 })



###############################################################################################################################################
#####                                                  Build Image                                                                           ##
###############################################################################################################################################

$Build.Add_Click({ 

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
    
    $json = Get-Content $jsonfile.value | ConvertFrom-Json 
    
    # Destination image resource group name
    $igr1 = $json.parameters.resourceGroupPrefix.value
    
    $imageResourceGroup = $igr1 + "IMG"
    
    # Azure region
    if ($answer.value -eq 6) {
    
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

    Start-Sleep -Seconds 120 
    
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
       -Sku $imageSKU.Text


##Get Storage Details
     
if ($answer.value -eq 6) {
    
    #Get Storage Account
    $files1 = $json.parameters.resourceGroupPrefix.value
    
    $fileresource = $files1 + "FILESERVICES"
    $share = get-azstorageaccount -ResourceGroupName $fileresource -Name $json.parameters.storageaccountName.value
    
    #Get Share Details
    $store = get-azstorageshare -Context $share.Context | Select-Object Name
    $files2 = "\\\\" + $share.StorageAccountName + ".file.core.windows.net\\" + $store.Name
    
    
    #Get Storage AccountDR
    $files1dr = $json.parameters.resourceGroupPrefix.value
    
    $fileresourcedr = $files1dr + "FILESERVICES-DR"
    $sharedr = get-azstorageaccount -ResourceGroupName $fileresourcedr -Name $json.parameters.storageaccountName2.value
    
    #Get Share Details
    $storedr = get-azstorageshare -Context $sharedr.Context | Select-Object Name
    $files2dr = "\\\\" + $sharedr.StorageAccountName + ".file.core.windows.net\\" + $storedr.Name
    
    $FSLogixCD = "type=smb,connectionString="+$files2+";type=smb,connectionString="+$files2DR
    $fslocation = "CCDLocations"
  }
  
  else {
  
  #Get Storage Account
  $files1 = $json.parameters.resourceGroupPrefix.value
  
  $fileresource = $files1 + "FILESERVICES"
  $share = get-azstorageaccount -ResourceGroupName $fileresource -Name $json.parameters.storageaccountName.value
  
  #Get Share Details
  $store = get-azstorageshare -Context $share.Context | Select-Object Name
  $files2 = "\\\\" + $share.StorageAccountName + ".file.core.windows.net\\" + $store.Name
  $fslocation = "VHDLocations"
  $FSLogixCD = $files2
  }


      #Set Variables
      $region1 = $json.parameters.sigLocation.value
      if ($answer.value -eq 6) {
      $region2 = $json.parameters.sigLocation2.value
      }
      else {
        $replregion2 = "ukwest"
      }
    
      
          ## 3.2 DOWNLOAD AND CONFIGURE THE TEMPLATE WITH YOUR PARAMS
    $templateFilePath = "armTemplateWinSIG.json"
    
    Invoke-WebRequest `
       -Uri "https://raw.githubusercontent.com/andrew-s-taylor/public/main/Powershell%20Scripts/AVD/avd-custom.json" `
       -OutFile $templateFilePath `
       -UseBasicParsing `
       -Headers @{"Cache-Control"="no-cache"}
    
    (Get-Content -path $templateFilePath -Raw ) `
       -replace '<subscriptionID>',$subscriptionID | Set-Content -Path $templateFilePath
    (Get-Content -path $templateFilePath -Raw ) `
       -replace '<rgName>',$imageResourceGroup | Set-Content -Path $templateFilePath
    (Get-Content -path $templateFilePath -Raw ) `
       -replace '<runOutputName>',$runOutputName | Set-Content -Path $templateFilePath
    (Get-Content -path $templateFilePath -Raw ) `
       -replace '<imageDefName>',$imageDefName | Set-Content -Path $templateFilePath
    (Get-Content -path $templateFilePath -Raw ) `
       -replace '<sharedImageGalName>',$myGalleryName | Set-Content -Path $templateFilePath
    (Get-Content -path $templateFilePath -Raw ) `
       -replace '<region1>',$location | Set-Content -Path $templateFilePath
    (Get-Content -path $templateFilePath -Raw ) `
       -replace '<region2>',$replRegion2 | Set-Content -Path $templateFilePath
    (Get-Content -path $templateFilePath -Raw ) `
       -replace '<imagebuildersku>',$json.parameters.imageSKU.value | Set-Content -Path $templateFilePath
    (Get-Content -path $templateFilePath -Raw ) `
       -replace '<locationtype>',$fslocation | Set-Content -Path $templateFilePath
    (Get-Content -path $templateFilePath -Raw ) `
       -replace '<location>',$FSLogixCD | Set-Content -Path $templateFilePath
    ((Get-Content -path $templateFilePath -Raw) -replace '<imgBuilderId>',$identityNameResourceId) | Set-Content -Path $templateFilePath

    
      ##CREATE THE IMAGE VERSION
      New-AzResourceGroupDeployment `
      -ResourceGroupName $imageResourceGroup `
      -TemplateFile $templateFilePath `
      -Pre `
      -api-version "2019-05-01-preview" `
      -imageTemplateName $imageTemplateName `
      -svclocation $location
   
      ##BUILD THE IMAGE
      Invoke-AzResourceAction `
      -ResourceName $imageTemplateName `
      -ResourceGroupName $imageResourceGroup `
      -ResourceType Microsoft.VirtualMachineImages/imageTemplates `
      -Pre `
      -Action Run `
      -ApiVersion "2019-05-01-preview" `
      -Force
   
   
      #This has now kicked of a build into the AIB service which will do its stuff.
      #To check the Image Build Process run the cmd below. 
      #It will go from Building, to Distributing to Complete, it will take some time.

           write-host "Image Building"
    
    
      #Wait for it to complete


    
      Do {
        $state = Get-AzImageBuilderTemplate -ImageTemplateName $imageTemplateName -ResourceGroupName $imageResourceGroup | Select-Object -Property Name, LastRunStatusRunState, LastRunStatusMessage
        Write-Host "Running"
        Start-Sleep 5
    }
    Until (
        
        $state.LastRunStatusRunState -eq "Succeeded"
    )
    Write-Host "Completed"
    
    
    
    
    
      write-host "Build Completed"



       Add-Type -AssemblyName PresentationCore,PresentationFramework
       $msgBody = "Environment Built"
       [System.Windows.MessageBox]::Show($msgBody)
     
       })




  
###############################################################################################################################################
#####                                                  DISPLAY FORM                                                                          ##
###############################################################################################################################################
[void]$AVDDeployment.ShowDialog()
