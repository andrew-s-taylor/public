<#
.SYNOPSIS
  Builds an Azure Landing Zone
.DESCRIPTION
Builds an Azure Landing Zone using Bicep with GUI

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
#Open Parameters File
#Create path for files
#Ask for something to keep files individual

#Create Temp Folder
$random = Get-Random -Maximum 1000 
$random = $random.ToString()
$date =get-date -format yyMMddmmss
$date = $date.ToString()
$path2 = $random + "-"  + $date
$path = "c:\temp\" + $path2 + "\"
$pathaz = "c:\temp\" + $path2 + "\az-landing-main"
$output3 = "c:\temp\" + $path2 + "\main.zip"

New-Item -ItemType Directory -Path $path


###############################################################################################################################################
#####                                                 SET VARIABLES                                                                          ##
###############################################################################################################################################
Write-Host "Directory Created"
Set-Location $path
$jsonfile = [PSCustomObject]@{value=$pathaz+"\parameters.json"}
$path2 = [PSCustomObject]@{value=$path}
$pathaz2 = [PSCustomObject]@{value=$pathaz}
$output2 = [PSCustomObject]@{value=$output3}


###############################################################################################################################################
#####                                                  CREATE FORM                                                                           ##
###############################################################################################################################################

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

$Form                            = New-Object system.Windows.Forms.Form
$Form.ClientSize                 = New-Object System.Drawing.Point(896,689)
$Form.text                       = "Azure Landing Zone Creation Tool - v1.0"
$Form.TopMost                    = $false

$OrgMgmtGrpName                  = New-Object system.Windows.Forms.Label
$OrgMgmtGrpName.text             = "Org Management Group Name"
$OrgMgmtGrpName.AutoSize         = $true
$OrgMgmtGrpName.width            = 25
$OrgMgmtGrpName.height           = 10
$OrgMgmtGrpName.location         = New-Object System.Drawing.Point(31,73)
$OrgMgmtGrpName.Font             = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$orggroup                        = New-Object system.Windows.Forms.TextBox
$orggroup.multiline              = $false
$orggroup.width                  = 178
$orggroup.height                 = 20
$orggroup.location               = New-Object System.Drawing.Point(253,72)
$orggroup.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label1                          = New-Object system.Windows.Forms.Label
$Label1.text                     = "Dev Management Group Name"
$Label1.AutoSize                 = $true
$Label1.width                    = 25
$Label1.height                   = 10
$Label1.location                 = New-Object System.Drawing.Point(31,108)
$Label1.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$devgroup                        = New-Object system.Windows.Forms.TextBox
$devgroup.multiline              = $false
$devgroup.width                  = 178
$devgroup.height                 = 20
$devgroup.location               = New-Object System.Drawing.Point(253,105)
$devgroup.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label2                          = New-Object system.Windows.Forms.Label
$Label2.text                     = "Test Management Group Name"
$Label2.AutoSize                 = $true
$Label2.width                    = 25
$Label2.height                   = 10
$Label2.location                 = New-Object System.Drawing.Point(31,135)
$Label2.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$testgroup                       = New-Object system.Windows.Forms.TextBox
$testgroup.multiline             = $false
$testgroup.width                 = 178
$testgroup.height                = 20
$testgroup.location              = New-Object System.Drawing.Point(253,132)
$testgroup.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label3                          = New-Object system.Windows.Forms.Label
$Label3.text                     = "Prod Management Grop Name"
$Label3.AutoSize                 = $true
$Label3.width                    = 25
$Label3.height                   = 10
$Label3.location                 = New-Object System.Drawing.Point(31,163)
$Label3.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$prodgroup                       = New-Object system.Windows.Forms.TextBox
$prodgroup.multiline             = $false
$prodgroup.width                 = 178
$prodgroup.height                = 20
$prodgroup.location              = New-Object System.Drawing.Point(253,159)
$prodgroup.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label4                          = New-Object system.Windows.Forms.Label
$Label4.text                     = "Exclusions Group Name"
$Label4.AutoSize                 = $true
$Label4.width                    = 25
$Label4.height                   = 10
$Label4.location                 = New-Object System.Drawing.Point(31,187)
$Label4.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$excgroup                        = New-Object system.Windows.Forms.TextBox
$excgroup.multiline              = $false
$excgroup.width                  = 178
$excgroup.height                 = 20
$excgroup.location               = New-Object System.Drawing.Point(253,184)
$excgroup.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label5                          = New-Object system.Windows.Forms.Label
$Label5.text                     = "Subscription ID"
$Label5.AutoSize                 = $true
$Label5.width                    = 25
$Label5.height                   = 10
$Label5.location                 = New-Object System.Drawing.Point(31,211)
$Label5.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$SubscriptionID                  = New-Object system.Windows.Forms.TextBox
$SubscriptionID.multiline        = $false
$SubscriptionID.width            = 178
$SubscriptionID.height           = 20
$SubscriptionID.location         = New-Object System.Drawing.Point(253,208)
$SubscriptionID.Font             = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label6                          = New-Object system.Windows.Forms.Label
$Label6.text                     = "Resource Tag Name"
$Label6.AutoSize                 = $true
$Label6.width                    = 25
$Label6.height                   = 10
$Label6.location                 = New-Object System.Drawing.Point(31,238)
$Label6.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$tagname                         = New-Object system.Windows.Forms.TextBox
$tagname.multiline               = $false
$tagname.width                   = 178
$tagname.height                  = 20
$tagname.location                = New-Object System.Drawing.Point(253,234)
$tagname.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label7                          = New-Object system.Windows.Forms.Label
$Label7.text                     = "Resource Tag Value"
$Label7.AutoSize                 = $true
$Label7.width                    = 25
$Label7.height                   = 10
$Label7.location                 = New-Object System.Drawing.Point(31,271)
$Label7.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$tagvalue                        = New-Object system.Windows.Forms.TextBox
$tagvalue.multiline              = $false
$tagvalue.width                  = 178
$tagvalue.height                 = 20
$tagvalue.location               = New-Object System.Drawing.Point(253,261)
$tagvalue.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label8                          = New-Object system.Windows.Forms.Label
$Label8.text                     = "Region"
$Label8.AutoSize                 = $true
$Label8.width                    = 25
$Label8.height                   = 10
$Label8.location                 = New-Object System.Drawing.Point(31,297)
$Label8.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$region                          = New-Object system.Windows.Forms.ComboBox
$region.text                     = "region"
$region.width                    = 178
$region.height                   = 20
@('uksouth','ukwest','northeurope','westeurope','australiaeast','australiasoutheast') | ForEach-Object {[void] $region.Items.Add($_)}
$region.location                 = New-Object System.Drawing.Point(253,286)
$region.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label9                          = New-Object system.Windows.Forms.Label
$Label9.text                     = "Hub Resource Group Name"
$Label9.AutoSize                 = $true
$Label9.width                    = 25
$Label9.height                   = 10
$Label9.location                 = New-Object System.Drawing.Point(31,326)
$Label9.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$hubrgname                       = New-Object system.Windows.Forms.TextBox
$hubrgname.multiline             = $false
$hubrgname.width                 = 178
$hubrgname.height                = 20
$hubrgname.location              = New-Object System.Drawing.Point(253,315)
$hubrgname.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label10                         = New-Object system.Windows.Forms.Label
$Label10.text                    = "Spoke Resource Group Name"
$Label10.AutoSize                = $true
$Label10.width                   = 25
$Label10.height                  = 10
$Label10.location                = New-Object System.Drawing.Point(32,348)
$Label10.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$spokergname                     = New-Object system.Windows.Forms.TextBox
$spokergname.multiline           = $false
$spokergname.width               = 178
$spokergname.height              = 20
$spokergname.location            = New-Object System.Drawing.Point(253,339)
$spokergname.Font                = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label11                         = New-Object system.Windows.Forms.Label
$Label11.text                    = "Hub Network Name"
$Label11.AutoSize                = $true
$Label11.width                   = 25
$Label11.height                  = 10
$Label11.location                = New-Object System.Drawing.Point(31,370)
$Label11.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$hubname                         = New-Object system.Windows.Forms.TextBox
$hubname.multiline               = $false
$hubname.width                   = 178
$hubname.height                  = 20
$hubname.location                = New-Object System.Drawing.Point(253,368)
$hubname.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label12                         = New-Object system.Windows.Forms.Label
$Label12.text                    = "Hub Network Address Space"
$Label12.AutoSize                = $true
$Label12.width                   = 25
$Label12.height                  = 10
$Label12.location                = New-Object System.Drawing.Point(30,398)
$Label12.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$hubspace                        = New-Object system.Windows.Forms.TextBox
$hubspace.multiline              = $false
$hubspace.width                  = 178
$hubspace.height                 = 20
$hubspace.location               = New-Object System.Drawing.Point(253,395)
$hubspace.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label13                         = New-Object system.Windows.Forms.Label
$Label13.text                    = "Hub Firewall Subnet Address Space"
$Label13.AutoSize                = $true
$Label13.width                   = 25
$Label13.height                  = 10
$Label13.location                = New-Object System.Drawing.Point(31,427)
$Label13.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$hubfwsubnet                     = New-Object system.Windows.Forms.TextBox
$hubfwsubnet.multiline           = $false
$hubfwsubnet.width               = 178
$hubfwsubnet.height              = 20
$hubfwsubnet.location            = New-Object System.Drawing.Point(252,424)
$hubfwsubnet.Font                = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label14                         = New-Object system.Windows.Forms.Label
$Label14.text                    = "Spoke Network Name"
$Label14.AutoSize                = $true
$Label14.width                   = 25
$Label14.height                  = 10
$Label14.location                = New-Object System.Drawing.Point(31,455)
$Label14.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$spokename                       = New-Object system.Windows.Forms.TextBox
$spokename.multiline             = $false
$spokename.width                 = 178
$spokename.height                = 20
$spokename.location              = New-Object System.Drawing.Point(253,452)
$spokename.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label15                         = New-Object system.Windows.Forms.Label
$Label15.text                    = "Spoke Address Space"
$Label15.AutoSize                = $true
$Label15.width                   = 25
$Label15.height                  = 10
$Label15.location                = New-Object System.Drawing.Point(31,480)
$Label15.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$spokespace                      = New-Object system.Windows.Forms.TextBox
$spokespace.multiline            = $false
$spokespace.width                = 178
$spokespace.height               = 20
$spokespace.location             = New-Object System.Drawing.Point(252,480)
$spokespace.Font                 = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label16                         = New-Object system.Windows.Forms.Label
$Label16.text                    = "Spoke Subnet Name"
$Label16.AutoSize                = $true
$Label16.width                   = 25
$Label16.height                  = 10
$Label16.location                = New-Object System.Drawing.Point(31,510)
$Label16.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$spokesnname                     = New-Object system.Windows.Forms.TextBox
$spokesnname.multiline           = $false
$spokesnname.width               = 178
$spokesnname.height              = 20
$spokesnname.location            = New-Object System.Drawing.Point(253,509)
$spokesnname.Font                = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label17                         = New-Object system.Windows.Forms.Label
$Label17.text                    = "Spoke Subnet Address Space"
$Label17.AutoSize                = $true
$Label17.width                   = 25
$Label17.height                  = 10
$Label17.location                = New-Object System.Drawing.Point(33,546)
$Label17.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$spokesnspace                    = New-Object system.Windows.Forms.TextBox
$spokesnspace.multiline          = $false
$spokesnspace.width              = 178
$spokesnspace.height             = 20
$spokesnspace.location           = New-Object System.Drawing.Point(253,545)
$spokesnspace.Font               = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label18                         = New-Object system.Windows.Forms.Label
$Label18.text                    = "Log Analytics Workspace Name"
$Label18.AutoSize                = $true
$Label18.width                   = 25
$Label18.height                  = 10
$Label18.location                = New-Object System.Drawing.Point(31,580)
$Label18.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$logAnalyticsWorkspaceName       = New-Object system.Windows.Forms.TextBox
$logAnalyticsWorkspaceName.multiline  = $false
$logAnalyticsWorkspaceName.width  = 178
$logAnalyticsWorkspaceName.height  = 20
$logAnalyticsWorkspaceName.location  = New-Object System.Drawing.Point(253,580)
$logAnalyticsWorkspaceName.Font  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label19                         = New-Object system.Windows.Forms.Label
$Label19.text                    = "Log Analytics Location"
$Label19.AutoSize                = $true
$Label19.width                   = 25
$Label19.height                  = 10
$Label19.location                = New-Object System.Drawing.Point(31,619)
$Label19.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$loganalyticslocation            = New-Object system.Windows.Forms.ComboBox
$loganalyticslocation.text       = "region"
$loganalyticslocation.width      = 178
$loganalyticslocation.height     = 20
@('uksouth','ukwest','northeurope','westeurope','australiaeast','australiasoutheast') | ForEach-Object {[void] $loganalyticslocation.Items.Add($_)} 
$loganalyticslocation.location   = New-Object System.Drawing.Point(254,619)
$loganalyticslocation.Font       = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label20                         = New-Object system.Windows.Forms.Label
$Label20.text                    = "Monitoring Resource Group Name"
$Label20.AutoSize                = $true
$Label20.width                   = 25
$Label20.height                  = 10
$Label20.location                = New-Object System.Drawing.Point(470,73)
$Label20.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$monitoringrg                    = New-Object system.Windows.Forms.TextBox
$monitoringrg.multiline          = $false
$monitoringrg.width              = 178
$monitoringrg.height             = 20
$monitoringrg.location           = New-Object System.Drawing.Point(694,72)
$monitoringrg.Font               = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label21                         = New-Object system.Windows.Forms.Label
$Label21.text                    = "Server Resource Group Name"
$Label21.AutoSize                = $true
$Label21.width                   = 25
$Label21.height                  = 10
$Label21.location                = New-Object System.Drawing.Point(470,108)
$Label21.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$serverrg                        = New-Object system.Windows.Forms.TextBox
$serverrg.multiline              = $false
$serverrg.width                  = 178
$serverrg.height                 = 20
$serverrg.location               = New-Object System.Drawing.Point(694,98)
$serverrg.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label22                         = New-Object system.Windows.Forms.Label
$Label22.text                    = "Server Admin Username"
$Label22.AutoSize                = $true
$Label22.width                   = 25
$Label22.height                  = 10
$Label22.location                = New-Object System.Drawing.Point(470,132)
$Label22.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$adminUserName                   = New-Object system.Windows.Forms.TextBox
$adminUserName.multiline         = $false
$adminUserName.width             = 178
$adminUserName.height            = 20
$adminUserName.location          = New-Object System.Drawing.Point(694,125)
$adminUserName.Font              = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label23                         = New-Object system.Windows.Forms.Label
$Label23.text                    = "Server Admin Password"
$Label23.AutoSize                = $true
$Label23.width                   = 25
$Label23.height                  = 10
$Label23.location                = New-Object System.Drawing.Point(470,163)
$Label23.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$adminPassword                   = New-Object system.Windows.Forms.TextBox
$adminPassword.multiline         = $false
$adminPassword.width             = 178
$adminPassword.height            = 20
$adminPassword.location          = New-Object System.Drawing.Point(694,159)
$adminPassword.Font              = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label24                         = New-Object system.Windows.Forms.Label
$Label24.text                    = "DNS Label Prefix"
$Label24.AutoSize                = $true
$Label24.width                   = 25
$Label24.height                  = 10
$Label24.location                = New-Object System.Drawing.Point(470,187)
$Label24.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$dnsLabelPrefix                  = New-Object system.Windows.Forms.TextBox
$dnsLabelPrefix.multiline        = $false
$dnsLabelPrefix.width            = 178
$dnsLabelPrefix.height           = 20
$dnsLabelPrefix.location         = New-Object System.Drawing.Point(694,184)
$dnsLabelPrefix.Font             = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label25                         = New-Object system.Windows.Forms.Label
$Label25.text                    = "Storage Account Name"
$Label25.AutoSize                = $true
$Label25.width                   = 25
$Label25.height                  = 10
$Label25.location                = New-Object System.Drawing.Point(470,211)
$Label25.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$storageAccountName              = New-Object system.Windows.Forms.TextBox
$storageAccountName.multiline    = $false
$storageAccountName.width        = 178
$storageAccountName.height       = 20
$storageAccountName.location     = New-Object System.Drawing.Point(694,208)
$storageAccountName.Font         = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label26                         = New-Object system.Windows.Forms.Label
$Label26.text                    = "VM name"
$Label26.AutoSize                = $true
$Label26.width                   = 25
$Label26.height                  = 10
$Label26.location                = New-Object System.Drawing.Point(470,238)
$Label26.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$vmName                          = New-Object system.Windows.Forms.TextBox
$vmName.multiline                = $false
$vmName.width                    = 178
$vmName.height                   = 20
$vmName.location                 = New-Object System.Drawing.Point(694,234)
$vmName.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label27                         = New-Object system.Windows.Forms.Label
$Label27.text                    = "Network Security Group Name"
$Label27.AutoSize                = $true
$Label27.width                   = 25
$Label27.height                  = 10
$Label27.location                = New-Object System.Drawing.Point(470,261)
$Label27.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$networkSecurityGroupName        = New-Object system.Windows.Forms.TextBox
$networkSecurityGroupName.multiline  = $false
$networkSecurityGroupName.width  = 178
$networkSecurityGroupName.height  = 20
$networkSecurityGroupName.location  = New-Object System.Drawing.Point(694,261)
$networkSecurityGroupName.Font   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label28                         = New-Object system.Windows.Forms.Label
$Label28.text                    = "VPN Subnet Address Space"
$Label28.AutoSize                = $true
$Label28.width                   = 25
$Label28.height                  = 10
$Label28.location                = New-Object System.Drawing.Point(470,287)
$Label28.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$vpnsubnet                       = New-Object system.Windows.Forms.TextBox
$vpnsubnet.multiline             = $false
$vpnsubnet.width                 = 178
$vpnsubnet.height                = 20
$vpnsubnet.location              = New-Object System.Drawing.Point(694,287)
$vpnsubnet.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label29                         = New-Object system.Windows.Forms.Label
$Label29.text                    = "VPN Gateway Public IP Name"
$Label29.AutoSize                = $true
$Label29.width                   = 25
$Label29.height                  = 10
$Label29.location                = New-Object System.Drawing.Point(470,320)
$Label29.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$vpngwpipname                    = New-Object system.Windows.Forms.TextBox
$vpngwpipname.multiline          = $false
$vpngwpipname.width              = 178
$vpngwpipname.height             = 20
$vpngwpipname.location           = New-Object System.Drawing.Point(694,315)
$vpngwpipname.Font               = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label30                         = New-Object system.Windows.Forms.Label
$Label30.text                    = "VPN Gateway Name"
$Label30.AutoSize                = $true
$Label30.width                   = 25
$Label30.height                  = 10
$Label30.location                = New-Object System.Drawing.Point(470,340)
$Label30.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$vpngwname                       = New-Object system.Windows.Forms.TextBox
$vpngwname.multiline             = $false
$vpngwname.width                 = 178
$vpngwname.height                = 20
$vpngwname.location              = New-Object System.Drawing.Point(694,339)
$vpngwname.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label31                         = New-Object system.Windows.Forms.Label
$Label31.text                    = "Local Network Gateway Name"
$Label31.AutoSize                = $true
$Label31.width                   = 25
$Label31.height                  = 10
$Label31.location                = New-Object System.Drawing.Point(470,370)
$Label31.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$localnetworkgwname              = New-Object system.Windows.Forms.TextBox
$localnetworkgwname.multiline    = $false
$localnetworkgwname.width        = 178
$localnetworkgwname.height       = 20
$localnetworkgwname.location     = New-Object System.Drawing.Point(694,368)
$localnetworkgwname.Font         = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label32                         = New-Object system.Windows.Forms.Label
$Label32.text                    = "Local Network Address Prefix"
$Label32.AutoSize                = $true
$Label32.width                   = 25
$Label32.height                  = 10
$Label32.location                = New-Object System.Drawing.Point(470,398)
$Label32.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$addressprefixes                 = New-Object system.Windows.Forms.TextBox
$addressprefixes.multiline       = $false
$addressprefixes.width           = 178
$addressprefixes.height          = 20
$addressprefixes.location        = New-Object System.Drawing.Point(694,395)
$addressprefixes.Font            = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label33                         = New-Object system.Windows.Forms.Label
$Label33.text                    = "Local Network Gateway IP"
$Label33.AutoSize                = $true
$Label33.width                   = 25
$Label33.height                  = 10
$Label33.location                = New-Object System.Drawing.Point(470,427)
$Label33.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$gwipaddress                     = New-Object system.Windows.Forms.TextBox
$gwipaddress.multiline           = $false
$gwipaddress.width               = 178
$gwipaddress.height              = 20
$gwipaddress.location            = New-Object System.Drawing.Point(694,424)
$gwipaddress.Font                = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label34                         = New-Object system.Windows.Forms.Label
$Label34.text                    = "BGP Peering Address"
$Label34.AutoSize                = $true
$Label34.width                   = 25
$Label34.height                  = 10
$Label34.location                = New-Object System.Drawing.Point(470,455)
$Label34.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$bgppeeringpddress               = New-Object system.Windows.Forms.TextBox
$bgppeeringpddress.multiline     = $false
$bgppeeringpddress.width         = 178
$bgppeeringpddress.height        = 20
$bgppeeringpddress.location      = New-Object System.Drawing.Point(694,452)
$bgppeeringpddress.Font          = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label35                         = New-Object system.Windows.Forms.Label
$Label35.text                    = "Server/Devices Subnet (spoke)"
$Label35.AutoSize                = $true
$Label35.width                   = 25
$Label35.height                  = 10
$Label35.location                = New-Object System.Drawing.Point(470,480)
$Label35.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$devicesubnet                    = New-Object system.Windows.Forms.TextBox
$devicesubnet.multiline          = $false
$devicesubnet.width              = 178
$devicesubnet.height             = 20
$devicesubnet.location           = New-Object System.Drawing.Point(694,480)
$devicesubnet.Font               = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label36                         = New-Object system.Windows.Forms.Label
$Label36.text                    = "Create Azure Landing Zone"
$Label36.AutoSize                = $true
$Label36.width                   = 25
$Label36.height                  = 10
$Label36.location                = New-Object System.Drawing.Point(309,15)
$Label36.Font                    = New-Object System.Drawing.Font('Calibri',20)

$update                          = New-Object system.Windows.Forms.Button
$update.text                     = "1-Update Params"
$update.width                    = 160
$update.height                   = 65
$update.location                 = New-Object System.Drawing.Point(469,514)
$update.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',13)

$login                           = New-Object system.Windows.Forms.Button
$login.text                      = "2-Azure Login"
$login.width                     = 170
$login.height                    = 65
$login.location                  = New-Object System.Drawing.Point(655,514)
$login.Font                      = New-Object System.Drawing.Font('Microsoft Sans Serif',13)

$deploy                          = New-Object system.Windows.Forms.Button
$deploy.text                     = "3-Deploy"
$deploy.width                    = 160
$deploy.height                   = 64
$deploy.location                 = New-Object System.Drawing.Point(469,589)
$deploy.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',13)

$exit                            = New-Object system.Windows.Forms.Button
$exit.text                       = "4-Exit"
$exit.width                      = 172
$exit.height                     = 64
$exit.location                   = New-Object System.Drawing.Point(654,589)
$exit.Font                       = New-Object System.Drawing.Font('Microsoft Sans Serif',13)

$Label37                         = New-Object system.Windows.Forms.Label
$Label37.text                    = "Created by Andrew Taylor (andrewstaylor.com)"
$Label37.AutoSize                = $true
$Label37.width                   = 25
$Label37.height                  = 10
$Label37.location                = New-Object System.Drawing.Point(5,668)
$Label37.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',8)

$Form.controls.AddRange(@($OrgMgmtGrpName,$orggroup,$Label1,$devgroup,$Label2,$testgroup,$Label3,$prodgroup,$Label4,$excgroup,$Label5,$SubscriptionID,$Label6,$tagname,$Label7,$tagvalue,$Label8,$region,$Label9,$hubrgname,$Label10,$spokergname,$Label11,$hubname,$Label12,$hubspace,$Label13,$hubfwsubnet,$Label14,$spokename,$Label15,$spokespace,$Label16,$spokesnname,$Label17,$spokesnspace,$Label18,$logAnalyticsWorkspaceName,$Label19,$loganalyticslocation,$Label20,$monitoringrg,$Label21,$serverrg,$Label22,$adminUserName,$Label23,$adminPassword,$Label24,$dnsLabelPrefix,$Label25,$storageAccountName,$Label26,$vmName,$Label27,$networkSecurityGroupName,$Label28,$vpnsubnet,$Label29,$vpngwpipname,$Label30,$vpngwname,$Label31,$localnetworkgwname,$Label32,$addressprefixes,$Label33,$gwipaddress,$Label34,$bgppeeringpddress,$Label35,$devicesubnet,$Label36,$update,$login,$deploy,$exit,$Label37))





###############################################################################################################################################
#####                                                  UPDATE PARAMETERS                                                                     ##
###############################################################################################################################################
$update.Add_Click({  

  #Download files and update parameters.json

  $url = "https://github.com/andrew-s-taylor/az-landing/archive/main.zip"
  $output = $output2.value
  $expath = $path2.value

    Invoke-WebRequest -Uri $url -OutFile $output -Method Get
    
  Expand-Archive $output -DestinationPath $expath -Force

  #Remove Zip file downloaded
  remove-item $output -Force

$json = Get-Content $jsonfile.value | ConvertFrom-Json 
    $json.parameters.orggroup.value = $orggroup.text
$json.parameters.devgroup.value = $devgroup.text
$json.parameters.testgroup.value = $testgroup.text
$json.parameters.prodgroup.value = $prodgroup.text
$json.parameters.excgroup.value = $excgroup.text
$json.parameters.SubscriptionID.value = $SubscriptionID.text
$json.parameters.tagname.value = $tagname.text
$json.parameters.tagvalue.value = $tagvalue.text
$json.parameters.region.value = $region.text
$json.parameters.hubrgname.value = $hubrgname.text
$json.parameters.spokergname.value = $spokergname.text
$json.parameters.hubname.value = $hubname.text
$json.parameters.hubspace.value = $hubspace.text
$json.parameters.hubfwsubnet.value = $hubfwsubnet.text
$json.parameters.spokename.value = $spokename.text
$json.parameters.spokespace.value = $spokespace.text
$json.parameters.spokesnname.value = $spokesnname.text
$json.parameters.spokesnspace.value = $spokesnspace.text
$json.parameters.logAnalyticsWorkspaceName.value = $logAnalyticsWorkspaceName.text
$json.parameters.logAnalyticslocation.value = $logAnalyticslocation.text
$json.parameters.monitoringrg.value = $monitoringrg.text
$json.parameters.serverrg.value = $serverrg.text
$json.parameters.adminUserName.value = $adminUserName.text
$json.parameters.adminPassword.value = $adminPassword.text
$json.parameters.dnsLabelPrefix.value = $dnsLabelPrefix.text
$json.parameters.storageAccountName.value = $storageAccountName.text
$json.parameters.vmName.value = $vmName.text
$json.parameters.networkSecurityGroupName.value = $networkSecurityGroupName.text
$json.parameters.vpnsubnet.value = $vpnsubnet.text
$json.parameters.vpngwpipname.value = $vpngwpipname.text
$json.parameters.vpngwname.value = $vpngwname.text
$json.parameters.localnetworkgwname.value = $localnetworkgwname.text
$json.parameters.addressprefixes.value = $addressprefixes.text
$json.parameters.gwipaddress.value = $gwipaddress.text
$json.parameters.bgppeeringpddress.value = $bgppeeringpddress.text
$json.parameters.devicesubnet.value = $devicesubnet.text

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
#Connectaz

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

#Deploy
Set-Location $pathaz
$Location =  $region.text

write-host "Deploying Environment using Bicep"

#Deploy Landing Zone
New-AzSubscriptionDeployment -Location $location -TemplateFile ./main.bicep -TemplateParameterFile ./parameters.json


Add-Type -AssemblyName PresentationCore,PresentationFramework
$msgBody = "Environment Built"
[System.Windows.MessageBox]::Show($msgBody)

 })






###############################################################################################################################################
#####                                                  PRE-LOAD ITEMS                                                                        ##
###############################################################################################################################################
$Form.Add_Load({

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




write-host "Importing Modules"
#Import AZ Module
import-module -Name Az

  })







###############################################################################################################################################
#####                                                  EXIT AND CLEANUP                                                                      ##
###############################################################################################################################################
$exit.Add_Click({ 

#Close Form and del dir
Set-Location "c:\windows"
Get-ChildItem -Path $pathaz2.value -Exclude 'parameters.json' | ForEach-Object {Remove-Item $_ -Recurse }
$form.Close()

 })






###############################################################################################################################################
#####                                                  LOAD FORM                                                                             ##
###############################################################################################################################################
[void]$Form.ShowDialog()
