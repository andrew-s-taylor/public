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
  Version:        1.1
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

# SIG # Begin signature block
# MIIoGQYJKoZIhvcNAQcCoIIoCjCCKAYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDY+m9R4YjAdl+q
# 5UBsi3Tcz/XU5vou0USi+FPgEGXO7aCCIRwwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggauMIIElqADAgECAhAHNje3JFR82Ees/ShmKl5bMA0GCSqG
# SIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDAeFw0yMjAzMjMwMDAwMDBaFw0zNzAzMjIyMzU5NTlaMGMx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMy
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcg
# Q0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDGhjUGSbPBPXJJUVXH
# JQPE8pE3qZdRodbSg9GeTKJtoLDMg/la9hGhRBVCX6SI82j6ffOciQt/nR+eDzMf
# UBMLJnOWbfhXqAJ9/UO0hNoR8XOxs+4rgISKIhjf69o9xBd/qxkrPkLcZ47qUT3w
# 1lbU5ygt69OxtXXnHwZljZQp09nsad/ZkIdGAHvbREGJ3HxqV3rwN3mfXazL6IRk
# tFLydkf3YYMZ3V+0VAshaG43IbtArF+y3kp9zvU5EmfvDqVjbOSmxR3NNg1c1eYb
# qMFkdECnwHLFuk4fsbVYTXn+149zk6wsOeKlSNbwsDETqVcplicu9Yemj052FVUm
# cJgmf6AaRyBD40NjgHt1biclkJg6OBGz9vae5jtb7IHeIhTZgirHkr+g3uM+onP6
# 5x9abJTyUpURK1h0QCirc0PO30qhHGs4xSnzyqqWc0Jon7ZGs506o9UD4L/wojzK
# QtwYSH8UNM/STKvvmz3+DrhkKvp1KCRB7UK/BZxmSVJQ9FHzNklNiyDSLFc1eSuo
# 80VgvCONWPfcYd6T/jnA+bIwpUzX6ZhKWD7TA4j+s4/TXkt2ElGTyYwMO1uKIqjB
# Jgj5FBASA31fI7tk42PgpuE+9sJ0sj8eCXbsq11GdeJgo1gJASgADoRU7s7pXche
# MBK9Rp6103a50g5rmQzSM7TNsQIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB
# /wIBADAdBgNVHQ4EFgQUuhbZbU2FL3MpdpovdYxqII+eyG8wHwYDVR0jBBgwFoAU
# 7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoG
# CCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29j
# c3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDig
# NqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZI
# hvcNAQELBQADggIBAH1ZjsCTtm+YqUQiAX5m1tghQuGwGC4QTRPPMFPOvxj7x1Bd
# 4ksp+3CKDaopafxpwc8dB+k+YMjYC+VcW9dth/qEICU0MWfNthKWb8RQTGIdDAiC
# qBa9qVbPFXONASIlzpVpP0d3+3J0FNf/q0+KLHqrhc1DX+1gtqpPkWaeLJ7giqzl
# /Yy8ZCaHbJK9nXzQcAp876i8dU+6WvepELJd6f8oVInw1YpxdmXazPByoyP6wCeC
# RK6ZJxurJB4mwbfeKuv2nrF5mYGjVoarCkXJ38SNoOeY+/umnXKvxMfBwWpx2cYT
# gAnEtp/Nh4cku0+jSbl3ZpHxcpzpSwJSpzd+k1OsOx0ISQ+UzTl63f8lY5knLD0/
# a6fxZsNBzU+2QJshIUDQtxMkzdwdeDrknq3lNHGS1yZr5Dhzq6YBT70/O3itTK37
# xJV77QpfMzmHQXh6OOmc4d0j/R0o08f56PGYX/sr2H7yRp11LB4nLCbbbxV7HhmL
# NriT1ObyF5lZynDwN7+YAN8gFk8n+2BnFqFmut1VwDophrCYoCvtlUG3OtUVmDG0
# YgkPCr2B2RP+v6TR81fZvAT6gt4y3wSJ8ADNXcL50CN/AAvkdgIm2fBldkKmKYcJ
# RyvmfxqkhQ/8mJb2VVQrH4D6wPIOK+XW+6kvRBVK5xMOHds3OBqhK/bt1nz8MIIG
# sDCCBJigAwIBAgIQCK1AsmDSnEyfXs2pvZOu2TANBgkqhkiG9w0BAQwFADBiMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQw
# HhcNMjEwNDI5MDAwMDAwWhcNMzYwNDI4MjM1OTU5WjBpMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0
# ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExMIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1bQvQtAorXi3XdU5WRuxiEL1M4zr
# PYGXcMW7xIUmMJ+kjmjYXPXrNCQH4UtP03hD9BfXHtr50tVnGlJPDqFX/IiZwZHM
# gQM+TXAkZLON4gh9NH1MgFcSa0OamfLFOx/y78tHWhOmTLMBICXzENOLsvsI8Irg
# nQnAZaf6mIBJNYc9URnokCF4RS6hnyzhGMIazMXuk0lwQjKP+8bqHPNlaJGiTUyC
# EUhSaN4QvRRXXegYE2XFf7JPhSxIpFaENdb5LpyqABXRN/4aBpTCfMjqGzLmysL0
# p6MDDnSlrzm2q2AS4+jWufcx4dyt5Big2MEjR0ezoQ9uo6ttmAaDG7dqZy3SvUQa
# khCBj7A7CdfHmzJawv9qYFSLScGT7eG0XOBv6yb5jNWy+TgQ5urOkfW+0/tvk2E0
# XLyTRSiDNipmKF+wc86LJiUGsoPUXPYVGUztYuBeM/Lo6OwKp7ADK5GyNnm+960I
# HnWmZcy740hQ83eRGv7bUKJGyGFYmPV8AhY8gyitOYbs1LcNU9D4R+Z1MI3sMJN2
# FKZbS110YU0/EpF23r9Yy3IQKUHw1cVtJnZoEUETWJrcJisB9IlNWdt4z4FKPkBH
# X8mBUHOFECMhWWCKZFTBzCEa6DgZfGYczXg4RTCZT/9jT0y7qg0IU0F8WD1Hs/q2
# 7IwyCQLMbDwMVhECAwEAAaOCAVkwggFVMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYD
# VR0OBBYEFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB8GA1UdIwQYMBaAFOzX44LScV1k
# TN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcD
# AzB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2lj
# ZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0
# cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmww
# HAYDVR0gBBUwEzAHBgVngQwBAzAIBgZngQwBBAEwDQYJKoZIhvcNAQEMBQADggIB
# ADojRD2NCHbuj7w6mdNW4AIapfhINPMstuZ0ZveUcrEAyq9sMCcTEp6QRJ9L/Z6j
# fCbVN7w6XUhtldU/SfQnuxaBRVD9nL22heB2fjdxyyL3WqqQz/WTauPrINHVUHmI
# moqKwba9oUgYftzYgBoRGRjNYZmBVvbJ43bnxOQbX0P4PpT/djk9ntSZz0rdKOtf
# JqGVWEjVGv7XJz/9kNF2ht0csGBc8w2o7uCJob054ThO2m67Np375SFTWsPK6Wrx
# oj7bQ7gzyE84FJKZ9d3OVG3ZXQIUH0AzfAPilbLCIXVzUstG2MQ0HKKlS43Nb3Y3
# LIU/Gs4m6Ri+kAewQ3+ViCCCcPDMyu/9KTVcH4k4Vfc3iosJocsL6TEa/y4ZXDlx
# 4b6cpwoG1iZnt5LmTl/eeqxJzy6kdJKt2zyknIYf48FWGysj/4+16oh7cGvmoLr9
# Oj9FpsToFpFSi0HASIRLlk2rREDjjfAVKM7t8RhWByovEMQMCGQ8M4+uKIw8y4+I
# Cw2/O/TOHnuO77Xry7fwdxPm5yg/rBKupS8ibEH5glwVZsxsDsrFhsP2JjMMB0ug
# 0wcCampAMEhLNKhRILutG4UI4lkNbcoFUCvqShyepf2gpx8GdOfy1lKQ/a+FSCH5
# Vzu0nAPthkX0tGFuv2jiJmCG6sivqf6UHedjGzqGVnhOMIIGwjCCBKqgAwIBAgIQ
# BUSv85SdCDmmv9s/X+VhFjANBgkqhkiG9w0BAQsFADBjMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0
# ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMB4XDTIzMDcxNDAw
# MDAwMFoXDTM0MTAxMzIzNTk1OVowSDELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMSAwHgYDVQQDExdEaWdpQ2VydCBUaW1lc3RhbXAgMjAyMzCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKNTRYcdg45brD5UsyPgz5/X
# 5dLnXaEOCdwvSKOXejsqnGfcYhVYwamTEafNqrJq3RApih5iY2nTWJw1cb86l+uU
# UI8cIOrHmjsvlmbjaedp/lvD1isgHMGXlLSlUIHyz8sHpjBoyoNC2vx/CSSUpIIa
# 2mq62DvKXd4ZGIX7ReoNYWyd/nFexAaaPPDFLnkPG2ZS48jWPl/aQ9OE9dDH9kgt
# XkV1lnX+3RChG4PBuOZSlbVH13gpOWvgeFmX40QrStWVzu8IF+qCZE3/I+PKhu60
# pCFkcOvV5aDaY7Mu6QXuqvYk9R28mxyyt1/f8O52fTGZZUdVnUokL6wrl76f5P17
# cz4y7lI0+9S769SgLDSb495uZBkHNwGRDxy1Uc2qTGaDiGhiu7xBG3gZbeTZD+BY
# QfvYsSzhUa+0rRUGFOpiCBPTaR58ZE2dD9/O0V6MqqtQFcmzyrzXxDtoRKOlO0L9
# c33u3Qr/eTQQfqZcClhMAD6FaXXHg2TWdc2PEnZWpST618RrIbroHzSYLzrqawGw
# 9/sqhux7UjipmAmhcbJsca8+uG+W1eEQE/5hRwqM/vC2x9XH3mwk8L9CgsqgcT2c
# kpMEtGlwJw1Pt7U20clfCKRwo+wK8REuZODLIivK8SgTIUlRfgZm0zu++uuRONhR
# B8qUt+JQofM604qDy0B7AgMBAAGjggGLMIIBhzAOBgNVHQ8BAf8EBAMCB4AwDAYD
# VR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAgBgNVHSAEGTAXMAgG
# BmeBDAEEAjALBglghkgBhv1sBwEwHwYDVR0jBBgwFoAUuhbZbU2FL3MpdpovdYxq
# II+eyG8wHQYDVR0OBBYEFKW27xPn783QZKHVVqllMaPe1eNJMFoGA1UdHwRTMFEw
# T6BNoEuGSWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRH
# NFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcmwwgZAGCCsGAQUFBwEBBIGD
# MIGAMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wWAYIKwYB
# BQUHMAKGTGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0
# ZWRHNFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcnQwDQYJKoZIhvcNAQEL
# BQADggIBAIEa1t6gqbWYF7xwjU+KPGic2CX/yyzkzepdIpLsjCICqbjPgKjZ5+PF
# 7SaCinEvGN1Ott5s1+FgnCvt7T1IjrhrunxdvcJhN2hJd6PrkKoS1yeF844ektrC
# QDifXcigLiV4JZ0qBXqEKZi2V3mP2yZWK7Dzp703DNiYdk9WuVLCtp04qYHnbUFc
# jGnRuSvExnvPnPp44pMadqJpddNQ5EQSviANnqlE0PjlSXcIWiHFtM+YlRpUurm8
# wWkZus8W8oM3NG6wQSbd3lqXTzON1I13fXVFoaVYJmoDRd7ZULVQjK9WvUzF4UbF
# KNOt50MAcN7MmJ4ZiQPq1JE3701S88lgIcRWR+3aEUuMMsOI5ljitts++V+wQtaP
# 4xeR0arAVeOGv6wnLEHQmjNKqDbUuXKWfpd5OEhfysLcPTLfddY2Z1qJ+Panx+VP
# NTwAvb6cKmx5AdzaROY63jg7B145WPR8czFVoIARyxQMfq68/qTreWWqaNYiyjvr
# moI1VygWy2nyMpqy0tg6uLFGhmu6F/3Ed2wVbK6rr3M66ElGt9V/zLY4wNjsHPW2
# obhDLN9OTH0eaHDAdwrUAuBcYLso/zjlUlrWrBciI0707NMX+1Br/wd3H3GXREHJ
# uEbTbDJ8WC9nR2XlG3O2mflrLAZG70Ee8PBf4NvZrZCARK+AEEGKMIIHWzCCBUOg
# AwIBAgIQCLGfzbPa87AxVVgIAS8A6TANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQG
# EwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0
# IFRydXN0ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0Ex
# MB4XDTIzMTExNTAwMDAwMFoXDTI2MTExNzIzNTk1OVowYzELMAkGA1UEBhMCR0Ix
# FDASBgNVBAcTC1doaXRsZXkgQmF5MR4wHAYDVQQKExVBTkRSRVdTVEFZTE9SLkNP
# TSBMVEQxHjAcBgNVBAMTFUFORFJFV1NUQVlMT1IuQ09NIExURDCCAiIwDQYJKoZI
# hvcNAQEBBQADggIPADCCAgoCggIBAMOkYkLpzNH4Y1gUXF799uF0CrwW/Lme676+
# C9aZOJYzpq3/DIa81oWv9b4b0WwLpJVu0fOkAmxI6ocu4uf613jDMW0GfV4dRodu
# tryfuDuit4rndvJA6DIs0YG5xNlKTkY8AIvBP3IwEzUD1f57J5GiAprHGeoc4Utt
# zEuGA3ySqlsGEg0gCehWJznUkh3yM8XbksC0LuBmnY/dZJ/8ktCwCd38gfZEO9UD
# DSkie4VTY3T7VFbTiaH0bw+AvfcQVy2CSwkwfnkfYagSFkKar+MYwu7gqVXxrh3V
# /Gjval6PdM0A7EcTqmzrCRtvkWIR6bpz+3AIH6Fr6yTuG3XiLIL6sK/iF/9d4U2P
# iH1vJ/xfdhGj0rQ3/NBRsUBC3l1w41L5q9UX1Oh1lT1OuJ6hV/uank6JY3jpm+Of
# Z7YCTF2Hkz5y6h9T7sY0LTi68Vmtxa/EgEtG6JVNVsqP7WwEkQRxu/30qtjyoX8n
# zSuF7TmsRgmZ1SB+ISclejuqTNdhcycDhi3/IISgVJNRS/F6Z+VQGf3fh6ObdQLV
# woT0JnJjbD8PzJ12OoKgViTQhndaZbkfpiVifJ1uzWJrTW5wErH+qvutHVt4/sEZ
# AVS4PNfOcJXR0s0/L5JHkjtM4aGl62fAHjHj9JsClusj47cT6jROIqQI4ejz1slO
# oclOetCNAgMBAAGjggIDMIIB/zAfBgNVHSMEGDAWgBRoN+Drtjv4XxGG+/5hewiI
# ZfROQjAdBgNVHQ4EFgQU0HdOFfPxa9Yeb5O5J9UEiJkrK98wPgYDVR0gBDcwNTAz
# BgZngQwBBAEwKTAnBggrBgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20v
# Q1BTMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzCBtQYDVR0f
# BIGtMIGqMFOgUaBPhk1odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEzODQyMDIxQ0ExLmNybDBToFGg
# T4ZNaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29k
# ZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAyMUNBMS5jcmwwgZQGCCsGAQUFBwEBBIGH
# MIGEMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXAYIKwYB
# BQUHMAKGUGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0
# ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3J0MAkGA1UdEwQC
# MAAwDQYJKoZIhvcNAQELBQADggIBAEkRh2PwMiyravr66Zww6Pjl24KzDcGYMSxU
# KOEU4bykcOKgvS6V2zeZIs0D/oqct3hBKTGESSQWSA/Jkr1EMC04qJHO/Twr/sBD
# CDBMtJ9XAtO75J+oqDccM+g8Po+jjhqYJzKvbisVUvdsPqFll55vSzRvHGAA6hjy
# DyakGLROcNaSFZGdgOK2AMhQ8EULrE8Riri3D1ROuqGmUWKqcO9aqPHBf5wUwia8
# g980sTXquO5g4TWkZqSvwt1BHMmu69MR6loRAK17HvFcSicK6Pm0zid1KS2z4ntG
# B4Cfcg88aFLog3ciP2tfMi2xTnqN1K+YmU894Pl1lCp1xFvT6prm10Bs6BViKXfD
# fVFxXTB0mHoDNqGi/B8+rxf2z7u5foXPCzBYT+Q3cxtopvZtk29MpTY88GHDVJsF
# MBjX7zM6aCNKsTKC2jb92F+jlkc8clCQQnl3U4jqwbj4ur1JBP5QxQprWhwde0+M
# ifDVp0vHZsVZ0pnYMCKSG5bUr3wOU7EP321DwvvEsTjCy/XDgvy8ipU6w3GjcQQF
# mgp/BX/0JCHX+04QJ0JkR9TTFZR1B+zh3CcK1ZEtTtvuZfjQ3viXwlwtNLy43vbe
# 1J5WNTs0HjJXsfdbhY5kE5RhyfaxFBr21KYx+b+evYyolIS0wR6New6FqLgcc4Ge
# 94yaYVTqMYIGUzCCBk8CAQEwfTBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGln
# aUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgQ29kZSBT
# aWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExAhAIsZ/Ns9rzsDFVWAgBLwDp
# MA0GCWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJ
# KoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQB
# gjcCARUwLwYJKoZIhvcNAQkEMSIEILVqKrBEm4L8VplXh1Z+HOw63VYBMGy9MgOk
# yEAdO6YnMA0GCSqGSIb3DQEBAQUABIICAFwneqq0Y1feahJqNso7iOc04ysgfGMC
# gs+AiNQ5K4kgmhNUsuFmulRmvl7ANSNLZ/qKieor17vKhlSVb9Vf4kP9hJfLG04O
# qGRbMeq252qk8Vv882JtlaHQy7aXNFguRyjWMMAYFPfNRvc+iNM7pzDhjOaxb2f9
# kXI7YdnJvsPKIsHU2ubLjBthhC7eyJO5JhtGqrJwoZ65tHG2gwngZDWECNiJzmFk
# /OxiMMHqejcrBFZt4Z2MPo4lB+D2c6ZwLJE2DVUm3uspOOMoyMP4r4rZgsZKRKx8
# mFisKdoPMAnDBOnjIy4vYXKh4LETu340gagMn2Tn2Us8VbLrTZ3LvFmh3OO2fYSa
# SAVJuqQW8fByOvC4QvNl21SgOQ7mZHdpDUDkGCoXK6ywIwIEVCZcJDt1+lL2pnfv
# yDWAyYHvDhJueSUdElDcOmXEjg6kF8bVK8CdYb+qcWvR7VMBper+64lG+fElEVdb
# eDxqsAJcZLA4SPZXtmK6aFt+YHNFtYzCjVFkC8HSWEk5O/ddECdsL+Aou13oogi+
# G7wzh5hLFvFY/YiYnD5mivoggZtBFENyoxfihrsszLIz+fm7RXMAfrjWcBymas9L
# 3eymkemUUGTV/yb4xcAPxs3SmujcXU6nmnSggIlb2bFxIv6CdYgvVb4YPd8p4I7W
# NX9S+xBUNOOroYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkG
# A1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdp
# Q2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQ
# BUSv85SdCDmmv9s/X+VhFjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzEL
# BgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIzMTExNTIwNDUwMlowLwYJKoZI
# hvcNAQkEMSIEIKe77WuJ5Gz5OJ4UwLLbt/9M+CcfXHORxDw2o5Egs4kuMA0GCSqG
# SIb3DQEBAQUABIICACtlA3ehbov1I/MyQiv/CLmjCPTRSusOMxbnmkNPi2bbZHwt
# ZcVy91c5UkxxPYRhqW+d0BepGf2Yo3DduFzZMKg/BE/fvxHC3DbqdAT0+vuV3jM7
# HxUFU9LdWfFBrGqXsJpxSCI4XhDuB3dcSQqg/1s1ayA66s9vdjPNvdcaeWxmnd1A
# ou1XUXsmgAdc7ZNSjkVBsqPFGDKG6UH5WzMLSUtZDbxxRwIiI/Ne7y2hMtnPWmjt
# jPaF2BiId9irLomRqZ1+0vfIMWDCHcg09Aybfef9tJr5BcW3sArBc8HMYr1Ee4O0
# AEQxGhSiOIQJAyQoIGDVo2HZucvB/LKKzGHrT56DYQ3c6M+TtKtG6qwLcfNNRi1Y
# 6VfQtlg6nVoo/Dfx+iUNr83PMQLpIm1T/Nd3LtUdKqt8RSD4o9LM3e7UjsxXnqAC
# 8oVPj4XLM8eebiZWUi3vyd+Y9eRDxrKxmgIUuf5v4+AGgItK0eBuP55mD3qwXOQ+
# Tdl4kWKL52sMUg4ioipelPM2i5x5ck7yeXwQJjP9OJEici9pfhwcwpm7Mdyq2CFm
# ubdmWa+g2qr9b2PDCQqJvvmqx7KoAE9aiTg4Zzt0HkLMrl1MMoq99oOX8LI1ad32
# IPoaACde/SWQHhtagDFCJwpFN8m2XgzhYV9NTHWs1rjfksGw+Q6lfGZ1otKS
# SIG # End signature block
