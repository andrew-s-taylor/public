<#
.SYNOPSIS
  Configures FSLogix on AVD

.DESCRIPTION
 Azure Runbook to configure FSLogix on an AVD deployment

.INPUTS
Resource Group Name, FSLogix Path

.OUTPUTS
Verbose output

.NOTES
  Version:        1.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  19/06/2021
  Purpose/Change: Initial script development
  
.EXAMPLE
Params prompted in runbook
#>


param (
    [Parameter(Mandatory=$true)] 
    [String]  $FSLogixCD = 'FS Logix Path',
    [Parameter(Mandatory=$true)] 
    [String]  $RGName = 'Resource Group Name'
)

# Ensures you do not inherit an AzContext in your runbook
Disable-AzContextAutosave –Scope Process

$connection = Get-AutomationConnection -Name AzureRunAsConnection

# Wrap authentication in retry logic for transient network failures
$logonAttempt = 0
while(!($connectionResult) -And ($logonAttempt -le 10))
{
    $LogonAttempt++
    # Logging in to Azure...
    $connectionResult =    Connect-AzAccount `
                               -ServicePrincipal `
                               -Tenant $connection.TenantID `
                               -ApplicationId $connection.ApplicationID `
                               -CertificateThumbprint $connection.CertificateThumbprint

    Start-Sleep -Seconds 30
}

$AzureContext = Get-AzSubscription -SubscriptionId $connection.SubscriptionID


$Script = '

##########################
#   Configure FSLogix    #
##########################


if((Test-Path -LiteralPath "HKLM:\SOFTWARE\FSLogix\Profiles") -ne $true) {  New-Item "HKLM:\SOFTWARE\FSLogix\Profiles" -force -ea SilentlyContinue };
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "Enabled" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "VHDLocations" -Value $FSLogixCD -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "ConcurrentUserSessions" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "IsDynamic" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "KeepLocalDir" -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "VolumeType" -Value "vhdx" -PropertyType String -Force -ea SilentlyContinue;
    
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\FSLogix\ODFC") -ne $true) {  New-Item "HKLM:\SOFTWARE\FSLogix\ODFC" -force -ea SilentlyContinue };
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\ODFC" -Name "Enabled" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\ODFC" -Name "VHDLocations" -Value $FSLogixCD -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\ODFC" -Name "IncludeOneDrive" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\ODFC" -Name "IncludeOneNote" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\ODFC" -Name "IncludeOneNote_UWP" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\ODFC" -Name "IncludeOutlook" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\ODFC" -Name "IncludeOutlookPersonalization" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\ODFC" -Name "IncludeSharepoint" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\FSLogix\ODFC" -Name "IncludeTeams" -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;'


Out-File -FilePath .\fslogix-config.ps1 -InputObject $Script


Import-Module Az.Compute
$MSHvms = Get-AzVM -ResourceGroupName $RGName
foreach ($mshvm in $MSHvms) {

$result = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -Name $mshvm.Name -CommandId 'RunPowerShellScript' -ScriptPath '.\fslogix-config.ps1'

$status = $result.value[0].message
write-output "Complete on $mshvm"
}

