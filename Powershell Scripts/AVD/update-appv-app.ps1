<#
.SYNOPSIS
  Updates App-V apps on WVD Machines

.DESCRIPTION
 Azure Runbook to update App-V apps on WVD machines

.INPUTS
Package name, Resource group name, host names (wildcard), packagepath

.OUTPUTS
Verbose output

.NOTES
  Version:        1.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  13/01/2020
  Purpose/Change: Initial script development
  
.EXAMPLE
Params prompted in runbook
#>


param (
    [Parameter(Mandatory=$true)] 
    [String]  $packagename = '',
    [Parameter(Mandatory=$true)] 
    [String]  $RGName = '',
    [Parameter(Mandatory=$true)] 
    [String]  $HostNames = '',    
    [Parameter(Mandatory=$true)]
    [String] $packagepath = ''
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
#   Update Application   #
##########################


#Stop the Package
Get-AppvClientPackage $packagename | Stop-AppvClientPackage -Global

#Update the Package
add-appvclientpackage $packagepath | publish-appvclientpackage -global'


Out-File -FilePath .\updatescript.ps1 -InputObject $Script


Import-Module Az.Compute
$MSHvms = Get-AzVM -ResourceGroupName $RGName -Name $HostNames
foreach ($mshvm in $MSHvms) {

$result = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -Name $mshvm.Name -CommandId 'RunPowerShellScript' -ScriptPath '.\updatescript.ps1'

$status = $result.value[0].message
write-output "Complete on $mshvm"
}

