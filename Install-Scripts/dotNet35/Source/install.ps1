Param(
[Parameter(Mandatory=$true)]
[ValidateSet("Install", "Uninstall")]
[String[]]
$Mode
)
 
If ($Mode -eq "Install")
 
{
if (Test-path .\sxs\Microsoft-Windows-NetFx3-OnDemand-Package*.cab)
{
#Offline Installer
Enable-WindowsOptionalFeature -Online -FeatureName 'NetFx3' -Source .\sxs\ -NoRestart -LimitAccess
 
}
else
{
#Online installer
Enable-WindowsOptionalFeature -Online -FeatureName 'NetFx3' -NoRestart
}
 
}
 
If ($Mode -eq "Uninstall")
 
{
 
Disable-WindowsOptionalFeature -Online -FeatureName 'NetFx3' -Remove -NoRestart
 
}