##Detect Teams Chat

$MSTeams = "MicrosoftTeams"
##Look for Package
$WinPackage = Get-AppxPackage -allusers | Where-Object {$_.Name -eq $MSTeams}
$ProvisionedPackage = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $WinPackage }
##Set a detection counter
$detection = 0
##If the package is found, increment the counter
if ($null -ne $WinPackage) 
{
    $detection++
} 
if ($null -ne $ProvisionedPackage) 
{
    $detection++
}

if ($detection -eq 0) {
    write-host "Teams Chat not found, compliance met"
    exit 0
}
else {
    write-host "Teams Chat found, compliance not met"
    exit 1
}

