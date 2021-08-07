$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
IF(!(Test-Path $registryPath))
{
New-Item -Path $registryPath -Force | Out-Null
}

$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
IF(!(Test-Path $registryPath))
{
New-Item -Path $registryPath -Force | Out-Null
}


$temppath = "C:\temp"
IF(!(Test-Path $temppath))
{
    New-Item -ItemType Directory -Path "C:\temp"
}

New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging' -Name 'LogDroppedPackets' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;

New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging' -Name 'LogSuccessfulConnections' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;



New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging' -Name 'LogFilePath' -Value "c:\temp\firewall.log" -PropertyType String -Force -ea SilentlyContinue;



New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging' -Name 'LogDroppedPackets' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;

New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging' -Name 'LogSuccessfulConnections' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;

New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging' -Name 'LogFilePath' -Value "c:\temp\firewall.log" -PropertyType String -Force -ea SilentlyContinue;