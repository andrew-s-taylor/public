## Disable FastBoot
Log-Write -LogPath $sLogFile -LineValue "Disable FastBoot"
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
$Name = "HiberbootEnabled"
$value = "0"
$Type = "DWORD"
addregkey($registryPath, $Name, $value, $Type)
