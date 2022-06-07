##Get BIOS Info
$biosinfo = Get-CimInstance -ClassName Win32_ComputerSystem
#Manufacturer
$manufacturer = $biosinfo.Manufacturer
#Total RAM
$RAM = $biosinfo.TotalPhysicalMemory

#Check if it's a Dell
if ($manufacturer -like "*Dell*") {
    $manufacturer = "Dell"
}
else {
    $manufacturer = "Unknown"
}

#Tidy the RAM
$RAM =  ($RAM / 1024 / 1024)
$RAM = [math]::Round($RAM, 0)

#Look for Steam
$InstalledSoftware = Get-ChildItem "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
if ($InstalledSoftware -like "*Steam*") {
    $steam = "Detected"
}
else {
    $steam = "Not Detected"
}

$hash = @{ Manufacturer = $manufacturer; RAM = $RAM; Steam = $steam}
return $hash | ConvertTo-Json -Compress
