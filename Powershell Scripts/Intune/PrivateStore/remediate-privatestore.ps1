Write-Host "Requiring Private Store Only"
$store = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
If (!(Test-Path $store)) {
    New-Item $store
}
Set-ItemProperty $store RequirePrivateStoreOnly -Value 1 