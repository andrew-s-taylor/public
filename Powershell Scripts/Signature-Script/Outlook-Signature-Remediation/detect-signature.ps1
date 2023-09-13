##Set Outlook Path
$OutlookRegistryPath = "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Profiles\Outlook";

#Check if path exists
if (Test-Path $OutlookRegistryPath) {

    # Check if the default signature exists.
    $defaultSignature = Get-ItemPropertyValue -Path "$OutlookRegistryPath\9375CFF0413111d3B88A00104B2A6676\00000002" -Name "New Signature" -ErrorAction SilentlyContinue;
    if ($defaultSignature) {
        Write-Output "The default signature exists.";
        Exit 0
    }
    else {
        Write-Output "The default signature does not exist.";
        Exit 1
    }

}
else {
    Write-Output "The registry path does not exist.";
    Exit 0
}