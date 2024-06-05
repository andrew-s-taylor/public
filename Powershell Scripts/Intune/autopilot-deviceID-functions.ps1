function get-deviceidentifierinfo {
    <#
.SYNOPSIS
This function is used to grab the Windows device identifier information
.DESCRIPTION
This function is used to grab the Windows device identifier information and return it or export it to a CSV file
.EXAMPLE
get-deviceidentifierinfo -export
Returns true or false
.NOTES
NAME: check-importeddevice
#>
[cmdletbinding()]

param
(
$export,
$outputfile
)
# Capture the output from WMI objects
$computerSystem = Get-WmiObject -Class Win32_ComputerSystem
$bios = Get-WmiObject -Class Win32_BIOS

$manufacturer = $computerSystem.Manufacturer
$model = $computerSystem.Model
$serial = $bios.SerialNumber

if ($export -eq $true) {
# Combine the results into a single string
$data = "$($computerSystem.Manufacturer),$($computerSystem.Model),$($bios.SerialNumber)"

# Write the data to a CSV file without headers
Set-Content -Path $outputfile -Value $data

} else {
    ##Create a custom object
    $deviceinfo = New-Object PSObject
    $deviceinfo | Add-Member -MemberType NoteProperty -Name "Manufacturer" -Value $manufacturer
    $deviceinfo | Add-Member -MemberType NoteProperty -Name "Model" -Value $model
    $deviceinfo | Add-Member -MemberType NoteProperty -Name "Serial" -Value $serial
    return $deviceinfo
}

}


function check-importeddevice {
    <#
.SYNOPSIS
This function is used to check if a device identifier (Windows) already exists in the Intune environment
.DESCRIPTION
This function is used to check if a device identifier (Windows) already exists in the Intune environment
.EXAMPLE
check-importeddevice -manufacturer "Microsoft Corporation" -model "Virtual Machine" -serial "xxxxx"
Returns true or false
.NOTES
NAME: check-importeddevice
#>
[cmdletbinding()]

param
(
$manufacturer,
$model,
$serial
)
##Check it exists
$uri = "https://graph.microsoft.com/beta/deviceManagement/importedDeviceIdentities/searchExistingIdentities"
$json = @"
{
"importedDeviceIdentities": [
    {
        "importedDeviceIdentifier": "$manufacturer,$model,$serial",
        "importedDeviceIdentityType": "manufacturerModelSerial"
    }
]
}
"@
$response = (Invoke-MgGraphRequest -Uri $uri -Method Post -Body $json -OutputType PSObject).value


if (!$response) {
return $false
} else {
return $true
}

}


function import-deviceidentifier {
    <#
.SYNOPSIS
This function is used to import a device identifier (Windows) already exists in the Intune environment
.DESCRIPTION
This function is used to import a device identifier (Windows) already exists in the Intune environment
.EXAMPLE
import-deviceidentifier -manufacturer "Microsoft Corporation" -model "Virtual Machine" -serial "xxxxx"
Returns true or false
.NOTES
NAME: import-deviceidentifier
#>
[cmdletbinding()]

param
(
$manufacturer,
$model,
$serial
)
##Send it
$uri = "https://graph.microsoft.com/beta/deviceManagement/importedDeviceIdentities/importDeviceIdentityList"

$json = @"
{
    "importedDeviceIdentities": [
        {
            "importedDeviceIdentifier": "$manufacturer,$model,$serial",
            "importedDeviceIdentityType": "manufacturerModelSerial"
        }
    ],
    "overwriteImportedDeviceIdentities": false
}
"@
Invoke-MgGraphRequest -Uri $uri -Method Post -Body $json -OutputType PSObject
}