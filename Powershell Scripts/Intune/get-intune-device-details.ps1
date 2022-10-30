
#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph) {
    Write-Host "Microsoft Graph Already Installed"
} 
else {
    try {
        Install-Module -Name Microsoft.Graph -Scope CurrentUser -Repository PSGallery -Force 
    }
    catch [Exception] {
        $_.message 
        exit
    }
}
import-module microsoft.graph.intune
##Authenticate
Select-MgProfile -Name Beta
Connect-MgGraph -Scopes DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, openid, profile, email, offline_access
   

$uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices"

$devices = Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject
$devices = $devices.value
$finaldevices = @()
foreach ($device in $devices) {
$finaldevices += $device | select-object deviceName,ownerType,complianceState,deviceType,osVersion,managementState,emailAddress,lastSyncDateTime,enrolledDateTime,imei,deviceRegistrationState,isEncrypted,userPrincipalName,model,manufacturer,serialNumber,userDisplayname,totalStorageSpaceInBytes,freeStorageSpaceInBytes,managedDeviceName,azureADDeviceId,azureADRegistered,joinType,deviceEnrollmentType
}
$finaldevices | Out-GridView -Title "Intune Devices"