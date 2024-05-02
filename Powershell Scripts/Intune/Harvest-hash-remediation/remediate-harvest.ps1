##Create a reg key in HKLM
$regkey = "HKLM:\Software\Harvester"
$regname = "Harvested"
$regvalue = "completed"
   New-Item -Path $regkey -Force | Out-Null
   New-ItemProperty -Path $regkey -Name "$regname" -Value "$regvalue" -PropertyType String -Force | Out-Null

##Get Hardware Details
# GET HARDWARE INFO
$serialNumber = (Get-WmiObject -Class Win32_BIOS).SerialNumber
$hardwareId = ((Get-WmiObject -Namespace root/cimv2/mdm/dmmap -Class MDM_DevDetail_Ext01 -Filter "InstanceID='Ext' AND ParentID='./DevDetail'").DeviceHardwareData)
$groupTag = "M365"

$webhook = "WEBHOOK URL HERE"

##Create webhook array with username
$webhookData = @{
    serialNumber = $serialNumber
    hardwareId = $hardwareId
    groupTag = $groupTag
}

##Convert to JSON
$body = $webhookData | ConvertTo-Json

##Invoke Webhook
Invoke-WebRequest -Method Post -Uri $webhook -Body $body -UseBasicParsing
write-output "Hardware hash sent to Azure"