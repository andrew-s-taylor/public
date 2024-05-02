[cmdletbinding()]
    
param
(
    [object] $WebHookData #Webhook data for Azure Automation

    )

##WebHook Data

if ($WebHookData){

    $bodyData = ConvertFrom-Json -InputObject $WebHookData.RequestBody

$serialNumber = ((($bodyData.serialNumber) | out-string).trim())
$hardwareId = ((($bodyData.hardwareId) | out-string).trim())
$groupTag = ((($bodyData.groupTag) | out-string).trim())


}

Connect-MgGraph -Identity
 
 # CONSTRUCT JSON
 $json = @"
 {
     "@odata.type": "#microsoft.graph.importedWindowsAutopilotDeviceIdentity",
     "groupTag":"$groupTag",
     "serialNumber":"$serialNumber",
     "productKey":"",
     "hardwareIdentifier":"$hardwareId",
     "assignedUserPrincipalName":"",
     "state":{
         "@odata.type":"microsoft.graph.importedWindowsAutopilotDeviceIdentityState",
         "deviceImportStatus":"pending",
         "deviceRegistrationId":"",
         "deviceErrorCode":0,
         "deviceErrorName":""
     }
 }
"@
 
 # POST DEVICE
 Invoke-MgGraphRequest -Method Post -Body $json -ContentType "application/json" -Uri "https://graph.microsoft.com/beta/deviceManagement/importedWindowsAutopilotDeviceIdentities"