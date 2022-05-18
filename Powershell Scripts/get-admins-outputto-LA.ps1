
# Replace with your Log Analytics Workspace ID
$CustomerId = ""  

# Replace with your Primary Key
$SharedKey = ""

#Control if you want to collect App or Device Inventory or both (True = Collect)
$CollectAppInventory = $true
$CollectDeviceInventory = $true

$AppLogName = "AppInventory"
$DeviceLogName = "DeviceInventory"
$Date = (Get-Date)

# You can use an optional field to specify the timestamp from the data. If the time field is not specified, Azure Monitor assumes the time is the message ingestion time
# DO NOT DELETE THIS VARIABLE. Recommened keep this blank. 
$TimeStampField = ""

#endregion initialize

#region functions
# Function to send data to log analytics
Function Send-LogAnalyticsData() {
	<#
   .SYNOPSIS
	   Send log data to Azure Monitor by using the HTTP Data Collector API
   
   .DESCRIPTION
	   Send log data to Azure Monitor by using the HTTP Data Collector API
   
   .NOTES
	   Author:      Jan Ketil Skanke
	   Contact:     @JankeSkanke
	   Created:     2022-01-14
	   Updated:     2022-01-14
   
	   Version history:
	   1.0.0 - (2022-01-14) Function created
   #>
   param(
	   [string]$sharedKey,
	   [array]$body, 
	   [string]$logType,
	   [string]$customerId
   )
   #Defining method and datatypes
   $method = "POST"
   $contentType = "application/json"
   $resource = "/api/logs"
   $date = [DateTime]::UtcNow.ToString("r")
   $contentLength = $body.Length
   #Construct authorization signature
   $xHeaders = "x-ms-date:" + $date
   $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource
   $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
   $keyBytes = [Convert]::FromBase64String($sharedKey)
   $sha256 = New-Object System.Security.Cryptography.HMACSHA256
   $sha256.Key = $keyBytes
   $calculatedHash = $sha256.ComputeHash($bytesToHash)
   $encodedHash = [Convert]::ToBase64String($calculatedHash)
   $signature = 'SharedKey {0}:{1}' -f $customerId, $encodedHash
   
   #Construct uri 
   $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"
   
   #validate that payload data does not exceed limits
   if ($body.Length -gt (31.9 *1024*1024))
   {
	   throw("Upload payload is too big and exceed the 32Mb limit for a single upload. Please reduce the payload size. Current payload size is: " + ($body.Length/1024/1024).ToString("#.#") + "Mb")
   }
   $payloadsize = ("Upload payload size is " + ($body.Length/1024).ToString("#.#") + "Kb ")
   
   #Create authorization Header
   $headers = @{
	   "Authorization"        = $signature;
	   "Log-Type"             = $logType;
	   "x-ms-date"            = $date;
	   "time-generated-field" = $TimeStampField;
   }
   #Sending data to log analytics 
   $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
   $statusmessage = "$($response.StatusCode) : $($payloadsize)"
   return $statusmessage 
}#end function
#Function to get AzureAD TenantID

#endregion functions

# Create custom PSObject
$admindetails = new-object -TypeName PSObject
$admins = Get-LocalGroupMember -Group "Administrators"
$admindetails | Add-Member -MemberType NoteProperty -Name "PCName" -Value $env:computername
$i = 1
foreach ($admin in $admins) {
    $name = "Admin Account "+$i
    $admindetails | Add-Member -MemberType NoteProperty -Name $name -Value $admin.Name
    $i++
}
# Sending the data $to Log Analytics Workspace
$Devicejson = $admindetails | ConvertTo-Json -Depth 5


# Submit the data to the API endpoint
$ResponseDeviceInventory = Send-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($Devicejson)) -logType $DeviceLogName

Exit 0
#endregion script