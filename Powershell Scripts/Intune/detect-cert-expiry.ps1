
#MDM Push
$7days = ((get-date).AddDays(7)).ToString("yyyy-MM-dd")
$pushuri = "https://graph.microsoft.com/beta/deviceManagement/applePushNotificationCertificate"
$pushcert = Invoke-MSGraphRequest -HttpMethod GET -Url $pushuri
$pushexpiry = ($pushcert.expirationDateTime).ToString("yyyy-MM-dd")
if ($pushexpiry -lt $7days) {
write-host "Cert Expiring" -ForegroundColor Red
Exit 1
}
else {
write-host "All fine" -ForegroundColor Green
exit 0
}


#VPP
$7days = ((get-date).AddDays(7)).ToString("yyyy-MM-dd")
$vppuri = "https://graph.microsoft.com/beta/deviceAppManagement/vppTokens"
$vppcert = Invoke-MSGraphRequest -HttpMethod GET -Url $vppuri
$vppexpiryvalue = $vppcert.value
$vppexpiry = ($vppexpiryvalue.expirationDateTime).ToString("yyyy-MM-dd")
if ($vppexpiry -lt $7days) {
write-host "Cert Expiring" -ForegroundColor Red
Exit 1
}
else {
write-host "All fine" -ForegroundColor Green
exit 0
}


#DEP
$7days = ((get-date).AddDays(7)).ToString("yyyy-MM-dd")
$depuri = "https://graph.microsoft.com/beta/deviceManagement/depOnboardingSettings"
$depcert = Invoke-MSGraphRequest -HttpMethod GET -Url $depuri
$depexpiryvalue = $depcert.value
$depexpiry = ($depexpiryvalue.tokenExpirationDateTime).ToString("yyyy-MM-dd")
if ($depexpiry -lt $7days) {
write-host "Cert Expiring" -ForegroundColor Red
Exit 1
}
else {
write-host "All fine" -ForegroundColor Green
exit 0
}
