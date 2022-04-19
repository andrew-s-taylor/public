$days = 30
$profiles = (get-CimInstance win32_userprofile | Where {$_.LastUseTime -lt $(Get-Date).Date.AddDays(-$days)})
$profilecount = $profiles.Count
if ($profilecount -gt 0) {
write-host "There are profiles to remove" -ForegroundColor Red
Exit 1
}
else {
write-host "No old profiles to remove" -ForegroundColor Green
Exit 0
}