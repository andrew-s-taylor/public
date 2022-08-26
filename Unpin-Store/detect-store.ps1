##We're looping through the verbs so it's going to be easier to count
$pinned = 0
##Loop through verbs for the store app
$apps = ((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() | Where-Object { $_.Name -eq "Microsoft Store" }).verbs()
foreach ($app in $apps) {
    ##Is Unpin an option?
if ($app.Name -eq "Unpin from tas&kbar") {
    ##Yep, increment the counter
$pinned++
}
}

#Has it been found?
if ($pinned -gt 0) {
Write-Warning "Store has been pinned"
exit 1
}
else {
write-host "Not pinned"
exit 0
}