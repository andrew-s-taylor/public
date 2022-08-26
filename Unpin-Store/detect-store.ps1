$apps = ((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items())
foreach ($app in $apps) {
$appname = $app.Name
if ($appname -like "*store*") {
$finalname = $app.Name
}
else {
    $finalname = ""
}
}

if ($finalname -eq "") {
    write-host "Store Not Pinned"
    exit 1
}
else {
    Write-Warning "Store Pinned, Remediating"
    exit 0
}