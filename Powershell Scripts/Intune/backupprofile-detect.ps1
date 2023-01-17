$todaysdate = Get-Date -Format "dd-MM-yyyy-HH"
$dir = $env:APPDATA + "\backup-restore"

##Open File to check contents
$backupfile = $dir + "\backup.txt"
$backupdate = Get-Content -Path $backupfile
$checkdate = (get-date $backupdate -Format "dd-MM-yyyy-HH")
##Check if date is more than 1 hour ago
if ($checkdate -lt $todaysdate) {
    write-host "Run again"
    exit 1
}
else {
    "Already run this hour"
    exit 0
}