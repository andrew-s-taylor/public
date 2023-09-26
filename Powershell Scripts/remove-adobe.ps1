##Search for 32-bit versions and uninstall them

$path1 =  "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
#Loop Through the apps if name has Adobe and NOT reader
$32apps = Get-ChildItem -Path $path1 | Get-ItemProperty | Where-Object {($_.DisplayName -match "^adobe Acrobat*") -and ($_.DisplayName -notmatch "^*Reader*")} | Select-Object -Property DisplayName, UninstallString

foreach ($32app in $32apps) {
#Get uninstall string
$string1 =  $32app.uninstallstring
#Check if it's an MSI install
if ($string1 -match "^msiexec*") {
#MSI install, replace the I with an X and make it quiet
$string2 = $string1 + " /quiet /norestart"
$string2 = $string2 -replace "/I", "/X "
#Remove msiexec as we need to split for the uninstall
$string2 = $string2 -replace "msiexec.exe", ""
#Uninstall with string2 params
Start-Process 'msiexec.exe' -ArgumentList $string2 -NoNewWindow -Wait
}
else {
#Exe installer, run straight path
$string2 = $string1
start-process $string2
}

}


##Search for 64-bit versions and uninstall them

$path2 =  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
#Loop Through the apps if name has Adobe and NOT reader
$64apps = Get-ChildItem -Path $path2 | Get-ItemProperty | Where-Object {($_.DisplayName -match "^adobe Acrobat*") -and ($_.DisplayName -notmatch "^*Reader*")} | Select-Object -Property DisplayName, UninstallString

foreach ($64app in $64apps) {
#Get uninstall string
$string1 =  $64app.uninstallstring
#Check if it's an MSI install
if ($string1 -match "^msiexec*") {
#MSI install, replace the I with an X and make it quiet
$string2 = $string1 + " /quiet /norestart"
$string2 = $string2 -replace "/I", "/X "
#Remove msiexec as we need to split for the uninstall
$string2 = $string2 -replace "msiexec.exe", ""
#Uninstall with string2 params
Start-Process 'msiexec.exe' -ArgumentList $string2 -NoNewWindow -Wait
}
else {
#Exe installer, run straight path
$string2 = $string1
start-process $string2
}

}
