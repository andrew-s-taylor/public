$days = 30
$profiles = (get-CimInstance win32_userprofile | Where {$_.LastUseTime -lt $(Get-Date).Date.AddDays(-$days)})
$profilecount = $profiles.Count
if ($profilecount -gt 0) {
write-host "There are profiles to remove" -ForegroundColor Red
##Temp location to use
$tempdir = $env:TEMP
##Comment out whichever version you don't want to use

##Download DelProf1
Invoke-WebRequest -URI "https://github.com/andrew-s-taylor/public/raw/main/delprof/delprof.exe" -OutFile "$tempdir\delprof.exe"
##Run DelProf1
Start-Process -FilePath "$tempdir\delprof.exe" -ArgumentList /Q /D:$days
Remove-Item "$tempdir\delprof.exe"

##Download DelProf2
Invoke-WebRequest -URI "https://github.com/andrew-s-taylor/public/raw/main/delprof/DelProf2.exe" -OutFile "$tempdir\delprof2.exe"
##Run DelProf2
Start-Process -FilePath "$tempdir\delprof2.exe" -ArgumentList /q /d:$days
remove-item "$tempdir\delprof2.exe"

}
else {
write-host "No old profiles to remove" -ForegroundColor Green
}