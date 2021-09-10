if not exist "C:\driversupd\" mkdir C:\driversupd
mkdir c:\driversupd\hp

copy %~dp0runupdate.bat c:\driversupd\runupdate.bat
copy %~dp0schtask.ps1 c:\driversupd\schtask.ps1

copy %~dp0hpupdate.exe c:\driversupd\hpupdate.exe
Powershell.exe -executionpolicy bypass -File c:\driversupd\schtask.ps1

start "" c:\driversupd\hpupdate.exe  /s /e /f c:\driversupd\hp