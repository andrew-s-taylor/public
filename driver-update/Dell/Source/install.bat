if not exist "C:\driversupd\" mkdir C:\driversupd

copy %~dp0runupdate.bat c:\driversupd\runupdate.bat
copy %~dp0schtask.ps1 c:\driversupd\schtask.ps1

Powershell.exe -executionpolicy bypass -File  c:\driversupd\schtask.ps1

start "" Dell-Command-Update-Application_8D5MC_WIN_4.3.0_A00_01.exe /s