if not exist "C:\driversupd\" mkdir C:\driversupd

copy %~dp0runupdate.bat c:\driversupd\runupdate.bat
copy %~dp0schtask.ps1 c:\driversupd\schtask.ps1

Powershell.exe -executionpolicy bypass -File  c:\driversupd\schtask.ps1

start "" Dell-Command-Update-Application-for-Windows-10_DF2DT_WIN_4.1.0_A00.exe /s