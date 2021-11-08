##Set Download Directory

$directory = $env:TEMP
#Create Temp location
$random = Get-Random -Maximum 1000 
$random = $random.ToString()
$date =get-date -format yyMMddmmss
$date = $date.ToString()
$path2 = $random + "-"  + $date
$path = $directory + "\" + $path2 + "\"
new-item -ItemType Directory -Path $path

##File Name
$templateFilePath = $path + "foxit.yaml"


Invoke-WebRequest `
   -Uri "https://raw.githubusercontent.com/andrew-s-taylor/winget/main/manifests/f/Foxit/FoxitReader/11.0.0.49893/Foxit.FoxitReader.yaml" `
   -OutFile $templateFilePath `
   -UseBasicParsing `
   -Headers @{"Cache-Control"="no-cache"}

   $Winget = Get-ChildItem -Path (Join-Path -Path (Join-Path -Path $env:ProgramFiles -ChildPath "WindowsApps") -ChildPath "Microsoft.DesktopAppInstaller*_x64*\AppInstallerCLI.exe")

   &$winget install --silent  --manifest $templateFilePath