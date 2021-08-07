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
$templateFilePathinstaller = $path + "chrome.installer.yaml"
$templateFilePathlocale = $path + "chrome.locale.yaml"
$templateFilePathversion = $path + "chrome.yaml"

Invoke-WebRequest `
   -Uri "https://raw.githubusercontent.com/andrew-s-taylor/winget/main/manifests/g/Google/Chrome/92.0.4515.107/Google.Chrome.installer.yaml" `
   -OutFile $templateFilePathinstaller `
   -UseBasicParsing `
   -Headers @{"Cache-Control"="no-cache"}


   Invoke-WebRequest `
   -Uri "https://raw.githubusercontent.com/andrew-s-taylor/winget/main/manifests/g/Google/Chrome/92.0.4515.107/Google.Chrome.locale.en-US.yaml" `
   -OutFile $templateFilePathlocale `
   -UseBasicParsing `
   -Headers @{"Cache-Control"="no-cache"}
   
   

   Invoke-WebRequest `
   -Uri "https://raw.githubusercontent.com/andrew-s-taylor/winget/main/manifests/g/Google/Chrome/92.0.4515.107/Google.Chrome.yaml" `
   -OutFile $templateFilePathversion `
   -UseBasicParsing `
   -Headers @{"Cache-Control"="no-cache"}  

   winget install --silent  --manifest $path