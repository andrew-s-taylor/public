<#PSScriptInfo
.VERSION 1.0.0
.GUID f83163ce-a3e2-4e00-839f-4081ac779a91
.AUTHOR AndrewTaylor
.DESCRIPTION Creates a Windows 10/11 ISO using the latest download and triggers autoattend to add to Autopilot
.COMPANYNAME 
.COPYRIGHT GPL
.TAGS intune endpoint MEM environment winget win32
.LICENSEURI https://github.com/andrew-s-taylor/public/blob/main/LICENSE
.PROJECTURI https://github.com/andrew-s-taylor/public
.ICONURI 
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
#>
<#
.SYNOPSIS
Creates a Windows 10/11 ISO using the latest download and triggers autoattend to add to Autopilot
.DESCRIPTION
.Downloads latest windows ISO
.Grabs Autopilot Profile
.Injects profile
.Creates new ISO

.INPUTS
Profile and Windows OS (from Gridview)
.OUTPUTS
In-Line Outputs
.NOTES
  Version:        1.0.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  27/06/2023
  Purpose/Change: Initial script development

.EXAMPLE
N/A
#>

[cmdletbinding()]
    
param
(
    [string]$tenant #Tenant ID (optional) for when automating and you want to use across tenants instead of hard-coded
    ,
    [string]$clientid #ClientID is the type of Azure AD App Reg ID
    ,
    [string]$clientsecret #ClientSecret is the type of Azure AD App Reg Secret
    ,
    [string]$isopath

    )



###############################################################################################################
######                                          Create Dir                                               ######
###############################################################################################################

#Create path for files
$DirectoryToCreate = "c:\temp"
if (-not (Test-Path -LiteralPath $DirectoryToCreate)) {
    
    try {
        New-Item -Path $DirectoryToCreate -ItemType Directory -ErrorAction Stop | Out-Null #-Force
    }
    catch {
        Write-Error -Message "Unable to create directory '$DirectoryToCreate'. Error was: $_" -ErrorAction Stop
    }
    "Successfully created directory '$DirectoryToCreate'."

}
else {
    "Directory already existed"
}


$random = Get-Random -Maximum 1000 
$random = $random.ToString()
$date =get-date -format yyMMddmmss
$date = $date.ToString()
$path2 = $random + "-"  + $date
$path = "c:\temp\" + $path2

New-Item -ItemType Directory -Path $path


###############################################################################################################
######                                              Execution                                            ######
###############################################################################################################


##Set filename and filepath
$isocontents = "$path\iso\"
$wimname = "$isocontents\sources\install.wim"
$wimnametemp = "$path\installtemp.wim"

##check if ISO path has been passed
$isocheck = $PSBoundParameters.ContainsKey('isopath')

if ($isocheck -eq $true) {
    $isofilename = $isopath
}

else {

$isofilename = "$path\microsoftwindows.iso"
write-host "Selecting OS"
write-host "Finding latest supported versions"
$allversions = @()
##Popup a gridview to select which OS to download and configure


###WINDOWS 11
$url = "https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information"
$content = (Invoke-WebRequest -Uri $url -UseBasicParsing).content
[regex]$regex = "(?s)<tr class=.*?</tr>"
$tables = $regex.matches($content).groups.value
$tables = $tables.replace("<td>","")
$tables = $tables.replace("</td>","")
$tables = $tables.replace('<td align="left">',"")
$tables = $tables.replace('<tr class="highlight">',"")
$tables = $tables.replace("</tr>","")

##Add each found version for array
$availableversions = @()
foreach ($table in $tables) {
    [array]$toArray = $table.Split("`n") | Where-Object {$_.Trim("")}
    $availableversions += ($toArray[0]).Trim()
}

##We want n-1 so grab the first two objects
$Win11versions = $availableversions | select-object -first 2



####WINDOWS 10
    ##Scrape the release information to find latest supported versions
    $url = "https://learn.microsoft.com/en-us/windows/release-health/release-information"
    $content = (Invoke-WebRequest -Uri $url -UseBasicParsing).content
    [regex]$regex = "(?s)<tr class=.*?</tr>"
    $tables = $regex.matches($content).groups.value
    $tables = $tables.replace("<td>","")
    $tables = $tables.replace("</td>","")
    $tables = $tables.replace('<td align="left">',"")
    $tables = $tables.replace('<tr class="highlight">',"")
    $tables = $tables.replace("</tr>","")
    
    ##Add each found version for array
    $availableversions = @()
    foreach ($table in $tables) {
        [array]$toArray = $table.Split("`n") | Where-Object {$_.Trim("")}
        $availableversions += ($toArray[0]).Trim()
    }

    ##We want n-1 so grab the first two objects
    $win10versions = $availableversions | select-object -first 2



##Create a custom object to store versions
foreach ($win11 in $Win11versions) {
    $os = "11"
    $osversion = $win11
    $objectdetails = [pscustomobject]@{
        Major = $os
        Minor = $osversion
        Name = "Windows $os $osversion"
    }
    $allversions += $objectdetails
}
foreach ($win10 in $Win10versions) {
    $os = "10"
    $osversion = $win10
    $objectdetails = [pscustomobject]@{
        Major = $os
        Minor = $osversion
        Name = "Windows $os $osversion"
    }
    $allversions += $objectdetails
}


$options = @()
foreach ($foundversion in $allversions) {
    $options += $foundversion.name
}
$object  = foreach($option in $options){new-object psobject -Property @{'Pick your Option' = $option}}
$osinput   = $object | Out-GridView -Title "Windows Selection" -PassThru
$selectedname = $osinput.'Pick your Option'
$selectedos = $allversions | Where-Object Name -eq "$selectedname"
write-host "$selectedname Chosen"

##Prompt for language
write-output "Select a language"
$url = "https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/available-language-packs-for-windows?view=windows-11"
$content = (Invoke-WebRequest -Uri $url -UseBasicParsing).content

# Use regex to extract the first table from the HTML content
$tableRegex = '<table.*?>(.*?)</table>'
$tableMatches = [regex]::Matches($content, $tableRegex, [System.Text.RegularExpressions.RegexOptions]::Singleline)
$firstTable = $tableMatches[0].Value
$rowRegex = '<tr.*?>\s*<td.*?>.*?</td>\s*<td.*?>(.*?)</td>'
$rowMatches = [regex]::Matches($firstTable, $rowRegex, [System.Text.RegularExpressions.RegexOptions]::Singleline)

$rowgroups = $rowMatches.Groups
$languages = @()
foreach ($row in $rowgroups) {
    $secondColumnContent = [regex]::Match($row.Value, '<td.*?>(.*?)</td>\s*<td.*?>(.*?)</td>').Groups[2].Value
    if ($secondColumnContent) {
        if ($secondColumnContent -notlike "*<p>*") {
    $languages += $secondColumnContent
        }
    }
}

$selectedlanguage = $languages | Out-GridView -Title "Select a Language" -PassThru

write-host "$selectedlanguage Chosen"

##Convert to text
switch ($selectedlanguage) {
    "ar-SA" { $Locale = "Arabic" }
    "pt-BR" { $Locale = "Brazilian Portuguese" }
    "bg-BG" { $Locale = "Bulgarian" }
    "zh-CN" { $Locale = "Chinese (Simplified)" }
    "zh-TW" { $Locale = "Chinese (Traditional)" }
    "hr-HR" { $Locale = "Croatian" }
    "cs-CZ" { $Locale = "Czech" }
    "da-DK" { $Locale = "Danish" }
    "nl-NL" { $Locale = "Dutch" }
    "en-US" { $Locale = "English" }
    "en-GB" { $Locale = "English International" }
    "et-EE" { $Locale = "Estonian" }
    "fi-FI" { $Locale = "Finnish" }
    "fr-FR" { $Locale = "French" }
    "fr-CA" { $Locale = "French Canadian" }
    "de-DE" { $Locale = "German" }
    "el-GR" { $Locale = "Greek" }
    "he-IL" { $Locale = "Hebrew" }
    "hu-HU" { $Locale = "Hungarian" }
    "it-IT" { $Locale = "Italian" }
    "ja-JP" { $Locale = "Japanese" }
    "ko-KR" { $Locale = "Korean" }
    "lv-LV" { $Locale = "Latvian" }
    "lt-LT" { $Locale = "Lithuanian" }
    "nb-NO" { $Locale = "Norwegian" }
    "pl-PL" { $Locale = "Polish" }
    "pt-PT" { $Locale = "Portuguese" }
    "ro-RO" { $Locale = "Romanian" }
    "ru-RU" { $Locale = "Russian" }
    "sr-Latn-RS" { $Locale = "Serbian Latin" }
    "sk-SK" { $Locale = "Slovak" }
    "sl-SI" { $Locale = "Slovenian" }
    "es-ES" { $Locale = "Spanish" }
    "es-MX" { $Locale = "Spanish (Mexico)" }
    "sv-SE" { $Locale = "Swedish" }
    "th-TH" { $Locale = "Thai" }
    "tr-TR" { $Locale = "Turkish" }
    "uk-UA" { $Locale = "Ukrainian" }
    default { $Locale = $selectedlanguage }
}
write-host "Locale $locale Selected"
##Download Fido
write-host "Downloading Fido"
$fidourl = "https://raw.githubusercontent.com/pbatard/Fido/master/Fido.ps1"
$fidopath = $path + "\fido.ps1"
Invoke-WebRequest -Uri $fidourl -OutFile $fidopath -UseBasicParsing
write-host "Fido Downloaded"
##Run Fido
# Set the parameters
$Win = $selectedos.Major
$Rel = $selectedos.Minor
$Ed = "Pro"
$GetUrl = $true
write-host "Grabbing ISO URL"
# Build the command string
$Command = "$fidopath -Lang '$Locale' -Win $Win -Rel $Rel -Ed $Ed -GetUrl"
write-host "Running $command"
# Run the command and store the output in a variable
$process = Start-Process -FilePath PowerShell.exe -ArgumentList "-Command & {$Command}" -NoNewWindow -PassThru -Wait -RedirectStandardOutput "$path\output.txt"
$windowsuri = Get-Content "$path\output.txt"


# Display the output
Write-Output $windowsuri


write-host "Downloading OS ISO"
##Download the OS
$download = Start-BitsTransfer -Source $windowsuri -Destination $isofilename -Asynchronous
while ($download.JobState -ne "Transferred") { 
    [int] $dlProgress = ($download.BytesTransferred / $download.BytesTotal) * 100;
    Write-Progress -Activity "Downloading File..." -Status "$dlProgress% Complete:" -PercentComplete $dlProgress; 
}
Complete-BitsTransfer $download.JobId;
write-host "Download Complete"
}
$isofilenamewithap = "$path\windowswithautopilot.iso"
##Mount the ISO
write-host "Mounting Windows ISO"
$mountiso = Mount-DiskImage $isofilename -PassThru
##Find the Drive Letter used
write-host "Detecting Drive Letter"
$ISODrive = (Get-DiskImage -ImagePath $isofilename | Get-Volume).DriveLetter
write-host "Drive Letter is $ISODrive"
##Copy the ISO files to manipulate
write-host "Copying ISO Contents"
$copyisofules = Copy-Item -Path $isodrive":" -Destination $isocontents -Recurse
write-host "Copying Complete"
##Select Image
write-host "Select Windows Version"
$wimpath = $isodrive+":\sources\install.wim"
$WinImages = Get-windowsimage -ImagePath $wimpath
$Report = @()
Foreach ($WinImage in $WinImages)
{
$curImage=Get-WindowsImage -ImagePath $wimpath -Index $WinImage.ImageIndex
$objImage = [PSCustomObject]@{
ImageIndex = $curImage.ImageIndex
ImageName = $curImage.ImageName
Version = $curImage.Version
Languages=$curImage.Languages
Architecture =$curImage.Architecture
}
$Report += $objImage
}
$imageselection = $Report | Out-GridView -PassThru
$imageindex = $imageselection.ImageIndex
##Copy the WIM to mount
write-host "Copying temporary WIM for manipulation"
$copywim = copy-item $wimname $wimnametemp
write-host "Copying Complete"

##Set further paths
$Image = $wimnametemp
$MountPoint = "$path\mount"
$InstallImage = $ISODrive+":"

$TargetISOFile = $isofilenamewithap
$ImageIndex = $imageindex


##WIM is read-only by default, we don't want that
write-host "Setting Temp WIM as read/write"
Set-ItemProperty -Path $image -Name IsReadOnly -Value $false
write-host "Set to read/write"
##Create the mount folder
write-host "Creating mount folder"
new-item "$path\mount" -ItemType Directory
Write-Host "Mount folder created"

##Mount the WIM
write-host "Mounting WIM"
Mount-WindowsImage -ImagePath $Image -Path $MountPoint -Index $ImageIndex
write-host "WIM Mounted"



##Inject the Autopilot JSON
write-host "Injecting Autopilot JSON"
$profilejson | Set-Content -Encoding Ascii "$MountPoint\Windows\Provisioning\Autopilot\AutopilotConfigurationFile.json"
write-host "JSON Injected"

##Dismount with the JSON injected
write-host "Dismounting WIM and Applying JSON"
Dismount-WindowsImage -Path $MountPoint -Save
write-host "WIM Dismounted"

##Again, install.wim is read-only
write-host "Setting install.wim as read/write"
Set-ItemProperty -Path $wimname -Name IsReadOnly -Value $false
write-host "Set to read/write"

##Remove the old install.wim
write-host "Removing install.wim from Sources directory"
remove-item $wimname
write-host "Removed"

#Export install.wim to replace old one
write-host "Exporting new install.wim to sources directory"
Export-WindowsIMage -SourceImagePath $Image -DestinationImagePath $wimname -SourceIndex $ImageIndex
write-host "Exported"

##Create a directory for oscdimg files
write-host "Creating oscdimg directory"
new-item -Path "$path\oscdimg" -ItemType Directory
write-host "Created"

#Set Paths for download
$url = "https://github.com/andrew-s-taylor/oscdimg/archive/main.zip"
$output = "$path\oscdimg.zip"

#Download Files
write-host "Downloading OSCDIMG Files"
Invoke-WebRequest -Uri $url -OutFile $output -Method Get
write-host "Download Complete"


#Unzip them
write-host "Unzipping Files"
Expand-Archive $output -DestinationPath "$path\oscdimg" -Force
Write-Host "Unzipped"

#Remove Zip file downloaded
write-host "Removing Zip File"
remove-item $output -Force
write-host "Removed"

# Create an ISO file from the installimage and new wim file
write-host "Creating ISO"
& "$path\oscdimg\oscdimg-main\oscdimg.exe" -b"$InstallImage\efi\microsoft\boot\efisys.bin" -pEF -u1 -udfver102 $isocontents $TargetISOFile
write-host "ISO $TargetISOFile created"

##Clean-up
write-host "Cleaning Environment"
##Dismount the ISO
write-host "Ejecting ISO"
$dismount = Dismount-DiskImage $isofilename
write-host "ISO Ejected"
##Remove the temporary wim
write-host "Removing temporary WIM"
remove-item $wimnametemp
write-host "Removed"
if ($isocheck -eq $true) {
  ##Leave ISO
}
else {
##Remove the original ISO
write-host "Removing original ISO"
remove-item $isofilename
write-host "Removed"
}

##Remove the extracted ISO contents
write-host "Removing extracted ISO contents"
remove-item $isocontents -Recurse -Force
write-host "Removed"
##Remove Mount folder
write-host "Removing mount folder"
remove-item "$path\mount" -recurse -Force
write-host "Removed"
##Remove oscdimg folder
write-host "Removing oscdimg folder"
remove-item "$path\oscdimg" -recurse -force
write-host "Removed"

##We're left with the new ISO and the autopilot JSON file
write-host "ISO Creation Complete"
