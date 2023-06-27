<#PSScriptInfo
.VERSION 1.0.0
.GUID 26fabcfd-1773-409e-a952-a8f94fbe660b
.AUTHOR AndrewTaylor
.DESCRIPTION Creates a Windows 10/11 ISO using the latest download and auto-injects Autopilot JSON
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
  Creates a Windows 10/11 ISO using the latest download and auto-injects Autopilot JSON
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
  Last Modified:  26/06/2023
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

    )

##Set the Windows 10 and 11 Download URLs
$windows11uri = "https://software.download.prss.microsoft.com/dbazure/Win11_22H2_EnglishInternational_x64v2.iso?t=a8779d0c-39d6-41c4-bceb-fab947ca22ec&e=1687961338&h=82a936411e001b899e7219225fc80035f79310cb317b20b651e91f2fbd9bc82b"
$windows10uri = "https://software.download.prss.microsoft.com/dbazure/Win10_22H2_EnglishInternational_x64v1.iso?t=298eeedb-6bc1-4f29-b3d2-253ca4498d80&e=1687961600&h=c584fe0e3c0cd265469fa921b75e66f3ec89f736aeb0460de0722702c0815501"


###############################################################################################################
######                                         Install Modules                                           ######
###############################################################################################################
Write-Host "Installing Intune modules if required (current user scope)"

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication) {
    Write-Host "Microsoft Graph Already Installed"
} 
else {

        Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser -Repository PSGallery -Force 

}

import-module microsoft.graph.authentication

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
######                                          Add Functions                                            ######
###############################################################################################################

function GrabProfiles() {

    # Defining Variables
$graphApiVersion = "beta"
$Resource = "deviceManagement/windowsAutopilotDeploymentProfiles"

$uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
$response = Invoke-MGGraphRequest -Uri $uri -Method Get -OutputType PSObject

    $profiles = $response.value

    $profilesNextLink = $response."@odata.nextLink"

    while ($null -ne $profilesNextLink) {
        $profilesResponse = (Invoke-MGGraphRequest -Uri $profilesNextLink -Method Get -outputType PSObject)
        $profilesNextLink = $profilesResponse."@odata.nextLink"
        $profiles += $profilesResponse.value
    }

    $selectedprofile = $profiles | out-gridview -passthru -title "Select a profile"
    return $selectedprofile.id

}

function grabandoutput() {
[cmdletbinding()]

param
(
[string]$id

)

        # Defining Variables
        $graphApiVersion = "beta"
    $Resource = "deviceManagement/windowsAutopilotDeploymentProfiles"

$uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$id"
$approfile = Invoke-MGGraphRequest -Uri $uri -Method Get -OutputType PSObject

# Set the org-related info
$script:TenantOrg = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/organization" -OutputType PSObject).value
foreach ($domain in $script:TenantOrg.VerifiedDomains) {
    if ($domain.isDefault) {
        $script:TenantDomain = $domain.name
    }
}
$oobeSettings = $approfile.outOfBoxExperienceSettings

# Build up properties
$json = @{}
$json.Add("Comment_File", "Profile $($_.displayName)")
$json.Add("Version", 2049)
$json.Add("ZtdCorrelationId", $_.id)
if ($approfile."@odata.type" -eq "#microsoft.graph.activeDirectoryWindowsAutopilotDeploymentProfile") {
    $json.Add("CloudAssignedDomainJoinMethod", 1)
}
else {
    $json.Add("CloudAssignedDomainJoinMethod", 0)
}
if ($approfile.deviceNameTemplate) {
    $json.Add("CloudAssignedDeviceName", $_.deviceNameTemplate)
}

# Figure out config value
$oobeConfig = 8 + 256
if ($oobeSettings.userType -eq 'standard') {
    $oobeConfig += 2
}
if ($oobeSettings.hidePrivacySettings -eq $true) {
    $oobeConfig += 4
}
if ($oobeSettings.hideEULA -eq $true) {
    $oobeConfig += 16
}
if ($oobeSettings.skipKeyboardSelectionPage -eq $true) {
    $oobeConfig += 1024
    if ($_.language) {
        $json.Add("CloudAssignedLanguage", $_.language)
    }
}
if ($oobeSettings.deviceUsageType -eq 'shared') {
    $oobeConfig += 32 + 64
}
$json.Add("CloudAssignedOobeConfig", $oobeConfig)

# Set the forced enrollment setting
if ($oobeSettings.hideEscapeLink -eq $true) {
    $json.Add("CloudAssignedForcedEnrollment", 1)
}
else {
    $json.Add("CloudAssignedForcedEnrollment", 0)
}

$json.Add("CloudAssignedTenantId", $script:TenantOrg.id)
$json.Add("CloudAssignedTenantDomain", $script:TenantDomain)
$embedded = @{}
$embedded.Add("CloudAssignedTenantDomain", $script:TenantDomain)
$embedded.Add("CloudAssignedTenantUpn", "")
if ($oobeSettings.hideEscapeLink -eq $true) {
    $embedded.Add("ForcedEnrollment", 1)
}
else {
    $embedded.Add("ForcedEnrollment", 0)
}
$ztc = @{}
$ztc.Add("ZeroTouchConfig", $embedded)
$json.Add("CloudAssignedAadServerData", (ConvertTo-JSON $ztc -Compress))

# Skip connectivity check
if ($approfile.hybridAzureADJoinSkipConnectivityCheck -eq $true) {
    $json.Add("HybridJoinSkipDCConnectivityCheck", 1)
}

# Hard-code properties not represented in Intune
$json.Add("CloudAssignedAutopilotUpdateDisabled", 1)
$json.Add("CloudAssignedAutopilotUpdateTimeout", 1800000)

# Return the JSON
ConvertTo-JSON $json
}


###############################################################################################################
######                                        Graph Connection                                           ######
###############################################################################################################

Write-Verbose "Connecting to Microsoft Graph"

if ($clientid -and $clientsecret -and $tenant) {
 
    $body = @{
        grant_type="client_credentials";
        client_id=$clientId;
        client_secret=$clientSecret;
        scope="https://graph.microsoft.com/.default";
    }
     
    $response = Invoke-RestMethod -Method Post -Uri https://login.microsoftonline.com/$tenant/oauth2/v2.0/token -Body $body
    $accessToken = $response.access_token
     
    $accessToken

    Select-MgProfile -Name Beta
Connect-MgGraph  -AccessToken $accessToken 
write-output "Graph Connection Established"
}
else {
##Connect to Graph
Select-MgProfile -Name Beta
Connect-MgGraph -scopes Group.ReadWrite.All, Device.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, DeviceManagementServiceConfig.ReadWrite.All, GroupMember.ReadWrite.All, Domain.ReadWrite.All
}
Write-Verbose "Graph connection established"
###############################################################################################################
######                                              Execution                                            ######
###############################################################################################################

##Grab all profiles and output to gridview
$selectedprofile = GrabProfiles

##Grab JSON for selected profile
$profilejson = grabandoutput -id $selectedprofile

##Set filename and filepath
$isofilename = "$path\microsoftwindows.iso"
$isocontents = "$path\iso\"
$wimname = "$isocontents\sources\install.wim"
$wimnametemp = "$path\installtemp.wim"




write-host "Selecting OS"
##Popup a gridview to select which OS to download and configure
$options = 'Windows 10 21H2', 'Windows 11 22H2'
$object  = foreach($option in $options){new-object psobject -Property @{'Pick your Option' = $option}}
$osinput   = $object | Out-GridView -Title "Windows Selection" -PassThru

switch($osinput.'Pick your Option'){
    'Windows 10 22H2'{
        $windowsuri = $windows10uri
        $imageindex = 5
        write-host "Windows 10 Selected"
    }
    'Windows 11 22H2'{
        $windowsuri = $windows11uri
        $imageindex = 6
        write-host "Windows 11 Selected"
    }
    default{
        $windowsuri = $windows11uri
        $imageindex = 6
        write-host "Nothing selected, defaulting to Windows 11"
    }
}

write-host "Downloading OS ISO"
##Download the OS
$download = Start-BitsTransfer -Source $windowsuri -Destination $isofilename -Asynchronous
while ($download.JobState -ne "Transferred") { 
    [int] $dlProgress = ($download.BytesTransferred / $download.BytesTotal) * 100;
    Write-Progress -Activity "Downloading File..." -Status "$dlProgress% Complete:" -PercentComplete $dlProgress; 
}
Complete-BitsTransfer $download.JobId;
write-host "Download Complete"
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
##Remove the original ISO
write-host "Removing original ISO"
remove-item $isofilename
write-host "Removed"
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