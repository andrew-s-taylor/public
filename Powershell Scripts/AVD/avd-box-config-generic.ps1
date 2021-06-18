
<#
.SYNOPSIS
  Configured AVD Host

.DESCRIPTION
 Configured a new AVD host for use with image builder.  Cleans image, installs chocolatey and enables App-V


.INPUTS
None

.OUTPUTS
Verbose output

.NOTES
  Version:        1.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  13/05/2021
  Purpose/Change: Initial script development
  
#>

##############################
#    AVD Script Parameters   #
##############################
Param (        
    [Parameter(Mandatory=$false)]
        [string]$RegistrationToken,
    [Parameter(Mandatory=$false)]
        [string]$Optimize = $true           
)
New-Item -Path c:\log -ItemType Directory
New-Item -Path c:\log\ -Name New-AVDSessionHost.log -ItemType File
######################
#    AVD Variables   #
######################
$LocalAVDpath            = "c:\temp\AVD\"
$AVDBootURI              = 'https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RWrxrH'
$AVDAgentURI             = 'https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RWrmXv'
$AVDAgentInstaller       = 'AVD-Agent.msi'
$AVDBootInstaller        = 'AVD-Bootloader.msi'


####################################
#    Test/Create Temp Directory    #
####################################
if((Test-Path c:\temp) -eq $false) {
    Add-Content -LiteralPath C:\log\New-AVDSessionHost.log "Create C:\temp Directory"
    Write-Host `
        -ForegroundColor Cyan `
        -BackgroundColor Black `
        "creating temp directory"
    New-Item -Path c:\temp -ItemType Directory
}
else {
    Add-Content -LiteralPath C:\log\New-AVDSessionHost.log "C:\temp Already Exists"
    Write-Host `
        -ForegroundColor Yellow `
        -BackgroundColor Black `
        "temp directory already exists"
}
if((Test-Path $LocalAVDpath) -eq $false) {
    Add-Content -LiteralPath C:\log\New-AVDSessionHost.log "Create C:\temp\AVD Directory"
    Write-Host `
        -ForegroundColor Cyan `
        -BackgroundColor Black `
        "creating c:\temp\AVD directory"
    New-Item -Path $LocalAVDpath -ItemType Directory
}
else {
    Add-Content -LiteralPath C:\log\New-AVDSessionHost.log "C:\temp\AVD Already Exists"
    Write-Host `
        -ForegroundColor Yellow `
        -BackgroundColor Black `
        "c:\temp\AVD directory already exists"
}

Add-Content `
-LiteralPath C:\log\New-AVDSessionHost.log `
"
ProfilePath       = $ProfilePath
RegistrationToken = $RegistrationToken
Optimize          = $Optimize
"



##############################
#    Prep for AVD Install    #
##############################

#Disable Security Warnings on MSI
$env:SEE_MASK_NOZONECHECKS = 1

Add-Content -LiteralPath C:\log\New-AVDSessionHost.log "Unzip FSLogix"
Expand-Archive `
    -LiteralPath "C:\temp\AVD\$FSInstaller" `
    -DestinationPath "$LocalAVDpath\FSLogix" `
    -Force `
    -Verbose
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
cd $LocalAVDpath 
Add-Content -LiteralPath C:\log\New-AVDSessionHost.log "UnZip FXLogix Complete"



##############################
#    OS Specific Settings    #
##############################
$OS = (Get-WmiObject win32_operatingsystem).name
If(($OS) -match 'server') {
    Add-Content -LiteralPath C:\log\New-AVDSessionHost.log "Windows Server OS Detected"
    write-host -ForegroundColor Cyan -BackgroundColor Black "Windows Server OS Detected"
    If(((Get-WindowsFeature -Name RDS-RD-Server).installstate) -eq 'Installed') {
        "Session Host Role is already installed"
    }
    Else {
        "Installing Session Host Role"
        Install-WindowsFeature `
            -Name RDS-RD-Server `
            -Verbose `
            -LogPath "$LocalAVDpath\RdsServerRoleInstall.txt"
    }
    $AdminsKey = "SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UsersKey = "SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    $BaseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey("LocalMachine","Default")
    $SubKey = $BaseKey.OpenSubkey($AdminsKey,$true)
    $SubKey.SetValue("IsInstalled",0,[Microsoft.Win32.RegistryValueKind]::DWORD)
    $SubKey = $BaseKey.OpenSubKey($UsersKey,$true)
    $SubKey.SetValue("IsInstalled",0,[Microsoft.Win32.RegistryValueKind]::DWORD)    
}
Else {
    Add-Content -LiteralPath C:\log\New-AVDSessionHost.log "Windows Client OS Detected"
    write-host -ForegroundColor Cyan -BackgroundColor Black "Windows Client OS Detected"
    if(($OS) -match 'Windows 10') {
        write-host `
            -ForegroundColor Yellow `
            -BackgroundColor Black  `
            "Windows 10 detected...skipping to next step"
        Add-Content -LiteralPath C:\log\New-AVDSessionHost.log "Windows 10 Detected...skipping to next step"     
    }    
    else {
        ##NOT DOING WIN7!!!
        }        
    }



############################
#      Install Apps        #
############################

#########################
#    Enable App-V       #
#########################
Enable-appv
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\AppV\Client\Scripting' -Name 'EnablePackageScripts' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name 'NtfsDisable8dot3NameCreation' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;


###############################
#   Enable Script Execution   #
###############################
Set-ExecutionPolicy Unrestricted



#########################
#    FSLogix Install    #
#########################
Add-Content -LiteralPath C:\log\New-AVDSessionHost.log "Installing FSLogix"
$fslogix_deploy_status = Start-Process `
    -FilePath "$LocalAVDpath\FSLogix\x64\Release\FSLogixAppsSetup.exe" `
    -ArgumentList "/install /quiet" `
    -Wait `
    -Passthru


##########################################
#    Enable Screen Capture Protection    #
##########################################
Add-Content -LiteralPath C:\log\New-AVDSessionHost.log "Enable Screen Capture Protection"
Push-Location 
Set-Location "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
New-ItemProperty `
    -Path .\ `
    -Name fEnableScreenCaptureProtection `
    -Value "1" `
    -PropertyType DWord `
    -Force
Pop-Location


##############################################
#    AVD Optimizer (Virtual Desktop Team)    #
##############################################
If ($Optimize -eq $true) {  
    Write-Output "Optimizer selected"  
    ################################
    #    Download AVD Optimizer    #
    ################################
    Add-Content -LiteralPath C:\log\New-AVDSessionHost.log "Optimize Selected"
    Add-Content -LiteralPath C:\log\New-AVDSessionHost.log "Creating C:\Optimize folder"
    New-Item -Path C:\ -Name Optimize -ItemType Directory -ErrorAction SilentlyContinue
    $LocalOptimizePath = "C:\Optimize\"
    ###Slightly modified to remove network optimizations
    $AVDOptimizeURL = 'https://github.com/andrew-s-taylor/andrewstaylor/blob/main/Powershell%20Scripts/AVD/Virtual-Desktop-Optimization-Tool-master.zip'
    $AVDOptimizeInstaller = "Windows_10_VDI_Optimize-master.zip"
    Invoke-WebRequest `
        -Uri $AVDOptimizeURL `
        -OutFile "$LocalOptimizePath$AVDOptimizeInstaller"


    ###############################
    #    Prep for AVD Optimize    #
    ###############################
    Add-Content -LiteralPath C:\log\New-AVDSessionHost.log "Optimize downloaded and extracted"
    Expand-Archive `
        -LiteralPath "C:\Optimize\Windows_10_VDI_Optimize-master.zip" `
        -DestinationPath "$LocalOptimizePath" `
        -Force `
        -Verbose
    Set-Location -Path C:\Optimize\Virtual-Desktop-Optimization-Tool-master


    #################################
    #    Run AVD Optimize Script    #
    #################################
    Add-Content -LiteralPath C:\log\New-AVDSessionHost.log "Begining Optimize"
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force -Verbose
    .\Win10_VirtualDesktop_Optimize.ps1 -WindowsVersion 2004 -Verbose
    Add-Content -LiteralPath C:\log\New-AVDSessionHost.log "Optimization Complete"
}
else {
    Write-Output "Optimize not selected"
    Add-Content -LiteralPath C:\log\New-AVDSessionHost.log "Optimize NOT selected"    
}


###########################
##     Install Choco     ##
###########################

Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

##########################
##    Allow Shortpath   ##
##########################

$WinstationsKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations'
New-ItemProperty -Path $WinstationsKey -Name 'fUseUdpPortRedirector' -ErrorAction:SilentlyContinue -PropertyType:dword -Value 1 -Force
New-ItemProperty -Path $WinstationsKey -Name 'UdpPortNumber' -ErrorAction:SilentlyContinue -PropertyType:dword -Value 3390 -Force
New-NetFirewallRule -DisplayName 'Remote Desktop - Shortpath (UDP-In)'  -Action Allow -Description 'Inbound rule for the Remote Desktop service to allow RDP traffic. [UDP 3390]' -Group '@FirewallAPI.dll,-28752' -Name 'RemoteDesktop-UserMode-In-Shortpath-UDP'  -PolicyStore PersistentStore -Profile Domain, Private -Service TermService -Protocol udp -LocalPort 3390 -Program '%SystemRoot%\system32\svchost.exe' -Enabled:True


#InstallTeamsMachinemode Preview Media Optimisations - Reg pre-reqs
New-Item -Path HKLM:\SOFTWARE\Microsoft\Teams -Force | Out-Null
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Teams -name IsWVDEnvironment -Value “1” -Force | Out-Null

##########################
#    Mark Complete       #
##########################
remove-item env:SEE_MASK_NOZONECHECKS
Add-Content -LiteralPath C:\log\New-AVDSessionHost.log "Process Complete - REBOOT"
