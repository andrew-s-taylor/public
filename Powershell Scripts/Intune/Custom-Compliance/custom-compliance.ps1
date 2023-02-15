<#
.SYNOPSIS
.Custom Intune Compliance Policy
.DESCRIPTION
.Checks Machine has updated recently
.Checks OS is supported
.Checks OS is up to date
.Checks if all firewalls are enabled
.Checks if all AV is enabled
.Checks AV is updated
.Checks for active malware


.INPUTS
.OUTPUTS
.NOTES
  Version:        1.0
  Author:         Andrew Taylor
  WWW:            andrewstaylor.com
  Creation Date:  10/02/2023
  Purpose/Change: Initial script development
  
.EXAMPLE
N/A
#>

### When did we last check for updates?
##Get the date
[datetime]$dtToday = [datetime]::NOW
$strCurrentMonth = $dtToday.Month.ToString()
$strCurrentYear = $dtToday.Year.ToString()
[datetime]$dtMonth = $strCurrentMonth + '/1/' + $strCurrentYear

while ($dtMonth.DayofWeek -ne 'Tuesday') { 
      $dtMonth = $dtMonth.AddDays(1) 
}

$strPatchTuesday = $dtMonth.AddDays(7)
$intOffSet = 7

if ([datetime]::NOW -lt $strPatchTuesday -or [datetime]::NOW -ge $strPatchTuesday.AddDays($intOffSet)) {
    $objUpdateSession = New-Object -ComObject Microsoft.Update.Session
    $objUpdateSearcher = $objUpdateSession.CreateupdateSearcher()
    $arrAvailableUpdates = @($objUpdateSearcher.Search("IsAssigned=1 and IsHidden=0 and IsInstalled=0").Updates)
    $strAvailableCumulativeUpdates = $arrAvailableUpdates | Where-Object {$_.title -like "*cumulative*"}

    if ($strAvailableCumulativeUpdates -eq $null) {
        $strUpdateStatus = "True"    } 
    else {
        $strUpdateStatus = "False"
    }
} 
else {
    $strUpdateStatus = "False"
}



[datetime]$Today = [datetime]::NOW
$7daysago = $Today.AddDays(-7)

##Which OS
##Check if we are running Win10 or 11
$OSname = Get-WMIObject win32_operatingsystem | select Caption
if ($OSname -like "*Windows 10*") {
    $OSname = "Windows 10"
}
if ($OSname -like "*Windows 11*") {
    $OSname = "Windows 11"
}

##Which OS Version?
##Check which version number
$OSVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name DisplayVersion).DisplayVersion

if ($OSname -eq "Windows 11") {
##Windows 11
##Scrape the release information to find latest supported versions
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
$supportedversions = $availableversions | select-object -first 2

##Check if we are supported
if ($OSVersion -in $supportedversions) {
    $OSsupported = "True"
}
else {
    $OSsupported = "False"
}
}


if ($OSname -eq "Windows 10") {
    ##Windows 10
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
    $supportedversions = $availableversions | select-object -first 2
    
    ##Check if we are supported
    if ($OSVersion -in $supportedversions) {
        $OSsupported = "True"
    }
    else {
        $OSsupported = "False"
    }
    }

##Domain Firewall
$domainfirewall= ((Get-NetFirewallProfile | select Name, Enabled | where-object Name -eq Domain | select Enabled).Enabled).ToString()

##Private Firewall
$privatefirewall= ((Get-NetFirewallProfile | select Name, Enabled | where-object Name -eq Private | select Enabled).Enabled).ToString()


##Public Firewall
$publicfirewall= ((Get-NetFirewallProfile | select Name, Enabled | where-object Name -eq Public | select Enabled).Enabled).ToString()

##Antivirus
$allav = Get-MpComputerStatus

##AM Enabled
$amenabled = ($allav.AMServiceEnabled).ToString()

##AS Enabled
$asenabled = ($allav.AntispywareEnabled).ToString()

##AS Age
$asage = $allav.AntispywareSignatureLastUpdated
if ($asage -lt $7daysago) {
    $asage = "False"
}
else {
    $asage = "True"
}


##AV Enabled
$avenabled = ($allav.AntivirusEnabled).ToString()

##AV Age
$avage = $allav.AntivirusSignatureLastUpdated
if ($avage -lt $7daysago) {
    $avage = "False"
}
else {
    $avage = "True"
}

##NISE Enabled
$niseenabled = ($allav.NISEnabled).ToString()

##NISE Age
$niseage = $allav.NISSignatureLastUpdated
if ($niseage -lt $7daysago) {
    $niseage = "False"
}
else {
    $niseage = "True"
}

##OP Enabled
$openabled = ($allav.OnAccessProtectionEnabled).ToString()

##RP Enabled
$rpenabled = ($allav.RealtimeProtectionEnabled).ToString()

##TP Enabled
$tpenabled = ($allav.IsTamperProtected).ToString()

##Quick Scan Overdue  
$quickscanoverdue = ($allav.QuickScanOverdue).ToString()

##Full Scan Overdue
$fullscanoverdue = ($allav.FullScanOverdue).ToString()

##Signature out of date
$signatureoutofdate = ($allav.DefenderSignaturesOutOfDate).ToString()

##Active Malware
$noactivemalware = Get-MpThreatDetection
if ($null -eq $noactivemalware) {
    $noactivemalware = "True"
}
else {
    $noactivemalware = "False"
}

##Encrypted


##TPM
$TPMpresent = ((get-tpm).TpmPresent).ToString()

##TPM Activated
$TPMactivated = ((get-tpm).TPMactivated).ToString()

##TPM Enabled
$TPMenabled = ((get-tpm).TPMenabled).ToString()


##Bitlocker
$bitlockerprotected = (get-bitlockervolume).ProtectionStatus
$bitlockerencryption = (get-bitlockervolume).VolumeStatus

if (($bitlockerprotected -eq "On") -and ($bitlockerencryption -eq "FullyEncrypted")) {
    $bitlocker = "True"
}
else {
    $bitlocker = "False"
}

$hash = @{ 
    UpdateStatus = $strUpdateStatus
    OSsupported = $OSsupported
    DomainFirewall = $domainfirewall
    PrivateFirewall = $privatefirewall
    PublicFirewall = $publicfirewall
    AMEnabled = $amenabled
    ASEnabled = $asenabled
    ASAge = $asage
    AVEnabled = $avenabled
    AVAge = $avage
    NISEnabled = $niseenabled
    NISEAge = $niseage
    OPEnabled = $openabled
    RPEEnabled = $rpenabled
    TPEEnabled = $tpenabled
    QuickScanOverdue = $quickscanoverdue
    FullScanOverdue = $fullscanoverdue
    SignatureOutOfDate = $signatureoutofdate
    NoActiveMalware = $noactivemalware
    Bitlocker = $bitlocker
    TPMpresent = $TPMpresent
    TPMactivated = $TPMactivated
    TPMenabled = $TPMenabled
}
return $hash | ConvertTo-Json -Compress