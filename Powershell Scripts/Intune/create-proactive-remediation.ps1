###############################################################################################################
#                                              Set Variables                                                  #
###############################################################################################################
##Variables
$DisplayName = "Remediate Fastboot Automated"
$Description = "This was created via PowerShell!"
$Publisher = "Andrew Taylor"
##RunAs can be "system" or "user"
$RunAs = "system"
##True for 32-bit, false for 64-bit
$RunAs32 = $true
##Daily or Hourly
$ScheduleType = "Daily"
##How Often
$ScheduleFrequency = "1"
##Start Time (if daily)
$StartTime = "01:00"
$AADGroupName = "Intune-Users"


###############################################################################################################
#                                                 Detection Script                                            #
###############################################################################################################
$detect = @'
$Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
$Name = "HiberbootEnabled"
$Type = "DWORD"
$Value = 0

Try {
    $Registry = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop | Select-Object -ExpandProperty $Name
    If ($Registry -eq $Value){
        Write-Output "Compliant"
        Exit 0
    } 
    Write-Warning "Not Compliant"
    Exit 1
} 
Catch {
    Write-Warning "Not Compliant"
    Exit 1
}
'@

###############################################################################################################
#                                             Remediation Script                                              #
###############################################################################################################
$remediate = @"
New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name 'HiberbootEnabled' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
"@


###############################################################################################################
#                                              CREATE IT                                                      #
###############################################################################################################

$params = @{
         DisplayName = $DisplayName
         Description = $Description
         Publisher = $Publisher
         RunAs32Bit = $RunAs32
         RunAsAccount = $RunAs
         EnforceSignatureCheck = $false
         DetectionScriptContent = [System.Text.Encoding]::ASCII.GetBytes($detect)
         RemediationScriptContent = [System.Text.Encoding]::ASCII.GetBytes($remediate)
         RoleScopeTagIds = @(
                 "0"
         )
}






$ErrorActionPreference = "Continue"
##Start Logging to %TEMP%\intune.log
$date = get-date -format ddMMyyyy
Start-Transcript -Path $env:TEMP\intuneproactive-$date.log
###############################################################################################################
######                                         Install Modules                                           ######
###############################################################################################################
Write-Host "Installing Intune modules if required (current user scope)"

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph.Intune) {
    Write-Host "Microsoft Graph Already Installed"
} 
else {
    try {
        Install-Module -Name Microsoft.Graph.Intune -Scope CurrentUser -Repository PSGallery -Force 
    }
    catch [Exception] {
        $_.message 
        exit
    }
}


Write-Host "Installing AzureAD modules if required (current user scope)"

#Install AZ Module if not available
if (Get-Module -ListAvailable -Name AzureAD) {
    Write-Host "AZ Ad Module Already Installed"
} 
else {
    try {
        Install-Module -Name AzureAD -Scope CurrentUser -Repository PSGallery -Force -AllowClobber 
    }
    catch [Exception] {
        $_.message 
        exit
    }
}






#Importing Modules
write-host "Importing AzureAD Module"
Import-Module AzureAD
write-host "Importing Microsoft Graph Module"
Import-Module Microsoft.Graph.Intune
##Connect to Graph
write-host "Connecting to Graph"
Connect-MSGraph



##Create It
write-host "Creating Proactive Remediation"
$graphApiVersion = "beta"
$Resource = "deviceManagement/deviceHealthScripts"
$uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"

try {
    $proactive = Invoke-MSGraphRequest -Url $uri -HttpMethod Post -Content $params
}
catch {
    Write-Error $_.Exception 
    
}

write-host "Proactive Remediation Created"

##Assign It
write-host "Assigning Proactive Remediation"
##Connect to Azure AD to find Group ID
write-host "Connecting to AzureAD to Query Group"
Connect-AzureAD

##Get Group ID
$AADGroupID = (get-azureadgroup | where-object DisplayName -eq $AADGroupName).ObjectID
write-host "Group ID discovered: $AADGroupID"
##Set the JSON
if ($ScheduleType -eq "Hourly") {
    write-host "Assigning Hourly Schedule running every $ScheduleFrequency hours"
$params = @{
	DeviceHealthScriptAssignments = @(
		@{
			Target = @{
				"@odata.type" = "#microsoft.graph.groupAssignmentTarget"
				GroupId = $AADGroupID
			}
			RunRemediationScript = $true
			RunSchedule = @{
				"@odata.type" = "#microsoft.graph.deviceHealthScriptHourlySchedule"
				Interval = $scheduleFrequency
			}
		}
	)
}
}
else {
    write-host "Assigning Daily Schedule running at $StartTime each $scheduleFrequency days"
    $params = @{
        DeviceHealthScriptAssignments = @(
            @{
                Target = @{
                    "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                    GroupId = $AADGroupID
                }
                RunRemediationScript = $true
                RunSchedule = @{
                    "@odata.type" = "#microsoft.graph.deviceHealthScriptDailySchedule"
                    Interval = $scheduleFrequency
                    Time = $StartTime
                    UseUtc = $false
                }
            }
        )
    }
    }

$remediationID = $proactive.ID


$graphApiVersion = "beta"
$Resource = "deviceManagement/deviceHealthScripts"
$uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$remediationID/assign"

try {
    $proactive = Invoke-MSGraphRequest -Url $uri -HttpMethod Post -Content $params
}
catch {
    Write-Error $_.Exception 
    
}
write-host "Remediation Assigned"

write-host "Complete"
Stop-Transcript