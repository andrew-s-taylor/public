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
Write-Host "Installing Microsoft Graph modules if required (current user scope)"

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph.Groups) {
    Write-Host "Microsoft Graph Already Installed"
} 
else {
    try {
        Install-Module -Name Microsoft.Graph.Groups -Scope CurrentUser -Repository PSGallery -Force 
    }
    catch [Exception] {
        $_.message 
        exit
    }
}


if (Get-Module -ListAvailable -Name Microsoft.Graph.authentication) {
    Write-Host "Microsoft Graph Already Installed"
} 
else {
    try {
        Install-Module -Name Microsoft.Graph.authentication -Scope CurrentUser -Repository PSGallery -Force 
    }
    catch [Exception] {
        $_.message 
        exit
    }
}


Function Connect-ToGraph {
    <#
.SYNOPSIS
Authenticates to the Graph API via the Microsoft.Graph.Authentication module.
 
.DESCRIPTION
The Connect-ToGraph cmdlet is a wrapper cmdlet that helps authenticate to the Intune Graph API using the Microsoft.Graph.Authentication module. It leverages an Azure AD app ID and app secret for authentication or user-based auth.
 
.PARAMETER Tenant
Specifies the tenant (e.g. contoso.onmicrosoft.com) to which to authenticate.
 
.PARAMETER AppId
Specifies the Azure AD app ID (GUID) for the application that will be used to authenticate.
 
.PARAMETER AppSecret
Specifies the Azure AD app secret corresponding to the app ID that will be used to authenticate.

.PARAMETER Scopes
Specifies the user scopes for interactive authentication.
 
.EXAMPLE
Connect-ToGraph -TenantId $tenantID -AppId $app -AppSecret $secret
 
-#>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $false)] [string]$Tenant,
        [Parameter(Mandatory = $false)] [string]$AppId,
        [Parameter(Mandatory = $false)] [string]$AppSecret,
        [Parameter(Mandatory = $false)] [string]$scopes
    )

    Process {
        Import-Module Microsoft.Graph.Authentication
        $version = (get-module microsoft.graph.authentication | Select-Object -expandproperty Version).major

        if ($AppId -ne "") {
            $body = @{
                grant_type    = "client_credentials";
                client_id     = $AppId;
                client_secret = $AppSecret;
                scope         = "https://graph.microsoft.com/.default";
            }
     
            $response = Invoke-RestMethod -Method Post -Uri https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token -Body $body
            $accessToken = $response.access_token
     
            $accessToken
            if ($version -eq 2) {
                write-host "Version 2 module detected"
                $accesstokenfinal = ConvertTo-SecureString -String $accessToken -AsPlainText -Force
            }
            else {
                write-host "Version 1 Module Detected"
                Select-MgProfile -Name Beta
                $accesstokenfinal = $accessToken
            }
            $graph = Connect-MgGraph  -AccessToken $accesstokenfinal 
            Write-Host "Connected to Intune tenant $TenantId using app-based authentication (Azure AD authentication not supported)"
        }
        else {
            if ($version -eq 2) {
                write-host "Version 2 module detected"
            }
            else {
                write-host "Version 1 Module Detected"
                Select-MgProfile -Name Beta
            }
            $graph = Connect-MgGraph -scopes $scopes
            Write-Host "Connected to Intune tenant $($graph.TenantId)"
        }
    }
}    

#Importing Modules
write-host "Importing Graph Module"
Import-Module Microsoft.Graph.groups
Import-Module Microsoft.Graph.authentication
##Connect to Graph
write-host "Connecting to Graph"
#Connect to Graph
Connect-ToGraph -Scopes "RoleAssignmentSchedule.ReadWrite.Directory, Domain.Read.All, Domain.ReadWrite.All, Directory.Read.All, Policy.ReadWrite.ConditionalAccess, DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, openid, profile, email, offline_access"




##Create It
write-host "Creating Proactive Remediation"
$graphApiVersion = "beta"
$Resource = "deviceManagement/deviceHealthScripts"
$uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"

try {
    $proactive = Invoke-MGGraphRequest -Uri $uri -Method Post -Body $params -ContentType "application/json" 
}
catch {
    Write-Error $_.Exception 
    
}

write-host "Proactive Remediation Created"

##Assign It
write-host "Assigning Proactive Remediation"

##Get Group ID
$AADGroupID = (get-mggroup | where-object DisplayName -eq $AADGroupName).ObjectID
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
    $proactive = Invoke-MGGraphRequest -Uri $uri -Method Post -Body $params -ContentType "application/json" 
}
catch {
    Write-Error $_.Exception 
    
}
write-host "Remediation Assigned"

write-host "Complete"
Stop-Transcript
