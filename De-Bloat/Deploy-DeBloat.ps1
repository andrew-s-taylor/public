<#PSScriptInfo
.VERSION 1.0
.GUID 729ebf90-26fe-4795-92dc-ca8f570cdd22
.AUTHOR AndrewTaylor
.DESCRIPTION Display an Intune applist in a grid to find more details
.COMPANYNAME 
.COPYRIGHT GPL
.TAGS az azure AVD WVD environment
.LICENSEURI https://github.com/andrew-s-taylor/public/blob/main/LICENSE
.PROJECTURI https://github.com/andrew-s-taylor/public
.ICONURI 
.EXTERNALMODULEDEPENDENCIES azureAD
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
#>
<#
.SYNOPSIS
  Displays List of apps from Intune
.DESCRIPTION
Display an Intune applist in a grid to find more details

.INPUTS
None required
.OUTPUTS
GridView
.NOTES
  Version:        1.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  11/06/2021
  Purpose/Change: Initial script development
  
.EXAMPLE
N/A
#>

####################################################

function Get-AuthToken {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthToken
    Authenticates you with the Graph API interface
    .NOTES
    NAME: Get-AuthToken
    #>
    
    [cmdletbinding()]
    
    param
    (
        [Parameter(Mandatory=$true)]
        $User
    )
    
    $userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User
    
    $tenant = $userUpn.Host
    
    Write-Host "Checking for AzureAD module..."
    
        $AadModule = Get-Module -Name "AzureAD" -ListAvailable
    
        if ($AadModule -eq $null) {
    
            install-module AzureAD -Scope CurrentUser -AllowClobber -Force
    
        }
    
    
    # Getting path to ActiveDirectory Assemblies
    # If the module count is greater than 1 find the latest version
    
        if($AadModule.count -gt 1){
    
            $Latest_Version = ($AadModule | select version | Sort-Object)[-1]
    
            $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }
    
                # Checking if there are multiple versions of the same module found
    
                if($AadModule.count -gt 1){
    
                $aadModule = $AadModule | select -Unique
    
                }
    
            $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
            $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    
        }
    
        else {
    
            $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
            $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    
        }
    
    [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
    
    [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null
    
    $clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
    
    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
    
    $resourceAppIdURI = "https://graph.microsoft.com"
    
    $authority = "https://login.microsoftonline.com/$Tenant"
    
        try {
    
        $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
    
        # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
        # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession
    
        $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"
    
        $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")
    
        $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId).Result
    
            # If the accesstoken is valid then create the authentication header
    
            if($authResult.AccessToken){
    
            # Creating header for Authorization token
    
            $authHeader = @{
                'Content-Type'='application/json'
                'Authorization'="Bearer " + $authResult.AccessToken
                'ExpiresOn'=$authResult.ExpiresOn
                }
    
            return $authHeader
    
            }
    
            else {
    
            Write-Host
            Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
            Write-Host
            break
    
            }
    
        }
    
        catch {
    
        write-host $_.Exception.Message -f Red
        write-host $_.Exception.ItemName -f Red
        write-host
        break
    
        }
    
    }
    
    ####################################################


####################################################

#region Authentication

write-host

# Checking if authToken exists before running authentication
if($global:authToken){

    # Setting DateTime to Universal time to work in all timezones
    $DateTime = (Get-Date).ToUniversalTime()

    # If the authToken exists checking when it expires
    $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes

        if($TokenExpires -le 0){

        write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
        write-host

            # Defining User Principal Name if not present

            if($User -eq $null -or $User -eq ""){

            $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
            Write-Host

            }

        $global:authToken = Get-AuthToken -User $User

        }
}

# Authentication doesn't exist, calling Get-AuthToken function

else {

    if($User -eq $null -or $User -eq ""){

    $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
    Write-Host

    }

# Getting the authorization token
$global:authToken = Get-AuthToken -User $User

}

#endregion

####################################################

#####Deploy DeBloat
#Create Temp location
$random = Get-Random -Maximum 1000 
$random = $random.ToString()
$date =get-date -format yyMMddmmss
$date = $date.ToString()
$path2 = $random + "-"  + $date
$path = "c:\temp\" + $path2 + "\"
New-Item -ItemType Directory -Path $path

# Find the app
$appurl = "https://github.com/andrew-s-taylor/public/tree/main/De-Bloat\removebloat.intunewin"

#Set the download location
$output = "c:\temp\" + $path2 + "\Deploy-Application.intunewin"

#Download it
Invoke-WebRequest -Uri $appurl -OutFile $output -Method Get


$SourceFile = $output

# Defining Intunewin32 detectionRules
#$DetectionXML = Get-IntuneWinXML "$SourceFile" -fileName "detection.xml"

# Defining Intunewin32 detectionRules
$FileRule = New-DetectionRule -File -Path "C:\ProgramData\Debloat" `
-FileOrFolderName "debloat.log" -FileDetectionType exists -check32BitOn64System False

# Creating Array for detection Rule
$DetectionRule = @($FileRule)

$ReturnCodes = Get-DefaultReturnCodes

# Win32 Application Upload
Upload-Win32Lob -SourceFile "$SourceFile" -DisplayName "Windows De-Bloat" -publisher "Andrew Taylor" `
-description "Removes Windows Bloat" -detectionRules $DetectionRule -returnCodes $ReturnCodes `
-installCmdLine 'powershell -executionpolicy bypass -file removebloat.ps1' `
-uninstallCmdLine 'cmd.exe /c'

# Assign it
$ApplicationName = "Windows De-Bloat"

$Application = Get-IntuneApplication | ? { $_.displayName -eq "$ApplicationName" }

#Install
$graphApiVersion = "Beta"
$ApplicationId = $Application.id
$TargetGroupId1 = $intunegrp.id
$InstallIntent1 = "required"


$Resource = "deviceAppManagement/mobileApps/$ApplicationId/assign"
$JSON = @"
{
    "mobileAppAssignments": [
      {
        "@odata.type": "#microsoft.graph.mobileAppAssignment",
        "target": {
        "@odata.type": "#microsoft.graph.groupAssignmentTarget",
        "groupId": "$TargetGroupId1"
        },
        "intent": "$InstallIntent1"
    }
    ]
}
"@

$uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"