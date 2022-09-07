<#PSScriptInfo
.VERSION 1.0.0
.GUID db5cbf82-a7cc-4c1b-beab-943f541a0895
.AUTHOR AndrewTaylor
.DESCRIPTION Moves all members of current Update Ring groups to new AutoPatch Groups, then unassigns old rings, deletes AzureAD groups and deletes old rings
.COMPANYNAME 
.COPYRIGHT GPL
.TAGS intune endpoint MEM environment autopatch
.LICENSEURI https://github.com/andrew-s-taylor/public/blob/main/LICENSE
.PROJECTURI https://github.com/andrew-s-taylor/public
.ICONURI 
.EXTERNALMODULEDEPENDENCIES AzureADPreview
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
#>
<#
.SYNOPSIS
Moves to Autpatch
.DESCRIPTION
Moves all members of current Update Ring groups to new AutoPatch Groups, then unassigns old rings, deletes AzureAD groups and deletes old rings
.INPUTS
None
.OUTPUTS
Creates a log file in %Temp%
.NOTES
  Version:        1.0.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  06/09/2022
  Purpose/Change: Initial script development

  
.EXAMPLE
N/A
#>
$ErrorActionPreference = "Continue"
##Start Logging to %TEMP%\autopatch-intune-DATE.log
$date = get-date -format ddMMyyyy
Start-Transcript -Path $env:TEMP\autopatch-intune-$date.log
write-host "Make it So" -ForegroundColor Green

##############################################################################################################
## Your Group Names
$broadname = "Broad"
$pilotname = "Pilot"
$previewname = "Preview"

#######
##Test = Pilot
##First = Preview
##Fast = IGNORED - will auto-populate
##Broad = Broad
##Note: Switching from 3 to 4 ring system

write-host "Installing AzureAD Module if Required"
####Install Modules
#Install AZ Module if not available
if (Get-Module -ListAvailable -Name AzureADPreview) {
    Write-Host "AZ Ad Preview Module Already Installed"
} 
else {
    try {
        Install-Module -Name AzureADPreview -Scope CurrentUser -Repository PSGallery -Force -AllowClobber 
    }
    catch [Exception] {
        $_.message 
        exit
    }
}


write-host "Unassign non-preview AAD module"
#Group creation needs preview module so we need to remove non-preview first
# Unload the AzureAD module (or continue if it's already unloaded)
Remove-Module AzureAD -force -ErrorAction SilentlyContinue
write-host "AAD Module Unassigned"
write-host "Assigning AzureADPreview Module"
# Load the AzureADPreview module
Import-Module AzureADPreview
write-host "AzureADPreview Module Assigned"


###############################################################################################################
######                                          Add Functions                                            ######
###############################################################################################################

write-host "Adding Functions for authentication"

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
    
            Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"
            $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable
    
        }
    
        if ($AadModule -eq $null) {
            write-host
            write-host "AzureAD Powershell module not installed..." -f Red
            write-host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
            write-host "Script can't continue..." -f Red
            write-host
            exit
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
    
###############################################################################################################

###############################################################################################################
######                                          MS Graph Implementations                                 ######
###############################################################################################################



#Authenticate for MS Graph
#region Authentication

write-host "Authenticating with MS Graph"

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

###############################################################################################################
######                                          Time to Boogie                                           ######
###############################################################################################################

#Create Folder
$csvfolder = "C:\ProgramData\UpdateRings"
If (Test-Path $csvfolder) {
    Write-Output "$csvfolder exists. Skipping."
}
Else {
    Write-Output "The folder '$csvfolder' doesn't exist. This folder will be used for storing logs created after the script runs. Creating now."
    Start-Sleep 1
    New-Item -Path "$csvfolder" -ItemType Directory
    Write-Output "The folder $csvfolder was successfully created."
}


#Get Update Rings
##Filter to only Update Policies
$updateringsurl = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$filter=(isof('microsoft.graph.windowsUpdateForBusinessConfiguration'))"

write-host "Getting Update Rings"
##Grab the Value
$currentpolicies = (Invoke-RestMethod -Uri $updateringsurl -Headers $authToken -Method Get).Value

write-host "Getting Policy IDs"
##Find each policy ID
foreach ($currentpolicy in $currentpolicies) {
$policyname = $currentpolicy.DisplayName

##Broad - Ignoring new Autopatch Group for now
if (($policyname -like "*$broadname*") -and ($policyname -ne "Modern Workplace Update Policy [Broad]-[Windows Autopatch]")) {
$broadid = $currentpolicy.Id
write-host "Broad ring is $broadid"
}
}

##Preview - Ignoring new Autopatch Group for now
if (($policyname -like "*$previewname*") -and ($policyname -ne "Modern Workplace Update Policy [Fast]-[Windows Autopatch]")-and ($policyname -ne "Modern Workplace Update Policy [First]-[Windows Autopatch]")-and ($policyname -ne "Modern Workplace Update Policy [Test]-[Windows Autopatch]")) {
$previewid = $currentpolicy.Id
write-host "Preview ring is $previewid"
}


##Pilot - Ignoring new Autopatch Group for now
if (($policyname -like "*$pilotname*") -and ($policyname -ne "Modern Workplace Update Policy [Fast]-[Windows Autopatch]")-and ($policyname -ne "Modern Workplace Update Policy [First]-[Windows Autopatch]")-and ($policyname -ne "Modern Workplace Update Policy [Test]-[Windows Autopatch]")) {
$pilotid = $currentpolicy.Id
write-host "Pilot ring is $pilotid"
}




#Get the Group ID Assigned

write-host "Finding AAD Group IDs currently used"
$broaduricurrent = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$broadid/groupAssignments"
$previewuricurrent = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$previewid/groupAssignments"
$piloturicurrent = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$pilotid/groupAssignments"

$broadgroupscurrent = ((Invoke-RestMethod -Uri $broaduricurrent -Headers $authToken -Method Get).Value).TargetGroupID
write-host "Broad Ring uses $broadgroupscurrent"
$previewgroupscurrent = ((Invoke-RestMethod -Uri $previewuricurrent -Headers $authToken -Method Get).Value).TargetGroupID
write-host "Preview Ring uses $previewgroupscurrent"
$pilotgroupscurrent = ((Invoke-RestMethod -Uri $piloturicurrent -Headers $authToken -Method Get).Value).TargetGroupID
write-host "Pilot Ring uses $pilotgroupscurrent"


write-host "Groups grabbed, removing assignments"
##Delete Old Assignments
foreach ($currentpolicy in $currentpolicies) {
$policyname = $currentpolicy.DisplayName

if (($policyname -ne "Modern Workplace Update Policy [Fast]-[Windows Autopatch]") -and ($policyname -ne "Modern Workplace Update Policy [First]-[Windows Autopatch]")-and ($policyname -ne "Modern Workplace Update Policy [Test]-[Windows Autopatch]")-and ($policyname -ne "Modern Workplace Update Policy [Broad]-[Windows Autopatch]")) {
$policyid = $currentpolicy.Id
write-host "Unassigning $policyname"
$uri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$policyid/assign"
$json = @"
{
    "assignments":  [
    ]

} 
"@
Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"
write-host "$policyname unassigned"
}
}


write-host "Assignments removed, populating groups"

connect-azureAD

##Move Broad Group Members
write-host "Getting members of Broad Group"
$currentbroadmembers = Get-AzureADGroupMember -ObjectId $broadgroupscurrent -All $true
$newbroadgroupid = (Get-AzureADGroup -SearchString "Windows Autopatch Device Registration").ObjectID
write-host "Exporting Pilot Members to CSV"
$currentbroadmembers | Export-Csv "$csvfolder\BroadMembers.csv"

write-host "Adding to Windows Autopatch Device Registration"
foreach ($broadmember in $currentbroadmembers) {
Add-AzureADGroupMember -ObjectId $newbroadgroupid -RefObjectId $broadmember.ObjectID
write-host "Added $broadmember.DisplayName to Windows Autopatch Device Registration"
}
##Remove Broad Group
write-host "Removing Broad AAD Group"
Remove-AzureADGroup -ObjectId $broadgroupscurrent
write-host "Broad Group AAD Removed"


##Move Preview Group Members
write-host "Getting members of Preview Group"
$previewbroadmembers = Get-AzureADGroupMember -ObjectId $previewgroupscurrent -All $true
$newpreviewgroupid = (Get-AzureADGroup -SearchString "Windows Autopatch Device Registration").ObjectID
write-host "Exporting Pilot Members to CSV"
$previewbroadmembers | Export-Csv "$csvfolder\PreviewMembers.csv"

write-host "Adding to Windows Autopatch Device Registration"
foreach ($previewmember in $previewbroadmembers) {
Add-AzureADGroupMember -ObjectId $newpreviewgroupid -RefObjectId $previewmember.ObjectID
write-host "Added $previewmember.DisplayName to Windows Autopatch Device Registration"
}
##Remove Broad Group
write-host "Removing Preview AAD Group"
Remove-AzureADGroup -ObjectId $previewgroupscurrent
write-host "Preview Group AAD Removed"

##Move Pilot Group 
write-host "Getting members of Pilot Group"
$pilotbroadmembers = Get-AzureADGroupMember -ObjectId $pilotgroupscurrent -All $true
$newpilotgroupid = (Get-AzureADGroup -SearchString "Windows Autopatch Device Registration").ObjectID
write-host "Exporting Pilot Members to CSV"
$pilotbroadmembers | Export-Csv "$csvfolder\PilotMembers.csv"
write-host "Adding to Windows Autopatch Device Registration"

foreach ($pilotmember in $pilotbroadmembers) {
Add-AzureADGroupMember -ObjectId $newpilotgroupid -RefObjectId $pilotmember.ObjectID
write-host "Added $pilotmember.DisplayName to Windows Autopatch Device Registration"
}
##Remove Broad Group
write-host "Removing Pilot AAD Group"
Remove-AzureADGroup -ObjectId $pilotgroupscurrent
write-host "Pilot Group AAD Removed"


write-host "Groups populated, and old groups removed"
write-host "Removing old policies"
##Finally Remove Policies
foreach ($currentpolicy in $currentpolicies) {
$policyname = $currentpolicy.DisplayName

if (($policyname -ne "Modern Workplace Update Policy [Fast]-[Windows Autopatch]") -and ($policyname -ne "Modern Workplace Update Policy [First]-[Windows Autopatch]")-and ($policyname -ne "Modern Workplace Update Policy [Test]-[Windows Autopatch]")-and ($policyname -ne "Modern Workplace Update Policy [Broad]-[Windows Autopatch]")) {
$policyid = $currentpolicy.Id
$uri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$policyid"
Invoke-RestMethod -Uri $uri -Headers $authToken -Method Delete
write-host "$policyname Deleted"
}
}
write-host "Policies removed, script complete"
invoke-item $csvfolder