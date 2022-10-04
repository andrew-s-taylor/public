<#PSScriptInfo
.VERSION 1.0.0
.GUID f08902ff-3e2f-4a51-995d-c686fc307325
.AUTHOR AndrewTaylor
.DESCRIPTION Creates Win32 apps, AAD groups and Proactive Remediations to keep apps updated
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
  Creates and uploads a win32 app from Winget
.DESCRIPTION
.Searches all Winget apps and displays GridView output
.Creates Intunewin
.Creates AAD Groups
.Creates Proactive Remediations (for auto updates)
.Uploads and assigns everything

.INPUTS
App ID and App name (from Gridview)
.OUTPUTS
In-Line Outputs
.NOTES
  Version:        1.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  30/09/2022
  Last Modified:  04/10/2022
  Purpose/Change: Initial script development
.EXAMPLE
N/A
#>
##########################################################################################

$ErrorActionPreference = "Continue"
##Start Logging to %TEMP%\intune.log
$date = get-date -format ddMMyyyy
Start-Transcript -Path $env:TEMP\intune-$date.log

##########################################################################################
$cred = Get-Credential -Message "Enter your Intune Credentials"
###############################################################################################################
######                                         Install Modules                                           ######
###############################################################################################################
Write-Host "Installing Intune modules if required (current user scope)"

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

##Import Modules
#Group creation needs preview module so we need to remove non-preview first
# Unload the AzureAD module (or continue if it's already unloaded)
Remove-Module AzureAD -force -ErrorAction SilentlyContinue
# Load the AzureADPreview module
Import-Module AzureADPreview

###############################################################################################################

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
$path = "c:\temp\" + $path2 + "\"

New-Item -ItemType Directory -Path $path

###############################################################################################################
######                                         Install Apps                                              ######
###############################################################################################################


##IntuneWinAppUtil
$intuneapputilurl = "https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool/raw/master/IntuneWinAppUtil.exe"
$intuneapputiloutput = $path + "IntuneWinAppUtil.exe"
Invoke-WebRequest -Uri $intuneapputilurl -OutFile $intuneapputiloutput

##Winget
$hasPackageManager = Get-AppPackage -name 'Microsoft.DesktopAppInstaller'
if (!$hasPackageManager -or [version]$hasPackageManager.Version -lt [version]"1.10.0.0") {
    "Installing winget Dependencies"
    Add-AppxPackage -Path 'https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx'
    $releases_url = 'https://api.github.com/repos/microsoft/winget-cli/releases/latest'

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $releases = Invoke-RestMethod -uri $releases_url
    $latestRelease = $releases.assets | Where { $_.browser_download_url.EndsWith('msixbundle') } | Select -First 1

    "Installing winget from $($latestRelease.browser_download_url)"
    Add-AppxPackage -Path $latestRelease.browser_download_url
}
else {
    "winget already installed"
}


###############################################################################################################
######                                          Add Functions                                            ######
###############################################################################################################
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
    
    ####################################################
    Function Add-MDMApplication(){

        <#
        .SYNOPSIS
        This function is used to add an MDM application using the Graph API REST interface
        .DESCRIPTION
        The function connects to the Graph API Interface and adds an MDM application from the itunes store
        .EXAMPLE
        Add-MDMApplication -JSON $JSON
        Adds an application into Intune
        .NOTES
        NAME: Add-MDMApplication
        #>
        
        [cmdletbinding()]
        
        param
        (
            $JSON
        )
        
        $graphApiVersion = "Beta"
        $App_resource = "deviceAppManagement/mobileApps"
        
            try {
        
                if(!$JSON){
        
                write-host "No JSON was passed to the function, provide a JSON variable" -f Red
                break
        
                }
        
                Test-JSON -JSON $JSON
        
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($App_resource)"
                Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/json" -Body $JSON -Headers $authToken
        
            }
        
            catch {
        
            $ex = $_.Exception
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            Write-Host "Response content:`n$responseBody" -f Red
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
            write-host
            break
        
            }
        
        }
        
        ####################################################
        
        Function Add-ApplicationAssignment(){
        
        <#
        .SYNOPSIS
        This function is used to add an application assignment using the Graph API REST interface
        .DESCRIPTION
        The function connects to the Graph API Interface and adds a application assignment
        .EXAMPLE
        Add-ApplicationAssignment -ApplicationId $ApplicationId -TargetGroupId $TargetGroupId -InstallIntent $InstallIntent
        Adds an application assignment in Intune
        .NOTES
        NAME: Add-ApplicationAssignment
        #>
        
        [cmdletbinding()]
        
        param
        (
            $ApplicationId,
            $TargetGroupId,
            $InstallIntent
        )
        
        $graphApiVersion = "Beta"
        $Resource = "deviceAppManagement/mobileApps/$ApplicationId/assign"
            
            try {
        
                if(!$ApplicationId){
        
                write-host "No Application Id specified, specify a valid Application Id" -f Red
                break
        
                }
        
                if(!$TargetGroupId){
        
                write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red
                break
        
                }
        
                
                if(!$InstallIntent){
        
                write-host "No Install Intent specified, specify a valid Install Intent - available, notApplicable, required, uninstall, availableWithoutEnrollment" -f Red
                break
        
                }
        
        $JSON = @"
        {
            "mobileAppAssignments": [
            {
                "@odata.type": "#microsoft.graph.mobileAppAssignment",
                "target": {
                "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                "groupId": "$TargetGroupId"
                },
                "intent": "$InstallIntent"
            }
            ]
        }
"@
        
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"
        
            }
            
            catch {
        
            $ex = $_.Exception
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            Write-Host "Response content:`n$responseBody" -f Red
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
            write-host
            break
        
            }
        
        }
        
        
        function CloneObject($object){
        
            $stream = New-Object IO.MemoryStream;
            $formatter = New-Object Runtime.Serialization.Formatters.Binary.BinaryFormatter;
            $formatter.Serialize($stream, $object);
            $stream.Position = 0;
            $formatter.Deserialize($stream);
        }
        
        ####################################################
        
        function WriteHeaders($authToken){
        
            foreach ($header in $authToken.GetEnumerator())
            {
                if ($header.Name.ToLower() -eq "authorization")
                {
                    continue;
                }
        
                Write-Host -ForegroundColor Gray "$($header.Name): $($header.Value)";
            }
        }
        
        ####################################################
        
        function MakeGetRequest($collectionPath){
        
            $uri = "$baseUrl$collectionPath";
            $request = "GET $uri";
            
            if ($logRequestUris) { Write-Host $request; }
            if ($logHeaders) { WriteHeaders $authToken; }
        
            try
            {
                Test-AuthToken
                $response = Invoke-RestMethod $uri -Method Get -Headers $authToken;
                $response;
            }
            catch
            {
                Write-Host -ForegroundColor Red $request;
                Write-Host -ForegroundColor Red $_.Exception.Message;
                throw;
            }
        }
        
        ####################################################
        
        function MakePatchRequest($collectionPath, $body){
        
            MakeRequest "PATCH" $collectionPath $body;
        
        }
        
        ####################################################
        
        function MakePostRequest($collectionPath, $body){
        
            MakeRequest "POST" $collectionPath $body;
        
        }
        
        ####################################################
        
        function MakeRequest($verb, $collectionPath, $body){
        
            $uri = "$baseUrl$collectionPath";
            $request = "$verb $uri";
            
            $clonedHeaders = CloneObject $authToken;
            $clonedHeaders["content-length"] = $body.Length;
            $clonedHeaders["content-type"] = "application/json";
        
            if ($logRequestUris) { Write-Host $request; }
            if ($logHeaders) { WriteHeaders $clonedHeaders; }
            if ($logContent) { Write-Host -ForegroundColor Gray $body; }
        
            try
            {
                Test-AuthToken
                $response = Invoke-RestMethod $uri -Method $verb -Headers $clonedHeaders -Body $body;
                $response;
            }
            catch
            {
                Write-Host -ForegroundColor Red $request;
                Write-Host -ForegroundColor Red $_.Exception.Message;
                throw;
            }
        }
        
        ####################################################
        
        function UploadAzureStorageChunk($sasUri, $id, $body){
        
            $uri = "$sasUri&comp=block&blockid=$id";
            $request = "PUT $uri";
        
            $iso = [System.Text.Encoding]::GetEncoding("iso-8859-1");
            $encodedBody = $iso.GetString($body);
            $headers = @{
                "x-ms-blob-type" = "BlockBlob"
            };
        
            if ($logRequestUris) { Write-Host $request; }
            if ($logHeaders) { WriteHeaders $headers; }
        
            try
            {
                $response = Invoke-WebRequest $uri -Method Put -Headers $headers -Body $encodedBody;
            }
            catch
            {
                Write-Host -ForegroundColor Red $request;
                Write-Host -ForegroundColor Red $_.Exception.Message;
                throw;
            }
        
        }
        
        ####################################################
        
        function FinalizeAzureStorageUpload($sasUri, $ids){
        
            $uri = "$sasUri&comp=blocklist";
            $request = "PUT $uri";
        
            $xml = '<?xml version="1.0" encoding="utf-8"?><BlockList>';
            foreach ($id in $ids)
            {
                $xml += "<Latest>$id</Latest>";
            }
            $xml += '</BlockList>';
        
            if ($logRequestUris) { Write-Host $request; }
            if ($logContent) { Write-Host -ForegroundColor Gray $xml; }
        
            try
            {
                Invoke-RestMethod $uri -Method Put -Body $xml;
            }
            catch
            {
                Write-Host -ForegroundColor Red $request;
                Write-Host -ForegroundColor Red $_.Exception.Message;
                throw;
            }
        }
        
        ####################################################
        
        function UploadFileToAzureStorage($sasUri, $filepath, $fileUri){
        
            try {
        
                $chunkSizeInBytes = 1024l * 1024l * $azureStorageUploadChunkSizeInMb;
                
                # Start the timer for SAS URI renewal.
                $sasRenewalTimer = [System.Diagnostics.Stopwatch]::StartNew()
                
                # Find the file size and open the file.
                $fileSize = (Get-Item $filepath).length;
                $chunks = [Math]::Ceiling($fileSize / $chunkSizeInBytes);
                $reader = New-Object System.IO.BinaryReader([System.IO.File]::Open($filepath, [System.IO.FileMode]::Open));
                $position = $reader.BaseStream.Seek(0, [System.IO.SeekOrigin]::Begin);
                
                # Upload each chunk. Check whether a SAS URI renewal is required after each chunk is uploaded and renew if needed.
                $ids = @();
        
                for ($chunk = 0; $chunk -lt $chunks; $chunk++){
        
                    $id = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($chunk.ToString("0000")));
                    $ids += $id;
        
                    $start = $chunk * $chunkSizeInBytes;
                    $length = [Math]::Min($chunkSizeInBytes, $fileSize - $start);
                    $bytes = $reader.ReadBytes($length);
                    
                    $currentChunk = $chunk + 1;			
        
                    Write-Progress -Activity "Uploading File to Azure Storage" -status "Uploading chunk $currentChunk of $chunks" `
                    -percentComplete ($currentChunk / $chunks*100)
        
                    $uploadResponse = UploadAzureStorageChunk $sasUri $id $bytes;
                    
                    # Renew the SAS URI if 7 minutes have elapsed since the upload started or was renewed last.
                    if ($currentChunk -lt $chunks -and $sasRenewalTimer.ElapsedMilliseconds -ge 450000){
        
                        $renewalResponse = RenewAzureStorageUpload $fileUri;
                        $sasRenewalTimer.Restart();
                    
                    }
        
                }
        
                Write-Progress -Completed -Activity "Uploading File to Azure Storage"
        
                $reader.Close();
        
            }
        
            finally {
        
                if ($reader -ne $null) { $reader.Dispose(); }
            
            }
            
            # Finalize the upload.
            $uploadResponse = FinalizeAzureStorageUpload $sasUri $ids;
        
        }
        
        ####################################################
        
        function RenewAzureStorageUpload($fileUri){
        
            $renewalUri = "$fileUri/renewUpload";
            $actionBody = "";
            $rewnewUriResult = MakePostRequest $renewalUri $actionBody;
            
            $file = WaitForFileProcessing $fileUri "AzureStorageUriRenewal" $azureStorageRenewSasUriBackOffTimeInSeconds;
        
        }
        
        ####################################################
        
        function WaitForFileProcessing($fileUri, $stage){
        
            $attempts= 600;
            $waitTimeInSeconds = 10;
        
            $successState = "$($stage)Success";
            $pendingState = "$($stage)Pending";
            $failedState = "$($stage)Failed";
            $timedOutState = "$($stage)TimedOut";
        
            $file = $null;
            while ($attempts -gt 0)
            {
                $file = MakeGetRequest $fileUri;
        
                if ($file.uploadState -eq $successState)
                {
                    break;
                }
                elseif ($file.uploadState -ne $pendingState)
                {
                    Write-Host -ForegroundColor Red $_.Exception.Message;
                    throw "File upload state is not success: $($file.uploadState)";
                }
        
                Start-Sleep $waitTimeInSeconds;
                $attempts--;
            }
        
            if ($file -eq $null -or $file.uploadState -ne $successState)
            {
                throw "File request did not complete in the allotted time.";
            }
        
            $file;
        }
        
        ####################################################
        
        function GetWin32AppBody(){
        
        param
        (
        
        [parameter(Mandatory=$true,ParameterSetName = "MSI",Position=1)]
        [Switch]$MSI,
        
        [parameter(Mandatory=$true,ParameterSetName = "EXE",Position=1)]
        [Switch]$EXE,
        
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$displayName,
        
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$publisher,
        
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$description,
        
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$filename,
        
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$SetupFileName,
        
        [parameter(Mandatory=$true)]
        [ValidateSet('system','user')]
        $installExperience = "system",
        
        [parameter(Mandatory=$true,ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        $installCommandLine,
        
        [parameter(Mandatory=$true,ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        $uninstallCommandLine,
        
        [parameter(Mandatory=$true,ParameterSetName = "MSI")]
        [ValidateNotNullOrEmpty()]
        $MsiPackageType,
        
        [parameter(Mandatory=$true,ParameterSetName = "MSI")]
        [ValidateNotNullOrEmpty()]
        $MsiProductCode,
        
        [parameter(Mandatory=$false,ParameterSetName = "MSI")]
        $MsiProductName,
        
        [parameter(Mandatory=$true,ParameterSetName = "MSI")]
        [ValidateNotNullOrEmpty()]
        $MsiProductVersion,
        
        [parameter(Mandatory=$false,ParameterSetName = "MSI")]
        $MsiPublisher,
        
        [parameter(Mandatory=$true,ParameterSetName = "MSI")]
        [ValidateNotNullOrEmpty()]
        $MsiRequiresReboot,
        
        [parameter(Mandatory=$true,ParameterSetName = "MSI")]
        [ValidateNotNullOrEmpty()]
        $MsiUpgradeCode
        
        )
        
            if($MSI){
        
                $body = @{ "@odata.type" = "#microsoft.graph.win32LobApp" };
                $body.applicableArchitectures = "x64,x86";
                $body.description = $description;
                $body.developer = "";
                $body.displayName = $displayName;
                $body.fileName = $filename;
                $body.installCommandLine = "msiexec /i `"$SetupFileName`""
                $body.installExperience = @{"runAsAccount" = "$installExperience"};
                $body.informationUrl = $null;
                $body.isFeatured = $false;
                $body.minimumSupportedOperatingSystem = @{"v10_1607" = $true};
                $body.msiInformation = @{
                    "packageType" = "$MsiPackageType";
                    "productCode" = "$MsiProductCode";
                    "productName" = "$MsiProductName";
                    "productVersion" = "$MsiProductVersion";
                    "publisher" = "$MsiPublisher";
                    "requiresReboot" = "$MsiRequiresReboot";
                    "upgradeCode" = "$MsiUpgradeCode"
                };
                $body.notes = "";
                $body.owner = "";
                $body.privacyInformationUrl = $null;
                $body.publisher = $publisher;
                $body.runAs32bit = $false;
                $body.setupFilePath = $SetupFileName;
                $body.uninstallCommandLine = "msiexec /x `"$MsiProductCode`""
        
            }
        
            elseif($EXE){
        
                $body = @{ "@odata.type" = "#microsoft.graph.win32LobApp" };
                $body.description = $description;
                $body.developer = "";
                $body.displayName = $displayName;
                $body.fileName = $filename;
                $body.installCommandLine = "$installCommandLine"
                $body.installExperience = @{"runAsAccount" = "$installExperience"};
                $body.informationUrl = $null;
                $body.isFeatured = $false;
                $body.minimumSupportedOperatingSystem = @{"v10_1607" = $true};
                $body.msiInformation = $null;
                $body.notes = "";
                $body.owner = "";
                $body.privacyInformationUrl = $null;
                $body.publisher = $publisher;
                $body.runAs32bit = $false;
                $body.setupFilePath = $SetupFileName;
                $body.uninstallCommandLine = "$uninstallCommandLine"
        
            }
        
            $body;
        }
        
        ####################################################
        
        function GetAppFileBody($name, $size, $sizeEncrypted, $manifest){
        
            $body = @{ "@odata.type" = "#microsoft.graph.mobileAppContentFile" };
            $body.name = $name;
            $body.size = $size;
            $body.sizeEncrypted = $sizeEncrypted;
            $body.manifest = $manifest;
            $body.isDependency = $false;
        
            $body;
        }
        
        ####################################################
        
        function GetAppCommitBody($contentVersionId, $LobType){
        
            $body = @{ "@odata.type" = "#$LobType" };
            $body.committedContentVersion = $contentVersionId;
        
            $body;
        
        }
        
        ####################################################
        
        Function Test-SourceFile(){
        
        param
        (
            [parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            $SourceFile
        )
        
            try {
        
                    if(!(test-path "$SourceFile")){
        
                    Write-Host
                    Write-Host "Source File '$sourceFile' doesn't exist..." -ForegroundColor Red
                    throw
        
                    }
        
                }
        
            catch {
        
                Write-Host -ForegroundColor Red $_.Exception.Message;
                Write-Host
                break
        
            }
        
        }
        
        ####################################################
        
        Function New-DetectionRule(){
        
        [cmdletbinding()]
        
        param
        (
         [parameter(Mandatory=$true,ParameterSetName = "PowerShell",Position=1)]
         [Switch]$PowerShell,
        
         [parameter(Mandatory=$true,ParameterSetName = "MSI",Position=1)]
         [Switch]$MSI,
        
         [parameter(Mandatory=$true,ParameterSetName = "File",Position=1)]
         [Switch]$File,
        
         [parameter(Mandatory=$true,ParameterSetName = "Registry",Position=1)]
         [Switch]$Registry,
        
         [parameter(Mandatory=$true,ParameterSetName = "PowerShell")]
         [ValidateNotNullOrEmpty()]
         [String]$ScriptFile,
        
         [parameter(Mandatory=$true,ParameterSetName = "PowerShell")]
         [ValidateNotNullOrEmpty()]
         $enforceSignatureCheck,
        
         [parameter(Mandatory=$true,ParameterSetName = "PowerShell")]
         [ValidateNotNullOrEmpty()]
         $runAs32Bit,
        
         [parameter(Mandatory=$true,ParameterSetName = "MSI")]
         [ValidateNotNullOrEmpty()]
         [String]$MSIproductCode,
           
         [parameter(Mandatory=$true,ParameterSetName = "File")]
         [ValidateNotNullOrEmpty()]
         [String]$Path,
         
         [parameter(Mandatory=$true,ParameterSetName = "File")]
         [ValidateNotNullOrEmpty()]
         [string]$FileOrFolderName,
        
         [parameter(Mandatory=$true,ParameterSetName = "File")]
         [ValidateSet("notConfigured","exists","modifiedDate","createdDate","version","sizeInMB")]
         [string]$FileDetectionType,
        
         [parameter(Mandatory=$false,ParameterSetName = "File")]
         $FileDetectionValue = $null,
        
         [parameter(Mandatory=$true,ParameterSetName = "File")]
         [ValidateSet("True","False")]
         [string]$check32BitOn64System = "False",
        
         [parameter(Mandatory=$true,ParameterSetName = "Registry")]
         [ValidateNotNullOrEmpty()]
         [String]$RegistryKeyPath,
        
         [parameter(Mandatory=$true,ParameterSetName = "Registry")]
         [ValidateSet("notConfigured","exists","doesNotExist","string","integer","version")]
         [string]$RegistryDetectionType,
        
         [parameter(Mandatory=$false,ParameterSetName = "Registry")]
         [ValidateNotNullOrEmpty()]
         [String]$RegistryValue,
        
         [parameter(Mandatory=$true,ParameterSetName = "Registry")]
         [ValidateSet("True","False")]
         [string]$check32BitRegOn64System = "False"
        
        )
        
            if($PowerShell){
        
                if(!(Test-Path "$ScriptFile")){
                    
                    Write-Host
                    Write-Host "Could not find file '$ScriptFile'..." -ForegroundColor Red
                    Write-Host "Script can't continue..." -ForegroundColor Red
                    Write-Host
                    break
        
                }
                
                $ScriptContent = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("$ScriptFile"));
                
                $DR = @{ "@odata.type" = "#microsoft.graph.win32LobAppPowerShellScriptDetection" }
                $DR.enforceSignatureCheck = $false;
                $DR.runAs32Bit = $false;
                $DR.scriptContent =  "$ScriptContent";
        
            }
            
            elseif($MSI){
            
                $DR = @{ "@odata.type" = "#microsoft.graph.win32LobAppProductCodeDetection" }
                $DR.productVersionOperator = "notConfigured";
                $DR.productCode = "$MsiProductCode";
                $DR.productVersion =  $null;
        
            }
        
            elseif($File){
            
                $DR = @{ "@odata.type" = "#microsoft.graph.win32LobAppFileSystemDetection" }
                $DR.check32BitOn64System = "$check32BitOn64System";
                $DR.detectionType = "$FileDetectionType";
                $DR.detectionValue = $FileDetectionValue;
                $DR.fileOrFolderName = "$FileOrFolderName";
                $DR.operator =  "notConfigured";
                $DR.path = "$Path"
        
            }
        
            elseif($Registry){
            
                $DR = @{ "@odata.type" = "#microsoft.graph.win32LobAppRegistryDetection" }
                $DR.check32BitOn64System = "$check32BitRegOn64System";
                $DR.detectionType = "$RegistryDetectionType";
                $DR.detectionValue = "";
                $DR.keyPath = "$RegistryKeyPath";
                $DR.operator = "notConfigured";
                $DR.valueName = "$RegistryValue"
        
            }
        
            return $DR
        
        }
        
        ####################################################
        
        function Get-DefaultReturnCodes(){
        
        @{"returnCode" = 0;"type" = "success"}, `
        @{"returnCode" = 1707;"type" = "success"}, `
        @{"returnCode" = 3010;"type" = "softReboot"}, `
        @{"returnCode" = 1641;"type" = "hardReboot"}, `
        @{"returnCode" = 1618;"type" = "retry"}
        
        }
        
        ####################################################
        
        function New-ReturnCode(){
        
        param
        (
        [parameter(Mandatory=$true)]
        [int]$returnCode,
        [parameter(Mandatory=$true)]
        [ValidateSet('success','softReboot','hardReboot','retry')]
        $type
        )
        
            @{"returnCode" = $returnCode;"type" = "$type"}
        
        }
        
        ####################################################
        
        Function Get-IntuneWinXML(){
        
        param
        (
        [Parameter(Mandatory=$true)]
        $SourceFile,
        
        [Parameter(Mandatory=$true)]
        $fileName,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("false","true")]
        [string]$removeitem = "true"
        )
        
        Test-SourceFile "$SourceFile"
        
        $Directory = [System.IO.Path]::GetDirectoryName("$SourceFile")
        
        Add-Type -Assembly System.IO.Compression.FileSystem
        $zip = [IO.Compression.ZipFile]::OpenRead("$SourceFile")
        
            $zip.Entries | where {$_.Name -like "$filename" } | foreach {
        
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, "$Directory\$filename", $true)
        
            }
        
        $zip.Dispose()
        
        [xml]$IntuneWinXML = gc "$Directory\$filename"
        
        return $IntuneWinXML
        
        if($removeitem -eq "true"){ remove-item "$Directory\$filename" }
        
        }
        
        ####################################################
        
        Function Get-IntuneWinFile(){
        
        param
        (
        [Parameter(Mandatory=$true)]
        $SourceFile,
        
        [Parameter(Mandatory=$true)]
        $fileName,
        
        [Parameter(Mandatory=$false)]
        [string]$Folder = "win32"
        )
        
            $Directory = [System.IO.Path]::GetDirectoryName("$SourceFile")
        
            if(!(Test-Path "$Directory\$folder")){
        
                New-Item -ItemType Directory -Path "$Directory" -Name "$folder" | Out-Null
        
            }
        
            Add-Type -Assembly System.IO.Compression.FileSystem
            $zip = [IO.Compression.ZipFile]::OpenRead("$SourceFile")
        
                $zip.Entries | where {$_.Name -like "$filename" } | foreach {
        
                [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, "$Directory\$folder\$filename", $true)
        
                }
        
            $zip.Dispose()
        
            return "$Directory\$folder\$filename"
        
            if($removeitem -eq "true"){ remove-item "$Directory\$filename" }
        
        }
        
        ####################################################
        
        function Upload-Win32Lob(){
        
        <#
        .SYNOPSIS
        This function is used to upload a Win32 Application to the Intune Service
        .DESCRIPTION
        This function is used to upload a Win32 Application to the Intune Service
        .EXAMPLE
        Upload-Win32Lob "C:\Packages\package.intunewin" -publisher "Microsoft" -description "Package"
        This example uses all parameters required to add an intunewin File into the Intune Service
        .NOTES
        NAME: Upload-Win32LOB
        #>
        
        [cmdletbinding()]
        
        param
        (
            [parameter(Mandatory=$true,Position=1)]
            [ValidateNotNullOrEmpty()]
            [string]$SourceFile,
        
            [parameter(Mandatory=$false)]
            [ValidateNotNullOrEmpty()]
            [string]$displayName,
        
            [parameter(Mandatory=$true,Position=2)]
            [ValidateNotNullOrEmpty()]
            [string]$publisher,
        
            [parameter(Mandatory=$true,Position=3)]
            [ValidateNotNullOrEmpty()]
            [string]$description,
        
            [parameter(Mandatory=$true,Position=4)]
            [ValidateNotNullOrEmpty()]
            $detectionRules,
        
            [parameter(Mandatory=$true,Position=5)]
            [ValidateNotNullOrEmpty()]
            $returnCodes,
        
            [parameter(Mandatory=$false,Position=6)]
            [ValidateNotNullOrEmpty()]
            [string]$installCmdLine,
        
            [parameter(Mandatory=$false,Position=7)]
            [ValidateNotNullOrEmpty()]
            [string]$uninstallCmdLine,
        
            [parameter(Mandatory=$false,Position=8)]
            [ValidateSet('system','user')]
            $installExperience = "system"
        )
        
            try	{
        
                $LOBType = "microsoft.graph.win32LobApp"
        
                Write-Host "Testing if SourceFile '$SourceFile' Path is valid..." -ForegroundColor Yellow
                Test-SourceFile "$SourceFile"
        
                $Win32Path = "$SourceFile"
        
                Write-Host
                Write-Host "Creating JSON data to pass to the service..." -ForegroundColor Yellow
        
                # Funciton to read Win32LOB file
                $DetectionXML = Get-IntuneWinXML "$SourceFile" -fileName "detection.xml"
        
                # If displayName input don't use Name from detection.xml file
                if($displayName){ $DisplayName = $displayName }
                else { $DisplayName = $DetectionXML.ApplicationInfo.Name }
                
                $FileName = $DetectionXML.ApplicationInfo.FileName
        
                $SetupFileName = $DetectionXML.ApplicationInfo.SetupFile
        
                $Ext = [System.IO.Path]::GetExtension($SetupFileName)
        
                if((($Ext).contains("msi") -or ($Ext).contains("Msi")) -and (!$installCmdLine -or !$uninstallCmdLine)){
        
                    # MSI
                    $MsiExecutionContext = $DetectionXML.ApplicationInfo.MsiInfo.MsiExecutionContext
                    $MsiPackageType = "DualPurpose";
                    if($MsiExecutionContext -eq "System") { $MsiPackageType = "PerMachine" }
                    elseif($MsiExecutionContext -eq "User") { $MsiPackageType = "PerUser" }
        
                    $MsiProductCode = $DetectionXML.ApplicationInfo.MsiInfo.MsiProductCode
                    $MsiProductVersion = $DetectionXML.ApplicationInfo.MsiInfo.MsiProductVersion
                    $MsiPublisher = $DetectionXML.ApplicationInfo.MsiInfo.MsiPublisher
                    $MsiRequiresReboot = $DetectionXML.ApplicationInfo.MsiInfo.MsiRequiresReboot
                    $MsiUpgradeCode = $DetectionXML.ApplicationInfo.MsiInfo.MsiUpgradeCode
                    
                    if($MsiRequiresReboot -eq "false"){ $MsiRequiresReboot = $false }
                    elseif($MsiRequiresReboot -eq "true"){ $MsiRequiresReboot = $true }
        
                    $mobileAppBody = GetWin32AppBody `
                        -MSI `
                        -displayName "$DisplayName" `
                        -publisher "$publisher" `
                        -description $description `
                        -filename $FileName `
                        -SetupFileName "$SetupFileName" `
                        -installExperience $installExperience `
                        -MsiPackageType $MsiPackageType `
                        -MsiProductCode $MsiProductCode `
                        -MsiProductName $displayName `
                        -MsiProductVersion $MsiProductVersion `
                        -MsiPublisher $MsiPublisher `
                        -MsiRequiresReboot $MsiRequiresReboot `
                        -MsiUpgradeCode $MsiUpgradeCode
        
                }
        
                else {
        
                    $mobileAppBody = GetWin32AppBody -EXE -displayName "$DisplayName" -publisher "$publisher" `
                    -description $description -filename $FileName -SetupFileName "$SetupFileName" `
                    -installExperience $installExperience -installCommandLine $installCmdLine `
                    -uninstallCommandLine $uninstallcmdline
        
                }
        
                if($DetectionRules.'@odata.type' -contains "#microsoft.graph.win32LobAppPowerShellScriptDetection" -and @($DetectionRules).'@odata.type'.Count -gt 1){
        
                    Write-Host
                    Write-Warning "A Detection Rule can either be 'Manually configure detection rules' or 'Use a custom detection script'"
                    Write-Warning "It can't include both..."
                    Write-Host
                    break
        
                }
        
                else {
        
                $mobileAppBody | Add-Member -MemberType NoteProperty -Name 'detectionRules' -Value $detectionRules
        
                }
        
                #ReturnCodes
        
                if($returnCodes){
                
                $mobileAppBody | Add-Member -MemberType NoteProperty -Name 'returnCodes' -Value @($returnCodes)
        
                }
        
                else {
        
                    Write-Host
                    Write-Warning "Intunewin file requires ReturnCodes to be specified"
                    Write-Warning "If you want to use the default ReturnCode run 'Get-DefaultReturnCodes'"
                    Write-Host
                    break
        
                }
        
                Write-Host
                Write-Host "Creating application in Intune..." -ForegroundColor Yellow
                $mobileApp = MakePostRequest "mobileApps" ($mobileAppBody | ConvertTo-Json);
        
                # Get the content version for the new app (this will always be 1 until the new app is committed).
                Write-Host
                Write-Host "Creating Content Version in the service for the application..." -ForegroundColor Yellow
                $appId = $mobileApp.id;
                $contentVersionUri = "mobileApps/$appId/$LOBType/contentVersions";
                $contentVersion = MakePostRequest $contentVersionUri "{}";
        
                # Encrypt file and Get File Information
                Write-Host
                Write-Host "Getting Encryption Information for '$SourceFile'..." -ForegroundColor Yellow
        
                $encryptionInfo = @{};
                $encryptionInfo.encryptionKey = $DetectionXML.ApplicationInfo.EncryptionInfo.EncryptionKey
                $encryptionInfo.macKey = $DetectionXML.ApplicationInfo.EncryptionInfo.macKey
                $encryptionInfo.initializationVector = $DetectionXML.ApplicationInfo.EncryptionInfo.initializationVector
                $encryptionInfo.mac = $DetectionXML.ApplicationInfo.EncryptionInfo.mac
                $encryptionInfo.profileIdentifier = "ProfileVersion1";
                $encryptionInfo.fileDigest = $DetectionXML.ApplicationInfo.EncryptionInfo.fileDigest
                $encryptionInfo.fileDigestAlgorithm = $DetectionXML.ApplicationInfo.EncryptionInfo.fileDigestAlgorithm
        
                $fileEncryptionInfo = @{};
                $fileEncryptionInfo.fileEncryptionInfo = $encryptionInfo;
        
                # Extracting encrypted file
                $IntuneWinFile = Get-IntuneWinFile "$SourceFile" -fileName "$filename"
        
                [int64]$Size = $DetectionXML.ApplicationInfo.UnencryptedContentSize
                $EncrySize = (Get-Item "$IntuneWinFile").Length
        
                # Create a new file for the app.
                Write-Host
                Write-Host "Creating a new file entry in Azure for the upload..." -ForegroundColor Yellow
                $contentVersionId = $contentVersion.id;
                $fileBody = GetAppFileBody "$FileName" $Size $EncrySize $null;
                $filesUri = "mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files";
                $file = MakePostRequest $filesUri ($fileBody | ConvertTo-Json);
            
                # Wait for the service to process the new file request.
                Write-Host
                Write-Host "Waiting for the file entry URI to be created..." -ForegroundColor Yellow
                $fileId = $file.id;
                $fileUri = "mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files/$fileId";
                $file = WaitForFileProcessing $fileUri "AzureStorageUriRequest";
        
                # Upload the content to Azure Storage.
                Write-Host
                Write-Host "Uploading file to Azure Storage..." -f Yellow
        
                $sasUri = $file.azureStorageUri;
                UploadFileToAzureStorage $file.azureStorageUri "$IntuneWinFile" $fileUri;
        
                # Need to Add removal of IntuneWin file
                $IntuneWinFolder = [System.IO.Path]::GetDirectoryName("$IntuneWinFile")
                Remove-Item "$IntuneWinFile" -Force
        
                # Commit the file.
                Write-Host
                Write-Host "Committing the file into Azure Storage..." -ForegroundColor Yellow
                $commitFileUri = "mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files/$fileId/commit";
                MakePostRequest $commitFileUri ($fileEncryptionInfo | ConvertTo-Json);
        
                # Wait for the service to process the commit file request.
                Write-Host
                Write-Host "Waiting for the service to process the commit file request..." -ForegroundColor Yellow
                $file = WaitForFileProcessing $fileUri "CommitFile";
        
                # Commit the app.
                Write-Host
                Write-Host "Committing the file into Azure Storage..." -ForegroundColor Yellow
                $commitAppUri = "mobileApps/$appId";
                $commitAppBody = GetAppCommitBody $contentVersionId $LOBType;
                MakePatchRequest $commitAppUri ($commitAppBody | ConvertTo-Json);
        
                Write-Host "Sleeping for $sleep seconds to allow patch completion..." -f Magenta
                Start-Sleep $sleep
                Write-Host
            
            }
            
            catch {
        
                Write-Host "";
                Write-Host -ForegroundColor Red "Aborting with exception: $($_.Exception.ToString())";
            
            }
        }
        
        ####################################################
        $user = $cred.UserName
        Function Test-AuthToken(){
        
            # Checking if authToken exists before running authentication
            if($global:authToken){
        
                # Setting DateTime to Universal time to work in all timezones
                $DateTime = (Get-Date).ToUniversalTime()
        
                # If the authToken exists checking when it expires
                $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes
        
                    if($TokenExpires -le 0){
        
                    write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
                    write-host
        
                        # Defining Azure AD tenant name, this is the name of your Azure Active Directory (do not use the verified domain name)
        
                        if($User -eq $null -or $User -eq ""){
                            $Global:User = $cred.UserName
                            #$Global:User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
                                Write-Host
        
                        }
        
                    $global:authToken = Get-AuthToken -User $User
        
                    }
            }
        
            # Authentication doesn't exist, calling Get-AuthToken function
        
            else {
        
                if($User -eq $null -or $User -eq ""){
                    $Global:User = $cred.UserName
                    #$Global:User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
                    Write-Host
        
                }
        
            # Getting the authorization token
            $global:authToken = Get-AuthToken -User $User
        
            }
        }
        
        ####################################################
        
        Test-AuthToken
        
        ####################################################
        
        $baseUrl = "https://graph.microsoft.com/beta/deviceAppManagement/"
        
        $logRequestUris = $true;
        $logHeaders = $false;
        $logContent = $true;
        
        $azureStorageUploadChunkSizeInMb = 6l;
        
        $sleep = 30
        
        Function Get-IntuneApplication(){
        
        <#
        .SYNOPSIS
        This function is used to get applications from the Graph API REST interface
        .DESCRIPTION
        The function connects to the Graph API Interface and gets any applications added
        .EXAMPLE
        Get-IntuneApplication
        Returns any applications configured in Intune
        .NOTES
        NAME: Get-IntuneApplication
        #>
        
        [cmdletbinding()]
        
        $graphApiVersion = "Beta"
        $Resource = "deviceAppManagement/mobileApps"
            
            try {
                
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | ? { (!($_.'@odata.type').Contains("managed")) }
        
            }
            
            catch {
        
            $ex = $_.Exception
            Write-Host "Request to $Uri failed with HTTP Status $([int]$ex.Response.StatusCode) $($ex.Response.StatusDescription)" -f Red
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            Write-Host "Response content:`n$responseBody" -f Red
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
            write-host
            break
        
            }
        
        }
        
Function Find-WinGetPackage{
    <#
        .SYNOPSIS
        Searches for a package on configured sources. 
        Additional options can be provided to filter the output, much like the search command.
        
        .DESCRIPTION
        By running this cmdlet with the required inputs, it will retrieve the packages installed on the local system.

        .PARAMETER Filter
        Used to search across multiple fields of the package.
        
        .PARAMETER Id
        Used to specify the Id of the package

        .PARAMETER Name
        Used to specify the Name of the package

        .PARAMETER Moniker
        Used to specify the Moniker of the package

        .PARAMETER Tag
        Used to specify the Tag of the package
        
        .PARAMETER Command
        Used to specify the Command of the package
        
        .PARAMETER Exact
        Used to specify an exact match for any parameters provided. Many of the other parameters may be used for case insensitive substring matches if Exact is not specified.

        .PARAMETER Source
        Name of the Windows Package Manager private source. Can be identified by running: "Get-WinGetSource" and using the source Name

        .PARAMETER Count
        Used to specify the maximum number of packages to return

        .PARAMETER Header
        Used to specify the value to pass as the "Windows-Package-Manager" HTTP header for a REST source.

        .PARAMETER VerboseLog
        Used to provide verbose logging for the Windows Package Manager.
        
        .PARAMETER AcceptSourceAgreement
        Used to accept any source agreement required for the source.

        .EXAMPLE
        Find-WinGetPackage -id "Publisher.Package"

        This example searches for a package containing "Publisher.Package" as a valid identifier on all configured sources.

        .EXAMPLE
        Find-WinGetPackage -id "Publisher.Package" -source "Private"

        This example searches for a package containing "Publisher.Package" as a valid identifier from the source named "Private".

        .EXAMPLE
        Find-WinGetPackage -Name "Package"

        This example searches for a package containing "Package" as a valid name on all configured sources.
    #>
    PARAM(
        [Parameter(Position=0)] $Filter,
        [Parameter()]           $Id,
        [Parameter()]           $Name,
        [Parameter()]           $Moniker,
        [Parameter()]           $Tag,
        [Parameter()]           $Command,
        [Parameter()] [switch]  $Exact,
        [Parameter()]           $Source,
        [Parameter()] [ValidateRange(1, [int]::maxvalue)][int]$Count,
        [Parameter()] [ValidateLength(1, 1024)]$Header,
        [Parameter()] [switch]  $VerboseLog,
        [Parameter()] [switch]  $AcceptSourceAgreement
    )
    BEGIN
    {
        [string[]]          $WinGetArgs  = @("Search")
        [WinGetPackage[]]   $Result      = @()
        [string[]]          $IndexTitles = @("Name", "Id", "Version", "Available", "Source")

        if($PSBoundParameters.ContainsKey('Filter')){
            ## Search across Name, ID, moniker, and tags
            $WinGetArgs += $Filter
        }
        if($PSBoundParameters.ContainsKey('Id')){
            ## Search for the ID
            $WinGetArgs += "--Id", $Id.Replace("…", "")
        }
        if($PSBoundParameters.ContainsKey('Name')){
            ## Search for the Name
            $WinGetArgs += "--Name", $Name.Replace("…", "")
        }
        if($PSBoundParameters.ContainsKey('Moniker')){
            ## Search for the Moniker
            $WinGetArgs += "--Moniker", $Moniker.Replace("…", "")
        }
        if($PSBoundParameters.ContainsKey('Tag')){
            ## Search for the Tag
            $WinGetArgs += "--Tag", $Tag.Replace("…", "")
        }
        if($PSBoundParameters.ContainsKey('Command')){
            ## Search for the Moniker
            $WinGetArgs += "--Command", $Command.Replace("…", "")
        }
        if($Exact){
            ## Search using exact values specified (case sensitive)
            $WinGetArgs += "--Exact"
        }
        if($PSBoundParameters.ContainsKey('Source')){
            ## Search for the Source
            $WinGetArgs += "--Source", $Source.Replace("…", "")
        }
        if($PSBoundParameters.ContainsKey('Count')){
            ## Specify the number of results to return
            $WinGetArgs += "--Count", $Count
        }
        if($PSBoundParameters.ContainsKey('Header')){
            ## Pass the value specified as the Windows-Package-Manager HTTP header
            $WinGetArgs += "--header", $Header
        }
        if($PSBoundParameters.ContainsKey('VerboseLog')){
            ## Search using exact values specified (case sensitive)
            $WinGetArgs += "--VerboseLog", $VerboseLog
        }
        if($AcceptSourceAgreement){
            ## Accept source agreements
            $WinGetArgs += "--accept-source-agreements"
        }
    }
    PROCESS
    {
        $List = Invoke-WinGetCommand -WinGetArgs $WinGetArgs -IndexTitles $IndexTitles
    
        foreach ($Obj in $List) {
            $Result += [WinGetPackage]::New($Obj) 
        }
    }
    END
    {
        return $Result
    }
}


Function Install-WinGetPackage
{
    <#
        .SYNOPSIS
        Installs a package on the local system. 
        Additional options can be provided to filter the output, much like the search command.
        
        .DESCRIPTION
        By running this cmdlet with the required inputs, it will retrieve the packages installed on the local system.

        .PARAMETER Filter
        Used to search across multiple fields of the package.
        
        .PARAMETER Id
        Used to specify the Id of the package

        .PARAMETER Name
        Used to specify the Name of the package

        .PARAMETER Moniker
        Used to specify the Moniker of the package

        .PARAMETER Tag
        Used to specify the Tag of the package
        
        .PARAMETER Command
        Used to specify the Command of the package

        .PARAMETER Scope
        Used to specify install scope (user or machine)
        
        .PARAMETER Exact
        Used to specify an exact match for any parameters provided. Many of the other parameters may be used for case insensitive substring matches if Exact is not specified.

        .PARAMETER Source
        Name of the Windows Package Manager private source. Can be identified by running: "Get-WinGetSource" and using the source Name

        .PARAMETER Interactive
        Used to specify the installer should be run in interactive mode.

        .PARAMETER Silent
        Used to specify the installer should be run in silent mode with no user input.

        .PARAMETER Locale
        Used to specify the locale for localized package installer.

        .PARAMETER Log
        Used to specify the location for the log location if it is supported by the package installer.

        .PARAMETER Header
        Used to specify the value to pass as the "Windows-Package-Manager" HTTP header for a REST source.

        .PARAMETER Version
        Used to specify the Version of the package

        .PARAMETER VerboseLog
        Used to provide verbose logging for the Windows Package Manager.
        
        .PARAMETER AcceptPackageAgreement
        Used to accept any package agreement required for the package.
        
        .PARAMETER AcceptSourceAgreement
        Used to explicitly accept any agreement required by the source.

        .PARAMETER Local
        Used to install from a local manifest

        .EXAMPLE
        Install-WinGetPackage -id "Publisher.Package"

        This example expects only a single package containing "Publisher.Package" as a valid identifier.

        .EXAMPLE
        Install-WinGetPackage -id "Publisher.Package" -source "Private"

        This example expects the source named "Private" contains a package with "Publisher.Package" as a valid identifier.

        .EXAMPLE
        Install-WinGetPackage -Name "Package"

        This example expects a configured source contains a package with "Package" as a valid name.
    #>

    PARAM(
        [Parameter(Position=0)] $Filter,
        [Parameter()]           $Name,
        [Parameter()]           $Id,
        [Parameter()]           $Moniker,
        [Parameter()]           $Source,
        [Parameter()] [ValidateSet("User", "Machine")] $Scope,
        [Parameter()] [switch]  $Interactive,
        [Parameter()] [switch]  $Silent,
        [Parameter()] [string]  $Version,
        [Parameter()] [switch]  $Exact,
        [Parameter()] [switch]  $Override,
        [Parameter()] [System.IO.FileInfo]  $Location,
        [Parameter()] [switch]  $Force,
        [Parameter()] [ValidatePattern("^([a-zA-Z]{2,3}|[iI]-[a-zA-Z]+|[xX]-[a-zA-Z]{1,8})(-[a-zA-Z]{1,8})*$")] [string] $Locale,
        [Parameter()] [System.IO.FileInfo]  $Log, ## This is a path of where to create a log.
        [Parameter()] [switch]  $AcceptSourceAgreements,
        [Parameter()] [switch]  $Local # This is for installing local manifests
    )
    BEGIN
    {
        $WinGetFindArgs = @{}
        [string[]] $WinGetInstallArgs  = "Install"
        IF($PSBoundParameters.ContainsKey('Filter')){
            IF($Local) {
                $WinGetInstallArgs += "--Manifest"
            }
            $WinGetInstallArgs += $Filter
        }
        IF($PSBoundParameters.ContainsKey('Filter')){
            IF($Local) {
                $WinGetInstallArgs += "--Manifest"
            }
            $WinGetInstallArgs += $Filter
            $WinGetFindArgs.Add('Filter', $Filter)
        }
        IF($PSBoundParameters.ContainsKey('Name')){
            $WinGetInstallArgs += "--Name", $Name
            $WinGetFindArgs.Add('Name', $Name)
        }
        IF($PSBoundParameters.ContainsKey('Id')){
            $WinGetInstallArgs += "--Id", $Id
            $WinGetFindArgs.Add('Id', $Id)
        }
        IF($PSBoundParameters.ContainsKey('Moniker')){
            $WinGetInstallArgs += "--Moniker", $Moniker
            $WinGetFindArgs.Add('Moniker', $Moniker)
        }
        IF($PSBoundParameters.ContainsKey('Source')){
            $WinGetInstallArgs += "--Source", $Source
            $WinGetFindArgs.Add('Source', $Source)
        }
        IF($PSBoundParameters.ContainsKey('Scope')){
            $WinGetInstallArgs += "--Scope", $Scope
        }
        IF($Interactive){
            $WinGetInstallArgs += "--Interactive"
        }
        IF($Silent){
            $WinGetInstallArgs += "--Silent"
        }
        IF($PSBoundParameters.ContainsKey('Locale')){
            $WinGetInstallArgs += "--locale", $Locale
        }
        if($PSBoundParameters.ContainsKey('Version')){
            $WinGetInstallArgs += "--Version", $Version
        }
        if($Exact){
            $WinGetInstallArgs += "--Exact"
            $WinGetFindArgs.Add('Exact', $true)
        }
        if($PSBoundParameters.ContainsKey('Log')){
            $WinGetInstallArgs += "--Log", $Log
        }
        if($PSBoundParameters.ContainsKey('Override')){
            $WinGetInstallArgs += "--override", $Override
        }
        if($PSBoundParameters.ContainsKey('Location')){
            $WinGetInstallArgs += "--Location", $Location
        }
        if($Force){
            $WinGetInstallArgs += "--Force"
        }
    }
    PROCESS
    {
        ## Exact, ID and Source - Talk with Demitrius tomorrow to better understand this.
        IF(!$Local) {
            $Result = Find-WinGetPackage @WinGetFindArgs
        }

        if($Result.count -eq 1 -or $Local) {
            & "WinGet" $WinGetInstallArgs
            $Result = ""
        }
        elseif($Result.count -lt 1){
            Write-Host "Unable to locate package for installation"
            $Result = ""
        }
        else {
            Write-Host "Multiple packages found matching input criteria. Please refine the input."
        }
    }
    END
    {
        return $Result
    }
}

filter Assert-WhiteSpaceIsNull {
    IF ([string]::IsNullOrWhiteSpace($_)){$null}
    ELSE {$_}
}

class WinGetSource
{
    [string] $Name
    [string] $Argument
    [string] $Data
    [string] $Identifier
    [string] $Type

    WinGetSource ()
    {  }

    WinGetSource ([string]$a, [string]$b, [string]$c, [string]$d, [string]$e)
    {
        $this.Name       = $a.TrimEnd() | Assert-WhiteSpaceIsNull
        $this.Argument   = $b.TrimEnd() | Assert-WhiteSpaceIsNull
        $this.Data       = $c.TrimEnd() | Assert-WhiteSpaceIsNull
        $this.Identifier = $d.TrimEnd() | Assert-WhiteSpaceIsNull
        $this.Type       = $e.TrimEnd() | Assert-WhiteSpaceIsNull
    }

    WinGetSource ([string[]]$a)
    {
        $this.name       = $a[0].TrimEnd() | Assert-WhiteSpaceIsNull
        $this.Argument   = $a[1].TrimEnd() | Assert-WhiteSpaceIsNull
        $this.Data       = $a[2].TrimEnd() | Assert-WhiteSpaceIsNull
        $this.Identifier = $a[3].TrimEnd() | Assert-WhiteSpaceIsNull
        $this.Type       = $a[4].TrimEnd() | Assert-WhiteSpaceIsNull
    }
    
    WinGetSource ([WinGetSource]$a)
    {
        $this.Name       = $a.Name.TrimEnd() | Assert-WhiteSpaceIsNull
        $this.Argument   = $a.Argument.TrimEnd() | Assert-WhiteSpaceIsNull
        $this.Data       = $a.Data.TrimEnd() | Assert-WhiteSpaceIsNull
        $this.Identifier = $a.Identifier.TrimEnd() | Assert-WhiteSpaceIsNull
        $this.Type       = $a.Type.TrimEnd() | Assert-WhiteSpaceIsNull

    }
    
    [WinGetSource[]] Add ([WinGetSource]$a)
    {
        $FirstValue  = [WinGetSource]::New($this)
        $SecondValue = [WinGetSource]::New($a)
        
        [WinGetSource[]] $Combined = @([WinGetSource]::New($FirstValue), [WinGetSource]::New($SecondValue))

        Return $Combined
    }

    [WinGetSource[]] Add ([String[]]$a)
    {
        $FirstValue  = [WinGetSource]::New($this)
        $SecondValue = [WinGetSource]::New($a)
        
        [WinGetSource[]] $Combined = @([WinGetSource]::New($FirstValue), [WinGetSource]::New($SecondValue))

        Return $Combined
    }
}

class WinGetPackage
{
    [string]$Name
    [string]$Id
    [string]$Version
    [string]$Available
    [string]$Source
    [string]$Match

    WinGetPackage ([string] $a, [string]$b, [string]$c, [string]$d, [string]$e)
    {
        $this.Name    = $a.TrimEnd() | Assert-WhiteSpaceIsNull
        $this.Id      = $b.TrimEnd() | Assert-WhiteSpaceIsNull
        $this.Version = $c.TrimEnd() | Assert-WhiteSpaceIsNull
        $this.Available = $d.TrimEnd() | Assert-WhiteSpaceIsNull
        $this.Source  = $e.TrimEnd() | Assert-WhiteSpaceIsNull
    }
    
    WinGetPackage ([WinGetPackage] $a) {
        $this.Name    = $a.Name | Assert-WhiteSpaceIsNull
        $this.Id      = $a.Id | Assert-WhiteSpaceIsNull
        $this.Version = $a.Version | Assert-WhiteSpaceIsNull
        $this.Available = $a.Available | Assert-WhiteSpaceIsNull
        $this.Source  = $a.Source | Assert-WhiteSpaceIsNull

    }
    WinGetPackage ([psobject] $a) {
        $this.Name      = $a.Name | Assert-WhiteSpaceIsNull
        $this.Id        = $a.Id | Assert-WhiteSpaceIsNull
        $this.Version   = $a.Version | Assert-WhiteSpaceIsNull
        $this.Available = $a.Available | Assert-WhiteSpaceIsNull
        $this.Source    = $a.Source | Assert-WhiteSpaceIsNull
    }
    
    WinGetSource ([string[]]$a)
    {
        $this.name      = $a[0].TrimEnd() | Assert-WhiteSpaceIsNull
        $this.Id        = $a[1].TrimEnd() | Assert-WhiteSpaceIsNull
        $this.Version   = $a[2].TrimEnd() | Assert-WhiteSpaceIsNull
        $this.Available = $a[3].TrimEnd() | Assert-WhiteSpaceIsNull
        $this.Source    = $a[4].TrimEnd() | Assert-WhiteSpaceIsNull
    }

    
    [WinGetPackage[]] Add ([WinGetPackage] $a)
    {
        $FirstValue  = [WinGetPackage]::New($this)
        $SecondValue = [WinGetPackage]::New($a)

        [WinGetPackage[]]$Result = @([WinGetPackage]::New($FirstValue), [WinGetPackage]::New($SecondValue))

        Return $Result
    }

    [WinGetPackage[]] Add ([String[]]$a)
    {
        $FirstValue  = [WinGetPackage]::New($this)
        $SecondValue = [WinGetPackage]::New($a)
        
        [WinGetPackage[]] $Combined = @([WinGetPackage]::New($FirstValue), [WinGetPackage]::New($SecondValue))

        Return $Combined
    }
}
Function Invoke-WinGetCommand
{
    PARAM(
        [Parameter(Position=0, Mandatory=$true)] [string[]]$WinGetArgs,
        [Parameter(Position=0, Mandatory=$true)] [string[]]$IndexTitles,
        [Parameter()]                            [switch] $JSON
    )
    BEGIN
    {
        $Index  = @()
        $Result = @()
        $i      = 0
        $IndexTitlesCount = $IndexTitles.Count
        $Offset = 0
        $Found = $false
        
        ## Remove two characters from the string length and add "..." to the end (only if there is the three below characters present).
        [string[]]$WinGetSourceListRaw = & "WinGet" $WingetArgs | out-string -stream | foreach-object{$_ -replace ("$([char]915)$([char]199)$([char]170)", "$([char]199)")}
    }
    PROCESS
    {
        if($JSON){
            ## If expecting JSON content, return the object
            return $WinGetSourceListRaw | ConvertFrom-Json
        }

        ## Gets the indexing of each title
        $rgex = $IndexTitles -join "|"
        for ($Offset=0; $Offset -lt $WinGetSourceListRaw.Length; $Offset++) {
            if($WinGetSourceListRaw[$Offset].Split(" ")[0].Trim() -match $rgex) {
                $Found = $true
                break
            }
        }
        if(!$Found) {
            Write-Error -Message "No results were found." -TargetObject $WinGetSourceListRaw
            return
        }
        
        foreach ($IndexTitle in $IndexTitles) {
            ## Creates an array of titles and their string location
            $IndexStart = $WinGetSourceListRaw[$Offset].IndexOf($IndexTitle)
            $IndexEnds  = ""

            IF($IndexStart -ne "-1") {
                $Index += [pscustomobject]@{
                    Title = $IndexTitle
                    Start = $IndexStart
                    Ends = $IndexEnds
                    }
            }
        }

        ## Orders the Object based on Index value
        $Index = $Index | Sort-Object Start

        ## Sets the end of string value
        while ($i -lt $IndexTitlesCount) {
            $i ++

            ## Sets the End of string value (if not null)
            if($Index[$i].Start) {
                $Index[$i-1].Ends = ($Index[$i].Start -1) - $Index[$i-1].Start 
            }
        }

        ## Builds the WinGetSource Object with contents
        $i = $Offset + 2
        while($i -lt $WinGetSourceListRaw.Length) {
            $row = $WinGetSourceListRaw[$i]
            try {
                [bool] $TestNotTitles     = $WinGetSourceListRaw[0] -ne $row
                [bool] $TestNotHyphenLine = $WinGetSourceListRaw[1] -ne $row -and !$Row.Contains("---")
                [bool] $TestNotNoResults  = $row -ne "No package found matching input criteria."
            }
            catch {Wait-Debugger}

            if(!$TestNotNoResults) {
                Write-LogEntry -LogEntry "No package found matching input criteria." -Severity 1
            }

            ## If this is the first pass containing titles or the table line, skip.
            if($TestNotTitles -and $TestNotHyphenLine -and $TestNotNoResults) {
                $List = @{}

                foreach($item in $Index) {
                    if($Item.Ends) {
                            $List[$Item.Title] = $row.SubString($item.Start,$Item.Ends)
                    }
                    else {
                        $List[$item.Title] = $row.SubString($item.Start, $row.Length - $Item.Start)
                    }
                }

                $result += [pscustomobject]$list
            }
            $i++
        }
    }
    END
    {
        return $Result
    }
}


Function Uninstall-WinGetPackage{
    <#
        .SYNOPSIS
        Uninstalls a package from the local system. 
        Additional options can be provided to filter the output, much like the search command.
        
        .DESCRIPTION
        By running this cmdlet with the required inputs, it will uninstall a package installed on the local system.

        .PARAMETER Filter
        Used to search across multiple fields of the package.
        
        .PARAMETER Id
        Used to specify the Id of the package

        .PARAMETER Name
        Used to specify the Name of the package

        .PARAMETER Moniker
        Used to specify the Moniker of the package

        .PARAMETER Version
        Used to specify the Version of the package
        
        .PARAMETER Exact
        Used to specify an exact match for any parameters provided. Many of the other parameters may be used for case insensitive substring matches if Exact is not specified.

        .PARAMETER Source
        Name of the Windows Package Manager private source. Can be identified by running: "Get-WinGetSource" and using the source Name

        .PARAMETER Interactive
        Used to specify the uninstaller should be run in interactive mode.

        .PARAMETER Silent
        Used to specify the uninstaller should be run in silent mode with no user input.

        .PARAMETER Log
        Used to specify the location for the log location if it is supported by the package uninstaller.

        .PARAMETER VerboseLog
        Used to provide verbose logging for the Windows Package Manager.

        .PARAMETER Header
        Used to specify the value to pass as the "Windows-Package-Manager" HTTP header for a REST source.
        
        .PARAMETER AcceptSourceAgreement
        Used to explicitly accept any agreement required by the source.

        .PARAMETER Local
        Used to uninstall from a local manifest

        .EXAMPLE
        Uninstall-WinGetPackage -id "Publisher.Package"

        This example expects only a single configured REST source with a package containing "Publisher.Package" as a valid identifier.

        .EXAMPLE
        Uninstall-WinGetPackage -id "Publisher.Package" -source "Private"

        This example expects the REST source named "Private" with a package containing "Publisher.Package" as a valid identifier.

        .EXAMPLE
        Uninstall-WinGetPackage -Name "Package"

        This example expects a configured source contains a package with "Package" as a valid name.
    #>

    PARAM(
        [Parameter(Position=0)] $Filter,
        [Parameter()]           $Name,
        [Parameter()]           $Id,
        [Parameter()]           $Moniker,
        [Parameter()]           $Source,
        [Parameter()] [switch]  $Interactive,
        [Parameter()] [switch]  $Silent,
        [Parameter()] [string]  $Version,
        [Parameter()] [switch]  $Exact,
        [Parameter()] [switch]  $Override,
        [Parameter()] [System.IO.FileInfo]  $Location,
        [Parameter()] [switch]  $Force,
        [Parameter()] [System.IO.FileInfo]  $Log, ## This is a path of where to create a log.
        [Parameter()] [switch]  $AcceptSourceAgreements,
        [Parameter()] [switch]  $Local # This is for installing local manifests
    )
    BEGIN
    {
        [string[]] $WinGetArgs  = "Uninstall"
        IF($PSBoundParameters.ContainsKey('Filter')){
            IF($Local) {
                $WinGetArgs += "--Manifest"
            }
            $WinGetArgs += $Filter
        }
        IF($PSBoundParameters.ContainsKey('Name')){
            $WinGetArgs += "--Name", $Name
        }
        IF($PSBoundParameters.ContainsKey('Id')){
            $WinGetArgs += "--Id", $Id
        }
        IF($PSBoundParameters.ContainsKey('Moniker')){
            $WinGetArgs += "--Moniker", $Moniker
        }
        IF($PSBoundParameters.ContainsKey('Source')){
            $WinGetArgs += "--Source", $Source
        }
        IF($Interactive){
            $WinGetArgs += "--Interactive"
        }
        IF($Silent){
            $WinGetArgs += "--Silent"
        }
        if($PSBoundParameters.ContainsKey('Version')){
            $WinGetArgs += "--Version", $Version
        }
        if($Exact){
            $WinGetArgs += "--Exact"
        }
        if($PSBoundParameters.ContainsKey('Log')){
            $WinGetArgs += "--Log", $Log
        }
        if($PSBoundParameters.ContainsKey('Location')){
            $WinGetArgs += "--Location", $Location
        }
        if($Force){
            $WinGetArgs += "--Force"
        }
    }
    PROCESS
    {
        ## Exact, ID and Source - Talk with tomorrow to better understand this.
        IF(!$Local) {
            $Result = Find-WinGetPackage -Filter $Filter -Name $Name -Id $Id -Moniker $Moniker -Tag $Tag -Command $Command -Source $Source
        }

        if($Result.count -eq 1 -or $Local) {
            & "WinGet" $WingetArgs
            $Result = ""
        }
        elseif($Result.count -lt 1){
            Write-Host "Unable to locate package for uninstallation"
            $Result = ""
        }
        else {
            Write-Host "Multiple packages found matching input criteria. Please refine the input."
        }
    }
    END
    {
        return $Result
    }
}


Function Upgrade-WinGetPackage
{
    <#
        .SYNOPSIS
        Upgrades a package on the local system. 
        Additional options can be provided to filter the output, much like the search command.
        
        .DESCRIPTION
        By running this cmdlet with the required inputs, it will retrieve the packages installed on the local system.

        .PARAMETER Filter
        Used to search across multiple fields of the package.
        
        .PARAMETER Id
        Used to specify the Id of the package

        .PARAMETER Name
        Used to specify the Name of the package

        .PARAMETER Moniker
        Used to specify the Moniker of the package

        .PARAMETER Tag
        Used to specify the Tag of the package
        
        .PARAMETER Command
        Used to specify the Command of the package

        .PARAMETER Channel
        Used to specify the channel of the package. Note this is not yet implemented in Windows Package Manager as of version 1.1.0.

        .PARAMETER Scope
        Used to specify install scope (user or machine)
        
        .PARAMETER Exact
        Used to specify an exact match for any parameters provided. Many of the other parameters may be used for case insensitive substring matches if Exact is not specified.

        .PARAMETER Source
        Name of the Windows Package Manager private source. Can be identified by running: "Get-WinGetSource" and using the source Name

        .PARAMETER Manifest
        Path to the manifest on the local file system. Requires local manifest setting to be enabled.

        .PARAMETER Interactive
        Used to specify the installer should be run in interactive mode.

        .PARAMETER Silent
        Used to specify the installer should be run in silent mode with no user input.

        .PARAMETER Locale
        Used to specify the locale for localized package installer.

        .PARAMETER Log
        Used to specify the location for the log location if it is supported by the package installer.

        .PARAMETER Override
        Used to override switches passed to installer.

        .PARAMETER Force
        Used to force the upgrade when the Windows Package Manager would ordinarily not upgrade the package.

        .PARAMETER Location
        Used to specify the location for the package to be upgraded.

        .PARAMETER Header
        Used to specify the value to pass as the "Windows-Package-Manager" HTTP header for a REST source.

        .PARAMETER Version
        Used to specify the Version of the package

        .PARAMETER VerboseLog
        Used to provide verbose logging for the Windows Package Manager.
        
        .PARAMETER AcceptPackageAgreement
        Used to accept any source package required for the package.

        .PARAMETER AcceptSourceAgreement

        .EXAMPLE
        Upgrade-WinGetPackage -id "Publisher.Package"

        This example expects only a single package containing "Publisher.Package" as a valid identifier.

        .EXAMPLE
        Upgrade-WinGetPackage -id "Publisher.Package" -source "Private"

        This example expects the source named "Private" contains a package with "Publisher.Package" as a valid identifier.

        .EXAMPLE
        Upgrade-WinGetPackage -Name "Package"

        This example expects the source named "Private" contains a package with "Package" as a valid name.
    #>

    PARAM(
        [Parameter(Position=0)] $Filter,
        [Parameter()]           $Name,
        [Parameter()]           $Id,
        [Parameter()]           $Moniker,
        [Parameter()]           $Source,
        [Parameter()] [ValidateSet("User", "Machine")] $Scope,
        [Parameter()] [switch]  $Interactive,
        [Parameter()] [switch]  $Silent,
        [Parameter()] [string]  $Version,
        [Parameter()] [switch]  $Exact,
        [Parameter()] [switch]  $Override,
        [Parameter()] [System.IO.FileInfo]  $Location,
        [Parameter()] [switch]  $Force,
        [Parameter()] [ValidatePattern("^([a-zA-Z]{2,3}|[iI]-[a-zA-Z]+|[xX]-[a-zA-Z]{1,8})(-[a-zA-Z]{1,8})*$")] [string] $Locale,
        [Parameter()] [System.IO.FileInfo]  $Log, ## This is a path of where to create a log.
        [Parameter()] [switch]  $AcceptSourceAgreements
    )
    BEGIN
    {
        [string[]] $WinGetArgs  = "Install"
        IF($PSBoundParameters.ContainsKey('Filter')){
            $WinGetArgs += $Filter
        }
        IF($PSBoundParameters.ContainsKey('Name')){
            $WinGetArgs += "--Name", $Name
        }
        IF($PSBoundParameters.ContainsKey('Id')){
            $WinGetArgs += "--Id", $Id
        }
        IF($PSBoundParameters.ContainsKey('Moniker')){
            $WinGetArgs += "--Moniker", $Moniker
        }
        IF($PSBoundParameters.ContainsKey('Source')){
            $WinGetArgs += "--Source", $Source
        }
        IF($PSBoundParameters.ContainsKey('Scope')){
            $WinGetArgs += "--Scope", $Scope
        }
        IF($Interactive){
            $WinGetArgs += "--Interactive"
        }
        IF($Silent){
            $WinGetArgs += "--Silent"
        }
        IF($PSBoundParameters.ContainsKey('Locale')){
            $WinGetArgs += "--locale", $Locale
        }
        if($PSBoundParameters.ContainsKey('Version')){
            $WinGetArgs += "--Version", $Version
        }
        if($Exact){
            $WinGetArgs += "--Exact"
        }
        if($PSBoundParameters.ContainsKey('Log')){
            $WinGetArgs += "--Log", $Log
        }
        if($PSBoundParameters.ContainsKey('Override')){
            $WinGetArgs += "--override", $Override
        }
        if($PSBoundParameters.ContainsKey('Location')){
            $WinGetArgs += "--Location", $Location
        }
        if($Force){
            $WinGetArgs += "--Force"
        }
    }
    PROCESS
    {
        ## Exact, ID and Source - Talk with Demitrius tomorrow to better understand this.
        $Result = Find-WinGetPackage -Filter $Filter -Name $Name -Id $Id -Moniker $Moniker -Tag $Tag -Command $Command -Source $Source

        if($Result.count -eq 1) {
            & "WinGet" $WingetArgs
            $Result = ""
        }
        elseif($Result.count -lt 1){
            Write-Host "Unable to locate package for installation"
            $Result = ""
        }
        else {
            Write-Host "Multiple packages found matching input criteria. Please refine the input."
        }
    }
    END
    {
        return $Result
    }
}

Function Get-WinGetPackage{
    <#
        .SYNOPSIS
        Gets installed packages on the local system. displays the packages installed on the system, as well as whether an update is available. 
        Additional options can be provided to filter the output, much like the search command.
        
        .DESCRIPTION
        By running this cmdlet with the required inputs, it will retrieve the packages installed on the local system.

        .PARAMETER Filter
        Used to search across multiple fields of the package.
        
        .PARAMETER Id
        Used to specify the Id of the package

        .PARAMETER Name
        Used to specify the Name of the package

        .PARAMETER Moniker
        Used to specify the Moniker of the package

        .PARAMETER Tag
        Used to specify the Tag of the package
        
        .PARAMETER Command
        Used to specify the Command of the package

        .PARAMETER Count
        Used to specify the maximum number of packages to return
        
        .PARAMETER Exact
        Used to specify an exact match for any parameters provided. Many of the other parameters may be used for case insensitive substring matches if Exact is not specified.

        .PARAMETER Source
        Name of the Windows Package Manager private source. Can be identified by running: "Get-WinGetSource" and using the source Name

        .PARAMETER Header
        Used to specify the value to pass as the "Windows-Package-Manager" HTTP header for a REST source.
        
        .PARAMETER AcceptSourceAgreement
        Used to accept any source agreements required by a REST source.

        .EXAMPLE
        Get-WinGetPackage -id "Publisher.Package"

        This example expects only a single configured REST source with a package containing "Publisher.Package" as a valid identifier.

        .EXAMPLE
        Get-WinGetPackage -id "Publisher.Package" -source "Private"

        This example expects the REST source named "Private" with a package containing "Publisher.Package" as a valid identifier.

        .EXAMPLE
        Get-WinGetPackage -Name "Package"

        This example expects the REST source named "Private" with a package containing "Package" as a valid name.
    #>

    PARAM(
        [Parameter(Position=0)] $Filter,
        [Parameter()]           $Name,
        [Parameter()]           $Id,
        [Parameter()]           $Moniker,
        [Parameter()]           $Tag,
        [Parameter()]           $Source,
        [Parameter()]           $Command,
        [Parameter()]           [ValidateRange(1, [int]::maxvalue)][int]$Count,
        [Parameter()]           [switch]$Exact,
        [Parameter()]           [ValidateLength(1, 1024)]$Header,
        [Parameter()]           [switch]$AcceptSourceAgreement
    )
    BEGIN
    {
        [string[]]       $WinGetArgs  = @("List")
        [WinGetPackage[]]$Result      = @()
        [string[]]       $IndexTitles = @("Name", "Id", "Version", "Available", "Source")

        if($Filter){
            ## Search across Name, ID, moniker, and tags
            $WinGetArgs += $Filter
        }
        if($PSBoundParameters.ContainsKey('Name')){
            ## Search for the Name
            $WinGetArgs += "--Name", $Name.Replace("…", "")
        }
        if($PSBoundParameters.ContainsKey('Id')){
            ## Search for the ID
            $WinGetArgs += "--Id", $Id.Replace("…", "")
        }
        if($PSBoundParameters.ContainsKey('Moniker')){
            ## Search for the Moniker
            $WinGetArgs += "--Moniker", $Moniker.Replace("…", "")
        }
        if($PSBoundParameters.ContainsKey('Tag')){
            ## Search for the Tag
            $WinGetArgs += "--Tag", $Tag.Replace("…", "")
        }
        if($PSBoundParameters.ContainsKey('Source')){
            ## Search for the Source
            $WinGetArgs += "--Source", $Source.Replace("…", "")
        }
        if($PSBoundParameters.ContainsKey('Count')){
            ## Specify the number of results to return
            $WinGetArgs += "--Count", $Count
        }
        if($Exact){
            ## Search using exact values specified (case sensitive)
            $WinGetArgs += "--Exact"
        }
        if($PSBoundParameters.ContainsKey('Header')){
            ## Pass the value specified as the Windows-Package-Manager HTTP header
            $WinGetArgs += "--header", $Header
        }
        if($AcceptSourceAgreement){
            ## Accept source agreements
            $WinGetArgs += "--accept-source-agreements"
        }
    }
    PROCESS
    {
        $List = Invoke-WinGetCommand -WinGetArgs $WinGetArgs -IndexTitles $IndexTitles
    
        foreach ($Obj in $List) {
            $Result += [WinGetPackage]::New($Obj) 
        }
    }
    END
    {
        return $Result
    }
}   


function new-aadgroups  {
    [cmdletbinding()]
        
    param
    (
        $appname,
        $grouptype
    )
    switch($grouptype) {
        "install" {
            $groupname = $appname + " Install Group"
            $nickname = $appname+"install"
            $groupdescription = "Group for installation and updating of $appname application"
        }
        "uninstall" {
            $groupname = $appname + " Uninstall Group"
            $nickname = $appname+"uninstall"
            $groupdescription = "Group for uninstallation of $appname application"
        }
    }

    $grp = New-AzureADMSGroup -DisplayName $groupname -Description $groupdescription -MailEnabled $False -MailNickName $nickname -SecurityEnabled $True

    return $grp.id

}

function new-detectionscript {
    param
    (
        $appid,
        $appname
    )
$detect =@'
$ResolveWingetPath = Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe"
    if ($ResolveWingetPath){
           $WingetPath = $ResolveWingetPath[-1].Path
    }

$Winget = $WingetPath + "\winget.exe"
$upgrades = &$winget upgrade
if ($upgrades -match SETAPPID) {
    Write-Host "Upgrade available for: SETAPPNAME"
    exit 1
}
else {
        Write-Host "No Upgrade available"
        exit 0
}
'@
$detect2 = $detect -replace "SETAPPID", $appid
$detect3 = $detect2 -replace "SETAPPNAME", $appname

return $detect3
}

function new-remediationscript {
    param
    (
        $appid,
        $appname
    )
        $remediate =@'
$ResolveWingetPath = Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe"
    if ($ResolveWingetPath){
        $WingetPath = $ResolveWingetPath[-1].Path
    }
        
    $Winget = $WingetPath + "\winget.exe"
    &$winget upgrade --id SETAPPID --silent --force --accept-package-agreements --accept-source-agreements

'@
$remediate2 = $remediate -replace "SETAPPID", $appid
        return $remediate2

}

function new-proac {
    param
    (
        $appid,
        $appname,
        $groupid
    )
    $detectscriptcontent = new-detectionscript -appid $appid -appname $appname
    $detect =[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($detectscriptcontent))
    $remediatecriptcontent = new-remediationscript -appid $appid -appname $appname
    $remediate =[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($remediatecriptcontent))

    $DisplayName = $appname + " Upgrade"
    $Description = "Upgrade $appname application"
    ##RunAs can be "system" or "user"
    $RunAs = "system"
    ##True for 32-bit, false for 64-bit
    $RunAs32 = $false
    ##Daily or Hourly
    $ScheduleType = "Hourly"
    ##How Often
    $ScheduleFrequency = "1"
    ##Start Time (if daily)
    $StartTime = "01:00"
    
    $proacparams = @{
        publisher = "Microsoft"
        displayName = $DisplayName
        description = $Description
        detectionScriptContent = $detect
        remediationScriptContent = $remediate
        runAs32Bit = $RunAs32
        enforceSignatureCheck = $false
        runAsAccount = $RunAs
        roleScopeTagIds = @(
            "0"
        )
        isGlobalScript = "false"
    }
    $paramsjson = $proacparams | convertto-json
        $graphApiVersion = "beta"
        $Resource = "deviceManagement/deviceHealthScripts"
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $proactive = Invoke-RestMethod -Uri $uri -Headers $authToken -Method POST -Body $paramsjson -ContentType "application/json"


        $assignparams = @{
            DeviceHealthScriptAssignments = @(
                @{
                    target = @{
                        "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                        groupId = $groupid
                    }
                    runRemediationScript = $true
                    runSchedule = @{
                        "@odata.type" = "#microsoft.graph.deviceHealthScriptHourlySchedule"
                        interval = $scheduleFrequency
                    }
                }
            )
        }
        $assignparamsjson = $assignparams | convertto-json -Depth 10
        $remediationID = $proactive.ID
        
        
        $graphApiVersion = "beta"
        $Resource = "deviceManagement/deviceHealthScripts"
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$remediationID/assign"
        
        $proactiveassign = 	Invoke-RestMethod -Uri $uri -Headers $authToken -Method POST -Body $assignparamsjson -ContentType "application/json"

        return "Success"

}

function new-intunewinfile {
    param
    (
        $appid,
        $appname,
        $apppath,
        $setupfilename
    )
    Start-Process $intuneapputiloutput -ArgumentList "-c $apppath -s $setupfilename -o $apppath <-q>" 

}

function new-detectionscript {
    param
    (
        $appid,
        $appname
    )
    $detection =@"
    `$ResolveWingetPath = Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe"
        if (`$ResolveWingetPath){
               `$WingetPath = `$ResolveWingetPath[-1].Path
        }
    
    `$Winget = `$WingetPath + "\winget.exe"
    `$wingettest = &`$winget list --id $appid
    if (`$wingettest -like "*$appid*"){
        Write-Host "Found it!"
    }
"@
    return $detection

}


function new-installscript {
    param
    (
        $appid,
        $appname
    )
    $install =@"
    `$ResolveWingetPath = Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe"
        if (`$ResolveWingetPath){
               `$WingetPath = `$ResolveWingetPath[-1].Path
        }
    
    `$Winget = `$WingetPath + "\winget.exe"
    &`$winget install --id $appid --silent --force --accept-package-agreements --accept-source-agreements
"@
    return $install

}

function new-uninstallscript {
    param
    (
        $appid,
        $appname
    )
    $uninstall =@"
    `$ResolveWingetPath = Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe"
        if (`$ResolveWingetPath){
               `$WingetPath = `$ResolveWingetPath[-1].Path
        }
    
    `$Winget = `$WingetPath + "\winget.exe"
    &`$winget uninstall --id $appid --silent --force --accept-package-agreements --accept-source-agreements
"@
    return $uninstall

}

function assign-win32app  {
    param
    (
        $appname,
        $installgroup,
        $uninstallgroup
    )
    $Application = Get-IntuneApplication | where-object { $_.displayName -eq "$appname" }

    #Install
    $graphApiVersion = "Beta"
    $ApplicationId = $Application.id
    $TargetGroupId1 = $installgroup
    $InstallIntent1 = "required"
    
    
    #Uninstall
    $ApplicationId = $Application.id
    $TargetGroupId = $uninstallgroup
    $InstallIntent = "uninstall"
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
        },
        {
            "@odata.type": "#microsoft.graph.mobileAppAssignment",
            "target": {
            "@odata.type": "#microsoft.graph.groupAssignmentTarget",
            "groupId": "$TargetGroupId"
            },
            "intent": "$InstallIntent"
        }
        ]
    }
    
"@
    
    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"
    
}

function new-win32app {
    [cmdletbinding()]
        
    param
    (
        $appid,
        $appname,
        $appfile,
        $installcmd,
        $uninstallcmd,
        $detectionfile
    )
# Defining Intunewin32 detectionRules
$PSRule = New-DetectionRule -PowerShell -ScriptFile $detectionfile -enforceSignatureCheck $false -runAs32Bit $false


# Creating Array for detection Rule
$DetectionRule = @($PSRule)

$ReturnCodes = Get-DefaultReturnCodes

# Win32 Application Upload
$appupload = Upload-Win32Lob -SourceFile "$appfile" -DisplayName "$appname" -publisher "Winget" `
-description "$appname Winget Package" -detectionRules $DetectionRule -returnCodes $ReturnCodes `
-installCmdLine "$installcmd" `
-uninstallCmdLine "$uninstallcmd"

return $appupload

}

############################################################################################################
######                          END FUNCTIONS SECTION                                               ########
############################################################################################################

###############################################################################################################
######                                          Connect                                                  ######
###############################################################################################################


##Get Credentials

Connect-AzureAD -Credential $cred
$user = $cred.UserName
#Authenticate for MS Graph
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
                $user = $cred.UserName
            #$User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
            Write-Host

            }

        $global:authToken = Get-AuthToken -User $User

        }
}

# Authentication doesn't exist, calling Get-AuthToken function

else {

    if($User -eq $null -or $User -eq ""){
        $user = $cred.UserName
    #$User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
    Write-Host

    }

# Getting the authorization token
$global:authToken = Get-AuthToken -User $User

}

#endregion

###############################################################################################################


find-wingetpackage '""' | out-gridview -PassThru -Title "Available Applications" | ForEach-Object {
    $appid = $_.Id.Trim()
    $appname = $_.Name.Trim()

    write-host "$appname Selected with ID of $appid"


##Create Directory
write-host "Creating Directory for $appname"
$apppath = $path + $appname
new-item -Path $apppath -ItemType Directory -Force
write-host "Directory $apppath Created"

##Create Groups
write-host "Creating AAD Groups for $appname"
$installgroup = new-aadgroups -appname $appname -grouptype "Install"
$uninstallgroup = new-aadgroups -appname $appname -grouptype "Uninstall"
write-host "Created $installgroup for installing $appname"
write-host "Created $uninstallgroup for uninstalling $appname"

##Create Install Script
write-host "Creating Install Script for $appname"
$installscript = new-installscript -appid $appid -appname $appname
$installfilename = "install$appname.ps1"
$installscriptfile = $apppath + "\" + $installfilename
$installscript | Out-File $installscriptfile
write-host "Script created at $installscriptfile"

##Create Uninstall Script
write-host "Creating Uninstall Script for $appname"
$uninstallscript = new-uninstallscript -appid $appid -appname $appname
$uninstallfilename = "uninstall$appname.ps1"
$uninstallscriptfile = $apppath + "\" + $uninstallfilename
$uninstallscript | Out-File $uninstallscriptfile
write-host "Script created at $uninstallscriptfile"

##Create Detection Script
write-host "Creating Detection Script for $appname"
$detectionscript = new-detectionscript -appid $appid -appname $appname
$detectionscriptfile = $apppath + "\detection$appname.ps1"
$detectionscript | Out-File $detectionscriptfile
write-host "Script created at $detectionscriptfile"


##Create Proac
write-host "Creation Proactive Remediation for $appname"
$proac = new-proac -appid $appid -appname $appname -groupid $installgroup
write-host "Proactive Remediation Created and Assigned for $appname"

##Create IntuneWin
write-host "Creating Intunewin File for $appname"
$intunewinpath = $apppath + "\install$appname.intunewin"
$intunewin = new-intunewinfile -appid $appid -appname $appname -apppath $apppath -setupfilename $installscriptfile
write-host "Intunewin $intunewinpath Created"
start-sleep -Seconds 10
##Create and upload Win32
write-host "Uploading $appname to Intune"
$installcmd = "powershell.exe -ExecutionPolicy Bypass -File $installfilename"
$uninstallcmd = "powershell.exe -ExecutionPolicy Bypass -File $uninstallfilename"
$win32 = new-win32app -appid $appid -appname $appname -appfile $intunewinpath -installcmd $installcmd -uninstallcmd $uninstallcmd -detectionfile $detectionscriptfile
write-host "$appname Created and uploaded"

##Assign Win32
write-host "Assigning Groups"
$assign = assign-win32app -appname $appname -installgroup $installgroup -uninstallgroup $uninstallgroup
write-host "Assigned $installgroup as Required Install to $appname"
write-host "Assigned $uninstallgroup as Required Uninstall to $appname"

##Done
write-host "$appname packaged and deployed"

}