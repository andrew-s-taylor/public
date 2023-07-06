###  For these you will need the MG Graph Authentication Module

if (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication) {
    Write-Host "Microsoft Graph Already Installed"
} 
else {
    try {
        Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser -Repository PSGallery -Force 
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

## And to Connect to Graph
Connect-ToGraph -Scopes Domain.Read.All, Directory.Read.All, DeviceManagementApps.ReadWrite.All, openid, profile, email, offline_access



Function Add-MSStoreApp(){
        
    <#
    .SYNOPSIS
    This function adds Microsoft Store Apps using Winget
    .DESCRIPTION
    The function connects to the Graph API Interface and creates a Microsoft Store App using the new experience
    .EXAMPLE
    Add-MSStoreApp -name "WhatsApp"
    .NOTES
    NAME: Add-MSStoreApp
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
$appName = $name
$storeSearchUrl = "https://storeedgefd.dsx.mp.microsoft.com/v9.0/manifestSearch"
$body = @{
    Query = @{
        KeyWord   = $appName
        MatchType = "Substring"
    }
} | ConvertTo-Json
$appSearch = Invoke-RestMethod -Uri $storeSearchUrl -Method POST -ContentType 'application/json' -body $body
$exactApp = $appSearch.Data | Where-Object { $_.PackageName -eq $appName }

$appUrl = "https://storeedgefd.dsx.mp.microsoft.com/v9.0/packageManifests/{0}" -f $exactApp.PackageIdentifier
$app = Invoke-RestMethod -Uri $appUrl -Method GET 
$appId = $app.Data.PackageIdentifier
$appInfo = $app.Data.Versions[-1].DefaultLocale
$appInstaller = $app.Data.Versions[-1].Installers


$imageUrl = "https://apps.microsoft.com/store/api/ProductsDetails/GetProductDetailsById/{0}?hl=en-US&gl=US" -f $exactApp.PackageIdentifier
$image = Invoke-RestMethod -Uri $imageUrl -Method GET 
$wc = New-Object System.Net.WebClient
$wc.DownloadFile($image.IconUrl, "./temp.jpg")
$base64string = [Convert]::ToBase64String([IO.File]::ReadAllBytes('./temp.jpg'))

    $appdescription = ($appInfo.Shortdescription).ToString()
    $appdescription2 = $appdescription.replace("`n"," ").replace("`r"," ").replace("\n"," ").replace("\\n"," ")
    $appdeveloper = $appInfo.Publisher
    $appdisplayName = $appInfo.packageName
    $appinformationUrl = $appInfo.PublisherSupportUrl
    $apprunAsAccount = ($appInstaller.scope | select-object -First 1)
    $appisFeatured = $false
    $apppackageIdentifier = $appId
    $appprivacyInformationUrl = $appInfo.PrivacyUrl
    $apppublisher = $appInfo.publisher


$deployUrl = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps"
$json = @"
{
	"@odata.type": "#microsoft.graph.winGetApp",
	"categories": [],
	"description": "$appdescription2",
	"developer": "$appdeveloper",
	"displayName": "$appdisplayName",
	"informationUrl": "$appinformationUrl",
	"installExperience": {
		"runAsAccount": "$apprunAsAccount"
	},
	"isFeatured": false,
	"largeIcon": {
        "@odata.type": "#microsoft.graph.mimeContent",
        "type": "string",
        "value": "$base64string"
    	},
	"notes": "",
	"owner": "",
	"packageIdentifier": "$apppackageIdentifier",
	"privacyInformationUrl": "$appprivacyInformationUrl",
	"publisher": "$apppublisher",
	"repositoryType": "microsoftStore",
	"roleScopeTagIds": []
}
"@

$appDeploy = Invoke-mggraphrequest -uri $deployUrl -Method POST -Body $json -ContentType "application/JSON"



return $appDeploy
}

Function Add-StoreAppAssignment(){

    <#
    .SYNOPSIS
    This function is used to add a store app assignment using the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and adds a store app assignment
    .EXAMPLE
    Add-StoreAppAssignment -StoreAppID $StoreAppIdId -TargetGroupId $TargetGroupId
    Adds a Store app assignment in Intune
    .NOTES
    NAME: Add-SStoreAppAssignment
    #>
    
    [cmdletbinding()]
    
    param
    (
        $StoreAppID,
        $TargetGroupId
    )
    
    $graphApiVersion = "Beta"
    $Resource = "deviceAppManagement/mobileApps/$storeAppID/assign"
        
        try {
    
            if(!$StoreAppID){
    
            write-host "No App Id specified, specify a valid App Id" -f Red
            break
    
            }
    
            if(!$TargetGroupId){
    
            write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red
            break
    
            }
    
            $JSON = @"
            {
                "mobileAppAssignments": [
                    {
                        "@odata.type": "#microsoft.graph.mobileAppAssignment",
                        "intent": "Required",
                        "settings": {
                            "@odata.type": "#microsoft.graph.winGetAppAssignmentSettings",
                            "installTimeSettings": null,
                            "notifications": "showAll",
                            "restartSettings": null
                        },
                        "target": {
                            "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                            "groupId": "$targetgroupid"
                        }
                    }
                ]
            }
"@
    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType "application/json"
    
    
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
        
    
        }
    
    }

    Function Get-MSStoreApps(){
        
        <#
        .SYNOPSIS
        This function is used to get MS Store Apps from the Graph API REST interface
        .DESCRIPTION
        The function connects to the Graph API Interface and gets any MS Store Apps
        .EXAMPLE
        Get-MSStoreApps
        Returns any MS Store Apps configured in Intune

        Get-MSStoreApps -id $id
        Returns specific app
        .NOTES
        NAME: Get-MSStoreApps
        #>
        
        [cmdletbinding()]
        
        param
        (
            $id
        )
        
        $graphApiVersion = "beta"
        $DCP_resource = "deviceAppManagement/MobileApps"
        
            try {
        
                if($Name){
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id"
        ((Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value)

                }
        
                else {
        
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)?`$filter=(isof('microsoft.graph.winGetApp'))"
        (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
        
                }
        
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
            
        
            }
        
        }


Function Add-MSStoreApp(){
        
    <#
    .SYNOPSIS
    This function adds Microsoft Store Apps using Winget
    .DESCRIPTION
    The function connects to the Graph API Interface and creates a Microsoft Store App using the new experience
    .EXAMPLE
    Add-MSStoreApp -name "WhatsApp"
    .NOTES
    NAME: Add-MSStoreApp
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
$appName = $name
$storeSearchUrl = "https://storeedgefd.dsx.mp.microsoft.com/v9.0/manifestSearch"
$body = @{
    Query = @{
        KeyWord   = $appName
        MatchType = "Substring"
    }
} | ConvertTo-Json
$appSearch = Invoke-RestMethod -Uri $storeSearchUrl -Method POST -ContentType 'application/json' -body $body
$exactApp = $appSearch.Data | Where-Object { $_.PackageName -eq $appName }

$appUrl = "https://storeedgefd.dsx.mp.microsoft.com/v9.0/packageManifests/{0}" -f $exactApp.PackageIdentifier
$app = Invoke-RestMethod -Uri $appUrl -Method GET 
$appId = $app.Data.PackageIdentifier
$appInfo = $app.Data.Versions[-1].DefaultLocale
$appInstaller = $app.Data.Versions[-1].Installers


$imageUrl = "https://apps.microsoft.com/store/api/ProductsDetails/GetProductDetailsById/{0}?hl=en-US&gl=US" -f $exactApp.PackageIdentifier
$image = Invoke-RestMethod -Uri $imageUrl -Method GET 
$wc = New-Object System.Net.WebClient
$wc.DownloadFile($image.IconUrl, "./temp.jpg")
$base64string = [Convert]::ToBase64String([IO.File]::ReadAllBytes('./temp.jpg'))


$deployUrl = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps"
$appBody = @{
    '@odata.type'         = "#microsoft.graph.winGetApp"
    description           = $appInfo.ShortDescription
    developer             = $appInfo.Publisher
    displayName           = $appInfo.packageName
    informationUrl        = $appInfo.PublisherSupportUrl
    largeIcon             = @{
        "@odata.type"= "#microsoft.graph.mimeContent"
        "type" ="String"
        "value" = $base64string 
    }
    installExperience     = @{
        runAsAccount = $appInstaller.scope
    }
    isFeatured            = $false
    packageIdentifier     = $appId
    privacyInformationUrl = $appInfo.PrivacyUrl
    publisher             = $appInfo.publisher
    repositoryType        = "microsoftStore"
    roleScopeTagIds       = @()
} | ConvertTo-Json 
$appDeploy = Invoke-MgGraphRequest -uri $deployUrl -Method POST -Body $appBody
return $appDeploy
}
