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
$appDeploy = Invoke-RestMethod -uri $deployUrl -Method POST -Headers $authHeader -Body $appBody
return $appDeploy
}
