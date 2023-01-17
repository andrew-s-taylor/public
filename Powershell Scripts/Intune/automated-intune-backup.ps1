<#PSScriptInfo
.VERSION 1.0.1
.GUID 62e6e98b-8580-4c72-b9a4-05c7793a8532
.AUTHOR AndrewTaylor
.DESCRIPTION Automates Backup of Intune Environment
.COMPANYNAME
.COPYRIGHT GPL
.TAGS intune endpoint MEM environment
.LICENSEURI https://github.com/andrew-s-taylor/public/blob/main/LICENSE
.PROJECTURI https://github.com/andrew-s-taylor/public
.ICONURI
.EXTERNALMODULEDEPENDENCIES microsoft.graph.intune, intunebackupandrestore
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
.PRIVATEDATA
#>
<# 

.DESCRIPTION 
Automates Backup of Intune Environment via Intune Backup and Restore module with AAD App Registration, Azure Blob and Azure Automation Account

#> 

import-module intunebackupandrestore

##############################################################################################################################################
##### UPDATE THESE VALUES #################################################################################################################
##############################################################################################################################################
## Your Azure Tenant Name
$tenant = "<YOUR TENANT NAME>"

##Your Azure Tenant ID
$tenantid = "<YOUR TENANT ID>"

##Your App Registration Details
$clientId = "<YOUR CLIENT ID>"
$clientSecret = "<YOUR CLIENT SECRET>"

##Your Storage Account Details
$storagegroup = "<YOUR STORAGE RESOURCE GROUP>"
$storageaccount = "<YOUR STORAGE ACCOUNT>"
$storagecontainer = "<YOUR STORAGE CONTAINER>"
$storagekey = "<YOUR STORAGE KEY>"



##############################################################################################################################################
##### DO NOT EDIT BELOW THIS LINE #############################################################################################################
##############################################################################################################################################
$authority = "https://login.windows.net/$tenant"

## Connect to MS Graph
Update-MSGraphEnvironment -AppId $clientId -Quiet
Update-MSGraphEnvironment -AuthUrl $authority -Quiet
Update-MSGraphEnvironment -SchemaVersion “Beta” -Quiet
Connect-MSGraph -ClientSecret $ClientSecret -Quiet

##Get Date
$date = get-date -format "dd_MM_yyy"

##Create temp folder
$dir = $env:temp + "\IntuneBackup" + $date
$tempFolder = New-Item -Type Directory -Force -Path $dir

##Backup Locally
Start-IntuneBackup `
		-Path $tempFolder
		
##Connect to AZURE
$azurePassword = ConvertTo-SecureString $clientSecret -AsPlainText -Force
$psCred = New-Object System.Management.Automation.PSCredential($clientID , $azurePassword)
Connect-AzAccount -Credential $psCred -TenantId $tenantid -ServicePrincipal

##Convert Storage Account to lowercase (just in case)

$storageaccount = $storageaccount.ToLower()

##Upload to Azure Blob
$files = "$env:TEMP\IntuneBackup$date" 
$context = New-AzStorageContext -StorageAccountName $storageaccount -StorageAccountKey $storagekey
Get-ChildItem -Path $files -File -Recurse | Set-AzStorageBlobContent -Container $storagecontainer -Context $context
