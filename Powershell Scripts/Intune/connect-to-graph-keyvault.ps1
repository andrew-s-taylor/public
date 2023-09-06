###############################################################################################################
######                                         Set Variables                                             ######
###############################################################################################################

$tenantid = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
$appid = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
$vaultname = "xxxxxxxxxxxx"
$certname = "xxxxxxxxxxxx"

###############################################################################################################
######                                         Install Modules                                           ######
###############################################################################################################
write-output "Installing Intune modules if required (current user scope)"
        # Get NuGet
        $provider = Get-PackageProvider NuGet -ErrorAction Ignore
        if (-not $provider) {
            Write-Host "Installing provider NuGet"
            Find-PackageProvider -Name NuGet -ForceBootstrap -IncludeDependencies
        }

write-output "Installing Microsoft Graph Authentication modules if required (current user scope)"

#Install Graph Groups module if not available

        Install-Module -Name Microsoft.Graph.Authentication -Repository PSGallery -Force -AllowClobber -Scope AllUsers

#Install Az.Accounts module if not available
if (Get-Module -ListAvailable -Name Az.Accounts) {
        write-output "Az.Accounts Module Already Installed"
    } 
    else {
        try {
            Install-Module -Name Az.Accounts -Scope CurrentUser -Repository PSGallery -Force -AllowClobber -RequiredVersion 2.12.1 
        }
        catch [Exception] {
            $_.message 
        }
    }
    
    
    #Install Az.KeyVault module if not available
    if (Get-Module -ListAvailable -Name Az.KeyVault) {
        write-output "Az.KeyVault Module Already Installed"
    } 
    else {
        try {
            Install-Module -Name Az.KeyVault -Scope CurrentUser -Repository PSGallery -Force -AllowClobber -RequiredVersion 4.9.2
        }
        catch [Exception] {
            $_.message 
        }
    }

    import-module Microsoft.Graph.Authentication
    import-module Az.KeyVault
    import-module az.Accounts

###############################################################################################################
######                                            Connect                                                ######
###############################################################################################################

    ##Get the certificate from key vault
write-host "Getting certificate from key vault"
# Ensures you do not inherit an AzContext in your runbook
Disable-AzContextAutosave -Scope Process | Out-Null

# Connect using a Managed Service Identity
try {
        $AzureContext = (Connect-AzAccount -Identity).context
    }
catch{
        Write-Output "There is no system-assigned user identity. Aborting."; 
        exit
    }

# set and store context
$AzureContext = Set-AzContext -SubscriptionName $AzureContext.Subscription `
    -DefaultProfile $AzureContext


        $CertificateSecret = Get-AzKeyVaultSecret -VaultName $vaultname -Name $certname -AsPlainText
        $CertificateBytes = [System.Convert]::FromBase64String($CertificateSecret)
        $CertificateObject = New-Object System.Security.Cryptography.x509Certificates.x509Certificate2Collection
        $CertificateObject.Import($CertificateBytes,$null,[System.Security.Cryptography.x509Certificates.x509KeyStorageFlags]::Exportable)
        $ProtectedCertificateBytes = $CertificateObject.Export([System.Security.Cryptography.x509Certificates.x509ContentType]::Pkcs12,"")
        [System.IO.File]::WriteAllBytes("c:\temp\Certificate.pfx",$ProtectedCertificateBytes)
        Import-PfxCertificate -FilePath "c:\temp\Certificate.pfx" Cert:\CurrentUser\My

        $thumbprint2 = Get-Item "Cert:\CurrentUser\My\$($CertificateObject.thumbprint)"
$thumbprint = $thumbprint2.Thumbprint

##Connect to Graph
write-host "Connecting to Graph"
Connect-MgGraph -TenantId $tenantid -ClientId $appid -CertificateThumbprint $thumbprint
write-host "Connected to Graph"

###############################################################################################################
######                                            Execute                                                ######
###############################################################################################################