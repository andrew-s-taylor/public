#What is your Tenant URL
$turl = "https://myurl.com"

# Login to Azure AD PowerShell With Admin Account
Connect-AzureAD 

# Create the self signed cert
$currentDate = Get-Date
$endDate = $currentDate.AddYears(1)
$notAfter = $endDate.AddYears(1)
$pwd = "Password12345@"
$thumb = (New-SelfSignedCertificate -CertStoreLocation cert:\localmachine\my -DnsName com.foo.bar -KeyExportPolicy Exportable -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" -NotAfter $notAfter).Thumbprint
$pwd = ConvertTo-SecureString -String $pwd -Force -AsPlainText
Export-PfxCertificate -cert "cert:\localmachine\my\$thumb" -FilePath c:\temp\examplecert.pfx -Password $pwd

# Load the certificate
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate("C:\temp\examplecert.pfx", $pwd)
$keyValue = [System.Convert]::ToBase64String($cert.GetRawCertData())


# Create the Azure Active Directory Application
$application = New-AzureADApplication -DisplayName "pshellsignature" -IdentifierUris $turl
New-AzureADApplicationKeyCredential -ObjectId $application.ObjectId -CustomKeyIdentifier "pshellsignature" -StartDate $currentDate -EndDate $endDate -Type AsymmetricX509Cert -Usage Verify -Value $keyValue

# Create the Service Principal and connect it to the Application
$sp=New-AzureADServicePrincipal -AppId $application.AppId

# Give the Service Principal Reader access to the current tenant (Get-AzureADDirectoryRole)
Add-AzureADDirectoryRoleMember -ObjectId 2bcf4db5-eac2-4ff6-9940-a3e692f9f2f1 -RefObjectId $sp.ObjectId