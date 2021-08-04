<#
Version: 1.0
Author:  Oliver Kieselbach
Script:  Get-DecryptInfoFromSideCarLogFiles.ps1

Description:
run as Admin on a device where you are AADJ and Intune enrolled to successfully decrypt 
the log message containing decryption info for Intune Win32 apps (.intunewin)

Release notes:
Version 1.0: Original published version.

The script is provided "AS IS" with no warranties.
#>

function Decrypt($base64string)
{
    [System.Reflection.Assembly]::LoadWithPartialName("System.Security") | Out-Null

    $content = [Convert]::FromBase64String($base64string)
    $envelopedCms = New-Object Security.Cryptography.Pkcs.EnvelopedCms
    $certCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    $envelopedCms.Decode($content)
    $envelopedCms.Decrypt($certCollection)

    $utf8content = [text.encoding]::UTF8.getstring($envelopedCms.ContentInfo.Content)

    return $utf8content
}

$agentLogPath = Join-Path $env:ProgramData "Microsoft\IntuneManagementExtension\Logs\IntuneManagementExtension.log"
$stringToSearch = "<![LOG[Get content info from service,ret = {"

Get-Content $agentLogPath | ForEach-Object {
    if ($nextLine) {
        $reply = "{$($_.ToString().TrimStart())}" | ConvertFrom-Json
        
        $responsePayload = ($reply.ResponsePayload | ConvertFrom-Json)
        $contentInfo = ($responsePayload.ContentInfo | ConvertFrom-Json)
        $decryptInfo = Decrypt(([xml]$responsePayload.DecryptInfo).EncryptedMessage.EncryptedContent) | ConvertFrom-Json

        "URL: $($contentInfo.UploadLocation)"
        "Key: $($decryptInfo.EncryptionKey)"
        "IV:  $($decryptInfo.IV)"

        # optional call:
        # .\IntuneWinAppUtilDecoder.exe `"$($contentInfo.UploadLocation)`" /key:$($decryptInfo.EncryptionKey) /iv:$($decryptInfo.IV)

        $nextLine = $false
    }
    if ($_.ToString().StartsWith($stringToSearch) -eq $true) {
        $nextLine = $true
    }
}