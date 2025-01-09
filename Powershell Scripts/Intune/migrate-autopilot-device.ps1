<#
.SYNOPSIS
 Migrates devices from Autopilot to Autopilot Device Prep.  Grabs hardware details and adds device identifiers.  Optionally removes from Autopilot
.DESCRIPTION
 Migrates devices from Autopilot to Autopilot Device Prep.  Grabs hardware details and adds device identifiers.  Optionally removes from Autopilot
.PARAMETER Path
    The path to the .
.PARAMETER LiteralPath
    Specifies a path to one or more locations. Unlike Path, the value of 
    LiteralPath is used exactly as it is typed. No characters are interpreted 
    as wildcards. If the path includes escape characters, enclose it in single
    quotation marks. Single quotation marks tell Windows PowerShell not to 
    interpret any characters as escape sequences.
.INPUTS
None
.OUTPUTS
Creates a log file in %Temp%
.NOTES
  Version:        1.0.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  09/01/2025
  Purpose/Change: Initial script development

  .EXAMPLE
N/A
#>

<#PSScriptInfo
.VERSION 1.0.0
.GUID f4ee964b-9018-407e-a314-4adeea19b3cd
.AUTHOR AndrewTaylor
.COMPANYNAME 
.COPYRIGHT GPL
.TAGS intune endpoint MEM environment
.LICENSEURI https://github.com/andrew-s-taylor/public/blob/main/LICENSE
.PROJECTURI https://github.com/andrew-s-taylor/public
.ICONURI 
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
#>


##################################################################################################################################
#################                                                  PARAMS                                        #################
##################################################################################################################################


[cmdletbinding()]
    
param
(
    [string[]]$serial #Serial number(s) to migrate
    , 
    [bool]$delete = $false #Delete old AP entry
    ,
    [string]$tenant #Tenant ID (optional) for when automating
    ,
    [string]$clientid #ClientID is the type of Azure AD App Reg ID
    ,
    [string]$clientsecret #ClientSecret is the type of Azure AD App Reg Secret
    )        

##################################################################################################################################
#################                                                  INITIALIZATION                                #################
##################################################################################################################################


write-output "Installing Microsoft Graph modules if required (current user scope)"


#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication) {
    write-output "Microsoft Graph Authentication Already Installed"
} 
else {
        Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser -Repository PSGallery -Force
        write-output "Microsoft Graph Authentication Installed"
}


##################################################################################################################################
#################                                                  FUNCTIONS                                     #################
##################################################################################################################################


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
Connect-ToGraph -Tenant $tenantID -AppId $app -AppSecret $secret
 
-#>
            [cmdletbinding()]
            param
            (
                [Parameter(Mandatory = $false)] [string]$Tenant,
                [Parameter(Mandatory = $false)] [string]$AppId,
                [Parameter(Mandatory = $false)] [string]$AppSecret,
                [Parameter(Mandatory = $false)] [string]$CertificateSubjectName,
                [Parameter(Mandatory = $false)] [string]$CertificateThumbprint,
                [Parameter(Mandatory = $false)] [string]$scopes
            )

            Process {
                Import-Module Microsoft.Graph.Authentication
                $version = (Get-Module microsoft.graph.authentication | Select-Object -ExpandProperty Version).major

                if ($AppId -ne "") {
                    if ($CertificateThumbprint) {
                        $graph = Connect-MgGraph -CertificateThumbprint $CertificateThumbprint -TenantId $Tenant -AppId $AppId 
                        Write-Host "Connected to Intune tenant $TenantId using certificate thumbprint authentication"
                    }
                    elseif ($CertificateSubjectName) {
                        $graph = Connect-MgGraph -CertificateName $CertificateSubjectName -TenantId $Tenant -AppId $AppId
                        Write-Host "Connected to Intune tenant $TenantId using certificate subject name authentication"
                    }
                    else {

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
                            Write-Host "Version 2 module detected"
                            $accesstokenfinal = ConvertTo-SecureString -String $accessToken -AsPlainText -Force
                        }
                        else {
                            Write-Host "Version 1 Module Detected"
                            Select-MgProfile -Name Beta
                            $accesstokenfinal = $accessToken
                        }

                        $graph = Connect-MgGraph -AccessToken $accesstokenfinal 
                        Write-Host "Connected to Intune tenant $TenantId using app-based authentication (Azure AD authentication not supported)"
                    }
                }
                else {
                    if ($version -eq 2) {
                        Write-Host "Version 2 module detected"
                    }
                    else {
                        Write-Host "Version 1 Module Detected"
                        Select-MgProfile -Name Beta
                    }
                    $graph = Connect-MgGraph -Scopes $scopes
                    Write-Host "Connected to Intune tenant $($graph.TenantId)"
                }
            }
        }  

        function getallpagination () {
            <#
    .SYNOPSIS
    This function is used to grab all items from Graph API that are paginated
    .DESCRIPTION
    The function connects to the Graph API Interface and gets all items from the API that are paginated
    .EXAMPLE
    getallpagination -url "https://graph.microsoft.com/v1.0/groups"
     Returns all items
    .NOTES
     NAME: getallpagination
    #>
            [cmdletbinding()]
        
            param
            (
                $url
            )
            $response = (Invoke-MgGraphRequest -Uri $url -Method Get -OutputType PSObject)
            $alloutput = $response.value
        
            $alloutputNextLink = $response."@odata.nextLink"
        
            while ($null -ne $alloutputNextLink) {
                $alloutputResponse = (Invoke-MgGraphRequest -Uri $alloutputNextLink -Method Get -OutputType PSObject)
                $alloutputNextLink = $alloutputResponse."@odata.nextLink"
                $alloutput += $alloutputResponse.value
            }
        
            return $alloutput
        }

        Function Remove-AutopilotDevice() {
            <#
.SYNOPSIS
Removes a specific device currently registered with Windows Autopilot.
 
.DESCRIPTION
The Remove-AutopilotDevice cmdlet removes the specified device, identified by its ID, from the list of devices registered with Windows Autopilot for the current Azure AD tenant.
 
.PARAMETER id
Specifies the ID (GUID) for a specific Windows Autopilot device
 
.EXAMPLE
Remove all Windows Autopilot devices from the current Azure AD tenant
 
Get-AutopilotDevice | Remove-AutopilotDevice
#>
            [cmdletbinding()]
            param
            (
                [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $True)] $id,
                [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $True)] $serialNumber
            )

            Begin {
                $bulkList = @()
            }

            Process {

                # Defining Variables
                $graphApiVersion = "beta"
                $Resource = "deviceManagement/windowsAutopilotDeviceIdentities"    
                $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$id"

                try {
                    Write-Verbose "DELETE $uri"
                    Invoke-MgGraphRequest -Uri $uri -Method DELETE
                }
                catch {
                    Write-Error $_.Exception 
                    break
                }
        
            }
        }



        function check-importeddevice {
            <#
    .SYNOPSIS
    This function is used to check if a device identifier (Windows) already exists in the Intune environment
    .DESCRIPTION
    This function is used to check if a device identifier (Windows) already exists in the Intune environment
    .EXAMPLE
    check-importeddevice -manufacturer "Microsoft Corporation" -model "Virtual Machine" -serial "xxxxx"
    Returns true or false
    .NOTES
    NAME: check-importeddevice
    #>
    [cmdletbinding()]
    
    param
    (
        $manufacturer,
        $model,
        $serial
    )
    ##Check it exists
    $uri = "https://graph.microsoft.com/beta/deviceManagement/importedDeviceIdentities/searchExistingIdentities"
    $json = @"
    {
        "importedDeviceIdentities": [
            {
                "importedDeviceIdentifier": "$manufacturer,$model,$serial",
                "importedDeviceIdentityType": "manufacturerModelSerial"
            }
        ]
    }
"@
    $response = (Invoke-MgGraphRequest -Uri $uri -Method Post -Body $json -OutputType PSObject).value
    
    
    if (!$response) {
        return $false
    } else {
        return $true
    }
    
    }
    

function import-deviceidentifier {
<#
.SYNOPSIS
This function is used to import a device identifier (Windows) already exists in the Intune environment
.DESCRIPTION
This function is used to import a device identifier (Windows) already exists in the Intune environment
.EXAMPLE
import-deviceidentifier -manufacturer "Microsoft Corporation" -model "Virtual Machine" -serial "xxxxx"
Returns true or false
.NOTES
NAME: import-deviceidentifier
#>
[cmdletbinding()]

param
(
$manufacturer,
$model,
$serial
)
##Send it
$uri = "https://graph.microsoft.com/beta/deviceManagement/importedDeviceIdentities/importDeviceIdentityList"

$json = @"
{
"importedDeviceIdentities": [
    {
        "importedDeviceIdentifier": "$manufacturer,$model,$serial",
        "importedDeviceIdentityType": "manufacturerModelSerial"
    }
],
"overwriteImportedDeviceIdentities": false
}
"@
Invoke-MgGraphRequest -Uri $uri -Method Post -Body $json -OutputType PSObject
}

##################################################################################################################################
#################                                              THE FUN BITS                                      #################
##################################################################################################################################


        # Connect
        if ($clientid -ne "") {
            Connect-ToGraph -AppId $clientid -AppSecret $clientsecret -Tenant $tenant
        }
        else {
            $graph = Connect-ToGraph -scopes "Device.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, DeviceManagementServiceConfig.ReadWrite.All"
            Write-Host "Connected to Intune tenant $($graph.TenantId)"
        }

##First check if the serials parameter is populated
if ($null -eq $serial) {

##Grab all Autopilot Devices
$allapdevicesuri = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities"

$allapdevices = (getallpagination -url $allapdevicesuri) | Select-Object id, serialNumber, manufacturer, model, manageddeviceID

$selecteddevices = $allapdevices | Out-GridView -PassThru -Title "Select Devices to Migrate"

##Popup asking if they are to be deleted

# Load the Windows Forms assembly
Add-Type -AssemblyName System.Windows.Forms

# Display a Yes/No message box
$result = [System.Windows.Forms.MessageBox]::Show(
    "Do you want to delete from Autopilot?",
    "Confirmation",
    [System.Windows.Forms.MessageBoxButtons]::YesNo,
    [System.Windows.Forms.MessageBoxIcon]::Question
)

# Set the variable based on the user's choice
if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
    $delete = $true
} else {
    $delete = $false
}

# Output the result
Write-Host "Deleting from Autopilot: $delete"


foreach ($device in $selecteddevices) {
    ##Grab the details we need

    $apid = $device.id
    $apserial = $device.serialNumber
    $apmanufacturer = $device.manufacturer
    $apmodel = $device.model

    ##Add the device identity
    write-host "Checking if device $apserial exists in AutoPilot Device prep"
    $exists = check-importeddevice -manufacturer $apmanufacturer -model $apmodel -serial $apserial
    if ($exists -eq $false) {
        write-host "Device $apserial does not exist in AutoPilot Device prep, adding it"
        $import = import-deviceidentifier -manufacturer $apmanufacturer -model $apmodel -serial $apserial
        write-host "Device $apserial added to AutoPilot Device Identifiers"
    }
    else {
        write-host "Device $apserial already exists in AutoPilot Device prep"
    }

    ##Check if delete is set to $true
    if ($delete) {
        write-host "Removing device $apserial from AutoPilot Devices"
        Remove-AutopilotDevice -id $apid
    }
}

}

else {
##Check if it's a single serial or multiple. If single, create an array
if ($serial -is [string]) {
    $serial = @($serial)
}

##Loop through each serial
foreach ($s in $serial) {

    ##Grab the device
    $deviceuri = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities?$filter=contains(serialNumber,'$s')"

    $device = (Invoke-MgGraphRequest -Uri $deviceuri -Method Get -OutputType PSObject).value

    ##If the device is not found, skip
    if ($null -eq $device) {
        write-output "Device with serial $s not found"
        continue
    }

    ##Grab the details we need

    $apid = $device.id
    $apserial = $device.serialNumber
    $apmanufacturer = $device.manufacturer
    $apmodel = $device.model

    ##Add the device identity
    write-host "Checking if device $apserial exists in AutoPilot Device Prep"
    $exists = check-importeddevice -manufacturer $apmanufacturer -model $apmodel -serial $apserial
    if ($exists -eq $false) {
        write-host "Device $apserial does not exist in AutoPilot Device prep, adding it"
        $import = import-deviceidentifier -manufacturer $apmanufacturer -model $apmodel -serial $apserial
        write-host "Device $apserial added to AutoPilot Device Identifiers"
    }
    else {
        write-host "Device $apserial already exists in AutoPilot Device prep"
    }

    ##Check if delete is set to $true
    if ($delete) {
        write-host "Removing device $apserial from AutoPilot Devices"
        Remove-AutopilotDevice -id $apid
    }



}

}


# SIG # Begin signature block
# MIIoEwYJKoZIhvcNAQcCoIIoBDCCKAACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBAw+volM+t1Tzx
# J5jFxyGMBo5JkMw52CSnSKb8zseGE6CCIRYwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggauMIIElqADAgECAhAHNje3JFR82Ees/ShmKl5bMA0GCSqG
# SIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDAeFw0yMjAzMjMwMDAwMDBaFw0zNzAzMjIyMzU5NTlaMGMx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMy
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcg
# Q0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDGhjUGSbPBPXJJUVXH
# JQPE8pE3qZdRodbSg9GeTKJtoLDMg/la9hGhRBVCX6SI82j6ffOciQt/nR+eDzMf
# UBMLJnOWbfhXqAJ9/UO0hNoR8XOxs+4rgISKIhjf69o9xBd/qxkrPkLcZ47qUT3w
# 1lbU5ygt69OxtXXnHwZljZQp09nsad/ZkIdGAHvbREGJ3HxqV3rwN3mfXazL6IRk
# tFLydkf3YYMZ3V+0VAshaG43IbtArF+y3kp9zvU5EmfvDqVjbOSmxR3NNg1c1eYb
# qMFkdECnwHLFuk4fsbVYTXn+149zk6wsOeKlSNbwsDETqVcplicu9Yemj052FVUm
# cJgmf6AaRyBD40NjgHt1biclkJg6OBGz9vae5jtb7IHeIhTZgirHkr+g3uM+onP6
# 5x9abJTyUpURK1h0QCirc0PO30qhHGs4xSnzyqqWc0Jon7ZGs506o9UD4L/wojzK
# QtwYSH8UNM/STKvvmz3+DrhkKvp1KCRB7UK/BZxmSVJQ9FHzNklNiyDSLFc1eSuo
# 80VgvCONWPfcYd6T/jnA+bIwpUzX6ZhKWD7TA4j+s4/TXkt2ElGTyYwMO1uKIqjB
# Jgj5FBASA31fI7tk42PgpuE+9sJ0sj8eCXbsq11GdeJgo1gJASgADoRU7s7pXche
# MBK9Rp6103a50g5rmQzSM7TNsQIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB
# /wIBADAdBgNVHQ4EFgQUuhbZbU2FL3MpdpovdYxqII+eyG8wHwYDVR0jBBgwFoAU
# 7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoG
# CCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29j
# c3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDig
# NqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZI
# hvcNAQELBQADggIBAH1ZjsCTtm+YqUQiAX5m1tghQuGwGC4QTRPPMFPOvxj7x1Bd
# 4ksp+3CKDaopafxpwc8dB+k+YMjYC+VcW9dth/qEICU0MWfNthKWb8RQTGIdDAiC
# qBa9qVbPFXONASIlzpVpP0d3+3J0FNf/q0+KLHqrhc1DX+1gtqpPkWaeLJ7giqzl
# /Yy8ZCaHbJK9nXzQcAp876i8dU+6WvepELJd6f8oVInw1YpxdmXazPByoyP6wCeC
# RK6ZJxurJB4mwbfeKuv2nrF5mYGjVoarCkXJ38SNoOeY+/umnXKvxMfBwWpx2cYT
# gAnEtp/Nh4cku0+jSbl3ZpHxcpzpSwJSpzd+k1OsOx0ISQ+UzTl63f8lY5knLD0/
# a6fxZsNBzU+2QJshIUDQtxMkzdwdeDrknq3lNHGS1yZr5Dhzq6YBT70/O3itTK37
# xJV77QpfMzmHQXh6OOmc4d0j/R0o08f56PGYX/sr2H7yRp11LB4nLCbbbxV7HhmL
# NriT1ObyF5lZynDwN7+YAN8gFk8n+2BnFqFmut1VwDophrCYoCvtlUG3OtUVmDG0
# YgkPCr2B2RP+v6TR81fZvAT6gt4y3wSJ8ADNXcL50CN/AAvkdgIm2fBldkKmKYcJ
# RyvmfxqkhQ/8mJb2VVQrH4D6wPIOK+XW+6kvRBVK5xMOHds3OBqhK/bt1nz8MIIG
# sDCCBJigAwIBAgIQCK1AsmDSnEyfXs2pvZOu2TANBgkqhkiG9w0BAQwFADBiMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQw
# HhcNMjEwNDI5MDAwMDAwWhcNMzYwNDI4MjM1OTU5WjBpMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0
# ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExMIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1bQvQtAorXi3XdU5WRuxiEL1M4zr
# PYGXcMW7xIUmMJ+kjmjYXPXrNCQH4UtP03hD9BfXHtr50tVnGlJPDqFX/IiZwZHM
# gQM+TXAkZLON4gh9NH1MgFcSa0OamfLFOx/y78tHWhOmTLMBICXzENOLsvsI8Irg
# nQnAZaf6mIBJNYc9URnokCF4RS6hnyzhGMIazMXuk0lwQjKP+8bqHPNlaJGiTUyC
# EUhSaN4QvRRXXegYE2XFf7JPhSxIpFaENdb5LpyqABXRN/4aBpTCfMjqGzLmysL0
# p6MDDnSlrzm2q2AS4+jWufcx4dyt5Big2MEjR0ezoQ9uo6ttmAaDG7dqZy3SvUQa
# khCBj7A7CdfHmzJawv9qYFSLScGT7eG0XOBv6yb5jNWy+TgQ5urOkfW+0/tvk2E0
# XLyTRSiDNipmKF+wc86LJiUGsoPUXPYVGUztYuBeM/Lo6OwKp7ADK5GyNnm+960I
# HnWmZcy740hQ83eRGv7bUKJGyGFYmPV8AhY8gyitOYbs1LcNU9D4R+Z1MI3sMJN2
# FKZbS110YU0/EpF23r9Yy3IQKUHw1cVtJnZoEUETWJrcJisB9IlNWdt4z4FKPkBH
# X8mBUHOFECMhWWCKZFTBzCEa6DgZfGYczXg4RTCZT/9jT0y7qg0IU0F8WD1Hs/q2
# 7IwyCQLMbDwMVhECAwEAAaOCAVkwggFVMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYD
# VR0OBBYEFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB8GA1UdIwQYMBaAFOzX44LScV1k
# TN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcD
# AzB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2lj
# ZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0
# cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmww
# HAYDVR0gBBUwEzAHBgVngQwBAzAIBgZngQwBBAEwDQYJKoZIhvcNAQEMBQADggIB
# ADojRD2NCHbuj7w6mdNW4AIapfhINPMstuZ0ZveUcrEAyq9sMCcTEp6QRJ9L/Z6j
# fCbVN7w6XUhtldU/SfQnuxaBRVD9nL22heB2fjdxyyL3WqqQz/WTauPrINHVUHmI
# moqKwba9oUgYftzYgBoRGRjNYZmBVvbJ43bnxOQbX0P4PpT/djk9ntSZz0rdKOtf
# JqGVWEjVGv7XJz/9kNF2ht0csGBc8w2o7uCJob054ThO2m67Np375SFTWsPK6Wrx
# oj7bQ7gzyE84FJKZ9d3OVG3ZXQIUH0AzfAPilbLCIXVzUstG2MQ0HKKlS43Nb3Y3
# LIU/Gs4m6Ri+kAewQ3+ViCCCcPDMyu/9KTVcH4k4Vfc3iosJocsL6TEa/y4ZXDlx
# 4b6cpwoG1iZnt5LmTl/eeqxJzy6kdJKt2zyknIYf48FWGysj/4+16oh7cGvmoLr9
# Oj9FpsToFpFSi0HASIRLlk2rREDjjfAVKM7t8RhWByovEMQMCGQ8M4+uKIw8y4+I
# Cw2/O/TOHnuO77Xry7fwdxPm5yg/rBKupS8ibEH5glwVZsxsDsrFhsP2JjMMB0ug
# 0wcCampAMEhLNKhRILutG4UI4lkNbcoFUCvqShyepf2gpx8GdOfy1lKQ/a+FSCH5
# Vzu0nAPthkX0tGFuv2jiJmCG6sivqf6UHedjGzqGVnhOMIIGvDCCBKSgAwIBAgIQ
# C65mvFq6f5WHxvnpBOMzBDANBgkqhkiG9w0BAQsFADBjMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0
# ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMB4XDTI0MDkyNjAw
# MDAwMFoXDTM1MTEyNTIzNTk1OVowQjELMAkGA1UEBhMCVVMxETAPBgNVBAoTCERp
# Z2lDZXJ0MSAwHgYDVQQDExdEaWdpQ2VydCBUaW1lc3RhbXAgMjAyNDCCAiIwDQYJ
# KoZIhvcNAQEBBQADggIPADCCAgoCggIBAL5qc5/2lSGrljC6W23mWaO16P2RHxjE
# iDtqmeOlwf0KMCBDEr4IxHRGd7+L660x5XltSVhhK64zi9CeC9B6lUdXM0s71EOc
# Re8+CEJp+3R2O8oo76EO7o5tLuslxdr9Qq82aKcpA9O//X6QE+AcaU/byaCagLD/
# GLoUb35SfWHh43rOH3bpLEx7pZ7avVnpUVmPvkxT8c2a2yC0WMp8hMu60tZR0Cha
# V76Nhnj37DEYTX9ReNZ8hIOYe4jl7/r419CvEYVIrH6sN00yx49boUuumF9i2T8U
# uKGn9966fR5X6kgXj3o5WHhHVO+NBikDO0mlUh902wS/Eeh8F/UFaRp1z5SnROHw
# SJ+QQRZ1fisD8UTVDSupWJNstVkiqLq+ISTdEjJKGjVfIcsgA4l9cbk8Smlzddh4
# EfvFrpVNnes4c16Jidj5XiPVdsn5n10jxmGpxoMc6iPkoaDhi6JjHd5ibfdp5uzI
# Xp4P0wXkgNs+CO/CacBqU0R4k+8h6gYldp4FCMgrXdKWfM4N0u25OEAuEa3Jyidx
# W48jwBqIJqImd93NRxvd1aepSeNeREXAu2xUDEW8aqzFQDYmr9ZONuc2MhTMizch
# NULpUEoA6Vva7b1XCB+1rxvbKmLqfY/M/SdV6mwWTyeVy5Z/JkvMFpnQy5wR14GJ
# cv6dQ4aEKOX5AgMBAAGjggGLMIIBhzAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/
# BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAgBgNVHSAEGTAXMAgGBmeBDAEE
# AjALBglghkgBhv1sBwEwHwYDVR0jBBgwFoAUuhbZbU2FL3MpdpovdYxqII+eyG8w
# HQYDVR0OBBYEFJ9XLAN3DigVkGalY17uT5IfdqBbMFoGA1UdHwRTMFEwT6BNoEuG
# SWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJTQTQw
# OTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcmwwgZAGCCsGAQUFBwEBBIGDMIGAMCQG
# CCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wWAYIKwYBBQUHMAKG
# TGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJT
# QTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcnQwDQYJKoZIhvcNAQELBQADggIB
# AD2tHh92mVvjOIQSR9lDkfYR25tOCB3RKE/P09x7gUsmXqt40ouRl3lj+8QioVYq
# 3igpwrPvBmZdrlWBb0HvqT00nFSXgmUrDKNSQqGTdpjHsPy+LaalTW0qVjvUBhcH
# zBMutB6HzeledbDCzFzUy34VarPnvIWrqVogK0qM8gJhh/+qDEAIdO/KkYesLyTV
# OoJ4eTq7gj9UFAL1UruJKlTnCVaM2UeUUW/8z3fvjxhN6hdT98Vr2FYlCS7Mbb4H
# v5swO+aAXxWUm3WpByXtgVQxiBlTVYzqfLDbe9PpBKDBfk+rabTFDZXoUke7zPgt
# d7/fvWTlCs30VAGEsshJmLbJ6ZbQ/xll/HjO9JbNVekBv2Tgem+mLptR7yIrpaid
# RJXrI+UzB6vAlk/8a1u7cIqV0yef4uaZFORNekUgQHTqddmsPCEIYQP7xGxZBIhd
# mm4bhYsVA6G2WgNFYagLDBzpmk9104WQzYuVNsxyoVLObhx3RugaEGru+SojW4dH
# PoWrUhftNpFC5H7QEY7MhKRyrBe7ucykW7eaCuWBsBb4HOKRFVDcrZgdwaSIqMDi
# CLg4D+TPVgKx2EgEdeoHNHT9l3ZDBD+XgbF+23/zBjeCtxz+dL/9NWR6P2eZRi7z
# cEO1xwcdcqJsyz/JceENc2Sg8h3KeFUCS7tpFk7CrDqkMIIHWzCCBUOgAwIBAgIQ
# CLGfzbPa87AxVVgIAS8A6TANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0
# ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExMB4XDTIz
# MTExNTAwMDAwMFoXDTI2MTExNzIzNTk1OVowYzELMAkGA1UEBhMCR0IxFDASBgNV
# BAcTC1doaXRsZXkgQmF5MR4wHAYDVQQKExVBTkRSRVdTVEFZTE9SLkNPTSBMVEQx
# HjAcBgNVBAMTFUFORFJFV1NUQVlMT1IuQ09NIExURDCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBAMOkYkLpzNH4Y1gUXF799uF0CrwW/Lme676+C9aZOJYz
# pq3/DIa81oWv9b4b0WwLpJVu0fOkAmxI6ocu4uf613jDMW0GfV4dRodutryfuDui
# t4rndvJA6DIs0YG5xNlKTkY8AIvBP3IwEzUD1f57J5GiAprHGeoc4UttzEuGA3yS
# qlsGEg0gCehWJznUkh3yM8XbksC0LuBmnY/dZJ/8ktCwCd38gfZEO9UDDSkie4VT
# Y3T7VFbTiaH0bw+AvfcQVy2CSwkwfnkfYagSFkKar+MYwu7gqVXxrh3V/Gjval6P
# dM0A7EcTqmzrCRtvkWIR6bpz+3AIH6Fr6yTuG3XiLIL6sK/iF/9d4U2PiH1vJ/xf
# dhGj0rQ3/NBRsUBC3l1w41L5q9UX1Oh1lT1OuJ6hV/uank6JY3jpm+OfZ7YCTF2H
# kz5y6h9T7sY0LTi68Vmtxa/EgEtG6JVNVsqP7WwEkQRxu/30qtjyoX8nzSuF7Tms
# RgmZ1SB+ISclejuqTNdhcycDhi3/IISgVJNRS/F6Z+VQGf3fh6ObdQLVwoT0JnJj
# bD8PzJ12OoKgViTQhndaZbkfpiVifJ1uzWJrTW5wErH+qvutHVt4/sEZAVS4PNfO
# cJXR0s0/L5JHkjtM4aGl62fAHjHj9JsClusj47cT6jROIqQI4ejz1slOoclOetCN
# AgMBAAGjggIDMIIB/zAfBgNVHSMEGDAWgBRoN+Drtjv4XxGG+/5hewiIZfROQjAd
# BgNVHQ4EFgQU0HdOFfPxa9Yeb5O5J9UEiJkrK98wPgYDVR0gBDcwNTAzBgZngQwB
# BAEwKTAnBggrBgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20vQ1BTMA4G
# A1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzCBtQYDVR0fBIGtMIGq
# MFOgUaBPhk1odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVk
# RzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEzODQyMDIxQ0ExLmNybDBToFGgT4ZNaHR0
# cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25p
# bmdSU0E0MDk2U0hBMzg0MjAyMUNBMS5jcmwwgZQGCCsGAQUFBwEBBIGHMIGEMCQG
# CCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXAYIKwYBBQUHMAKG
# UGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENv
# ZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3J0MAkGA1UdEwQCMAAwDQYJ
# KoZIhvcNAQELBQADggIBAEkRh2PwMiyravr66Zww6Pjl24KzDcGYMSxUKOEU4byk
# cOKgvS6V2zeZIs0D/oqct3hBKTGESSQWSA/Jkr1EMC04qJHO/Twr/sBDCDBMtJ9X
# AtO75J+oqDccM+g8Po+jjhqYJzKvbisVUvdsPqFll55vSzRvHGAA6hjyDyakGLRO
# cNaSFZGdgOK2AMhQ8EULrE8Riri3D1ROuqGmUWKqcO9aqPHBf5wUwia8g980sTXq
# uO5g4TWkZqSvwt1BHMmu69MR6loRAK17HvFcSicK6Pm0zid1KS2z4ntGB4Cfcg88
# aFLog3ciP2tfMi2xTnqN1K+YmU894Pl1lCp1xFvT6prm10Bs6BViKXfDfVFxXTB0
# mHoDNqGi/B8+rxf2z7u5foXPCzBYT+Q3cxtopvZtk29MpTY88GHDVJsFMBjX7zM6
# aCNKsTKC2jb92F+jlkc8clCQQnl3U4jqwbj4ur1JBP5QxQprWhwde0+MifDVp0vH
# ZsVZ0pnYMCKSG5bUr3wOU7EP321DwvvEsTjCy/XDgvy8ipU6w3GjcQQFmgp/BX/0
# JCHX+04QJ0JkR9TTFZR1B+zh3CcK1ZEtTtvuZfjQ3viXwlwtNLy43vbe1J5WNTs0
# HjJXsfdbhY5kE5RhyfaxFBr21KYx+b+evYyolIS0wR6New6FqLgcc4Ge94yaYVTq
# MYIGUzCCBk8CAQEwfTBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQs
# IEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgQ29kZSBTaWduaW5n
# IFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExAhAIsZ/Ns9rzsDFVWAgBLwDpMA0GCWCG
# SAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcN
# AQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUw
# LwYJKoZIhvcNAQkEMSIEIHv3rvBPt6bhTn7yU534h1AAcdnJTgtUgFR353LfiBi6
# MA0GCSqGSIb3DQEBAQUABIICAMJKumyoPvjSZ/XgtRTaXmDgcN9BokdUa7kR/YZs
# T5uK35YjZkl7uwDsUOvn8DPc7QgbbFEn+xD/VnW0RFF4MPXlOXJb+Z9RhgjHroUU
# U0SVRSRXcLWG/Za9Nv+dGNBmZpRyZLCQhp79JEJW4QnuEFfYGLRUAelxB51ZCt2r
# vMuu/F8QCKflOsyoVttDhUTYAw1coqvPaeH6XxdqeM+pqqPxAKNqbeMzXoWFesaC
# Oir+HL5xiZw2JJMpdIVUn8reoKjImtpZ0j7qmSIFm4lQLq3TK19SR6URit8fHA6i
# Uc1yS65dGRj4oeCsVXGJ33uPpTFKBisF7SrXQvMEERHQ/BGYLPrQhsd6H8j4upsM
# wqgmOyKxXHTZB2y01yA/vRRHoga2s0rl2HZRHeTKYfZaDt6dwLMJCPiW0CLXJaAd
# zhGtKSOSPaeZoITqNr5UDXjf/RYlFvnFwkTyFJZ1+7Qu+jUS8LSqZSEdTUCT7lzt
# j7V9HFLjHJXIV6fMrZm9X0N7n6fwGPXlqG4T0wTEhhdDicGq710GyscYrZNz76m4
# 9SmnTVzwHES/t+E4Qa67UCXMfC99xjni7gxnupBfXCEEID73DkqtGs0wicJztO76
# xq/wU9UnIdSoBhHgO5dBRzCl8it8dT2E4FipiLXGt4VVTe0KanHpsoWT6yZiZvDz
# maaToYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMC
# VVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBU
# cnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQC65mvFq6
# f5WHxvnpBOMzBDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG
# 9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1MDEwOTEzNDcyNlowLwYJKoZIhvcNAQkE
# MSIEINtqWA+PTJR8I+JOUrXg9NdiUgpT1q/UChYzJ0+qNCtSMA0GCSqGSIb3DQEB
# AQUABIICAICSgNtBEYZq9v8Imufdhmbf+DKMMRR/U5fGe1F0JrGzCkvnOz8ccWpf
# vs50m86AuusZgkGg1he7hwsY6NtXVdnFtY4dPBjkSnxhcFr7go5UFDQoj3zYFTrh
# 6+BOvsPAGMkJQtIE2MTG1xh50Y5bdAg3yE4JJzC2SgTnrvBp9HX+7r5E5rmkf27o
# QKaKQrL0OGJDwl56Y6BJ5QIwzgTT4D3As4HDJM1slcdB4OxARWc6wMH3o+LiuKSe
# F8LHfGk/HYkf/OeoBrrkJx9e2ZH17BdZsN3pgUxykRh5QTX9j4Vymb0mZBk75lF6
# Hzrk8W0r3W/PwXOcayMTGw/ksCcpy9ZAB6aMCsJYCkmg0fEVgwmFmKz7Rhcc/oVW
# r2V3v5Xzzb6oBbsXAudmONSQyx5YZSMssODWs7Do5iPlqs6ahuf6YTgQxE5CN3oP
# q7IeZi+0g6p/51EK7z0OEjHGkDm+0V2eKHY0cKkBSVU2THmMHDsAX97Yc8cMhyNT
# dxltzvGgaMgYMtAqjHa/GKiLf2foyTmUUJ0ew6FECenYC+A4Y/evqah3PHOx4A/V
# yO1KjPGvmYOvq8nSJDFaawsMI1vWnbO5KPiFy9GHrXgjIUoWjoJ6HOvbSMdueF0S
# y2YLbqASqOVzs+lk6uSWAPO8e2u1lphiG6u5Si1mtPy4Jk6Pi6yv
# SIG # End signature block
