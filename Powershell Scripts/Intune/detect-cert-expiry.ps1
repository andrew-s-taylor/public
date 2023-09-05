<#PSScriptInfo
.VERSION 1.0.4
.GUID 1000d8c2-73b3-48a8-b1ec-f894fec7df58
.AUTHOR AndrewTaylor
.DESCRIPTION Alerts when a certificate is due to expire
.COMPANYNAME
.COPYRIGHT GPL
.TAGS intune endpoint MEM environment
.LICENSEURI https://github.com/andrew-s-taylor/public/blob/main/LICENSE
.PROJECTURI https://github.com/andrew-s-taylor/public
.ICONURI
.EXTERNALMODULEDEPENDENCIES microsoft.graph.intune, microsoft.graph.users.actions
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
.PRIVATEDATA
#>
<# 

.DESCRIPTION 
Alerts on expiry of Apple Certificates with AAD App Registration, Azure Blob and Azure Automation Account

#> 


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

$EmailAddress = "<YOUR EMAIL ADDRESS>"

##From Address
$MailSender = "<YOUR FROM ADDRESS>"


##############################################################################################################################################


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


#Get Creds and connect
#Connect to Graph
write-host "Connecting to Graph"
write-host $body

Connect-ToGraph -Tenant $tenant -AppId $clientId -AppSecret $clientSecret
write-host "Graph Connection Established"

#MDM Push
$30days = ((get-date).AddDays(30)).ToString("yyyy-MM-dd")
$pushuri = "https://graph.microsoft.com/beta/deviceManagement/applePushNotificationCertificate"
$pushcert = Invoke-MgGraphRequest -Uri $pushuri -Method Get -OutputType PSObject
$pushexpiryplaintext = $pushcert.expirationDateTime
$pushexpiry = ($pushcert.expirationDateTime).ToString("yyyy-MM-dd")
if ($pushexpiry -lt $30days) {
write-host "Cert Expiring" -ForegroundColor Red

#Send Mail    
$URLsend = "https://graph.microsoft.com/v1.0/users/$MailSender/sendMail"
$BodyJsonsend = @"
                    {
                        "message": {
                          "subject": "Apple Push Certificate Expiry",
                          "body": {
                            "contentType": "HTML",
                            "content": "Your Apple Push Certificate is due to expire on <br>
                            $pushexpiryplaintext <br>
                            Please Renew before this date
                            "
                          },
                          "toRecipients": [
                            {
                              "emailAddress": {
                                "address": "$EmailAddress"
                              }
                            }
                          ]
                        },
                        "saveToSentItems": "false"
                      }
"@

Invoke-MgGraphRequest -Method POST -Uri $URLsend -Body $BodyJsonsend -ContentType "application/json"

}
else {
write-host "All fine" -ForegroundColor Green
}


#VPP
$30days = ((get-date).AddDays(30)).ToString("yyyy-MM-dd")
$vppuri = "https://graph.microsoft.com/beta/deviceAppManagement/vppTokens"
$vppcert = Invoke-MgGraphRequest -Uri $vppuri -Method Get -OutputType PSObject
$vppexpiryvalue = $vppcert.value
$vppexpiryplaintext = $vppexpiryvalue.expirationDateTime
$vppexpiry = ($vppexpiryvalue.expirationDateTime).ToString("yyyy-MM-dd")
if ($vppexpiry -lt $30days) {
write-host "Cert Expiring" -ForegroundColor Red
#Send Mail    
$URLsend = "https://graph.microsoft.com/v1.0/users/$MailSender/sendMail"
$BodyJsonsend = @"
                    {
                        "message": {
                          "subject": "Apple VPP Certificate Expiry",
                          "body": {
                            "contentType": "HTML",
                            "content": "Your Apple VPP Certificate is due to expire on <br>
                            $vppexpiryplaintext <br>
                            Please Renew before this date
                            "
                          },
                          "toRecipients": [
                            {
                              "emailAddress": {
                                "address": "$EmailAddress"
                              }
                            }
                          ]
                        },
                        "saveToSentItems": "false"
                      }
"@

Invoke-MgGraphRequest -Method POST -Uri $URLsend -Body $BodyJsonsend -ContentType "application/json"
}
else {
write-host "All fine" -ForegroundColor Green
}






#DEP
$30days = ((get-date).AddDays(30)).ToString("yyyy-MM-dd")
$depuri = "https://graph.microsoft.com/beta/deviceManagement/depOnboardingSettings"
$depcert = Invoke-MgGraphRequest -Uri $depuri -Method Get -OutputType PSObject
$depexpiryvalue = $depcert.value
$depexpiryplaintext = $depexpiryvalue.tokenexpirationDateTime

$depexpiry = ($depexpiryvalue.tokenExpirationDateTime).ToString("yyyy-MM-dd")
if ($depexpiry -lt $30days) {
write-host "Cert Expiring" -ForegroundColor Red

#Send Mail    
$URLsend = "https://graph.microsoft.com/v1.0/users/$MailSender/sendMail"
$BodyJsonsend = @"
                    {
                        "message": {
                          "subject": "Apple DEP Certificate Expiry",
                          "body": {
                            "contentType": "HTML",
                            "content": "Your Apple DEP Certificate is due to expire on <br>
                            $depexpiryplaintext <br>
                            Please Renew before this date
                            "
                          },
                          "toRecipients": [
                            {
                              "emailAddress": {
                                "address": "$EmailAddress"
                              }
                            }
                          ]
                        },
                        "saveToSentItems": "false"
                      }
"@

Invoke-MgGraphRequest -Method POST -Uri $URLsend -Body $BodyJsonsend
}
else {
write-host "All fine" -ForegroundColor Green
}
