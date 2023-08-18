<#PSScriptInfo
.VERSION 1.0.0
.GUID 1ae3c3de-1218-4a15-a888-f6f2f75882fd
.AUTHOR AndrewTaylor
.DESCRIPTION Runs a basic license check on a 365 environment
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
<#
.SYNOPSIS
 Runs a basic license check on a 365 environment
.DESCRIPTION
.Checks Licenses
.Emails a report

.INPUTS
None
.OUTPUTS
In-Line Outputs
.NOTES
  Version:        1.0.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  18/08/2023
  Purpose/Change: Initial script development
.EXAMPLE
N/A
#>

##################################################################################################################################
#################                                                  PARAMS                                        #################
##################################################################################################################################

[cmdletbinding()]
    
param
(

    [string]$tenant #Tenant ID (optional) for when automating and you want to use across tenants instead of hard-coded
    ,
    [string]$clientid #ClientID is the type of Azure AD App Reg ID
    ,
    [string]$clientsecret #ClientSecret is the type of Azure AD App Reg Secret
    ,
    [string]$email #Email address to send report to
    ,
    [string]$recipient #Email address to send report to
    ,
    [object] $WebHookData #Webhook data for Azure Automation

    )

##WebHook Data

if ($WebHookData){

    $bodyData = ConvertFrom-Json -InputObject $WebHookData.RequestBody


$tenant = ((($bodyData.tenant) | out-string).trim())
$clientid = ((($bodyData.clientid) | out-string).trim())
$clientsecret = ((($bodyData.clientsecret) | out-string).trim())
$email = ((($bodyData.email) | out-string).trim())
$recipient = ((($bodyData.recipient) | out-string).trim())




##Check if parameters have been set

$clientidcheck = $PSBoundParameters.ContainsKey('clientid')
$clientsecretcheck = $PSBoundParameters.ContainsKey('clientsecret')

if (($clientidcheck -eq $true) -and ($clientsecretcheck -eq $true)) {
##AAD Secret passed, use to login
$aadlogin = "yes"

}



}
###############################################################################################################
######                                  Create GUI for Tenant Details                                    ######
###############################################################################################################
if (!$tenant) {
##Prompt for tenant ID in a GUI window
Add-Type -AssemblyName System.Windows.Forms

# Create a new form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Enter the Tenant ID"
$form.Width = 300
$form.Height = 150
$form.StartPosition = "CenterScreen"

# Create a label to display instructions
$label = New-Object System.Windows.Forms.Label
$label.Location = New-Object System.Drawing.Point(10, 20)
$label.Size = New-Object System.Drawing.Size(280, 20)
$label.Text = "Please enter the Tenant ID:"
$form.Controls.Add($label)

# Create a text box for user input
$textbox = New-Object System.Windows.Forms.TextBox
$textbox.Location = New-Object System.Drawing.Point(10, 50)
$textbox.Size = New-Object System.Drawing.Size(280, 20)
$form.Controls.Add($textbox)

# Create a button to submit the input
$button = New-Object System.Windows.Forms.Button
$button.Location = New-Object System.Drawing.Point(100, 80)
$button.Size = New-Object System.Drawing.Size(100, 30)
$button.Text = "Submit"
$button.DialogResult = [System.Windows.Forms.DialogResult]::OK
$form.AcceptButton = $button
$form.Controls.Add($button)

# Show the form and wait for user input
$result = $form.ShowDialog()

# Get the user input from the text box
if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    $tenantid = $textbox.Text
}
}
else {
    $tenantid = $tenant
}
###############################################################################################################
######                                           Output Folder Creation                                  ######
###############################################################################################################
write-output "Creating Folder for Reports"
##Create a folder to store the output
$folder = "$env:temp\Reports"
if (!(Test-Path $folder)) {
    New-Item -ItemType Directory -Path $folder
}

write-output "Folder Created"


##################################################################################################################################
#################                                                  INITIALIZATION                                #################
##################################################################################################################################
$ErrorActionPreference = "Continue"
$date = Get-Date -Format "dd-MM-yyyy"
$logpath = "$env:temp\Reports\licensecheck_$tenantid" + "_$date.log"
Start-Transcript -Path $logpath -Append


###############################################################################################################
######                                         Install Modules                                           ######
###############################################################################################################


##Install and Import MgGraph Authentication Module
Write-Host "Installing Intune modules if required (current user scope)"


Write-Host "Installing Microsoft Graph Groups modules if required (current user scope)"

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication) {
    Write-Host "Microsoft Graph Already Installed"
} 
else {
    try {
        Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser -Repository PSGallery -Force 
        Write-Host "Microsoft Graph Installed"
    }
    catch [Exception] {
        $_.message 
    }
}



#Importing Modules
Write-Host "Importing Microsoft Graph Authentication Module"
import-module microsoft.graph.authentication
write-host "Imported Microsoft Graph Authentication"


##Add custom logging for runbook
$Logfile = "$env:TEMP\licensereview-$date.log"
function WriteLog
{
Param ([string]$LogString)
$Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
$LogMessage = "$Stamp $LogString \n"
Add-content $LogFile -value $LogMessage
}

Function Connect-ToGraph {
    <#
.SYNOPSIS
Authenticates to the Graph API via the Microsoft.Graph.Authentication module.
 
.DESCRIPTION
The Connect-ToGraph cmdlet is a wrapper cmdlet that helps authenticate to the Intune Graph API using the Microsoft.Graph.Authentication module. It leverages an Entra ID app ID and app secret for authentication or user-based auth.
 
.PARAMETER Tenant
Specifies the tenant (e.g. contoso.onmicrosoft.com) to which to authenticate.
 
.PARAMETER AppId
Specifies the Entra ID app ID (GUID) for the application that will be used to authenticate.
 
.PARAMETER AppSecret
Specifies the Entra ID app secret corresponding to the app ID that will be used to authenticate.

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
            Write-Host "Connected to Intune tenant $TenantId using app-based authentication (Entra ID authentication not supported)"
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

function getallpagination () {
    [cmdletbinding()]
        
    param
    (
        $url
    )
        $response = (Invoke-MgGraphRequest -uri $url -Method Get -OutputType PSObject)
        $alloutput = $response.value
        
        $alloutputNextLink = $response."@odata.nextLink"
        
        while ($null -ne $alloutputNextLink) {
            $alloutputResponse = (Invoke-MGGraphRequest -Uri $alloutputNextLink -Method Get -outputType PSObject)
            $alloutputNextLink = $alloutputResponse."@odata.nextLink"
            $alloutput += $alloutputResponse.value
        }
        
        return $alloutput
        }
###############################################################################################################
######                                            Connect                                                ######
###############################################################################################################
##Authenticate to Graph
if (($WebHookData) -or ($aadlogin -eq "yes")) {
 
    Connect-ToGraph -Tenant $tenant -AppId $clientId -AppSecret $clientSecret
    write-output "Graph Connection Established"
    writelog "Graph Connection Established"
    
    }
    else {
write-host "Authenticating to Microsoft Graph"
Connect-ToGraph -Scopes "User.ReadWrite.All, AuditLog.Read.All, Reports.Read.All, Group.Read.All, ReportSettings.ReadWrite.All"
write-host "Authenticated to Microsoft Graph"
    }



###############################################################################################################
######                                            Query                                                  ######
###############################################################################################################

##Get the domain name
$uri = "https://graph.microsoft.com/beta/organization"
$tenantdetails = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
$domain = ($tenantdetails.VerifiedDomains | Where-Object isDefault -eq $true).name

## Check unused licenses
write-output "Checking Unused Licenses"
writelog "Checking Unused Licenses"

$graphurl = "https://graph.microsoft.com/v1.0/subscribedSkus"

$licenses = getallpagination -url $graphurl


$translationTable = Invoke-RestMethod -Method Get -Uri "https://download.microsoft.com/download/e/3/e/e3e9faf2-f28b-490a-9ada-c6089a1fc5b0/Product%20names%20and%20service%20plan%20identifiers%20for%20licensing.csv" | ConvertFrom-Csv
$unused = @()
$total = @()
foreach ($license in $licenses) {
$skuNamePretty = ($translationTable | Where-Object {$_.GUID -eq $license.skuId} | Sort-Object Product_Display_Name -Unique).Product_Display_Name

$available = (($license.prepaidUnits.enabled) - ($license.consumedUnits))
if (($skuNamePretty -notmatch "free") -and ($skuNamePretty -notmatch "trial")) {
$objectdetailstotal = [pscustomobject]@{
    name = $skuNamePretty
    total = $license.prepaidUnits.enabled
    used = $license.consumedUnits
    unused = $available
}
$total += $objectdetailstotal
}

if (($available -gt 0) -and ($skuNamePretty -notmatch "free") -and ($skuNamePretty -notmatch "trial")) {

$licensename = $skuNamePretty
Write-Output "$licensename has $available unused licenses"
writelog "$licensename has $available unused licenses"
$objectdetails = [pscustomobject]@{
    name = $licensename
    unused = $available
}
$unused += $objectdetails
}
}
$total = $total | Sort-Object Unused -Descending
Write-Output "Unused Licenses Checked"
writelog "Unused Licenses Checked"
##Check Unused users with licenses

Write-Output "Checking Unused Users"
writelog "Checking Unused Users"

##Unused Users first
$usersuri = "https://graph.microsoft.com/beta/users"

$users = (Invoke-MgGraphRequest -Uri $usersuri -Method GET -OutputType PSObject).value

$today = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
$90daysago = (Get-Date).AddDays(-90).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

$oldusers = @()

$loginlogsuri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=(createdDateTime+ge+$90daysago+and+createdDateTime+lt+$today)"
$userscheck = (Invoke-MgGraphRequest -uri $loginlogsuri -Method GET -OutputType PSObject).value | Select-Object userID
$counter = 0
foreach ($user in $users) {
    $counter++
$userid = $user.id
$userupn = $user.userPrincipalName
Write-Progress -Activity 'Processing Entries' -CurrentOperation $userupn -PercentComplete (($counter / $users.count) * 100)
##Check if userID is in $userscheck
if ($userid -in $userscheck) {
##Ignore these
}
else {
    $objectdetails = [pscustomobject]@{
        name = $userupn
        userid = $userid
    }
    $oldusers+= $objectdetails
    write-output "$userupn has not been seen for 90 days or more"
    writelog "$userupn has not been seen for 90 days or more"
}
}

write-output "Unused Users Checked"
writelog "Unused Users Checked"

##Check each old user for licenses

write-output "Checking Unused Licenses for Unused Users"
writelog "Checking Unused Licenses for Unused Users"

$licensestorelease = @()
foreach ($olduser in $oldusers) {
    $olduserid = $olduser.userid
    $olduserupn = $olduser.name
$licenseuricheck = "https://graph.microsoft.com/v1.0/users/$olduserid/licenseDetails"
$userlicence = getallpagination -url $licenseuricheck
    if ($userlicence.Count -gt 0) {
        Write-Output "$olduserupn has a license assigned"
        writelog "$olduserupn has a license assigned"
        foreach ($individuallicense in $userlicence) {
            $skuNamePretty = ($translationTable | Where-Object {$_.GUID -eq $individuallicense.skuId} | Sort-Object Product_Display_Name -Unique).Product_Display_Name
        $objectdetails = [pscustomobject]@{
            name = $olduserupn
            license = $skuNamePretty
        }
        $licensestorelease += $objectdetails
    }
    }
    else {
        write-output "$olduserupn has no license assigned"
        writelog "$olduserupn has no license assigned"
    }


}

Write-Output "Unused Licenses for Unused Users Checked"
writelog "Unused Licenses for Unused Users Checked"


write-output "Checks completed, creating output file"
writelog "Checks completed, creating output file"

###############################################################################################################
######                                            Reporting                                              ######
###############################################################################################################

$html = @"
<html>
<head>
<title>License Report</title>
<style type="text/css">
/* Set default font family and color for entire page */
body {
    font-family: Arial, sans-serif;
    color: #333;
  }
  
  /* Center all headings */
  h1, h2, h3 {
    text-align: center;
  }
  
  /* Style for main heading */
  h1 {
    font-size: 2.5rem;
    margin: 2rem 0;
    color: #ff6633; /* blue */
  }
  
  /* Style for subheadings */
  h2 {
    font-size: 2rem;
    margin: 1.5rem 0;
    color: #cc3399; /* orange */
  }
  
  /* Style for sub-subheadings */
  h3 {
    font-size: 1.5rem;
    margin: 1rem 0;
    color: #ff6633; /* blue */
  }
  
  /* Style for tables */
  table {
    border-collapse: collapse;
    width: 100%;
    margin-bottom: 2rem;
  }
  
  /* Style for table headers */
  th {
    text-align: left;
    background-color: #0066ff;
    padding: 0.5rem;
    border: 1px solid #ddd;
    color: #ffffff;
  }
  
  /* Style for table cells */
  td {
    border: 1px solid #ddd;
    padding: 0.5rem;
  }
  
  /* Alternate row background color */
  tr:nth-child(even) {
    background-color: #ffffff;
    color: #000000;
  }

   /* Alternate row background color */
   tr:nth-child(odd) {
    background-color: #eeeeee;
    color: #000000;
  }

  /* Blue link color */
  a {
    color: #0066ff;
  }
  
  #container {
    width: 80%;
    margin: 0 auto;
  }
  
  #header {
    background-color: #eee;
    padding: 1rem;
  }
  #contents {
    padding: 1rem;
  }
</style>
</head>
<body>
<div id="container">
<div id="header">
<img src="https://andrewstaylor.com/wp-content/uploads/2023/08/andrewstaylor-final-files-01.jpg" alt="6dg Logo">
</div>
<div id="contents">
<a id="top"></a>
<a href="#total">Total Licenses</a> | <a href="#unused">Unused Licenses</a> | <a href="#oldusers">Old Users with Licenses</a> 
</div>
"@
##Add a header
$html += "<h1>License Report for $domain</h1>"
$html += "<h2>Report Generated on $(Get-Date)</h2>"
$html += '<h2 id="total">Total Licenses</h2>'
$totalhtml = $total | ConvertTo-Html -Fragment
$html += $totalhtml
$html += '<h2 id="unused">Unused Licenses</h2>'
$unusedhtml = $unused | ConvertTo-Html -Fragment
$html += $unusedhtml
$html += '<h2 id="oldusers">Old Users (not seen in 90 days)</h2>'
$usedhtml = $licensestorelease | ConvertTo-Html -Fragment
$html += $usedhtml

##Close the HTML
$html += @"
</div>
</body>
</html>
"@

$outputfile = "$folder\license_report_$tenantid" + "_$date.html"

write-output "Generating HTML Report"
writelog "Generating HTML Report"
#The command below will generate the report to an HTML file
$html | Out-File $outputfile

##Confirm where report is saved
write-output "Report saved to $outputfile"
writelog "Report saved to $outputfile"

###############################################################################################################
######                                            PROCESS REPORTS                                        ######
###############################################################################################################


$FileName=Split-Path $outputfile -leaf
$base64string = [Convert]::ToBase64String([IO.File]::ReadAllBytes($outputfile))

##Email it
write-output "Sending Email"
$URLsend = "https://graph.microsoft.com/v1.0/users/$email/sendMail"
$BodyJsonsend = @"
                    {
                        "message": {
                          "subject": "License Report",
                          "body": {
                            "contentType": "HTML",
                            "content": "Please find your license report attached"
                          },
                          "toRecipients": [
                            {
                              "emailAddress": {
                                "address": "$recipient"
                              }
                            }
                          ]
                          ,"attachments": [
                            {
                              "@odata.type": "#microsoft.graph.fileAttachment",
                              "name": "$filename",
                              "contentType": "text/plain",
                              "contentBytes": "$base64string"
                            }
                          ]
                        },
                        "saveToSentItems": "false"
                      }
"@
write-output $URLsend
Invoke-MgGraphRequest -Method POST -Uri $URLsend -Body $BodyJsonsend -ContentType "application/json"
write-output "Email Sent"
writelog "Email Sent"

Stop-Transcript