###############################################################################################################
######                                         Install Modules                                           ######
###############################################################################################################


##Install and Import MgGraph Authentication Module
Write-Host "Installing Intune modules if required (current user scope)" -ForegroundColor Green


Write-Host "Installing Microsoft Graph Groups modules if required (current user scope)" -ForegroundColor Green

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication) {
    Write-Host "Microsoft Graph Already Installed" -ForegroundColor Green
} 
else {
    try {
        Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser -Repository PSGallery -Force 
        Write-Host "Microsoft Graph Installed" -ForegroundColor Green
    }
    catch [Exception] {
        $_.message 
    }
}

if (Get-Module -ListAvailable -Name Microsoft.Graph.Groups) {
    Write-Host "Microsoft Graph Groups Already Installed" -ForegroundColor Green
} 
else {
    try {
        Install-Module -Name Microsoft.Graph.Groups -Scope CurrentUser -Repository PSGallery -Force 
        Write-Host "Microsoft Graph Groups Installed" -ForegroundColor Green
    }
    catch [Exception] {
        $_.message 
    }
}


#Importing Modules
Write-Host "Importing Microsoft Graph Authentication Module" -ForegroundColor Green
import-module microsoft.graph.authentication
write-host "Imported Microsoft Graph Authentication" -ForegroundColor Green

Write-Host "Importing Microsoft Graph Groups Module" -ForegroundColor Green
import-module microsoft.graph.Groups
write-host "Imported Microsoft Graph Groups" -ForegroundColor Green


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


###############################################################################################################
######                                            Connect                                                ######
###############################################################################################################
##Authenticate to Graph

write-host "Authenticating to Microsoft Graph" -ForegroundColor Green
Connect-ToGraph -Scopes "User.ReadWrite.All, Group.ReadWrite.All"
write-host "Authenticated to Microsoft Graph" -ForegroundColor Green

###############################################################################################################
######                                              Run                                                  ######
###############################################################################################################

##Prompt for users email
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Source Email'
$form.Size = New-Object System.Drawing.Size(300,200)
$form.StartPosition = 'CenterScreen'

$okButton = New-Object System.Windows.Forms.Button
$okButton.Location = New-Object System.Drawing.Point(75,120)
$okButton.Size = New-Object System.Drawing.Size(75,23)
$okButton.Text = 'OK'
$okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
$form.AcceptButton = $okButton
$form.Controls.Add($okButton)

$cancelButton = New-Object System.Windows.Forms.Button
$cancelButton.Location = New-Object System.Drawing.Point(150,120)
$cancelButton.Size = New-Object System.Drawing.Size(75,23)
$cancelButton.Text = 'Cancel'
$cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.CancelButton = $cancelButton
$form.Controls.Add($cancelButton)

$label = New-Object System.Windows.Forms.Label
$label.Location = New-Object System.Drawing.Point(10,20)
$label.Size = New-Object System.Drawing.Size(280,20)
$label.Text = 'Please enter the source email address:'
$form.Controls.Add($label)

$textBox = New-Object System.Windows.Forms.TextBox
$textBox.Location = New-Object System.Drawing.Point(10,40)
$textBox.Size = New-Object System.Drawing.Size(260,20)
$form.Controls.Add($textBox)

$form.Topmost = $true

$form.Add_Shown({$textBox.Select()})
$result = $form.ShowDialog()

if ($result -eq [System.Windows.Forms.DialogResult]::OK)
{
    $sourceemail = $textBox.Text
    write-host "Source user set to $sourceemail"
    write-host "Getting User ID"
$usersuri = "https://graph.microsoft.com/v1.0/users?`$filter=userPrincipalName eq '$sourceemail'"
$userid = (Invoke-MgGraphRequest -Uri $usersuri -Method GET -OutputType PSObject).value.id
write-host "User ID is $userid"
write-host "Finding Groups"
$groupsuri = "https://graph.microsoft.com/v1.0/users/$userid/memberOf"
$allgroups = (Invoke-MgGraphRequest -Uri $groupsuri -Method GET -OutputType PSObject).value | Where-Object onPremisesSyncEnabled -ne "True"
}


$form2 = New-Object System.Windows.Forms.Form
$form2.Text = 'Destination Email'
$form2.Size = New-Object System.Drawing.Size(300,200)
$form2.StartPosition = 'CenterScreen'

$okButton2 = New-Object System.Windows.Forms.Button
$okButton2.Location = New-Object System.Drawing.Point(75,120)
$okButton2.Size = New-Object System.Drawing.Size(75,23)
$okButton2.Text = 'OK'
$okButton2.DialogResult = [System.Windows.Forms.DialogResult]::OK
$form2.AcceptButton = $okButton2
$form2.Controls.Add($okButton2)

$cancelButton2 = New-Object System.Windows.Forms.Button
$cancelButton2.Location = New-Object System.Drawing.Point(150,120)
$cancelButton2.Size = New-Object System.Drawing.Size(75,23)
$cancelButton2.Text = 'Cancel'
$cancelButton2.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form2.CancelButton = $cancelButton2
$form2.Controls.Add($cancelButton2)

$label2 = New-Object System.Windows.Forms.Label
$label2.Location = New-Object System.Drawing.Point(10,20)
$label2.Size = New-Object System.Drawing.Size(280,20)
$label2.Text = 'Please enter the destination email address:'
$form2.Controls.Add($label2)

$textBox2 = New-Object System.Windows.Forms.TextBox
$textBox2.Location = New-Object System.Drawing.Point(10,40)
$textBox2.Size = New-Object System.Drawing.Size(260,20)
$form2.Controls.Add($textBox2)

$form2.Topmost = $true

$form2.Add_Shown({$textBox2.Select()})
$result2 = $form2.ShowDialog()

if ($result2 -eq [System.Windows.Forms.DialogResult]::OK)
{
    $destemail = $textBox2.Text
    write-host "Destination user set to $destemail"
    write-host "Getting User ID"
$dusersuri = "https://graph.microsoft.com/v1.0/users?`$filter=userPrincipalName eq '$destemail'"
$duserid = (Invoke-MgGraphRequest -Uri $dusersuri -Method GET -OutputType PSObject).value.id
write-host "User ID is $duserid"

##Add to groups

foreach ($group in $allgroups) {
    $groupid = $group.id
    $groupname = $group.displayName
    write-host "Adding $destemail to $groupname"
New-MgGroupMember -GroupId $groupid -DirectoryObjectId $duserid
write-host " $destemail added to $groupname"
    }

}