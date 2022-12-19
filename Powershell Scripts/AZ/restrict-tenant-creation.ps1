##Install MS Graph Authentication Module (current user)
Install-Module -Name microsoft.graph.authentication -Scope CurrentUser -Force

##Import the module
Import-Module -Name microsoft.graph.authentication

##Connect to MS Graph
Select-MgProfile -Name "beta"
Connect-MgGraph -Scopes "Policy.Read.All", "Policy.ReadWrite.Authorization"

##Set the Policy to false
$uri = "https://graph.microsoft.com/beta/policies/authorizationPolicy/authorizationPolicy"

$json = @'
{"defaultUserRolePermissions":{"allowedToCreateTenants":false}}
'@
Invoke-MgGraphRequest -uri $uri -Method Patch -Body $json -ContentType "application/json"

##Disconnect
Disconnect-MgGraph