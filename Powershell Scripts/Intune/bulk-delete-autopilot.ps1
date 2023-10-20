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
                    write-output "Version 2 module detected"
                    $accesstokenfinal = ConvertTo-SecureString -String $accessToken -AsPlainText -Force
                }
                else {
                    write-output "Version 1 Module Detected"
                    Select-MgProfile -Name Beta
                    $accesstokenfinal = $accessToken
                }
                $graph = Connect-MgGraph  -AccessToken $accesstokenfinal 
                write-output "Connected to Intune tenant $TenantId using app-based authentication (Azure AD authentication not supported)"
            }
            else {
                if ($version -eq 2) {
                    write-output "Version 2 module detected"
                }
                else {
                    write-output "Version 1 Module Detected"
                    Select-MgProfile -Name Beta
                }
                $graph = Connect-MgGraph -scopes $scopes
                write-output "Connected to Intune tenant $($graph.TenantId)"
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

    
        if (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication) {
            write-output "Microsoft Graph Authentication Already Installed"
            writelog "Microsoft Graph Authentication Already Installed"
        } 
        else {
                Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser -Repository PSGallery -Force
                write-output "Microsoft Graph Authentication Installed"
                writelog "Microsoft Graph Authentication Installed"
        }

        Import-Module microsoft.graph.authentication

        Connect-ToGraph -Scopes "Policy.ReadWrite.ConditionalAccess, CloudPC.ReadWrite.All, DeviceManagementServiceConfig.ReadWrite.All, RoleAssignmentSchedule.ReadWrite.Directory, Domain.Read.All, Domain.ReadWrite.All, Directory.Read.All, Policy.ReadWrite.ConditionalAccess, DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, openid, profile, email, offline_access, DeviceManagementRBAC.Read.All, DeviceManagementRBAC.ReadWrite.All"

        $autopilotdevices = getallpagination -url "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities"
        $selecteddevices = $autopilotdevices | Out-GridView -Title "select devices to remove" -PassThru

        foreach ($device in $selecteddevices) {
            $deviceid = $device.id
            write-host "Removing device $deviceid"
            $url = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities/$deviceid"
            Invoke-MgGraphRequest -Uri $url -Method Delete
            write-host "Device $deviceid removed"
        }