##Bulk assigns all Managed Play Store apps as Available to All Users

Write-Host "Installing Microsoft Graph modules if required (current user scope)"

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication) {
    Write-Host "Microsoft Graph Already Installed"
} 
else {
    try {
        Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser -Repository PSGallery -Force 
    }
    catch [Exception] {
        $_.message 
        exit
    }
}


# Load the Graph module
Import-Module microsoft.graph.authentication  

Select-MgProfile -Name Beta
Connect-MgGraph -Scopes  RoleAssignmentSchedule.ReadWrite.Directory, Domain.Read.All, Domain.ReadWrite.All, Directory.Read.All, Policy.ReadWrite.ConditionalAccess, DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, openid, profile, email, offline_access

Function Add-ApplicationAssignment() {
    <#
.SYNOPSIS
This function is used to add an application assignment using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a application assignment
.EXAMPLE
Add-ApplicationAssignment -ApplicationId $ApplicationId
Adds an application assignment in Intune
.NOTES
NAME: Add-ApplicationAssignment
#>
    [cmdletbinding()]

    param

    (
        $ApplicationId

    )

    $graphApiVersion = "Beta"
    $Resource = "deviceAppManagement/mobileApps/$ApplicationId/assign"

    try {
        if (!$ApplicationId) {
            write-host "No Application Id specified, specify a valid Application Id" -f Red
            break
        }


        $JSON = @"
        {
            "mobileAppAssignments": [
            {
            "@odata.type": "#microsoft.graph.mobileAppAssignment",
            "intent": "Available",
            "settings": {
            "@odata.type": "#microsoft.graph.androidManagedStoreAppAssignmentSettings",
            "androidManagedStoreAppTrackIds": [],
            "autoUpdateMode": "default"
            },
            "target": {
            "@odata.type": "#microsoft.graph.allLicensedUsersAssignmentTarget"
            }
            }
            ]
            }
"@

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType "application/json"
    }

   

    catch {
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break
    }

}



$uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=((isof('microsoft.graph.androidManagedStoreApp') and microsoft.graph.androidManagedStoreApp/isSystemApp eq false)) and (microsoft.graph.managedApp/appAvailability eq null or microsoft.graph.managedApp/appAvailability eq 'lineOfBusiness' or isAssigned eq true)"
$app = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value

foreach ($app in $apps) {
    $appid = $app.id
    Add-ApplicationAssignment -ApplicationId $appid
}

