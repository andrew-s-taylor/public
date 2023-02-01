Function Add-ApplicationAssignmentVPPiOS() {
    <#
.SYNOPSIS
This function is used to add an application assignment using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a application assignment
.EXAMPLE
Add-ApplicationAssignmentVPPiOS -ApplicationId $ApplicationId -TargetGroupId $TargetGroupId -InstallIntent $InstallIntent
Adds an application assignment in Intune
.NOTES
NAME: Add-ApplicationAssignmentVPPiOS
#>

    [cmdletbinding()]
    param
    (
        $ApplicationId,
        $TargetGroupId,
        $InstallIntent
    )
    $graphApiVersion = "Beta"
    $Resource = "deviceAppManagement/mobileApps/$ApplicationId/assign"
    try {

        if (!$ApplicationId) {
            write-host "No Application Id specified, specify a valid Application Id" -f Red
            break
        }
        if (!$TargetGroupId) {
            write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red
            break
        }

        if (!$InstallIntent) {
            write-host "No Install Intent specified, specify a valid Install Intent - available, notApplicable, required, uninstall, availableWithoutEnrollment" -f Red
            break
        }
        $JSON = @"
{
    "mobileAppAssignments": [
    {
        "@odata.type": "#microsoft.graph.mobileAppAssignment",
        "settings": {
            "@odata.type": "#microsoft.graph.iosVppAppAssignmentSettings",
            "isRemovable": true,
            "uninstallOnDeviceRemoval": false,
            "useDeviceLicensing": true,
            "vpnConfigurationId": null
        },
        "target": {
        "@odata.type": "#microsoft.graph.groupAssignmentTarget",
        "groupId": "$TargetGroupId"
        },
        "intent": "$InstallIntent"
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


