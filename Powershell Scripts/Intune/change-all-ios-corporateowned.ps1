Write-Host "Installing Microsoft Graph modules if required (current user scope)"

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph) {
    Write-Host "Microsoft Graph Already Installed"
} 
else {
    try {
        Install-Module -Name Microsoft.Graph -Scope CurrentUser -Repository PSGallery -Force 
    }
    catch [Exception] {
        $_.message 
        exit
    }
}


# Load the Graph module
Import-Module microsoft.graph

Function Set-ManagedDevice(){

<#
.SYNOPSIS
This function is used to set Managed Device property from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and sets a Managed Device property
.EXAMPLE
Set-ManagedDevice -id $id -ownerType company
Returns Managed Devices configured in Intune
.NOTES
NAME: Set-ManagedDevice
#>

[cmdletbinding()]

param
(
    $id,
    $ownertype
)


$graphApiVersion = "Beta"
$Resource = "deviceManagement/managedDevices"

    try {

        if($id -eq "" -or $id -eq $null){

        write-host "No Device id specified, please provide a device id..." -f Red
        break

        }
        
        if($ownerType -eq "" -or $ownerType -eq $null){

            write-host "No ownerType parameter specified, please provide an ownerType. Supported value personal or company..." -f Red
            Write-Host
            break

            }

        elseif($ownerType -eq "company"){

$JSON = @"

{
    ownerType:"company"
}

"@


            
                # Send Patch command to Graph to change the ownertype
                $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices('$ID')"
                Invoke-MgGraphRequest -Uri $uri -Body $json -method Patch -ContentType "application/json"
            }

        elseif($ownerType -eq "personal"){

$JSON = @"

{
    ownerType:"personal"
}

"@


            
                # Send Patch command to Graph to change the ownertype
                $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices('$ID')"
                Invoke-MgGraphRequest -Uri $uri -Body $json -method Patch -ContentType "application/json"
            }

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

###############################################################################################################
######                                          MS Graph Implementations                                 ######
###############################################################################################################
#Connect to Graph
Select-MgProfile -Name Beta
Connect-MgGraph -Scopes  	RoleAssignmentSchedule.ReadWrite.Directory, Domain.Read.All, Domain.ReadWrite.All, Directory.Read.All, Policy.ReadWrite.ConditionalAccess, DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, openid, profile, email, offline_access


$uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=deviceType eq 'iPhone'"
$iphones = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
foreach ($iphone in $iphones) {
$phoneid = $iphone.id
write-host "Setting $phoneid to Corporate Owned"
    Set-ManagedDevice -id $phoneid -ownertype company

}
