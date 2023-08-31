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

function getallusers () {
$allusers = getallpagination -url "https://graph.microsoft.com/beta/users"

return $allusers
}


function getgroupsandmembers() {
$allgroups = getallpagination -url "https://graph.microsoft.com/beta/groups"
$hshGrp = @{}

foreach ($group in $allgroups) {
    $hshGrp[$group.displayName] = New-Object Collections.Arraylist
    $groupmembers = getallpagination -url "https://graph.microsoft.com/beta/groups/$($group.id)/members"
    ForEach ($member in $groupmembers)
    {
        $hshGrp[$group.displayName].add($member.id) > $nul
    } 

}

return $hshGrp
}


function getdevicesandusers() {
$alldevices = getallpagination -url "https://graph.microsoft.com/beta/devicemanagement/manageddevices"
$outputarray = @()
foreach ($value in $alldevices) {
    $objectdetails = [pscustomobject]@{
        DeviceID = $value.id
        DeviceName = $value.deviceName
        OSVersion = $value.operatingSystem
        PrimaryUser = $value.userPrincipalName
    }


    $outputarray += $objectdetails

}

return $outputarray
}
