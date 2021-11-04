#Assign Autopilot
$PolicyName = "AutoPilot Profile"

$DCP = Get-AutoPilotProfile -name "$PolicyName"

if($DCP){
$TargetGroupId = $pilotgrp.id
$apid = $DCP.id
$TargetGroup = New-Object -TypeName psobject
$TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value 'microsoft.graph.deviceAndAppManagementAssignmentTarget'
$TargetGroup | Add-Member -MemberType NoteProperty -Name 'deviceAndAppManagementAssignmentFilterType' -Value 'include'



$TargetGroup | Add-Member -MemberType NoteProperty -Name 'deviceAndAppManagementAssignmentFilterId' -Value "$TargetGroupId"

$Target = New-Object -TypeName psobject
$Target | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.windowsAutopilotDeploymentProfileAssignment'
$Target | Add-Member -MemberType NoteProperty -Name 'target' -Value $TargetGroup
$Target | Add-Member -MemberType NoteProperty -Name 'sourceId' -Value $TargetGroupId
$Target | Add-Member -MemberType NoteProperty -Name 'source' -Value "direct"

$TargetGroups = $Target
$graphApiVersion = "Beta"
$Resource = "deviceManagement/windowsAutopilotDeploymentProfiles/$apid/assignments"

$uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"


# Creating JSON object to pass to Graph
$Output = New-Object -TypeName psobject

$Output | Add-Member -MemberType NoteProperty -Name 'assignments' -Value @($TargetGroups)

$JSON = $Output | ConvertTo-Json -Depth 3

    #$Assignment = Add-AutoPilotProfileAssignment -ConfigurationPolicyId $DCP.id -TargetGroupId $pilotgrp.id -AssignmentType Included
    Write-Host "Assigned 'TargetGroupId' to $($DCP.displayName)/$($DCP.id)" -ForegroundColor Green
    Write-Host

}

else {

    Write-Host "Can't find Device Configuration Policy with name '$PolicyName'..." -ForegroundColor Red
    Write-Host 

}