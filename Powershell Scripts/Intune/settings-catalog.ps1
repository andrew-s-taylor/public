##Category URIs for each different type:

$windowscategoriesuri = "https://graph.microsoft.com/beta/deviceManagement/configurationCategories?=&`$filter=(platforms has 'windows10') and (technologies has 'mdm')"
$ioscategoriesuri = "https://graph.microsoft.com/beta/deviceManagement/configurationCategories?=&`$filter=(platforms has 'iOS') and (technologies has 'mdm' or technologies has 'appleRemoteManagement')"
$securitycategoriesuri = "https://graph.microsoft.com/beta/deviceManagement/configurationCategories?templateCategory=True&`$filter=(platforms has 'windows10') and (technologies has 'microsoftSense')"
$macoscategoriesuri = "https://graph.microsoft.com/beta/deviceManagement/configurationCategories?=&`$filter=(platforms has 'macOS') and (technologies has 'mdm' or technologies has 'appleRemoteManagement')"

##Create an array to dump the categories into
$catselect = @()
##Add the URI and platform for each into the array
$catobj1 = New-Object -TypeName PSCustomObject
$catobj1 | Add-Member -MemberType NoteProperty -Name "Type" -Value "Windows"
$catobj1 | Add-Member -MemberType NoteProperty -Name "description" -Value $windowscategoriesuri
$catobj1 | Add-Member -MemberType NoteProperty -Name "platform" -Value "windows10"
$catselect += $catobj1
$catobj2 = New-Object -TypeName PSCustomObject
$catobj2 | Add-Member -MemberType NoteProperty -Name "Type" -Value "iOS"
$catobj2 | Add-Member -MemberType NoteProperty -Name "description" -Value $ioscategoriesuri
$catobj2 | Add-Member -MemberType NoteProperty -Name "platform" -Value "iOS"
$catselect += $catobj2
$catobj3 = New-Object -TypeName PSCustomObject
$catobj3 | Add-Member -MemberType NoteProperty -Name "Type" -Value "Security"
$catobj3 | Add-Member -MemberType NoteProperty -Name "description" -Value $securitycategoriesuri
$catobj3 | Add-Member -MemberType NoteProperty -Name "platform" -Value "windows10"
$catselect += $catobj3
$catobj4 = New-Object -TypeName PSCustomObject
$catobj4 | Add-Member -MemberType NoteProperty -Name "Type" -Value "macOS"
$catobj4 | Add-Member -MemberType NoteProperty -Name "description" -Value $macoscategoriesuri
$catobj4 | Add-Member -MemberType NoteProperty -Name "platform" -Value "macOS"
$catselect += $catobj4

##Pop out to select
$cat = $catselect | Out-GridView -PassThru
$categoriesuri = $cat.description
$platform = $cat.platform

##Get list of categories for platform chosen
$categorylist = (Invoke-MgGraphRequest -Method GET -Uri $categoriesuri -OutputType PSObject).value | select-object id, displayName, description, platform

##Pop out to select
$category = $categorylist | Out-GridView -PassThru

$categoryid = $category.id

##Get list of policies for category chosen
$policiesuri = "https://graph.microsoft.com/beta/deviceManagement/configurationSettings?&`$filter=categoryId eq '$categoryid'"
$policies = (Invoke-MgGraphRequest -Method GET -Uri $policiesuri -OutputType PSObject).value | select-object name, description, '@odata.type', rootDefinitionId, options, @{Name="Platform"; Expression={ $_.applicability | Select-Object platform}},@{Name="technologies"; Expression={ $_.applicability | Select-Object technologies}},valuedefinition, id

##Pop out to select
$policy = $policies | Out-GridView -PassThru

##Get the policy details
$policysettingid = $policy.rootDefinitionId
$policyoptions = $policy.options
$policytechnologies = $policy.technologies.technologies
$policyid = $policy.id

##Pop out options to select from
$selectedoption = $policyoptions | Select-Object name, description, itemID, dependenton, dependedOnBy | Out-GridView -PassThru

$selectedvalue = $selectedoption.itemId

##See if it's a group setting
$dependancy = $selectedoption.dependenton.parentsettingid
$json1 = @"
{
    "name": "Test Policy as Code",
    "description": "",
    "platforms": "$platform",
    "technologies": "$policytechnologies",
    "roleScopeTagIds": [
        "0"
    ],
    "settings": [
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
"@


##Non group setting
$json2a = @"

"settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "$policysettingid",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "$selectedvalue",
                    "children": []
                }
            }
"@

##Group setting
$json2b = @"

"settingInstance": {
    "@odata.type": "#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance",
    "groupSettingCollectionValue": [
        {
            "children": [
                {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                    "choiceSettingValue": {
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                        "children": [],
                        "value": "$selectedvalue"
                    },
                    "settingDefinitionId": "$policyid"
                }
            ]
        }
    ],
    "settingDefinitionId": "$dependancy"
}
"@

$json3 = @"
        }
    ]
}
"@

##Select the right json
if ($dependancy -eq $null) {
    $json2 = $json2a
} else {
    $json2 = $json2b
}

##Combine the json
$finaljson = $json1 + $json2 + $json3

##Create the policy
Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies" -Body $finaljson -ContentType "application/json"