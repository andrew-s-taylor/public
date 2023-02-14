Function Add-DevopsFile(){
    
    <#
    .SYNOPSIS
    This function is used to add a file to an Azure Devops Repository
    .DESCRIPTION
    The function connects to the Azure Devops API and adds a file to a repository
    .EXAMPLE
    add-devopsfile -repo reponame -project projectname -organization orgname -filename filename -filecontent filecontent -token token
    .NOTES
    NAME: add-devopsfile
    #>
    
    [cmdletbinding()]
    
    param
    (
        $repo,
        $project,
        $organization,
        $filename,
        $filecontent,
        $token
    )
    

    $base64AuthInfo= [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($token)"))
    $encryptedcontent= [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($filecontent)"))

    $repoUrl = "https://dev.azure.com/$organization/$project/_apis/git/repositories/$repo"

    $repo = Invoke-RestMethod -Uri $repoUrl -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method Get
    $repoId = $repo.id

    ##Check for commits
    $pushiduri = "https://dev.azure.com/$organization/$project/_apis/git/repositories/$repoId/pushes?&`$top=1&searchCriteria.refName=refs/heads/master&api-version=6.0"
    $pushid = ((Invoke-RestMethod -Uri $pushiduri -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method Get).value).pushId
    $commituri = "https://dev.azure.com/$organization/$project/_apis/git/repositories/$repoID/pushes/$pushid`?api-version=6.0"
    $commit = ((Invoke-RestMethod -Uri $commituri -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method Get).commits).commitId

    if ($commit) {
        $oldid = $commit
    } else {
        $oldid = "0000000000000000000000000000000000000000"
    }


    # Push the commit
$pushUrl = "https://dev.azure.com/$organization/$project/_apis/git/repositories/$repoId/pushes?api-version=6.0"
$json = @"
{
    "refUpdates": [
      {
        "name": "refs/heads/master",
        "oldObjectId": "$oldid"
      }
    ],
    "commits": [
      {
        "comment": "Added new file.",
        "changes": [
          {
            "changeType": "add",
            "item": {
              "path": "/$filename"
            },
            "newContent": {
              "content": "$encryptedcontent",
              "contentType": "base64encoded"
            }
          }
        ]
      }
    ]
  }
"@
Invoke-RestMethod -Uri $pushUrl -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method Post -Body $json -ContentType "application/json"   
}

Function Get-DevOpsCommits(){
    
    <#
    .SYNOPSIS
    This function is used to get commits from an Azure Devops Repository
    .DESCRIPTION
    The function connects to the Azure Devops API and gets commits from a repository
    .EXAMPLE
    Get-DevOpsCommits -repo reponame -project projectname -organization orgname -token token
    .NOTES
    NAME: Get-DevOpsCommits
    #>
    
    [cmdletbinding()]
    
    param
    (
        $repo,
        $project,
        $organization,
        $token
    )
    

    $base64AuthInfo= [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($token)"))
    $repoUrl = "https://dev.azure.com/$organization/$project/_apis/git/repositories/$repo"
    $repo = Invoke-RestMethod -Uri $repoUrl -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method Get
    $repoId = $repo.id

    # Get the commits
$ProjectUrl = "https://dev.azure.com/$organization/$project/_apis/git/repositories/$repoId/commits?api-version=7.0"
$CommitInfo = (Invoke-RestMethod -Uri $ProjectUrl -Method Get -UseDefaultCredential -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)}).value

return $CommitInfo
}


