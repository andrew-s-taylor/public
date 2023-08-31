[cmdletbinding()]
    
param
(
    [string]$url,
    [string]$ownername,
    [string]$reponame,
    [string]$token,
    [string]$key
    )



function getpowershellgalleryscripts() {
    [cmdletbinding()]
    
    param
    (
        $url
    )
$webpage = Invoke-WebRequest -Uri $url -UseBasicParsing | Select-Object -ExpandProperty Links
##Restrict to only those with /packages/ in the URL
$webpage = $webpage | Where-Object {$_.href -like "*packages/*"}
$allpages = @()
foreach ($page in $webpage) {
    $packagename = ($page.href -split "/")[2]
    $allpages += $packagename + ".ps1"
}
$removed = $allpages | Select-Object -Skip 1
##Remove duplicates
$final = $removed | Select-Object -Unique
return $final
}

function getgitfilename() {
    [cmdletbinding()]
    
    param
    (
        $ownername,
        $reponame,
        $token
    )
##Grab GitHub Commits
write-host "Finding Latest PS1 Commit from Repo $reponame in $ownername GitHub"
$uri = "https://api.github.com/repos/$ownername/$reponame/commits"
$events = (Invoke-RestMethod -Uri $uri -Method Get -Headers @{'Authorization' = 'bearer ' + $token; 'Accept' = 'Accept: application/vnd.github+json' }).commit

##Loop through until we hit a PS1 file
##We don't want to grab anything else in the repo
##When we find a PS1, break the loop
foreach ($event in $events) {
    $eventsuri = $event.url
    $commitid = Split-Path $eventsuri -Leaf
    $commituri = "https://api.github.com/repos/$ownername/$reponame/commits/$commitid"
    $commitfilename2 = ((Invoke-RestMethod -Uri $commituri -Method Get -Headers @{'Authorization' = 'token ' + $token; 'Accept' = 'application/json' }).Files).raw_url
    $commitfileext = split-path $commitfilename2 -Leaf
    $commitext = [System.IO.Path]::GetExtension($commitfileext)
    if ($commitext -eq ".ps1") {
        $commitfilename = $commitfilename2
        break;
    }
}

##Split the filename on both / and %2F
##This is because the raw URL has %2F instead of /
$commitfilenameonly = $commitfilename -split "/"
$commitfilenameonly = $commitfilename -split "%2F"
$commitfilenameonly = $commitfilenameonly[-1]
return $commitfilenameonly, $commitfilename
}

$allscripts = getpowershellgalleryscripts -url $url

$lastcommit = getgitfilename -ownername $ownername -reponame $reponame -token $token

##Check if last commit is in $allscripts
if ($allscripts -contains $lastcommit[0]) {
    write-host "Script is good to go"
    ##Download it to the local machine
    $uri = $lastcommit[1]
    $output = $lastcommit[0]
    Invoke-WebRequest -Uri $uri -OutFile $output

    ##Add to PSGallery
    publish-script -Path "$output" -NuGetApiKey $key -Verbose


}
