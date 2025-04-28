##############################################
#                                            #
# File:     download-sched.ps1               #
# Author:   Duncan Russell                   #
#           http://www.sysadmintechnotes.com #
# Edited:   Andrew Johnson                   #
#           http://www.andrewj.net           #
#           Evan Yeung                       #
#           http://www.forevanyeung.com      #
#           Chris Kibble                     #
#           http://www.christopherkibble.com #
#           Jon Warnken                      #
#           http://www.mrbodean.net          #
#           Oliver Baddeley Edited For       #
#           Desert Edition                   #
#           https://andrewstaylor.com        #
#           Andrew Taylor Edited for MEM     #
#           Summit 2024                      #
#           And MEM Summit 2025              #
##############################################
function Invoke-BasicHTMLParser ($html) {
    $html = $html.Replace("<br>", "`r`n").Replace("<br/>", "`r`n").Replace("<br />", "`r`n") # replace <br> with new line
  
    # Speaker Spacing
    $html = $html.Replace("<div class=`"sched-person-session`">", "`r`n`r`n")
  
    # Link parsing
    $linkregex = '(?<texttoreplace><a.*?href="(?<link>.*?)".*?>(?<content>.*?)<\/a>)'
    $links = [regex]::Matches($html, $linkregex, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    foreach ($l in $links) {
      if (-not $l.Groups['link'].Value.StartsWith("http")) { $link = "$SchedBaseURL/$($l.Groups['link'].Value)" }else { $link = $l.Groups['link'].Value }
      $html = $html.Replace($l.Groups['texttoreplace'].Value, " [$($l.Groups['content'].Value)]($link)")
    }
  
    # List Parsing
    $listRegex = '(?<texttoreplace><ul[^>]?>(?<content>.*?)<\/ul>)'
    $lists = [regex]::Matches($html, $listRegex, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    foreach ($l in $lists) {
      $content = $l.Groups['content'].Value.Replace("<li>", "`r`n* ").Replace("</li>", "")
      $html = $html.Replace($l.Groups['texttoreplace'].Value, $content)
    }
  
    # General Cleanup
    $html = $html.replace("&rarr;", "")
    $html = $html -replace '<div[^>]+>', "`r`n"
    $html = $html -replace '<[^>]+>', '' # Strip all HTML tags
  
    ## Future revisions
    # do something about <b> / <i> / <strong> / etc...
    # maybe a converter to markdown
    
    return $html
  }

  # Check PowerShell Version
  if ($PSVersionTable.PSVersion.Major -lt 7) {
        Write-Host "INFO: This script is recommended to be run in PowerShell 7 or higher." -ForegroundColor Yellow
        Write-Host "If you encounter any problems, please try running it in PowerShell 7: https://aka.ms/powershell-release?tag=stable" -ForegroundColor Yellow
    }

  ## Hide Invoke-WebRequest progress bar. There's a bug that doesn't clear the bar after a request is finished. 
  $ProgressPreference = "SilentlyContinue"
  
  $schedurl = 'https://endpointsummit2025.sched.com/'
  
  
    $SchedLoginURL = $schedurl + "login"
    Add-Type -AssemblyName System.Web
    ## Connect to Sched
    $creds = $host.UI.PromptForCredential('Sched Credentials', "Enter Credentials for the MEM Event", '', '')
    if ($creds) {
      #$form = $web.Forms[1]
      #$form.fields['username'] = $creds.UserName;
      #$form.fields['password'] = $creds.GetNetworkCredential().Password;
  
      $username = $creds.UserName
      $password = $creds.GetNetworkCredential().Password
  
      # Updated POST body
      $body = "landing_conf=" + [System.Uri]::EscapeDataString($schedurl) + "&username=" + [System.Uri]::EscapeDataString($username) + "&password=" + [System.Uri]::EscapeDataString($password) + "&login="
  
      # SEND IT
      $web = Invoke-WebRequest $SchedLoginURL -SessionVariable MEM -Method POST -Body $body
  
    }
    else {
      $web = Invoke-WebRequest $SchedLoginURL -SessionVariable MEM
    }
  
    $schedname = $web.links.outertext | select-object -first 1
    
    $baseLocation = "$env:temp\Conferences\$schedname"
    ##Create if it doesn't exist
    if((Test-Path -Path $($baseLocation)) -eq $false) { New-Item -ItemType Directory -Force -Path $baseLocation | Out-Null }
    Write-Output "Logging in to $schedurl"
  
    ## Check if we connected (if required):
    if (-Not ($web.InputFields.FindByName("login"))) {
      ##
      Write-Output "Downloaded content can be found in $baseLocation"
  
      $sched = Invoke-WebRequest -Uri $($schedurl + "list/descriptions") -WebSession $MEM
      $links = $sched.Links
  
      # For indexing available downloads later
      $eventsList = New-Object -TypeName System.Collections.Generic.List[int]
      $links | ForEach-Object -Process {
        if ($_.href -like "event/*") {
          [void]$eventsList.Add($links.IndexOf($_))
        }
      }
      $eventCount = $eventsList.Count
  
      for ($i = 0; $i -lt $eventCount; $i++) {
        [int]$linkIndex = $eventsList[$i]
        [int]$nextLinkIndex = $eventsList[$i + 1]
        $eventobj = $links[($eventsList[$i])]
  
        # Get/Fix the Session Title:
        $titleRegex = '<a.*?href="(?<url>.*?)".*?>(?<title>.*?)<\/a>'
        $titleMatches = [regex]::Matches($eventobj.outerHTML.Replace("`r", "").Replace("`n", ""), $titleRegex, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        [string]$eventTitle = $titleMatches.Groups[0].Groups['title'].Value.Trim()
        [string]$eventUrl = $titleMatches.Groups[0].Groups['url'].Value.Trim()
  
        # Generate session info string
        [string]$sessionInfoText = ""
        $sessionInfoText += "Session Title: `r`n$eventTitle`r`n`r`n"
        $downloadTitle = $eventTitle -replace "[^A-Za-z0-9-_. ]", ""
        $downloadTitle = $downloadTitle.Trim()
        $downloadTitle = $downloadTitle -replace "\W+", "_"
  
        ## Set the download destination:
        $downloadPath = $baseLocation + "\" + $downloadTitle
  
          $sessionLinkInfo = (Invoke-WebRequest -Uri $($schedurl + $eventUrl) -WebSession $MEM).Content.Replace("`r", "").Replace("`n", "")
  
          $descriptionPattern = '<div class="tip-description">(?<description>.*?)<hr style="clear:both"'
          $description = [regex]::Matches($sessionLinkInfo, $descriptionPattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
          if ($description.Count -gt 0) { $sessionInfoText += "$(Invoke-BasicHTMLParser -html $description.Groups[0].Groups['description'].Value)`r`n`r`n" }
  
          $rolesPattern = "<div class=`"tip-roles`">(?<roles>.*?)<br class='s-clr'"
          $roles = [regex]::Matches($sessionLinkInfo, $rolesPattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
          if ($roles.Count -gt 0) { $sessionInfoText += "$(Invoke-BasicHTMLParser -html $roles.Groups[0].Groups['roles'].Value)`r`n`r`n" }
  
          if ((Test-Path -Path $($downloadPath)) -eq $false) { New-Item -ItemType Directory -Force -Path $downloadPath | Out-Null }
          Out-File -FilePath "$downloadPath\Session Info.txt" -InputObject $sessionInfoText -Force -Encoding default
        
  
        $downloads = $links[($linkIndex + 1)..($nextLinkIndex - 1)] | Where-Object { $_.href -like "*hosted_files*" } #prefilter
        foreach ($download in $downloads) {
          $filename = Split-Path $download.href -Leaf
          # Replace HTTP Encoding Characters (e.g. %20) with the proper equivalent.
          $filename = [System.Web.HttpUtility]::UrlDecode($filename)
          # Replace non-standard characters
          $filename = $filename -replace "[^A-Za-z0-9\.\-_ ]", ""
  
          $outputFilePath = $downloadPath + '\' + $filename
  
          # Reduce Total Path to 255 characters.
          $outputFilePathLen = $outputFilePath.Length
          if ($outputFilePathLen -ge 255) {
            $fileExt = [System.IO.Path]::GetExtension($outputFilePath)
            $newFileName = $outputFilePath.Substring(0, $($outputFilePathLen - $fileExt.Length))
            $newFileName = $newFileName.Substring(0, $(255 - $fileExt.Length)).trim()
            $newFileName = "$newFileName$fileExt"
            $outputFilePath = $newFileName
          }
  
          # Download the file
          if ((Test-Path -Path $($downloadPath)) -eq $false) { New-Item -ItemType Directory -Force -Path $downloadPath | Out-Null }
          if ((Test-Path -Path $outputFilePath) -eq $false) {
            Write-host -ForegroundColor Green "...attempting to download '$filename' because it doesn't exist"
            try {
              Invoke-WebRequest -Uri $download.href -OutFile $outputfilepath -WebSession $MEM
              if ($win) { Unblock-File $outputFilePath }
            }
            catch {
              Write-Output ".................$($PSItem.Exception) for '$($download.href)'...moving to next file..."
            }
          }
          else {
              Write-Output "...attempting to download '$filename'"
              $oldHash = (Get-FileHash $outputFilePath).Hash
              try {
                Invoke-WebRequest -Uri $download.href -OutFile "$($outputfilepath).new" -WebSession $MEM
                if ($win) { Unblock-File "$($outputfilepath).new" }
                $NewHash = (Get-FileHash "$($outputfilepath).new").Hash
                if ($NewHash -ne $oldHash) {
                  Write-Host -ForegroundColor Green " => HASH is different. Keeping new file"
                  Move-Item "$($outputfilepath).new" $outputfilepath -Force
                }
                else {
                  Write-Output " => Hash is the same. "
                  Remove-item "$($outputfilepath).new" -Force
                }
              }
              catch {
                Write-Output ".................$($PSItem.Exception) for '$($download.href)'...moving to next file..."
            }
          }
        } # end procesing downloads
      } # end processing session
      Write-Host "Downloads completed and stored in: $baseLocation" -ForegroundColor Cyan
    } # end connectivity/login check
    else {
      Write-Output "Login to $schedurl failed."
    }
  
  
