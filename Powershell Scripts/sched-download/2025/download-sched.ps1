##############################################
#                                            #
# File:     CopyMEM2018Files.ps1             #
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


$schedurl = 'https://endpointsummit2025.sched.com/'

Add-Type -AssemblyName System.Web
$web = Invoke-WebRequest "$schedurl/login" -SessionVariable MEM
$c = $host.UI.PromptForCredential('Sched Credentials', 'Enter Credentials', '', '')
$form = $web.Forms[0]
$form.fields['username'] = $c.UserName
$form.fields['password'] = $c.GetNetworkCredential().Password
"Logging in..."

$MEMHome = Invoke-WebRequest "$schedurl" -WebSession $MEM

$htmlDate = $MEMHome.ParsedHtml.IHTMLDocument3_GetElementById('sched-sidebar-filters-dates')
$htmlPopoverBody = $htmlDate.outerText -split "\r\n" 
##Ignore first 2 elements in the array, as they are not dates
$htmlPopoverBody = $htmlPopoverBody[2..$($htmlPopoverBody.Count - 1)]
$htmlPopoverBody = $htmlPopoverBody | ForEach-Object {
    $date = $_ -replace ".*, ", ""
    $year = $schedurl.Substring(0, $schedurl.Length - 11).Substring($schedurl.Length - 15, 4)
    $dateWithYear = "$date $year"
    $parsedDate = Get-Date $dateWithYear -Format "ddMMyyyy"
    $parsedDate
}
$schedname = $MEMHome.links.outertext | select-object -first 1

$baseLocation = "C:\Temp\Conferences\$schedname"
##Create if it doesn't exist
if((Test-Path -Path $($baseLocation)) -eq $false) { New-Item -ItemType Directory -Force -Path $baseLocation | Out-Null }

$web = Invoke-WebRequest "$schedurl/login" -WebSession $MEM -Method POST -Body $form.Fields
if(-Not ($web.InputFields.FindByName("login"))) {
    ForEach ($Date in $htmlPopoverBody) {
        "Checking day '{0}' for downloads" -f $Date
        $dateurl = "$schedurl$Date/list/descriptions"
        $sched = Invoke-WebRequest -Uri $dateurl -WebSession $MEM
        $links = $sched.Links

        $eventsIndex = @()
        $links | ForEach-Object { if(($_.href -like "*event/*") -and ($_.innerText -notlike "here")) { 
            $eventsIndex += (, ($links.IndexOf($_), $_.innerText))
        } }

        $i = 0
        While($i -lt $eventsIndex.Count) {
            $eventTitle = $eventsIndex[$i][1]
            $eventTitle = $eventTitle -replace "[^A-Za-z0-9-_. ]", ""
            $eventTitle = $eventTitle.Trim()
            $eventTitle = $eventTitle -replace "\W+", "_"

            $links[$eventsIndex[$i][0]..$(if($i -eq $eventsIndex.Count - 1) {$links.Count-1} else {$eventsIndex[$i+1][0]})] | ForEach-Object { 
                if($_.href -like "*hosted_files*") { 
                    $downloadPath = $baseLocation + "\$schedname\" + $Date + '\' + $eventTitle
                    $filename = $_.href
                    $filename = $filename.substring(40)
                    
                    # Replace HTTP Encoding Characters (e.g. %20) with the proper equivalent.
                    $filename = [System.Web.HttpUtility]::UrlDecode($filename)
                    
                    # Replace non-standard characters
                    $filename = $filename -replace "[^A-Za-z0-9\.\-_ ]", ""
                                        
                    $outputFilePath = $downloadPath + '\' + $filename

                    # Reduce Total Path to 255 characters.
                    $outputFilePathLen = $outputFilePath.Length

                    If($outputFilePathLen -ge 255) { 
                        $fileExt = [System.IO.Path]::GetExtension($outputFilePath)
                        $newFileName = $outputFilePath.Substring(0,$($outputFilePathLen - $fileExt.Length))
                        $newFileName = $newFileName.Substring(0, $(255 - $fileExt.Length)).trim()
                        $newFileName = "$newFileName$fileExt"
                        $outputFilePath = $newFileName
                    }

                    if((Test-Path -Path $($downloadPath)) -eq $false) { New-Item -ItemType Directory -Force -Path $downloadPath | Out-Null }
                    if((Test-Path -Path $outputFilePath) -eq $false)
                    {
                        "...attempting to download '{0}'" -f $filename
                        Invoke-WebRequest -Uri $_.href -OutFile $outputfilepath -WebSession $MEM
                        Unblock-File $outputFilePath
                    }
                } 
            }

            $i++
        }
    }
} else {
    "Login failed. Exiting script."
}
