<#
.SYNOPSIS
  Exports Chrome bookmarks to Edge/IE

.DESCRIPTION
 Exports chrome bookmarks to json in temp directory and then imports into Edge and IE


.INPUTS
None

.OUTPUTS
Verbose output

.NOTES
  Version:        1.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  13/01/2020
  Purpose/Change: Initial script development
  
.EXAMPLE
N/A
#>

#-----------------------------------------------------------[Execution]------------------------------------------------------------

#Path to chrome bookmarks
$pathToJsonFile = "$env:localappdata\Google\Chrome\User Data\Default\Bookmarks"

#Helper vars
$temp = "$env:TEMP\google-bookmarks.json"
$timestamp = Get-Date -Format yyyymmmdd_hhmmss

$global:bookmarks = @()

#A nested function to enumerate bookmark folders
Function Get-BookmarkFolder {
[cmdletbinding()]
Param(
[Parameter(Position=0,ValueFromPipeline=$True)]
$Node
)

Process 
{

 foreach ($child in $node.children) 
 {
   #get parent folder name
   $parent = $node.Name
   $folder = If (!$node.Folder) {""} Else {$node.Folder}
   $folder = $folder + $parent + "/" 
   $child | Add-Member @{Folder= $folder}
   if ($child.type -eq 'Folder') 
   {
     # Write-Verbose "Processing $($child.Name)"
     Get-BookmarkFolder $child
   }
   else 
   {
        $hash= [ordered]@{
          Folder = $parent
          Name = $child.name
          URL = $child.url
          Path = $child.folder.substring(0,$child.folder.Length-1)
          Added = "{0:yyyyMMddHHmmssfff}" -f [datetime]::FromFileTime(([double]$child.Date_Added)*10)
        }
        #add ascustom object to collection
        $global:bookmarks += New-Object -TypeName PSobject -Property $hash
  } #else url
 } #foreach
 } #process
} #end function

$data = Get-content $pathToJsonFile -Encoding UTF8 | out-string | ConvertFrom-Json

#process top level "folders"
$data.roots.bookmark_bar | Get-BookmarkFolder
$data.roots.other | Get-BookmarkFolder
$data.roots.synced | Get-BookmarkFolder

#create a new JSON file
$empty | Set-Content $temp -Force
'{
"bookmarks":' | Add-Content $temp

#these should be the top level "folders"
$global:bookmarks | ConvertTo-Json | Add-Content $temp

'}' | Add-Content $temp

Write-Verbose $temp
$Content = @()
$Content += '<!DOCTYPE NETSCAPE-Bookmark-file-1>
<!-- This is an automatically generated file.
     It will be read and overwritten.
     DO NOT EDIT! -->
<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">
<TITLE>Bookmarks</TITLE>
<H1>Bookmarks</H1>
<DL><p>
    <DT><H3 ITEM_ID="{A62AF571-6A95-4BA2-8EDD-92A8BB9743F3}" LAST_MODIFIED="1574154228" >Favorites Bar</H3>
    <DL><p>
    </DL><p>'
$bookmarks = Get-Content $temp -Raw |
ConvertFrom-Json |
select -ExpandProperty bookmarks
#Export-CSV c:\share\ChromeBookmarks_$timestamp.csv -NoTypeInformation

foreach ($bookie in $bookmarks) {
$content += "<DT><A HREF="""+$bookie.URL+'"'+' LAST_MODIFIED="1574154228" >'+$bookie.Name+"</A>"
## MicrosoftEdge favorit path
[STRING]$EdgePath = $($env:LOCALAPPDATA + "\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\MicrosoftEdge\User\Default\Favorites")

 [STRING]$IEPath = $env:Favorites
## Favorder Registry path
#Copy to Edge Folder
$Name = $bookie.Name
$Shell = New-Object -ComObject WScript.Shell
$FullPath = Join-Path -Path $EdgePath -ChildPath "$($Name).url"
$URL = $bookie.URL
$shortcut = $Shell.CreateShortcut($FullPath)
$shortcut.TargetPath = $Url
$shortcut.Save()

#Copy to IE folder
$Shell2 = New-Object -ComObject WScript.Shell
$FullPath2 = Join-Path -Path $IEPath -ChildPath "$($Name).url"
$shortcut2 = $Shell.CreateShortcut($FullPath2)
$shortcut2.TargetPath = $Url
$shortcut2.Save()
}
$content += "</DL><p>"
$content | out-file -Encoding "UTF8" c:\temp\bookmarks.html
[string]$FavOrder = "HKCR:\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FavOrder"
        ## Get HKEY_CLASSES_ROOT
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
 
        ## verify if registry key FavOrder is valid
        IF(Test-Path -Path $FavOrder)
            {
                # Delete Registry Item FavOrder   
                Remove-Item -Path $FavOrder -Recurse
            }
 
        ## Remove PSdrive
        Remove-PSDrive -Name HKCR

 
Remove-Item $temp