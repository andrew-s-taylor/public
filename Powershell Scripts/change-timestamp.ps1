<#
.SYNOPSIS
  Changes user timestamp and clears profiles

.DESCRIPTION
  #Purpose: Used to set the ntuser.dat last modified date to that of the last modified date on the user profile folder.
#This is needed because windows cumulative updates are altering the ntuser.dat last modified date which then defeats
#the ability for GPO to delete profiles based on date and USMT migrations based on date.

.INPUTS
Params: days to delete

.OUTPUTS


.NOTES
  Version:        1.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  13/01/2020
  Purpose/Change: Initial script development
  
.EXAMPLE
change-timestamp.ps1 -days "25"
#>




param (
    [Parameter(Mandatory=$true)]
    [String] $days = ''
)
##########################################
###########  Change Me          ##########
##########################################
$command = '\\path-to-delprof2.exe'
##########################################
$ErrorActionPreference = "SilentlyContinue"
$Report = $Null
$Path = "C:\Users"
$UserFolders = $Path | GCI -Directory
ForEach ($UserFolder in $UserFolders)
{
$UserName = $UserFolder.Name
If (Test-Path "$Path\$UserName\NTUSer.dat")
    {
    $Dat = Get-Item "$Path\$UserName\NTUSer.dat" -force 
    $DatTime = $Dat.LastWriteTime
    If ($UserFolder.Name -ne "default"){
        $Dat.LastWriteTime = $UserFolder.LastWriteTime
    }
    Write-Host $UserName $DatTime
    Write-Host (Get-item $Path\$UserName -Force).LastWriteTime
    $Report = $Report + "$UserName`t$DatTime`r`n" 
    $Dat = $Null
    }
}

#Now clear old profiles

$params = '/d:25 /q /i'
$Prms = $params.Split(" ")
& "$command" $Prms
