<#
.SYNOPSIS
  Gets Users Mapped Drives

.DESCRIPTION
 Gets mapped drives for logged in user on all remote machines in OU and saves as csv


.INPUTS
OU, outputfile and offlinemachines (file)

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
get-drives.ps1 -OU "OU" -outputfile "c:\temp\drives.csv" -offlinemachines "c:\temp\offline.txt"
#>


param (
    [Parameter(Mandatory=$true)] 
    [String]  $OU = '',
    
    [Parameter(Mandatory=$true)] 
    [String]  $outputfile = '',

    [Parameter(Mandatory=$true)]
    [String] $offlinemachines = ''
)

Import-Module ActiveDirectory
function Get-MappedDrives($ComputerName){
  $Report = @() 
  #Ping remote machine, continue if available
  if(Test-Connection -ComputerName $ComputerName -Count 1 -Quiet){
    #Get remote explorer session to identify current user
    $explorer = Get-WmiObject -ComputerName $ComputerName -Class win32_process | ?{$_.name -eq "explorer.exe"}
    
    #If a session was returned check HKEY_USERS for Network drives under their SID
    if($explorer){
      $Hive = [long]$HIVE_HKU = 2147483651
      $sid = ($explorer.GetOwnerSid()).sid
      $owner  = $explorer.GetOwner()
      $RegProv = get-WmiObject -List -Namespace "root\default" -ComputerName $ComputerName | Where-Object {$_.Name -eq "StdRegProv"}
      $DriveList = $RegProv.EnumKey($Hive, "$($sid)\Network")
      
      #If the SID network has mapped drives iterate and report on said drives
      if($DriveList.sNames.count -gt 0){
        $Person = "$($owner.Domain)\$($owner.user)"
        foreach($drive in $DriveList.sNames){
	  $hash = [ordered]@{
	    ComputerName	= $ComputerName
	    User		= $Person
	    Drive		= $drive
	    Share		= "$(($RegProv.GetStringValue($Hive, "$($sid)\Network\$($drive)", "RemotePath")).sValue)"
	  }
	    # Add the hash to a new object
	  $objDriveInfo = new-object PSObject -Property $hash
	    # Store our new object within the report array
	  $Report += $objDriveInfo
        }
      }else{
	  $hash = [ordered]@{
	    ComputerName	= $ComputerName
	    User		= $Person
	    Drive		= ""
	    Share		= "No mapped drives"
	  }
	  $objDriveInfo = new-object PSObject -Property $hash
	  $Report += $objDriveInfo
      }
    }else{
	$hash = [ordered]@{
	  ComputerName	= $ComputerName
	  User		= "Nobody"
	  Drive		= ""
	  Share		= "explorer not running"
	}
	$objDriveInfo = new-object PSObject -Property $hash
	$Report += $objDriveInfo
      }
  }else{
      $hash = [ordered]@{
	ComputerName	= $ComputerName
	User		= "Nobody"
	Drive		= ""
	Share		= "Cannot connect"
      }
      $objDriveInfo = new-object PSObject -Property $hash
      $Report += $objDriveInfo
  }
  return $Report
}

$computers = Get-ADComputer -filter * -SearchBase $OU
foreach ($computer2 in $computers) {
$pcname = $computer2.Name
write-host $pcname
if (Test-Connection -Computername $pcname -BufferSize 16 -Count 1 -Quiet) {
    Get-MappedDrives($pcname) | Export-Csv $outputfile -Append
    Write-Host $pcname+"Online"
    }
    else {
    $pcname | add-content $offlinemachines
    }
}
