<#
.SYNOPSIS
  Adds device to SCCM collection

.DESCRIPTION
  Adds an existing device to an SCCM collection, ideal for rebuilds

.INPUTS
Params: OU, Name, Packagepath

.OUTPUTS
Logged by Intune

.NOTES
  Version:        1.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  13/01/2020
  Purpose/Change: Initial script development
  
.EXAMPLE
add-sccm.ps1 -sccmsrv = "Server" -hosts "PC-Name" -site "Sccm Site" -collName "Collection Name" -CollID "Collection ID"
#>


param (   
    [Parameter(Mandatory=$True)]
    [string] $hosts = "",  
    [switch] $addcomputer = $false,  
    [switch] $removecomputer = $false,  
    [string] $sccmsrv = "",  
    [string] $site = "",  
    [string] $collName = "",  
    [string] $collID = "",  
    [string] $log = "")  
   
   
 #### Function for adding a computer to an SCCM collection  
 function addComputerToCollection ([string]$collectionID, [string]$SccmServer, $fsccmSQLServer, [string]$site, [string]$srv){  
    $found = $false  
 
    # checking if the direct membership for the computer exist or not  
    foreach($member in $global:mc.CollectionRules){  
       if($member.RuleName -ieq $srv){  
          $found = $true  
          break  
       }  
    }  
   
    if($found){  
       $retVal = "host has already got direct membership"  
    }  
    else{  
   
       # getting resource ID of the computer  
       $queryResult = execSQLQuery $fsccmSQLServer "SMS_$site" "select ResourceID from v_R_System where name0 = '$srv'"  
       $computerResID = $queryResult.ResourceID  
          
       if($computerResID){  
   
       # creating DirectRule  
          $objColRuledirect = [WmiClass]"\\$SccmServer\ROOT\SMS\site_$($site):SMS_CollectionRuleDirect"  
          $objColRuleDirect.psbase.properties["ResourceClassName"].value = "SMS_R_System"  
          $objColRuleDirect.psbase.properties["ResourceID"].value = $computerResID  
   
          #target collection  
          $InParams = $global:mc.psbase.GetMethodParameters('AddMembershipRule')  
          $InParams.collectionRule = $objColRuleDirect  
          $R = $global:mc.PSBase.InvokeMethod('AddMembershipRule', $inParams, $Null)  
   
          if($r.ReturnValue -eq 0){$retVal = "OK" }  
          else   {$retVal = "Err"}  
       }  
       else{  
       $retVal = "Computer is not in SCCM DB"  
       }  
    }  
    return $retVal  
 }  
   
   
 #### Function for a computer from an SCCM collection  
 function removeComputerFromCollection ([string]$collectionID, [string]$srv){  
    $found = $false  
   
    foreach($member in $global:mc.CollectionRules){  
       if($member.RuleName -ieq $srv){  
          $res = $global:mc.deletemembershiprule($member)  
          $found = $true  
          break  
       }  
    }  
    if($res.ReturnValue -eq 0){$retVal = "OK" }  
    else   {$retVal = "Err"}  
   
    if(!$found){$retVal = "No direct membership of $srv in collection $collectionID"}  
    return $retVal  
 }  
   
   
   
 #### Function for enumerating ID of an SCCM collection  
 function lookupCollID ([string]$fsccmSQLServer, [string]$site, [string] $collectionName){  
    $queryResult = execSQLQuery $fsccmSQLServer "SMS_$site" "select CollectionID from v_Collection where name like '$collectionName'"  
    $fcount = ($queryResult | Group-Object -Property CollectionID).count  
   
    if($fcount -eq 1){  
       $fcollectionID = $queryResult.CollectionID  
   
       if(!$fcollectionID){  
          exit  
       }  
       else{  
          return $fcollectionID  
       }  
    }  
    elseif($fcount -gt 1){  
       exit  
    }  
    else{  
       exit  
    }  
 }  
   
   
   
 #### Function for executing a SQL query with integrated authentication    
 function execSQLQuery ([string]$fSQLServer, [string]$db, [string]$query){    
    $objConnection = New-Object System.Data.SqlClient.SqlConnection    
    $objConnection.ConnectionString = "Server = $fSQLServer; Database = $db; trusted_connection=true;"    
    $SqlCmd = New-Object System.Data.SqlClient.SqlCommand $query, $objConnection    
    trap {Write-Host -ForegroundColor 'red' "($sqlsrv/$db not accessible)";continue}    
    $SqlCmd.Connection.Open()    
   
    if ($SqlCmd.Connection.State -ine 'Open') {    
       $SqlCmd.Connection.Close()    
       return    
    }    
    $dr = $SqlCmd.ExecuteReader()    
   
    #get the data    
    $dt = new-object "System.Data.DataTable"    
    $dt.Load($dr)    
    $SqlCmd.Connection.Close()    
    $dr.Close()    
    $dr.Dispose()    
    $objConnection.Close()    
    return $dt    
 }    
   
   
 Function Get-ScriptVersion(){
    
   <#
   .SYNOPSIS
   This function is used to check if the running script is the latest version
   .DESCRIPTION
   This function checks GitHub and compares the 'live' version with the one running
   .EXAMPLE
   Get-ScriptVersion
   Returns a warning and URL if outdated
   .NOTES
   NAME: Get-ScriptVersion
   #>
   
   [cmdletbinding()]
   
   param
   (
       $liveuri
   )
$contentheaderraw = (Invoke-WebRequest -Uri $liveuri -Method Get)
$contentheader = $contentheaderraw.Content.Split([Environment]::NewLine)
$liveversion = (($contentheader | Select-String 'Version:') -replace '[^0-9.]','') | Select-Object -First 1
$currentversion = ((Get-Content -Path $PSCommandPath | Select-String -Pattern "Version: *") -replace '[^0-9.]','') | Select-Object -First 1
if ($liveversion -ne $currentversion) {
write-warning "Script has been updated, please download the latest version from $liveuri"
}
}
Get-ScriptVersion -liveuri "https://raw.githubusercontent.com/andrew-s-taylor/public/main/Powershell%20Scripts/add-sccm.ps1"
   
 ##################################################### Body #####################################################  
   
 # if site is not specified, let's get it from the SCCM server itself  
 if(!$site){  
    $site = (gwmi -ComputerName $sccmsrv -Namespace root\sms -Class SMS_ProviderLocation).sitecode  
 }  
   
   
 #### Collate the host list.  
 $hostlist = @($Input)  
 if ($hosts) {  
    if($hosts -imatch " "){  
       $hostsArr = @($hosts.split(" "))  
       $hostlist += $hostsArr  
    }  
    else{  
       $hostlist += $hosts  
    }  
 }  
   
 # if -collName, we need to enumerate the collection ID  
 if(!$collID -and $collName){  
    $collID = lookupCollID $sccmsrv $site $collName  
 }  
   
 if($($hostlist.length) -gt 0){  
    $global:mc = ""  
    #Binding collection $collID  
    $global:mc = [wmi]"\\$sccmsrv\root\sms\site_$($site):SMS_Collection.CollectionID='$collID'"  
   
    if($global:mc){  
   
       $hostlistlength = $hostlist.length  
       $k = 1  
       $objColl = @()  
   
       foreach ($srv in $hostlist) {  
          $result = $result2 = ""  
   
          if($srv -ne ""){       # if the hostname is not empty  
             Write-Progress -activity "Performing checks" -Status "Processing host $k of $hostlistlength : $srv " -PercentComplete ($k/$hostlistlength * 100) -currentoperation "checking Client state..."  
   
             # if -addcomputer, then we need to add computers to collections (direct membership)  
             
                $sObject = new-Object -typename System.Object  
                $sObject | add-Member -memberType noteProperty -name Hostname -Value $srv  
   
                # adding host to collection $collName $collID  
                $result = addComputerToCollection $collID $sccmsrv $sccmsrv $site $srv  
   
                $sObject | add-Member -memberType noteProperty -name Result -Value $result  
                $objColl += $sObject  
              
   
             # if -removecomputer, then we need to remove computers from collections (direct membership)  
             if($removecomputer){  
                $sObject = new-Object -typename System.Object  
                $sObject | add-Member -memberType noteProperty -name Hostname -Value $srv  
   
                # removing host from collection $collName $collID  
                $result = removeComputerFromCollection $collID $srv  
   
                $sObject | add-Member -memberType noteProperty -name Result -Value $result  
                $objColl += $sObject  
             }  
          }  
          $k++  
       }  
    }  
    else{  
    "Could not bind collection"  
    }  
 }  
 else{  
    "No hostname or hostlist is specified."  
 }  
   
 $objColl  