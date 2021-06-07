<#
.SYNOPSIS
  Removes a PC

.DESCRIPTION
 Removes a PC from AD only


.INPUTS
PC Name (prompted)
AD credentials (prompted)

.OUTPUTS
Confirmation

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

if (Get-Module -ListAvailable -Name MSOnline) {
    Write-Host "Module exists"
} 
else {
    Write-Host "Module does not exist Installing"
    Install-Module MSOnline -Force
}

if (Get-Module -ListAvailable -Name WindowsAutoPilotIntune) {
    Write-Host "Module exists"
} 
else {
    Write-Host "Module does not exist Installing"
    Install-Module MSOnline -Force
}

if (Get-Module -ListAvailable -Name AzureAD) {
    Write-Host "Module exists"
} 
else {
    Write-Host "Module does not exist Installing"
    Install-Module MSOnline -Force
}
 
 
# Import Module 
 
Import-Module ActiveDirectory 
Import-Module MSOnline
Import-Module WindowsAutoPilotIntune
Import-Module AzureAD
 
# Variables 
$computer = Read-Host -Prompt ("What is the computer name?")
$localdc = Read-Host -Prompt ("What is the DC name?")
    $credentials = Get-Credential   # This should be Admin Credentials 
 
# AD      
    $ADResult = (Get-ADComputer -Filter {cn -like $computer}  -Server "$localdc" -Credential $credentials  ).name -eq $computer  
    $dclist = (Get-ADDomain -Server "$localdc" -Credential $credentials).ReplicaDirectoryServers     
     
    $arrDc = @() 
    foreach ($obj in $dclist) { 
    $nlist = $obj.Replace("`.XYZ.com","")  # Replace XYZ.com with your Domain Name 
    $arrDc += $nlist 
    } 
     
# If you want to remove it from AD remove -wahtif and un-commnted -confirm:$false     
     
    if ($ADResult -eq $true) { 
     
    Write-Host -ForegroundColor  Red "$computer exists in AD, I am going to remove it" 
     
    foreach ( $dc in $arrdc) { 
        Remove-ADComputer -Identity "$computer"  -Server $dc  -Credential $credentials  -confirm:$false 
        write-host $([char]7) 
        write-Host "$computer is deleted on $dc " -ForegroundColor Green 
        }     
        } 
                 