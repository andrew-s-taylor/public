<#
.SYNOPSIS
  Adds App-V Package to multiple servers

.DESCRIPTION
  Adds App-V package to multiple machines in an OU looking for a particular naming convention.  Useful for RDS etc.

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
add-appvpackage.ps1 -OU "YourOU" -Namingconvention "Names*" -packagepath "\\path"
#>

param (
    [Parameter(Mandatory=$true)] 
    [String]  $OU = '',
    
    [Parameter(Mandatory=$true)] 
    [String]  $NamingConvention = '',

    [Parameter(Mandatory=$true)]
    [String] $packagepath = ''
)

$servers = Get-ADComputer -SearchBase $OU -Filter * | Where-Object Name -like $NamingConvention | select Name
foreach ($server in $servers) {
Invoke-Command -ComputerName $server.name -ScriptBlock {add-appvclientpackage $packagepath | publish-appvclientpackage -global}
}