<#
.SYNOPSIS
  Adds registry keys to enable WinRM

.DESCRIPTION
  Enabled Windows Remoting 
Device Context 32-bit

.INPUTS
None required

.OUTPUTS
Logged by Intune

.NOTES
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

Enable-PSRemoting -SkipNetworkProfileCheck -Force