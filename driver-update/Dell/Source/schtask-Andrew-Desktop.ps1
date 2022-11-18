<#
.SYNOPSIS
  Updates drivers
.DESCRIPTION
Configures a scheduled task to update drivers on a machine
.INPUTS
None required
.OUTPUTS
N/A
.NOTES
  Version:        1.1
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  11/06/2021
  Purpose/Change: Initial script development
  Change: Fixes applied, thanks to Colton Chladek in the blog comments
  
.EXAMPLE
N/A
#>

#Configure Scheduled Task for driver updates

#Set the action
$action = New-ScheduledTaskAction -Execute “C:\Program Files\Dell\CommandUpdate\dcu-cli.exe” -Argument “/applyUpdates -silent -reboot=disable -outputlog=c:\driversupd\log.log”

#Set a trigger
$trigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval 2 -DaysOfWeek Friday -At 1pm 

#Set to run as system
$principal= New-ScheduledTaskPrincipal -UserID “NT AUTHORITY\SYSTEM” -LogonType “ServiceAccount” -RunLevel “Highest”

#Set a Name
$taskname = "Intune Driver Updates"

#Set a Description
$taskdescription = "Weekly driver update Friday at 13:00"

#Require AC Power
$Settings = @{
    AllowStartIfOnBatteries = $false
    DontStopIfGoingOnBatteries = $false
}
$settings= New-ScheduledTaskSettingsSet @settings



#Register the Task
Register-ScheduledTask -TaskName $taskname -Trigger $trigger -Action $action -Principal $principal -Settings $settings -Description $taskdescription -Force