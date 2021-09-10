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
  Version:        1.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  11/06/2021
  Purpose/Change: Initial script development
  
.EXAMPLE
N/A
#>

#Configure Scheduled Task for driver updates

#Set the action
$action = New-ScheduledTaskAction -Execute 'c:\driversupd\runupdate.bat'

#Set a trigger
$trigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval 2 -DaysOfWeek Friday -At 1pm 

#Set a Name
$taskname = "Intune Driver Updates"

#Set a Description
$taskdescription = "Weekly driver update Friday at 13:00"

#Register the Task
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $taskname -Description $taskdescription