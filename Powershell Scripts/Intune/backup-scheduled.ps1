<#
.SYNOPSIS
  Runs a backup script on user login
.DESCRIPTION
Backs up all key user data to Onedrive

.INPUTS
None required
.OUTPUTS
Within Azure
.NOTES
  Version:        1.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  21/08/2021
  Purpose/Change: Initial script development
  
.EXAMPLE
N/A
#>

#Create path for files
$DirectoryToCreate = "c:\backup-restore"
if (-not (Test-Path -LiteralPath $DirectoryToCreate)) {
    
    try {
        New-Item -Path $DirectoryToCreate -ItemType Directory -ErrorAction Stop | Out-Null #-Force
    }
    catch {
        Write-Error -Message "Unable to create directory '$DirectoryToCreate'. Error was: $_" -ErrorAction Stop
    }
    "Successfully created directory '$DirectoryToCreate'."

}
else {
    "Directory already existed"
}

##Download Backup Script
$backupurl="https://raw.githubusercontent.com/andrew-s-taylor/public/main/Batch%20Scripts/backup.bat"
$backupscript = "c:\backup-restore\backup.bat"
Invoke-WebRequest -Uri $backupurl -OutFile $backupscript -UseBasicParsing

##Download Restore Script
$restoreurl="https://raw.githubusercontent.com/andrew-s-taylor/public/main/Batch%20Scripts/NEWrestore.bat"
$restorescript = "c:\backup-restore\restore.bat"
Invoke-WebRequest -Uri $restoreurl -OutFile $restorescript -UseBasicParsing

##Create scheduled task
# Create a new task action
$taskAction = New-ScheduledTaskAction -Execute 'c:\backup-restore\backup.bat' 

##Create Trigger (login)
$taskTrigger = New-ScheduledTaskTrigger -AtLogOn

# Register the new PowerShell scheduled task

#Name it
$taskName = "UserBackup"

#Describe it
$description = "Backs up User profile to OneDrive"

# Register it
Register-ScheduledTask `
    -TaskName $taskName `
    -Action $taskAction `
    -Trigger $taskTrigger `
    -Description $description