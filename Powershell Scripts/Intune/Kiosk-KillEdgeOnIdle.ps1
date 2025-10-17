$TaskName = "KillEdgeOnIdle"

$service = New-Object -ComObject("Schedule.Service")
$service.Connect()
$rootFolder = $service.GetFolder("")

$taskdef = $service.NewTask(0)

# Creating task settings with idle detection for 30 minutes
$sets = $taskdef.Settings
$sets.AllowDemandStart = $true
$sets.Compatibility = 2
$sets.Enabled = $true
$sets.RunOnlyIfIdle = $true
$sets.IdleSettings.IdleDuration = "PT30M"
$sets.IdleSettings.WaitTimeout = "PT1M"
$sets.IdleSettings.StopOnIdleEnd = $false

# Creating a reoccurring daily trigger that checks every 5 minutes
$trg = $taskdef.Triggers.Create(2)
$trg.StartBoundary = ([datetime]::Now).ToString("yyyy-MM-dd'T'HH:mm:ss")
$trg.Enabled = $true
$trg.DaysInterval = 1
$trg.Repetition.Duration = "P1D"
$trg.Repetition.Interval = "PT5M"
$trg.Repetition.StopAtDurationEnd = $true

# The command to kill Edge processes
$act = $taskdef.Actions.Create(0)
$act.Path = "powershell.exe"
$act.Arguments = "-WindowStyle Hidden -Command `"Get-Process -Name msedge -ErrorAction SilentlyContinue | Stop-Process -Force`""

# Register the task under the current Windows user
$user = [environment]::UserDomainName + "\" + [environment]::UserName
$rootFolder.RegisterTaskDefinition($TaskName, $taskdef, 6, $user, $null, 3)