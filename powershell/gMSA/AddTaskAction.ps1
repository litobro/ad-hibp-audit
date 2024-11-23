$taskName = "TASK NAME"
$task = Get-ScheduledTask -TaskName $taskName

$task.Actions

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "ARGS"

$existingActions = $task.Actions
$allActions = @($existingActions + $action)

Set-ScheduledTask -TaskName $taskName -Action $allActions