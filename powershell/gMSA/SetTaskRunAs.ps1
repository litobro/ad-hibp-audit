$taskName = "TASK NAME"
$user = Get-ADServiceAccount -Identity "SERVICE_ACC_NAME"

$newPrincipal = New-ScheduledTaskPrincipal -UserId $user.SamAccountName -RunLevel Highest -LogonType Password

Set-ScheduledTask $taskName -Principal $newPrincipal