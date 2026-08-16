# Register the logon-monitor task for the decoy account
#
# Creates a scheduled task that runs `duress_guard.py on-login` whenever the decoy
# account logs in through the OFFICIAL Windows login screen. Logging into the decoy
# account IS the duress event: the machine looks like a normal successful login, and
# this task silently performs the configured duress actions (encrypt folders, arm
# pre-boot partition wipes, alert).
#
# Usage (admin PowerShell):
#   .\register_logon_task.ps1 -DecoyUser "decoy" `
#       -PythonExe "C:\Python312\python.exe" `
#       -ScriptDir "D:\DuressGuard" `
#       -StorageDir "D:\MyStuff\.config"
#
# Requirements:
#   - The decoy account must already exist (it can be a standard, non-admin user).
#   - The encryption passphrase must be set in the decoy account's environment as
#     DURESS_KEY (or the encryption action will be skipped - see PAPER.md).
param(
    [Parameter(Mandatory = $true)][string]$DecoyUser,
    [Parameter(Mandatory = $true)][string]$PythonExe,
    [Parameter(Mandatory = $true)][string]$ScriptDir,
    [Parameter(Mandatory = $true)][string]$StorageDir
)

$argument = "duress_guard.py on-login --storage-dir `"$StorageDir`" --expected-user `"$DecoyUser`""
$action = New-ScheduledTaskAction -Execute $PythonExe `
    -Argument $argument `
    -WorkingDirectory $ScriptDir
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $DecoyUser
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

Register-ScheduledTask -TaskName "DuressGuardLogonMonitor" `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Description "Runs Duress-Guard duress actions when the decoy account logs in" `
    -Force

Write-Output "Logon monitor registered for user '$DecoyUser'."
Write-Output "Verify with:  Get-ScheduledTask -TaskName DuressGuardLogonMonitor"
