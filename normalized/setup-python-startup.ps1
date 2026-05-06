# ============================================
# ASK USER FOR PYTHON FILE
# ============================================

$PythonFile = Read-Host "Enter full path of your Python file (e.g. C:\scripts\app.py)"

if (!(Test-Path $PythonFile)) {
    Write-Host "File not found. Exiting..."
    exit
}

# ============================================
# FIND PYTHON EXECUTABLE
# ============================================

$PythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source

if (!$PythonExe) {
    Write-Host "Python not found in PATH. Enter full path to python.exe"
    $PythonExe = Read-Host "Python path (e.g. C:\Python310\python.exe)"
    
    if (!(Test-Path $PythonExe)) {
        Write-Host "Invalid Python path. Exiting..."
        exit
    }
}

# ============================================
# TASK CONFIG
# ============================================

$TaskName = "PythonStartupTask"

# Run python script silently
$Action = New-ScheduledTaskAction `
    -Execute $PythonExe `
    -Argument "`"$PythonFile`""

# Trigger at system startup
$Trigger = New-ScheduledTaskTrigger -AtStartup

# Run as SYSTEM (runs even before login)
$Principal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel Highest

# Settings
$Settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries

# ============================================
# CREATE TASK
# ============================================

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $Action `
    -Trigger $Trigger `
    -Principal $Principal `
    -Settings $Settings `
    -Force

Write-Host "SUCCESS: Python script will now run at every startup!"