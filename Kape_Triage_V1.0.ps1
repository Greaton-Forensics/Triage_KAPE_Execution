<#
#################################################################################################
# Script Name:     Scheduled Task for KAPE Execution
# Author:          Greaton Forensics 
# Email:           Admin@greaton.co.uk
# Version:         1.0
# Description:     This script automates the execution of the SANS Triage process using KAPE 
#                  (Kroll Artifact Parser and Extractor). It validates the paths, creates a 
#                  scheduled task, and executes KAPE with pre-defined arguments to capture a 
#                  forensic triage image. The task runs with SYSTEM privileges and starts 
#                  immediately after registration for a stealthy and efficient operation.
# Usage:           Run this script with Administrator privileges.
#################################################################################################
# Pre-requisites:
# - Administrator Privileges
# - PowerShell 5.1 or later
# - KAPE tools present in the specified folder structure
#################################################################################################
# DISCLAIMER:
# This script is provided "as-is" without warranty of any kind. Use it at your own risk.
#################################################################################################
#>


# ---------- Helper Functions ----------
function Get-UsbRoot {
    if ($PSScriptRoot) {
        return (Split-Path $PSScriptRoot -Qualifier)
    }
    # Fallback for compiled EXE
    $exePath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    return (Split-Path $exePath -Qualifier)
}

function Ensure-Admin {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Error "This script must be run as Administrator."
        exit 1
    }
}

function Find-KapeOnUSB {
    param([string]$UsbRoot)
    Write-Host "Searching for kape.exe on USB..."
    $kape = Get-ChildItem -Path $UsbRoot -Filter "kape.exe" -Recurse -ErrorAction SilentlyContinue -Depth 6
    if ($kape) {
        Write-Host "KAPE found at: $($kape[0].FullName)"
        return $kape[0].FullName
    } else {
        Write-Error "KAPE executable not found on USB: $UsbRoot"
        exit 1
    }
}

# ---------- Main Script ----------
Ensure-Admin

$usbRoot = Get-UsbRoot
Write-Host "USB root detected: $usbRoot"

# Find KAPE executable
$kapeExe = Find-KapeOnUSB -UsbRoot $usbRoot

# Build output folder
$timestamp = (Get-Date).ToString("yyyyMMdd-HHmm")
$systemName = $env:COMPUTERNAME
$caseFolder = "CASE-$timestamp-$systemName"
$outputPath = Join-Path $usbRoot $caseFolder
New-Item -Path $outputPath -ItemType Directory -Force | Out-Null
Write-Host "Output folder created: $outputPath"

# Build KAPE arguments (visible)
$kapeArgs = @(
    "--tsource C:",
    "--tdest `"$outputPath`"",
    "--target !SANS_Triage",
    "--vhdx ${systemName}_Triage",
    "--zv false",
    "--gui"
) -join " "

# Scheduled task info
$taskName = "Portable-KAPE-Task-$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
$description = "Portable KAPE triage task (visible, auditable)"

# Create wrapper script for the scheduled task
$wrapperPath = Join-Path $outputPath "KAPE_Task_Wrapper.ps1"
$wrapperContent = @"
param(
    [string]`$KapeExe,
    [string]`$KapeArgs,
    [string]`$OutputPath,
    [string]`$TaskName
)

# Logging helpers
function Write-Log {
    param([string]`$Message)
    `$ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Add-Content -Path (Join-Path `$OutputPath "runlog.txt") -Value "`$ts - `$Message"
}

function Write-JsonLog {
    param([pscustomobject]`$Object)
    `$jsonPath = Join-Path `$OutputPath "runlog.json"
    `$existing = @()
    if (Test-Path `$jsonPath) {
        try { `$existing = Get-Content `$jsonPath -Raw | ConvertFrom-Json } catch { `$existing = @() }
    }
    `$combined = @()
    if (`$existing -is [System.Collections.IEnumerable]) { `$combined += `$existing }
    `$combined += `$Object
    `$combined | ConvertTo-Json -Depth 5 | Set-Content -Path `$jsonPath -Encoding UTF8
}

try {
    `$startTime = Get-Date
    Write-Log "Wrapper started. KAPE exe: `$KapeExe"
    Write-JsonLog @{ event="start"; time=`$startTime.ToString("o"); kape=`$KapeExe; system=`$env:COMPUTERNAME }

    # Start KAPE process (visible)
    `$proc = Start-Process -FilePath `$KapeExe -ArgumentList `$KapeArgs -Wait -PassThru
    `$exitCode = `$proc.ExitCode

    `$endTime = Get-Date
    Write-Log "KAPE finished. ExitCode=`$exitCode"
    Write-JsonLog @{ event="end"; time=`$endTime.ToString("o"); exitCode=`$exitCode; duration=(New-TimeSpan `$startTime `$endTime).ToString() }

} catch {
    `$err = `$_.Exception.Message
    Write-Log "Error during KAPE execution: `$err"
    Write-JsonLog @{ event="error"; time=(Get-Date).ToString("o"); message=`$err; stack=`$_.Exception.StackTrace }
}
"@

# Save wrapper script
$wrapperContent | Out-File -FilePath $wrapperPath -Encoding UTF8 -Force
Write-Host "Wrapper script created at: $wrapperPath"

# Create scheduled task (visible)
$wrapperArgs = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", "`"$wrapperPath`"",
    "-KapeExe", "`"$kapeExe`"",
    "-KapeArgs", "`"$kapeArgs`"",
    "-OutputPath", "`"$outputPath`"",
    "-TaskName", "`"$taskName`""
) -join " "

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $wrapperArgs
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

try {
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Description $description -Force
    Write-Host "Scheduled task '$taskName' created and will run shortly."
} catch {
    Write-Error "Failed to register scheduled task: $_"
    exit 1
}

# Start the scheduled task immediately
try {
    Start-ScheduledTask -TaskName $taskName
    Write-Host "Scheduled task started successfully."
} catch {
    Write-Error "Failed to start scheduled task: $_"
    exit 1
}

Write-Host "KAPE will run via the scheduled task. Output and logs will be in: $outputPath"
