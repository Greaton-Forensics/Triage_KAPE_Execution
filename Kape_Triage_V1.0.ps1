<#
.SYNOPSIS
Automated forensic triage acquisition using KAPE with scheduled task execution.

.DESCRIPTION
This script performs a controlled, auditable forensic triage acquisition using
the Kroll Artifact Parser and Extractor (KAPE). It:

    - Identifies the location of kape.exe on the removable media
    - Builds a case-specific output directory on the USB device
    - Generates a wrapper script to execute KAPE with predefined arguments
    - Registers and starts a one-time scheduled task running as SYSTEM
    - Logs execution metadata (timestamps, exit codes, errors)

All evidence and logs remain on the removable media to support evidence
segregation and portability. The workflow is intended for incident response
and DFIR operations where rapid, consistent triage acquisition is required
with minimal analyst interaction.

.AUTHOR
    Greaton Forensics
    Contact: Admin@greaton.co.uk

.VERSION
    Script Version : 1.3.0
    Release Date   : 2025-01-01
    Release Status : Stable

.COMPLIANCE (ISO 27001 ALIGNMENT)
    This script is designed to support technical and procedural controls commonly
    associated with an ISO/IEC 27001-aligned Information Security Management System
    (ISMS), including but not limited to:

        - A.6.1.2  : Segregation of duties
        - A.12.1   : Change management (through documented versioning)
        - A.12.4   : Logging and monitoring (runlog.txt / runlog.json)
        - A.12.5   : Control of operational software (controlled deployment & use)
        - A.16.1   : Management of information security incidents
        - A.18.1.3 : Protection of records (forensic logs and case evidence)

    IMPORTANT:
        - This script alone does not constitute ISO 27001 compliance.
        - It is a technical control to be used within a documented ISMS
          with appropriate policies, procedures, and governance.

.CHAIN_OF_CUSTODY
    This script can form part of a wider chain-of-custody process by generating
    consistent, timestamped logs and case directories. It is recommended that
    each execution is associated with clearly defined metadata, such as:

        - CaseId              : External or internal case reference
        - IncidentId          : Incident / ticket reference
        - OperatorName        : Analyst / responder executing the script
        - OperatorId          : Internal analyst ID (if applicable)
        - AuthorisationRef    : Legal / management authorisation reference
        - EvidenceDeviceId    : Identifier / serial of removable media
        - Hostname            : Target system name
        - AcquisitionStartUtc : Start timestamp (UTC)
        - AcquisitionEndUtc   : End timestamp (UTC)
        - ScriptVersion       : As per .VERSION above
        - Notes               : Free-text for contextual details

    Best practice:
        - Mirror this metadata in a formal chain-of-custody form.
        - Ensure removable media is uniquely labelled and tracked.
        - Store logs (runlog.txt / runlog.json) as part of the case record.

.REQUIREMENTS
    - Administrative privileges (enforced at runtime)
    - PowerShell 5.1 or later
    - KAPE executable (kape.exe) present on the USB media
    - Windows Task Scheduler available and functional
    - Sufficient free storage on removable media for triage output

.USAGE
    Run from an elevated PowerShell session, optionally providing case metadata:

        PS C:\> .\Run-KapeTriage.ps1

    The script will:
        1. Detect the USB root path
        2. Locate kape.exe
        3. Create a case folder (timestamp + hostname)
        4. Generate a wrapper script for KAPE execution
        5. Register and launch a SYSTEM-level scheduled task
        6. Store logs and output on the USB media

.OUTPUT
    CASE-<timestamp>-<hostname>\
        ├── runlog.txt           # Text-based execution log
        ├── runlog.json          # Structured JSON log
        ├── KAPE_Task_Wrapper.ps1
        └── KAPE output (incl. VHDX if configured)

.DISCLAIMER
    This script is provided "as is" without any warranties, express or implied,
    including but not limited to the implied warranties of merchantability,
    fitness for a particular purpose, or non-infringement.

    Greaton Forensics and the author accept no responsibility or liability for:
        - Misuse of this script
        - Improper or unauthorised forensic acquisition
        - Data loss, business interruption, or system impact

    Use of this script is only permitted where legally authorised. It is the
    operator’s responsibility to ensure compliance with all applicable laws,
    regulations, contracts, and organisational policies before execution.

.NOTES
    Purpose     : Portable, repeatable, auditable forensic triage acquisition
    Privilege   : Must be executed from an elevated PowerShell session
    IntendedUse : DFIR / IR operations under appropriate legal authority

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
