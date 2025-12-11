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
    Run from an elevated PowerShell session:

        PS C:\> .\Run-KapeTriage.ps1
        PS C:\> .\Run-KapeTriage.ps1 -CaseId "IR-2025-001" -OperatorName "J.Doe"

    If metadata is not supplied, reasonable defaults are generated automatically
    (e.g. CaseId based on date/hostname, OperatorName from the current user).

.OUTPUT
    CASE-<timestamp>-<hostname>\
        ├── runlog.txt           # Text-based execution log
        ├── runlog.json          # Structured JSON log (incl. chain-of-custody)
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

param(
    [string]$CaseId,
    [string]$IncidentId,
    [string]$OperatorName,
    [string]$OperatorId,
    [string]$AuthorisationRef,
    [string]$EvidenceDeviceId,
    [string]$Notes
)

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
    Write-Verbose "Searching for kape.exe on USB root: $UsbRoot"
    $kape = Get-ChildItem -Path $UsbRoot -Filter "kape.exe" -Recurse -ErrorAction SilentlyContinue -Depth 6
    if ($kape) {
        Write-Verbose "KAPE found at: $($kape[0].FullName)"
        return $kape[0].FullName
    } else {
        Write-Error "KAPE executable not found on USB: $UsbRoot"
        exit 1
    }
}

# ---------- Main Script ----------
Ensure-Admin

$usbRoot   = Get-UsbRoot
$driveId   = $usbRoot.TrimEnd('\')
$hostName  = $env:COMPUTERNAME
$userName  = $env:USERNAME

Write-Verbose "USB root detected: $usbRoot"

# Automatic defaults for optional metadata (no prompts, no interaction)
if (-not $CaseId) {
    $CaseId = ("AUTO-{0}-{1}" -f (Get-Date -Format "yyyyMMddHHmmss"), $hostName)
}
if (-not $OperatorName) {
    $OperatorName = if ($userName) { $userName } else { "Unknown" }
}
if (-not $OperatorId) {
    $OperatorId = if ($env:USERDOMAIN -and $userName) {
        "$($env:USERDOMAIN)\$userName"
    } else {
        $OperatorName
    }
}
if (-not $AuthorisationRef) {
    $AuthorisationRef = "AUTO"
}
if (-not $EvidenceDeviceId) {
    $EvidenceDeviceId = $driveId
}
if (-not $Notes) {
    $Notes = ""
}

# Find KAPE executable
$kapeExe = Find-KapeOnUSB -UsbRoot $usbRoot

# Build output folder
$timestamp  = (Get-Date).ToString("yyyyMMdd-HHmm")
$caseFolder = "CASE-$timestamp-$hostName"
$outputPath = Join-Path $usbRoot $caseFolder
New-Item -Path $outputPath -ItemType Directory -Force | Out-Null
Write-Verbose "Output folder created: $outputPath"

# Build KAPE arguments (stealthy: no GUI)
$kapeArgs = @(
    "--tsource C:",
    "--tdest `"$outputPath`"",
    "--target !SANS_Triage",
    "--vhdx ${hostName}_Triage",
    "--zv false"
) -join " "

# Scheduled task info
$taskName    = "Portable-KAPE-Task-$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
$description = "Portable KAPE triage task (background, auditable)"

# Path to log scheduler issues (outside wrapper)
$schedulerLog = Join-Path $outputPath "scheduler_error.txt"

# Create wrapper script for the scheduled task
$wrapperPath = Join-Path $outputPath "KAPE_Task_Wrapper.ps1"
$wrapperContent = @"
param(
    [string]`$KapeExe,
    [string]`$KapeArgs,
    [string]`$OutputPath,
    [string]`$TaskName,
    [string]`$CaseId,
    [string]`$IncidentId,
    [string]`$OperatorName,
    [string]`$OperatorId,
    [string]`$AuthorisationRef,
    [string]`$EvidenceDeviceId,
    [string]`$Notes
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
    `$startTimeUtc = [DateTime]::UtcNow
    `$startTime    = Get-Date
    `$usbRoot      = Split-Path `$OutputPath -Qualifier

    `$chainOfCustody = [pscustomobject]@{
        CaseId              = `$CaseId
        IncidentId          = `$IncidentId
        OperatorName        = `$OperatorName
        OperatorId          = `$OperatorId
        AuthorisationRef    = `$AuthorisationRef
        EvidenceDeviceId    = `$EvidenceDeviceId
        Hostname            = `$env:COMPUTERNAME
        AcquisitionStartUtc = `$startTimeUtc.ToString("o")
        AcquisitionEndUtc   = `$null
        ScriptVersion       = "1.3.0"
        Notes               = `$Notes
    }

    Write-Log "Wrapper started. KAPE exe: `$KapeExe"
    Write-JsonLog @{
        event          = "start"
        time           = `$startTime.ToString("o")
        kape           = `$KapeExe
        system         = `$env:COMPUTERNAME
        outputPath     = `$OutputPath
        usbRoot        = `$usbRoot
        taskName       = `$TaskName
        chainOfCustody = `$chainOfCustody
    }

    # Start KAPE process (hidden window, background)
    `$proc = Start-Process -FilePath `$KapeExe -ArgumentList `$KapeArgs -WindowStyle Hidden -Wait -PassThru
    `$exitCode = `$proc.ExitCode

    `$endTimeUtc = [DateTime]::UtcNow
    `$endTime    = Get-Date

    `$chainOfCustody.AcquisitionEndUtc = `$endTimeUtc.ToString("o")

    Write-Log "KAPE finished. ExitCode=`$exitCode"
    Write-JsonLog @{
        event          = "end"
        time           = `$endTime.ToString("o")
        exitCode       = `$exitCode
        duration       = (New-TimeSpan `$startTime `$endTime).ToString()
        outputPath     = `$OutputPath
        usbRoot        = `$usbRoot
        taskName       = `$TaskName
        chainOfCustody = `$chainOfCustody
    }

} catch {
    `$err       = `$_.Exception.Message
    `$usbRoot   = Split-Path `$OutputPath -Qualifier
    `$errorTime = Get-Date

    Write-Log "Error during KAPE execution: `$err"
    Write-JsonLog @{
        event      = "error"
        time       = `$errorTime.ToString("o")
        message    = `$err
        stack      = `$_.Exception.StackTrace
        outputPath = `$OutputPath
        usbRoot    = `$usbRoot
        taskName   = `$TaskName
        caseId     = `$CaseId
        incidentId = `$IncidentId
    }
}
"@

# Save wrapper script
$wrapperContent | Out-File -FilePath $wrapperPath -Encoding UTF8 -Force
Write-Verbose "Wrapper script created at: $wrapperPath"

# Create scheduled task (stealth: hidden PowerShell window)
$wrapperArgs = @(
    "-NoProfile",
    "-WindowStyle", "Hidden",
    "-NonInteractive",
    "-ExecutionPolicy", "Bypass",
    "-File", "`"$wrapperPath`"",
    "-KapeExe", "`"$kapeExe`"",
    "-KapeArgs", "`"$kapeArgs`"",
    "-OutputPath", "`"$outputPath`"",
    "-TaskName", "`"$taskName`"",
    "-CaseId", "`"$CaseId`"",
    "-IncidentId", "`"$IncidentId`"",
    "-OperatorName", "`"$OperatorName`"",
    "-OperatorId", "`"$OperatorId`"",
    "-AuthorisationRef", "`"$AuthorisationRef`"",
    "-EvidenceDeviceId", "`"$EvidenceDeviceId`"",
    "-Notes", "`"$Notes`""
) -join " "

$action    = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $wrapperArgs
$trigger   = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

try {
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Description $description -Force -ErrorAction Stop | Out-Null
    Write-Verbose "Scheduled task '$taskName' created."
} catch {
    $msg = "[{0}] Failed to register scheduled task '{1}': {2}" -f (Get-Date), $taskName, $_.Exception.Message
    Add-Content -Path $schedulerLog -Value $msg
    # Do NOT rethrow – avoids PS2EXE popup
    return
}

# Start the scheduled task immediately (still silent for the user)
try {
    Start-ScheduledTask -TaskName $taskName -ErrorAction Stop | Out-Null
    Write-Verbose "Scheduled task started successfully."
} catch {
    $msg = "[{0}] Failed to start scheduled task '{1}': {2}" -f (Get-Date), $taskName, $_.Exception.Message
    Add-Content -Path $schedulerLog -Value $msg
    # Do NOT rethrow – avoids PS2EXE popup
    return
}

Write-Verbose "KAPE will run via the scheduled task. Output and logs will be in: $outputPath"
