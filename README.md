# Portable KAPE Triage Automation

**Stealth, Auditable, ISO-Aligned DFIR Collection Toolkit**

------------------------------------------------------------------------

## 📌 Overview

This project provides a fully portable, self-contained, and auditable
forensic triage automation tool built around **KAPE (Kroll Artifact
Parser and Extractor)**.

Designed for **incident responders, DFIR analysts, and field
operators**, the tool executes a silent triage acquisition using a
SYSTEM-level scheduled task and stores all evidence on the removable
media it is executed from.

Once compiled to an `.exe`, the tool can be launched directly from a USB
drive without installers, external dependencies, or user interaction.

------------------------------------------------------------------------

## 🚀 Key Features

### ✔ Fully Portable

Runs directly from a USB pendrive. Automatically detects its own drive
letter, regardless of how Windows assigns it.

### ✔ Stealth Mode (No Popups / No GUI / No User Impact)

-   Runs entirely in the background\
-   Uses hidden PowerShell processes\
-   No GUI elements\
-   No console window interaction\
-   No prompts or user interruptions

### ✔ Automatic Metadata & Chain-of-Custody Logging

Automatically logs:

-   Case ID (auto-generated unless provided)\
-   Operator name (auto-detected from environment)\
-   Incident reference\
-   Authorisation reference\
-   Evidence device ID\
-   Hostname\
-   UTC timestamps\
-   Script version

Results stored in:

    runlog.txt  
    runlog.json

### ✔ ISO 27001-Aligned Controls

Supports DFIR workflows and processes aligned to:

-   A.12.4 -- Logging and Monitoring\
-   A.12.5 -- Control of Operational Software\
-   A.16.1 -- Incident Management\
-   A.18.1.3 -- Protection of Records

### ✔ Automatic Case Folder Handling

    CASE-<YYYYMMDD-HHMM>-<HOSTNAME>```

    ### ✔ SYSTEM-Level Background Execution  

    ### ✔ Dynamic KAPE Discovery  
    Searches up to 6 directory levels for `kape.exe`.

    ---

    ## 📂 Directory Structure

USB_DRIVE:  │ RunTriage.exe\
│\
└── CASE-20250101-1210-HOST123  ├── runlog.txt\
├── runlog.json\
├── KAPE_Task_Wrapper.ps1\
└── `<KAPE Output / VHDX>`{=html}


    ---

    ## 🛠️ Usage

    ### Silent Mode (Recommended)

RunTriage.exe


    ### With Optional Metadata

RunTriage.exe -CaseId "IR-2025-001" -OperatorName "J.Doe"


    Metadata fields are optional — defaults are auto-generated.

    ---

    ## 🔒 Chain-of-Custody Logging

    Example JSON entry:

    ```json
    {
      "CaseId": "AUTO-20250101-HOST123",
      "OperatorName": "jdoe",
      "AuthorisationRef": "AUTO",
      "EvidenceDeviceId": "E:",
      "Hostname": "HOST123",
      "AcquisitionStartUtc": "...",
      "AcquisitionEndUtc": "...",
      "ScriptVersion": "1.3.0"
    }

------------------------------------------------------------------------

## 📜 Important Notes

This automation script is **independently developed** to streamline and
operationalise the execution of **KAPE** in DFIR workflows.

### 👑 Credit to the Original Creator

**All credit for KAPE goes to its author, Eric Zimmerman**, the original
creator of this exceptional forensic triage tool.

### 🏢 KAPE Maintainer

KAPE is maintained and distributed by **Kroll**, who continue to enhance
and support the tool.

Official KAPE repository and downloads:

👉 https://www.kroll.com/en/services/cyber-risk/eric-zimmerman-tools

Always obtain KAPE from official, trusted sources.

------------------------------------------------------------------------

## 🧩 Configuration & Extensibility

The script can be extended to:

-   Add organisation-specific metadata fields\
-   Modify KAPE targets\
-   Encrypt output\
-   Add offloading to network shares\
-   Integrate automated case numbering schemes

------------------------------------------------------------------------

## 🖥️ System Requirements

-   Windows 10 / 11 / Windows Server\
-   PowerShell 5.1+\
-   Administrator privileges\
-   KAPE on the same USB drive

------------------------------------------------------------------------

## 📦 Compiling to EXE

Recommended tools:

-   **PS2EXE**\
-   **PowerShell Pro Tools**\
-   **SAPIEN PowerShell Studio**

Key notes:

✔ USB detection works identically\
✔ Stealth mode preserved\
✔ No hardcoded paths needed\
✔ KAPE still auto-discovered

------------------------------------------------------------------------

## 👤 Author

**Greaton Forensics**\
📧 Admin@greaton.co.uk

------------------------------------------------------------------------

## ⚖️ Legal Disclaimer

This software is provided *"as-is"* without warranty of any kind.\
Use is restricted to legally authorised forensic, security, or incident
response activities.

The author and Greaton Forensics assume no liability for:

-   Misuse\
-   Unauthorised acquisition\
-   Data loss\
-   System impact

Ensure compliance with all applicable laws and organisational policies.

------------------------------------------------------------------------

## 🔐 Ethical Use

This tool must only be used with:

-   Proper authorisation\
-   Documented investigative scope\
-   A lawful mandate\
-   Appropriate approvals

Any misuse is strictly prohibited.

------------------------------------------------------------------------

## ⭐ Final Notes

This tool is designed to be:

-   Stealthy\
-   Reliable\
-   Court-defensible\
-   Portable\
-   Enterprise-ready\
-   Field-operable

If you require additional documentation files (LICENSE, CHANGELOG,
CONTRIBUTING, architecture diagrams), they can be generated upon
request.
