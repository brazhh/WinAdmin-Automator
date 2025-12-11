# WinAdmin-Automator
SysAdmin Operations Toolkit (PowerShell)

## 📋 Overview

The SysAdmin Operations Toolkit is a modular, menu-driven CLI utility designed to streamline Level 1 and Level 2 IT support tasks. It consolidates over 18 essential diagnostic, maintenance, and forensic tools into a single portable script.

Unlike standard maintenance scripts, this toolkit utilizes hybrid execution models (PowerShell + Native CMD) to bypass object processing overhead for high-velocity file operations, and includes enterprise-grade features such as RAID-aware health checks and persistent auditing logs.

## 🚀 Key Features

## 🛠 Automated Maintenance

Hyper-Velocity Cleanup: Utilizes a custom "Blind Fire" logic piping paths directly to cmd.exe to bypass PowerShell's Get-ChildItem latency on massive file structures.

Intelligent Locking Handling: Automatically detects and terminates locked processes (Browsers, Office 365, Teams) to ensure deep cleaning of AppData caches.

Print Spooler Reset: Performs a "Hard Reset" on the print system (Service Kill -> Queue Purge -> Restart) to resolve corruption that standard restarts miss.

## 🔍 Advanced Diagnostics

RAID-Aware Disk Health: Interprets raw S.M.A.R.T. data and translates generic Driver Codes (e.g., PERC H730 0 status) into human-readable health metrics.

Resource Hog Hunter: Captures a 1-second CPU sample to calculate true processor percentage (accounting for logical cores), preventing the misleading "Total Processor Time" data often returned by basic scripts.

Network Chain Analysis: Diagnosis connectivity layer-by-layer: Gateway -> ISP (ICMP) -> Web Traffic (TCP/443) -> DNS Resolution.

## 🛡 Administrative & Audit

Forensic Logging: All actions are timestamped and logged to C:\ProgramData\SysAdminLogs, creating an immutable audit trail of technician activity.

Forensic Uptime: Queries WMI for the LastBootUpTime object to detect "Fast Startup" masking, revealing the true system uptime.

Windows Update Orchestration: Triggers the modern USOClient (Update Session Orchestrator) and creates a direct URI link (ms-settings:windowsupdate) for real-time visual feedback.

## 📸 Screenshots

![Main Menu](WinAdmin.PNG)


## 💻 Installation & Usage

No installation is required. This tool is designed to be portable (USB/Network Share) for field service environments.

Download the HelpDeskTool.ps1 file.

Run as Administrator (Required for Service management and WMI queries).

Execute via PowerShell:
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
.\HelpDeskTool.ps1
```

## 🧠 Technical Highlights (Why it was built this way)

1. Hybrid Deletion Logic

Standard Remove-Item can be slow on spinning HDDs containing thousands of small cache files due to object instantiation overhead. This tool constructs path strings dynamically and passes them to the Windows Command Processor (del /f /s /q) for near-instant execution.

2. Stream Redirection (2>&1)

All background process calls utilize stream merging (2>&1 | Out-Null) to ensure that non-critical errors (such as attempting to kill a closed process) do not bleed onto the console UI, maintaining a clean user experience.

3. Hardware Abstraction Layer

The disk health module casts specific WMI properties to Integers [int] before evaluation. This ensures compatibility with both Consumer NVMe drives (which return Strings like "Healthy") and Enterprise RAID Controllers (which return Integers like 0).

## ⚠️ Disclaimer

This tool performs powerful administrative actions, including force-closing applications and deleting system files. While designed with safety checks (e.g., ErrorAction SilentlyContinue), it should be tested in a non-production environment before deployment.

Developed by Brazhh