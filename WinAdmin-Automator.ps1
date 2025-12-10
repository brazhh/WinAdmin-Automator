# ==========================================
# 1. HEADER
# ==========================================
# Title: WinAdmin-Automator
# Author: https://github.com/brazhh

# ==========================================
# 2. FUNCTIONS
# ==========================================

#1. Clean System Temps & Browsers
function Clean-AllSystemJunk {
    Write-Host "STARTING DEEP CLEANUP..." -ForegroundColor Cyan

    # ---------------------------------------------------------
    # 1. KILL APPS & SERVICES
    # ---------------------------------------------------------
    Write-Host "Killing processes to release locks..." -ForegroundColor Yellow
    
    # Kill Services
    taskkill /F /FI "SERVICES eq wuauserv" /T 2>&1 | Out-Null
    taskkill /F /FI "SERVICES eq Spooler" /T 2>&1 | Out-Null
    taskkill /F /FI "SERVICES eq ClickToRunSvc" /T 2>&1 | Out-Null # Office Updates

    # Kill Apps (Browsers, Office, Teams, PDF Readers)
    $Apps = @(
        "chrome", "msedge", "firefox", "brave", 
        "outlook", "winword", "excel", "powerpnt", "onenote", "visio", "mspub", "lync",
        "teams", "msteams", "onedrive", 
        "acrobat", "AcroRd32"
    )
    foreach ($app in $Apps) { 
        taskkill /F /IM "$app.exe" /T 2>&1 | Out-Null 
    }
    
    Start-Sleep -Seconds 1

    # ---------------------------------------------------------
    # 2. THE MASTER TARGET LIST
    # ---------------------------------------------------------
    $JunkFolders = @(
        # --- WINDOWS SYSTEM JUNK ---
        "C:\Windows\Temp\*",
        "C:\Windows\Prefetch\*",
        "C:\Windows\SoftwareDistribution\Download\*",
        "C:\Windows\Minidump\*",
        "C:\Windows\System32\LogFiles\WMI\*",
        "C:\Windows\Logs\CBS\*",                       # Component-Based Servicing Logs
        "C:\Windows\Downloaded Program Files\*",        # ActiveX/Java Applets
        "C:\ProgramData\Microsoft\Windows\WER\ReportArchive\*",
        "C:\ProgramData\Microsoft\Windows\WER\ReportQueue\*",

        # --- USER TEMP & INTERNET CACHE ---
        "C:\Users\*\AppData\Local\Temp\*",
        "C:\Users\*\AppData\Local\Microsoft\Windows\INetCache\*",   # Temporary Internet Files
        "C:\Users\*\AppData\Local\Microsoft\Windows\IECompatCache\*",
        "C:\Users\*\AppData\Local\D3DSCache\*",        # DirectX Shader Cache (Graphics Junk)
        "C:\Users\*\AppData\Local\Microsoft\Terminal Server Client\Cache\*", # RDP Bitmap Cache

        # --- BROWSER CACHES (Cache Only - No Cookies) ---
        "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Cache\*",
        "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Code Cache\*",
        "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\GPUCache\*",
        "C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default\Cache\*",
        "C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default\Code Cache\*",
        "C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default\GPUCache\*",
        "C:\Users\*\AppData\Local\Mozilla\Firefox\Profiles\*\cache2\*",
        
        # --- OUTLOOK & OFFICE ---
        "C:\Users\*\AppData\Local\Microsoft\Office\16.0\OfficeFileCache\*",
        "C:\Users\*\AppData\Local\Microsoft\Office\16.0\WeF\*",             # Web Extensions
        "C:\Users\*\AppData\Local\Microsoft\Outlook\RoamCache\*",           # Autocomplete/Stream Cache (Can be huge)
        "C:\Users\*\AppData\Local\Microsoft\Outlook\Offline Address Books\*", # OAB (Safe to delete, rebuilds on sync)

        # --- TEAMS & COLLAB ---
        "C:\Users\*\AppData\Roaming\Microsoft\Teams\Cache\*",
        "C:\Users\*\AppData\Roaming\Microsoft\Teams\Code Cache\*",
        "C:\Users\*\AppData\Roaming\Microsoft\Teams\blob_storage\*",
        "C:\Users\*\AppData\Roaming\Microsoft\Teams\Service Worker\CacheStorage\*"
    )

    # ---------------------------------------------------------
    # 3. THE CLEANUP LOOP (Fast Mode)
    # ---------------------------------------------------------
    Write-Host "Targeting and Deleting..." -ForegroundColor Cyan

    # Resolve wildcards
    $FoundPaths = Get-ChildItem -Path $JunkFolders -ErrorAction SilentlyContinue

    foreach ($item in $FoundPaths) {
        $path = $item.FullName
        
        Write-Host "Cleaning: $path" -ForegroundColor DarkGray

        if (-not $item.PSIsContainer) {
            # File
            cmd /c "del /f /q `"$path`" 2>&1" | Out-Null
        }
        else {
            # Folder
            cmd /c "del /f /s /q `"$path`" 2>&1" | Out-Null
        }
    }

    # ---------------------------------------------------------
    # 4. EXTRAS & RESTORE
    # ---------------------------------------------------------
    Write-Host "Emptying Recycle Bin..." -ForegroundColor DarkGray
    Clear-RecycleBin -Force -ErrorAction SilentlyContinue
    
    Write-Host "Restarting Services..." -ForegroundColor Yellow
    Start-Service -Name wuauserv -ErrorAction SilentlyContinue
    Start-Service -Name Spooler -ErrorAction SilentlyContinue

    Write-Host "Done." -ForegroundColor Green
}

#2. Restart Print Spooler
function Fix-PrintSystem {
    Write-Host "INITIALIZING PRINT SYSTEM REPAIR..." -ForegroundColor Cyan
    # ---------------------------------------------------------
    # STEP 1: STOP THE SERVICE (The Hard Way)
    # ---------------------------------------------------------
    Write-Host "1. Stopping Print Spooler..." -ForegroundColor Yellow
    
    # This is crucial because a corrupt driver often freezes the service
    taskkill /F /FI "SERVICES eq Spooler" /T 2>&1 | Out-Null

    # Wait a moment to ensure the file locks are released
    Start-Sleep -Seconds 2

    # ---------------------------------------------------------
    # STEP 2: PURGE THE QUEUE (The Magic Fix)
    # ---------------------------------------------------------
    Write-Host "2. Removing Stuck Print Jobs..." -ForegroundColor Cyan
    
    # The Spooler stores temporary job files here. 
    # If these are corrupt, the printer will never work.
    $SpoolPath = "C:\Windows\System32\spool\PRINTERS\*"
    
    # We check if files exist first to avoid errors
    if (Test-Path $SpoolPath) {
        Remove-Item -Path $SpoolPath -Force -Recurse -ErrorAction SilentlyContinue -Verbose
    }
    else {
        Write-Host "   - Queue was already empty." -ForegroundColor DarkGray
    }

    # ---------------------------------------------------------
    # STEP 3: RESTART
    # ---------------------------------------------------------
    Write-Host "3. Restarting Spooler Service..." -ForegroundColor Yellow
    
    try {
        Start-Service -Name Spooler -ErrorAction Stop
        
        # Verify status
        $Status = Get-Service -Name Spooler
        if ($Status.Status -eq 'Running') {
            Write-Host "SUCCESS: Print System is back online." -ForegroundColor Green
            Write-Host "   - You may try printing now." -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "CRITICAL ERROR: The Spooler refused to start." -ForegroundColor Red
        Write-Host "   - Error Details: $_" -ForegroundColor Red
    }
}

#3. Force Group Policy Update
function Run-GPOUpdate {
    Write-Host "CONTACTING DOMAIN CONTROLLER..." -ForegroundColor Cyan
    Write-Host "Forcing Group Policy Update (Computer & User)..." -ForegroundColor Yellow
    
    # We use the native Windows binary.
    # /Force = Reapplies all settings, even if they haven't changed.
    # /Wait:0 = Don't wait for network processing to finish before returning control.
    gpupdate /force /wait:0
    
    # Check the "LastExitCode" to see if it worked
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "SUCCESS: Policies retrieved from Domain." -ForegroundColor Green
        Write-Host "NOTE: If you saw a message about 'Logoff' or 'Restart', please do so." -ForegroundColor Gray
    }
    else {
        Write-Host ""
        Write-Host "ERROR: The update failed." -ForegroundColor Red
        Write-Host "   - Check your VPN or Network Cable." -ForegroundColor DarkGray
        Write-Host "   - Verify you can reach the Domain Controller." -ForegroundColor DarkGray
    }
}

#4. Trigger Windows Updates
function Trigger-WindowsUpdate {
    Write-Host "Triggering Windows Update Scan..." -ForegroundColor Cyan

    # Ensure service is up
    Start-Service -Name wuauserv -ErrorAction SilentlyContinue

    # Fire the background scan
    Start-Process -FilePath "usoclient.exe" -ArgumentList "StartScan"

    # Open the GUI for the user to see
    Write-Host "Opening Windows Update Settings..." -ForegroundColor Yellow
    Start-Sleep -Seconds 3
    Start-Process "ms-settings:windowsupdate"

    Write-Host "Done. Updates should appear shortly." -ForegroundColor Green
}

#5. Check Disk Space and users
function Check-StorageSpace {
    Write-Host "ANALYZING SYSTEM STORAGE..." -ForegroundColor Cyan
    Write-Host ""

    # ==========================================
    # PART 1: OVERALL DRIVE STATUS (Instant)
    # ==========================================
    $Disk = Get-Volume -DriveLetter C
    $Size = [math]::Round($Disk.Size / 1GB, 2)
    $Free = [math]::Round($Disk.SizeRemaining / 1GB, 2)
    $Used = [math]::Round(($Disk.Size - $Disk.SizeRemaining) / 1GB, 2)
    $Percent = [math]::Round(($Disk.SizeRemaining / $Disk.Size) * 100, 0)

    Write-Host "--- [ C: DRIVE OVERVIEW ] ---" -ForegroundColor Yellow
    Write-Host "   Total Capacity : $Size GB"
    Write-Host "   Used Space     : $Used GB"
    Write-Host "   Free Space     : $Free GB ($Percent%)"
    Write-Host ""
# ---------------------------------------------
    # PART 2: USER FOLDERS (Reliable Scan)
    # ---------------------------------------------
    Write-Host "--- [ USER PROFILES ] ---" -ForegroundColor Yellow
    Write-Host "Scanning user data (Please wait)..." -ForegroundColor DarkGray
    
    $UserFolders = Get-ChildItem "C:\Users" -Directory -Force -ErrorAction SilentlyContinue

    foreach ($folder in $UserFolders) {
        # We use standard PowerShell measurement. It handles permissions better.
        $Measure = Get-ChildItem -Path $folder.FullName -Recurse -Force -ErrorAction SilentlyContinue | 
                   Measure-Object -Property Length -Sum
        
        # Calculate GB
        $SizeGB = [math]::Round(($Measure.Sum / 1GB), 2)

        # Logic to make the output readable
        if ($Measure.Sum -gt 0) {
            if ($SizeGB -gt 10) {
                # Highlight massive users in Magenta
                Write-Host "   $($folder.Name) : $SizeGB GB" -ForegroundColor Magenta
            }
            else {
                Write-Host "   $($folder.Name) : $SizeGB GB" -ForegroundColor Gray
            }
        }
        else {
            # If 0, it's either truly empty or totally locked (like "All Users" shortcuts)
            Write-Host "   $($folder.Name) : -- (Empty or System Locked)" -ForegroundColor DarkGray
        }
    }
    
    Write-Host ""
    Write-Host "Analysis Complete." -ForegroundColor Green
}

#6. Check Disk Health
function Check-DiskHealth {
    Write-Host "DIAGNOSING DRIVES (RAW INTEGER CHECK)..." -ForegroundColor Cyan
    Write-Host ""

    $Disks = Get-PhysicalDisk | Sort-Object Number

    foreach ($d in $Disks) {
        Write-Host "--- [ DISK $($d.DeviceId) ] ---" -ForegroundColor Yellow
        Write-Host "   Model  : $($d.FriendlyName)"
        Write-Host "   Type   : $($d.MediaType)"
        
        # We force the value to be a number using [int]
        # 0 = Healthy
        # 2 = OK
        
        $HealthCode = [int]$d.HealthStatus
        $StatusCode = [int]$d.OperationalStatus[0] # OpStatus is an array, we take the first code

        # CHECK HEALTH (0 is the universal code for Success/Healthy)
        if ($HealthCode -eq 0) {
            Write-Host "   Health : Healthy ($HealthCode)" -ForegroundColor Green
        }
        else {
            Write-Host "   Health : ERROR CODE $HealthCode" -ForegroundColor Red
            Write-Host "   WARNING: DRIVE FAILURE IMMINENT." -ForegroundColor Red -BackgroundColor Black
        }

        # CHECK STATUS (2 is the universal code for OK)
        if ($StatusCode -eq 2) {
            Write-Host "   Status : OK ($StatusCode)" -ForegroundColor Green
        }
        else {
            Write-Host "   Status : ERROR CODE $StatusCode" -ForegroundColor Red
        }
        Write-Host ""
    }
    
    Write-Host "Diagnostics Complete." -ForegroundColor Green
}

#7. Check System Resource
function Manage-SystemHogs {
    Write-Host "ANALYZING SYSTEM RESOURCES (CPU & RAM)..." -ForegroundColor Cyan
    Write-Host "Please wait 1 second for CPU sampling..." -ForegroundColor DarkGray
    
    # 1. CPU Sampling (The Math)
    # We take two snapshots to calculate the usage over 1 second
    $Sample1 = Get-Process
    Start-Sleep -Seconds 1
    $Sample2 = Get-Process
    $LogicalCores = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
    
    $ProcessList = foreach ($p2 in $Sample2) {
        $p1 = $Sample1 | Where-Object { $_.Id -eq $p2.Id }
        if ($p1) {
            $CPU_Diff = $p2.CPU - $p1.CPU
            $CPU_Pct = [math]::Round(($CPU_Diff / $LogicalCores) * 100, 1)
            
            [PSCustomObject]@{
                Id      = $p2.Id
                Name    = $p2.ProcessName
                CPU     = $CPU_Pct
                RAM_MB  = [math]::Round($p2.WorkingSet / 1MB, 0)
            }
        }
    }

    Clear-Host
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "       SYSTEM RESOURCE MONITOR" -ForegroundColor White
    Write-Host "==========================================" -ForegroundColor Cyan
    
    # 2. Display TOP 5 CPU Hogs
    Write-Host ""
    Write-Host "--- [ TOP 5 CPU CONSUMERS ] ---" -ForegroundColor Yellow
    $ProcessList | Sort-Object CPU -Descending | Select-Object -First 5 | Format-Table -AutoSize

    # 3. Display TOP 5 RAM Hogs
    Write-Host "--- [ TOP 5 RAM CONSUMERS ] ---" -ForegroundColor Magenta
    $ProcessList | Sort-Object RAM_MB -Descending | Select-Object -First 5 | Format-Table -AutoSize

    # 4. The Kill Switch
    Write-Host ""
    $KillID = Read-Host "Enter ID to KILL (or press Enter to exit)"
    
    if ($KillID) {
        # Check if process exists first
        if ($Target = $ProcessList | Where-Object {$_.Id -eq $KillID}) {
            Stop-Process -Id $KillID -Force -ErrorAction SilentlyContinue
            Write-Host "Terminated $($Target.Name) ($KillID)." -ForegroundColor Red
        }
        else {
            Write-Host "ID not found or already closed." -ForegroundColor DarkGray
        }
    }
}

#8. Check For Pending Reboot
function Check-PendingReboot {
    Write-Host "CHECKING PENDING REBOOT STATUS..." -ForegroundColor Cyan
    $RebootRequired = $false

    # 1. Component Based Servicing (Windows Updates)
    # The most common flag. Used by almost all modern updates.
    $CBSPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
    if (Test-Path $CBSPath) {
        Write-Host " [!] Reboot Pending: Windows Component Update (CBS)" -ForegroundColor Yellow
        $RebootRequired = $true
    }

    # 2. Windows Update (Auto Update)
    # Often used by WSUS or automatic background downloads.
    $WUPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
    if (Test-Path $WUPath) {
        Write-Host " [!] Reboot Pending: Windows Update Agent" -ForegroundColor Yellow
        $RebootRequired = $true
    }

    # 3. Pending File Rename Operations (Drivers & Apps)
    # This key contains a list of files waiting to be swapped at boot.
    $SessionManagerPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    $PendingFileRename = Get-ItemProperty -Path $SessionManagerPath -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
    
    if ($PendingFileRename) {
        Write-Host " [!] Reboot Pending: File Rename Operations (Driver/App Install)" -ForegroundColor Yellow
        $RebootRequired = $true
    }

    # 4. SCCM (Configuration Manager)
    # Specific to enterprise environments managed by Endpoint Manager.
    try {
        $SCCM = Get-CimInstance -Namespace "root\ccm\ClientSDK" -ClassName "CCM_ClientUtilities" -ErrorAction SilentlyContinue
        if ($SCCM.DetermineIfRebootPending().RebootPending) {
            Write-Host " [!] Reboot Pending: SCCM Client Request" -ForegroundColor Yellow
            $RebootRequired = $true
        }
    } catch {
        # Silent fail if SCCM is not installed
    }

    # FINAL VERDICT
    Write-Host ""
    if ($RebootRequired) {
        Write-Host "RESULT: REBOOT IS REQUIRED." -ForegroundColor Red -BackgroundColor Black
        
        $choice = Read-Host "Do you want to reboot now? (y/n)"
        if ($choice -eq 'y') {
            Restart-Computer -Force
        }
    }
    else {
        Write-Host "RESULT: No reboot pending. System is clean." -ForegroundColor Green
    }
}

#9. Repair Windows Image
function Repair-WindowsImage {
    Write-Host "INITIALIZING SYSTEM REPAIR SUITE..." -ForegroundColor Cyan
    Write-Host "WARNING: This process takes 10-20 minutes. Do not close." -ForegroundColor Red
    Write-Host ""

    # STEP 1: CHECK HEALTH (Fast)
    Write-Host "1. Scanning Windows Image Health (DISM)..." -ForegroundColor Yellow
    # /ScanHealth is read-only. It tells us if corruption exists.
    $DISMScan = Start-Process "dism.exe" -ArgumentList "/Online /Cleanup-Image /ScanHealth" -Wait -PassThru
    
    if ($DISMScan.ExitCode -eq 0) {
        Write-Host "   - Image is Healthy. Skipping Restore." -ForegroundColor Green
    }
    else {
        # STEP 2: RESTORE HEALTH (Slow but necessary if corruption found)
        Write-Host "   - Corruption Detected. Repairing Component Store..." -ForegroundColor Red
        Start-Process "dism.exe" -ArgumentList "/Online /Cleanup-Image /RestoreHealth" -Wait
    }

    Write-Host ""

    # STEP 3: SYSTEM FILE CHECKER (SFC)
    Write-Host "2. Verifying System Files (SFC)..." -ForegroundColor Yellow
    Write-Host "   - Comparing active files against the Component Store..." -ForegroundColor DarkGray
    
    # We pipe to Out-String to capture the text output for analysis
    # This command can take 5-10 minutes.
    Start-Process "sfc.exe" -ArgumentList "/scannow" -Wait

    Write-Host ""
    
    # STEP 4: DISK CHECK (Read-Only)
    Write-Host "3. Rapid Disk Scan (ChkDsk)..." -ForegroundColor Yellow
    # We run in Read-Only mode. If we use /F, it forces a reboot, which is annoying.
    # This just tells you if you NEED to schedule a repair.
    Start-Process "chkdsk.exe" -ArgumentList "C:" -Wait

    Write-Host ""
    Write-Host "Repair Protocol Complete." -ForegroundColor Green
}

#10. Test Internet Connection 
function Test-NetworkChain {
    Write-Host "DIAGNOSING CONNECTION CHAIN..." -ForegroundColor Cyan
    Write-Host ""

    # STEP 1: GATEWAY (The Router)
    # We automatically find your router's IP to test local connection first.
    $Gateway = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NextHop -First 1
    
    if ($Gateway) {
        if (Test-Connection -ComputerName $Gateway -Count 1 -Quiet) {
            Write-Host "   1. [OK] Gateway ($Gateway) is reachable." -ForegroundColor Green
        } else {
            Write-Host "   1. [!!] Gateway ($Gateway) is DOWN. Check Router/Cable." -ForegroundColor Red
        }
    } else {
        Write-Host "   1. [!!] No Network Found. Check Wi-Fi/Ethernet." -ForegroundColor Red
        return # Stop execution if we can't even find a router
    }

    # STEP 2: INTERNET CORE (Ping 8.8.8.8)
    if (Test-Connection -ComputerName "8.8.8.8" -Count 1 -Quiet) {
        Write-Host "   2. [OK] Internet Core (Google) is reachable." -ForegroundColor Green
    } else {
        Write-Host "   2. [!!] Internet Core is UNREACHABLE. Check ISP." -ForegroundColor Red
    }

    # STEP 3: WEB TRAFFIC (Port 443 Check)
    # This is the "Pro" check. We use Test-NetConnection to see if HTTPs is allowed.
    $TCP = Test-NetConnection -ComputerName "microsoft.com" -Port 443 -InformationLevel Quiet
    if ($TCP) {
        Write-Host "   3. [OK] HTTPS Traffic (Port 443) is OPEN." -ForegroundColor Green
    } else {
        Write-Host "   3. [!!] HTTPS Traffic is BLOCKED. Check Firewall." -ForegroundColor Red
    }

    # STEP 4: DNS RESOLUTION (Name to IP)
    # Can we turn "google.com" into numbers?
    try {
        $null = Resolve-DnsName -Name "google.com" -ErrorAction Stop
        Write-Host "   4. [OK] DNS Resolution is working." -ForegroundColor Green
    } catch {
        Write-Host "   4. [!!] DNS Resolution FAILED. Check DNS Settings." -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "Test Complete." -ForegroundColor Gray
}

#11. Get Network Information
function Get-NetworkIntel {
    Write-Host "GATHERING NETWORK INTELLIGENCE..." -ForegroundColor Cyan
    Write-Host ""

    # 1. PUBLIC IP (Ask the Internet who we are)
    # We use a simple external API to see our WAN IP
    try {
        $PublicIP = Invoke-RestMethod -Uri "https://api.ipify.org" -ErrorAction Stop
        Write-Host "--- [ EXTERNAL (WAN) ] ---" -ForegroundColor Yellow
        Write-Host "   Public IP   : $PublicIP" -ForegroundColor Green
    }
    catch {
        Write-Host "   Public IP   : [Offline / Blocked]" -ForegroundColor Red
    }
    Write-Host ""

    # 2. INTERNAL DETAILS (The Active Adapter)
    # We filter for adapters that actually have a Gateway (Meaning they are connected)
    $ActiveCards = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null }

    foreach ($Card in $ActiveCards) {
        Write-Host "--- [ INTERNAL (LAN): $($Card.InterfaceAlias) ] ---" -ForegroundColor Yellow
        Write-Host "   IPv4 Address: $($Card.IPv4Address.IPAddress)"
        Write-Host "   Gateway     : $($Card.IPv4DefaultGateway.NextHop)"
        
        # DNS Servers often come as a list, so we join them with commas
        Write-Host "   DNS Servers : $($Card.DNSServer.ServerAddresses -join ', ')"
        
        # We need a separate command just to get the MAC Address cleanly
        $MAC = Get-NetAdapter -InterfaceIndex $Card.InterfaceIndex
        Write-Host "   MAC Address : $($MAC.MacAddress)"
        Write-Host "   Link Speed  : $($MAC.LinkSpeed)"
        Write-Host ""
    }
}

#12. Manage Wifi
function Manage-WifiPasswords {
    Write-Host "SCANNING WI-FI VAULT..." -ForegroundColor Cyan

    # 1. Get the list of names
    # We parse the text output of 'netsh' to find profile names
    $RawProfiles = (netsh wlan show profiles) | Select-String "All User Profile" 
    
    if (-not $RawProfiles) {
        Write-Host "No saved Wi-Fi profiles found." -ForegroundColor Red
        return
    }

    # 2. Build the Database (Name + Password)
    $WifiDB = @()
    $Index = 1

    foreach ($Item in $RawProfiles) {
        # Clean up the name (remove "All User Profile : ")
        $Name = $Item.ToString().Split(":")[1].Trim()
        
        # Get the password for this specific network
        $Details = netsh wlan show profile name="$Name" key=clear
        $PassLine = $Details | Select-String "Key Content"
        
        if ($PassLine) {
            $Password = $PassLine.ToString().Split(":")[1].Trim()
        } else {
            $Password = "-- Open / No Key --"
        }

        # Add to list
        $WifiDB += [PSCustomObject]@{
            Num  = $Index
            SSID = $Name
            Key  = $Password
        }
        $Index++
    }

    # 3. Display the Menu
    Clear-Host
    Write-Host "--- [ SAVED WI-FI PROFILES ] ---" -ForegroundColor Yellow
    $WifiDB | Format-Table -AutoSize

    # 4. Delete Logic
    Write-Host ""
    $Choice = Read-Host "Enter number to DELETE (or press Enter to exit)"

    if ($Choice) {
        $Target = $WifiDB | Where-Object { $_.Num -eq $Choice }
        
        if ($Target) {
            Write-Host "Deleting '$($Target.SSID)'..." -ForegroundColor Red
            netsh wlan delete profile name="$($Target.SSID)"
            Write-Host "Profile Removed." -ForegroundColor Green
        }
        else {
            Write-Host "Invalid number." -ForegroundColor DarkGray
        }
    }
}

#13. Serial Number & BIOS
function Get-AssetInfo {
    Write-Host "PULLING HARDWARE IDENTITY..." -ForegroundColor Cyan
    Write-Host ""

    $Bios = Get-CimInstance Win32_BIOS
    $System = Get-CimInstance Win32_ComputerSystem

    Write-Host "--- [ HARDWARE IDENTITY ] ---" -ForegroundColor Yellow
    Write-Host "   Manufacturer  : $($System.Manufacturer)"
    Write-Host "   Model         : $($System.Model)"
    Write-Host "   Serial (S/N)  : $($Bios.SerialNumber)" -ForegroundColor Magenta
    Write-Host "   BIOS Version  : $($Bios.SMBIOSBIOSVersion)"
    Write-Host "   Total RAM     : $([math]::Round($System.TotalPhysicalMemory / 1GB, 0)) GB"
    Write-Host ""
    Write-Host "Done." -ForegroundColor Green
}

#14. Get System Uptime
function Get-SystemUptime {
    Write-Host "CALCULATING TRUE UPTIME..." -ForegroundColor Cyan
    
    $OS = Get-CimInstance Win32_OperatingSystem
    $LastBoot = $OS.LastBootUpTime
    $Uptime = (Get-Date) - $LastBoot

    Write-Host ""
    Write-Host "   Last Reboot : $LastBoot"
    
    # Logic to highlight "Bad" uptime (over 7 days) in Red
    if ($Uptime.Days -gt 7) {
        Write-Host "   Current Uptime : $($Uptime.Days) Days, $($Uptime.Hours) Hours" -ForegroundColor Red
        Write-Host "   VERDICT: User needs to restart." -ForegroundColor Yellow
    }
    else {
        Write-Host "   Current Uptime : $($Uptime.Days) Days, $($Uptime.Hours) Hours" -ForegroundColor Green
        Write-Host "   VERDICT: Freshly booted." -ForegroundColor Green
    }
}

#15. Fix System Clock
function Fix-SystemTime {
    Write-Host "SYNCHRONIZING SYSTEM CLOCK..." -ForegroundColor Cyan
    
    # 1. Restart the Time Service to wake it up
    Write-Host "   - Restarting W32Time Service..." -ForegroundColor DarkGray
    Restart-Service w32time -Force -ErrorAction SilentlyContinue

    # 2. Force the Sync
    Write-Host "   - Contacting Time Server..." -ForegroundColor DarkGray
    $Result = w32tm /resync
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "SUCCESS: Time is now synced." -ForegroundColor Green
    }
    else {
        Write-Host "ERROR: Could not reach time server." -ForegroundColor Red
    }
}

#15. Generate Battery Health Report
function Get-BatteryReport {
    Write-Host "GENERATING BATTERY HEALTH REPORT..." -ForegroundColor Cyan
    
    $Path = "$env:TEMP\battery_report.html"
    
    # Run the native power config tool
    powercfg /batteryreport /output "$Path" | Out-Null
    
    Write-Host "Report generated at: $Path" -ForegroundColor Green
    Write-Host "Opening report in browser..." -ForegroundColor Yellow
    
    # Open it automatically
    Start-Process "$Path"
    
    Write-Host "Done. Check the 'Design Capacity' vs 'Full Charge Capacity'." -ForegroundColor Magenta
}

#16. Check Windows License Status
function Check-WindowsLicense {
    Write-Host "CHECKING ACTIVATION STATUS..." -ForegroundColor Cyan
    
    # Get the license that actually has a key attached
    $License = Get-CimInstance SoftwareLicensingProduct | Where-Object { $_.PartialProductKey } | Select-Object -First 1
    
    if ($License) {
        Write-Host "   Product      : $($License.Name)"
        Write-Host "   License Key  : ...$($License.PartialProductKey)"
        
        # Status Code 1 means "Licensed" (Activated)
        if ($License.LicenseStatus -eq 1) {
            Write-Host "   Status       : ACTIVATED (Permanent/Licensed)" -ForegroundColor Green
        }
        else {
            Write-Host "   Status       : NOT ACTIVATED / ERROR ($($License.LicenseStatus))" -ForegroundColor Red
            Write-Host "   Recommended  : Run 'slmgr /ato' to force activation." -ForegroundColor Gray
        }
    }
    else {
        Write-Host "Error: No license key found in firmware." -ForegroundColor Red
    }
    Write-Host ""
}

#17. List Local Admin Users
function Get-LocalAdmins {
    Write-Host "AUDITING LOCAL ADMINISTRATORS..." -ForegroundColor Cyan
    Write-Host ""
    
    # Get members of the built-in Administrators group
    $Admins = Get-LocalGroupMember -Group "Administrators"
    
    foreach ($user in $Admins) {
        # Check if it is a Domain Account or Local Account
        if ($user.ObjectClass -eq 'User') {
            Write-Host "   [USER]  $($user.Name)" -ForegroundColor Yellow
        }
        elseif ($user.ObjectClass -eq 'Group') {
            Write-Host "   [GROUP] $($user.Name)" -ForegroundColor Cyan
        }
        else {
            Write-Host "   [OTHER] $($user.Name)" -ForegroundColor Gray
        }
    }
    
    Write-Host ""
    Write-Host "Done. Verify these users should actually be here." -ForegroundColor Green
}

## LOG STUFF
function Write-ToolLog {
    param (
        [string]$Action
    )

    # 1. Define the "Professional" Path
    # ProgramData is where legitimate admin tools store their data.
    $LogDir = "C:\ProgramData\SysAdminLogs"
    
    # Create directory if it doesn't exist (Silent)
    if (-not (Test-Path $LogDir)) { 
        New-Item -Path $LogDir -ItemType Directory -Force | Out-Null 
    }

    # 2. Daily Log Rotation
    # We put the Date in the filename so you have a history (Log_2023-10-27.txt)
    $DateStamp = Get-Date -Format "yyyy-MM-dd"
    $LogFile = "$LogDir\Helpdesk_Activity_$DateStamp.log"

    # 3. Construct the Data Entry
    $Time = Get-Date -Format "HH:mm:ss"
    $User = $env:USERNAME
    $Computer = $env:COMPUTERNAME
    
    # Format: [TIME] [USER@HOST] ACTION
    $LogEntry = "[$Time] [$User@$Computer] $Action"

    # 4. Write to Disk
    Add-Content -Path $LogFile -Value $LogEntry
}

# Open log
function Open-LogFolder {
    Write-Host "OPENING LOG DIRECTORY..." -ForegroundColor Cyan
    $LogDir = "C:\ProgramData\SysAdminLogs"
    
    if (Test-Path $LogDir) {
        # Opens the folder in Windows Explorer
        Invoke-Item $LogDir
        Write-Host "Folder opened." -ForegroundColor Green
    }
    else {
        Write-Host "No logs found yet." -ForegroundColor Red
    }
}

# ---------------------------------------------------------
# MAIN EXECUTION LOOP
# ---------------------------------------------------------
$RunMenu = $true

while ($RunMenu) {
    # 1. Clear the screen for a fresh look
    Clear-Host
    
    # 2. Draw the Menu
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "      WinAdmin-Automator v1.0" -ForegroundColor White
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "=== MAINTENANCE (THE FIXES) ===" -ForegroundColor Yellow
    Write-Host " 1. Clean System Temps & Browsers"
    Write-Host " 2. Restart Print Spooler"
    Write-Host " 3. Force Group Policy Update"
    Write-Host " 4. Trigger Windows Updates"

    Write-Host "=== SYSTEM HEALTH (THE CHECKS) ===" -ForegroundColor Magenta
    Write-Host " 5. Check Disk Space Usage"
    Write-Host " 6. Check Disk Health (SMART/RAID)"
    Write-Host " 7. Check System Resources (Hogs)"
    Write-Host " 8. Check for Pending Reboot"
    Write-Host " 9. Repair Windows Image (DISM/SFC)"

    Write-Host "=== NETWORK (THE CONNECTIVITY) ===" -ForegroundColor Green
    Write-Host "10. Test Internet Connection Chain"
    Write-Host "11. Get Network Identity (IP/DNS)"
    Write-Host "12. Manage Saved Wi-Fi Profiles"

    Write-Host "=== QUICK INFO (TICKET HELP) ===" -ForegroundColor Cyan
    Write-Host "13. Get Serial Number (Service Tag)"
    Write-Host "14. Show True System Uptime"
    Write-Host "15. Fix System Time Sync"

    Write-Host "=== ADVANCED / AUDIT ===" -ForegroundColor Red
    Write-Host "16. Generate Battery Health Report"
    Write-Host "17. Check Windows License Status"
    Write-Host "18. List Local Admin Users"
    Write-Host "99. Open Activity Logs"
    
    Write-Host ""
    Write-Host " Q. Quit"
    Write-Host "==========================================" -ForegroundColor Cyan

    # 3. Capture Input
    $option = Read-Host "Select an option"

    # 4. Execute Logic
    switch ($option) {
        "1" { 
            Write-ToolLog "Run: Clean-AllSystemJunk"
            Clean-AllSystemJunk
            Pause 
        }
        "2" { 
            Write-ToolLog "Run: Fix-PrintSystem"
            Fix-PrintSystem
            Pause 
        }
        "3" { 
            Write-ToolLog "Run: Run-GPOUpdate"
            Run-GPOUpdate
            Pause 
        }
        "4" { 
            Write-ToolLog "Run: Trigger-WindowsUpdate"
            Trigger-WindowsUpdate
            Pause 
        }
        "5" { 
            Write-ToolLog "Run: Check-StorageSpace"
            Check-StorageSpace
            Pause 
        }
        "6" { 
            Write-ToolLog "Run: Check-DiskHealth"
            Check-DiskHealth
            Pause 
        }
        "7" { 
            Write-ToolLog "Run: Manage-SystemHogs"
            Manage-SystemHogs
            Pause 
        }
        "8" { 
            Write-ToolLog "Run: Check-PendingReboot"
            Check-PendingReboot
            Pause 
        }
        "9" { 
            Write-ToolLog "Run: Repair-WindowsImage"
            Repair-WindowsImage
            Pause 
        }
        "10" { 
            Write-ToolLog "Run: Test-NetworkChain"
            Test-NetworkChain
            Pause 
        }
        "11" { 
            Write-ToolLog "Run: Get-NetworkIntel"
            Get-NetworkIntel
            Pause 
        }
        "12" { 
            Write-ToolLog "Run: Manage-WifiPasswords"
            Manage-WifiPasswords
            Pause 
        }
        "13" { 
            Write-ToolLog "Run: Get-AssetInfo"
            Get-AssetInfo
            Pause 
        }
        "14" { 
            Write-ToolLog "Run: Get-SystemUptime"
            Get-SystemUptime
            Pause 
        }
        "15" { 
            Write-ToolLog "Run: Fix-SystemTime"
            Fix-SystemTime
            Pause 
        }
        "16" { 
            Write-ToolLog "Run: Get-BatteryReport"
            Get-BatteryReport
            Pause 
        }
        "17" { 
            Write-ToolLog "Run: Check-WindowsLicense"
            Check-WindowsLicense
            Pause 
        }
        "18" { 
            Write-ToolLog "Run: Get-LocalAdmins"
            Get-LocalAdmins
            Pause 
        }
        "99" {
            Write-ToolLog "Action: Viewed Logs"
            Open-LogFolder
            Pause
        }
        "Q" {
            Write-ToolLog "Session Ended"
            Write-Host "Goodbye!" -ForegroundColor Green
            Start-Sleep -Seconds 1
            $RunMenu = $false
        }
        "q" {
            Write-ToolLog "Session Ended"
            Write-Host "Goodbye!" -ForegroundColor Green
            Start-Sleep -Seconds 1
            $RunMenu = $false
        }
        Default { 
            Write-Host "Invalid option. Please try again." -ForegroundColor Red 
            Start-Sleep -Seconds 1
        }
    }
}