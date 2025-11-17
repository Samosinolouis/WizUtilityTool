#Requires -Version 5.1

# Wiz Utility Tool 
# 11/17/2025

# Function to check if running as administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Auto-elevate if not running as administrator
if (-not (Test-Administrator)) {
    Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$isAdmin = Test-Administrator

# Create the main form
$form = New-Object System.Windows.Forms.Form
$wrenchEmoji = [char]::ConvertFromUtf32(0x1F527)
$form.Text = "$wrenchEmoji Wiz Utility Tool"
if (-not $isAdmin) {
    $form.Text = "$wrenchEmoji Wiz Utility Tool (Not Admin)"
}
$form.Size = New-Object System.Drawing.Size(900, 600)
$form.StartPosition = "CenterScreen"
$form.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$form.MinimumSize = New-Object System.Drawing.Size(800, 500)
$form.ShowIcon = $false

# Create a panel for the left side controls
$leftPanel = New-Object System.Windows.Forms.Panel
$leftPanel.Location = New-Object System.Drawing.Point(10, 10)
$leftPanel.Size = New-Object System.Drawing.Size(180, 550)
$leftPanel.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$leftPanel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Bottom
$leftPanel.AutoScroll = $true
$form.Controls.Add($leftPanel)

# Create radio buttons
$radioSystemInfo = New-Object System.Windows.Forms.RadioButton
$radioSystemInfo.Location = New-Object System.Drawing.Point(10, 20)
$radioSystemInfo.Size = New-Object System.Drawing.Size(130, 30)
$radioSystemInfo.Text = "System Info"
$radioSystemInfo.ForeColor = [System.Drawing.Color]::White
$radioSystemInfo.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$radioSystemInfo.Checked = $true
$leftPanel.Controls.Add($radioSystemInfo)

$radioCPUMemory = New-Object System.Windows.Forms.RadioButton
$radioCPUMemory.Location = New-Object System.Drawing.Point(10, 60)
$radioCPUMemory.Size = New-Object System.Drawing.Size(130, 30)
$radioCPUMemory.Text = "CPU & Memory"
$radioCPUMemory.ForeColor = [System.Drawing.Color]::White
$radioCPUMemory.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$leftPanel.Controls.Add($radioCPUMemory)

$radioDiskInfo = New-Object System.Windows.Forms.RadioButton
$radioDiskInfo.Location = New-Object System.Drawing.Point(10, 100)
$radioDiskInfo.Size = New-Object System.Drawing.Size(160, 30)
$radioDiskInfo.Text = "Disk Info"
$radioDiskInfo.ForeColor = [System.Drawing.Color]::White
$radioDiskInfo.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$leftPanel.Controls.Add($radioDiskInfo)

$radioNetworkInfo = New-Object System.Windows.Forms.RadioButton
$radioNetworkInfo.Location = New-Object System.Drawing.Point(10, 140)
$radioNetworkInfo.Size = New-Object System.Drawing.Size(160, 30)
$radioNetworkInfo.Text = "Network Info"
$radioNetworkInfo.ForeColor = [System.Drawing.Color]::White
$radioNetworkInfo.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$leftPanel.Controls.Add($radioNetworkInfo)

$radioFullSnapshot = New-Object System.Windows.Forms.RadioButton
$radioFullSnapshot.Location = New-Object System.Drawing.Point(10, 180)
$radioFullSnapshot.Size = New-Object System.Drawing.Size(160, 30)
$radioFullSnapshot.Text = "Full System Snapshot"
$radioFullSnapshot.ForeColor = [System.Drawing.Color]::White
$radioFullSnapshot.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$leftPanel.Controls.Add($radioFullSnapshot)

# Create Show Info button
$buttonShowInfo = New-Object System.Windows.Forms.Button
$buttonShowInfo.Location = New-Object System.Drawing.Point(10, 230)
$buttonShowInfo.Size = New-Object System.Drawing.Size(160, 40)
$buttonShowInfo.Text = "Show Info"
$buttonShowInfo.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
$buttonShowInfo.ForeColor = [System.Drawing.Color]::White
$buttonShowInfo.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$buttonShowInfo.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(100, 100, 100)
$buttonShowInfo.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$buttonShowInfo.Cursor = [System.Windows.Forms.Cursors]::Hand
$leftPanel.Controls.Add($buttonShowInfo)

# Create separator label
$labelSeparator = New-Object System.Windows.Forms.Label
$labelSeparator.Location = New-Object System.Drawing.Point(10, 290)
$labelSeparator.Size = New-Object System.Drawing.Size(160, 2)
$labelSeparator.BackColor = [System.Drawing.Color]::FromArgb(100, 100, 100)
$leftPanel.Controls.Add($labelSeparator)

# Create Quick Repairs label
$labelQuickRepairs = New-Object System.Windows.Forms.Label
$labelQuickRepairs.Location = New-Object System.Drawing.Point(10, 300)
$labelQuickRepairs.Size = New-Object System.Drawing.Size(160, 25)
$labelQuickRepairs.Text = "Quick Repairs"
$labelQuickRepairs.ForeColor = [System.Drawing.Color]::FromArgb(180, 180, 180)
$labelQuickRepairs.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$labelQuickRepairs.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$leftPanel.Controls.Add($labelQuickRepairs)

# Create Flush DNS button
$buttonFlushDNS = New-Object System.Windows.Forms.Button
$buttonFlushDNS.Location = New-Object System.Drawing.Point(10, 330)
$buttonFlushDNS.Size = New-Object System.Drawing.Size(160, 35)
$buttonFlushDNS.Text = "Flush DNS"
$buttonFlushDNS.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 50)
$buttonFlushDNS.ForeColor = [System.Drawing.Color]::White
$buttonFlushDNS.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$buttonFlushDNS.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(80, 80, 80)
$buttonFlushDNS.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$buttonFlushDNS.Cursor = [System.Windows.Forms.Cursors]::Hand
$leftPanel.Controls.Add($buttonFlushDNS)

# Create Clear Temp Files button
$buttonClearTemp = New-Object System.Windows.Forms.Button
$buttonClearTemp.Location = New-Object System.Drawing.Point(10, 370)
$buttonClearTemp.Size = New-Object System.Drawing.Size(160, 35)
$buttonClearTemp.Text = "Clear Temp Files"
$buttonClearTemp.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 50)
$buttonClearTemp.ForeColor = [System.Drawing.Color]::White
$buttonClearTemp.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$buttonClearTemp.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(80, 80, 80)
$buttonClearTemp.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$buttonClearTemp.Cursor = [System.Windows.Forms.Cursors]::Hand
$leftPanel.Controls.Add($buttonClearTemp)

# Create Restart Print Spooler button
$buttonRestartSpooler = New-Object System.Windows.Forms.Button
$buttonRestartSpooler.Location = New-Object System.Drawing.Point(10, 410)
$buttonRestartSpooler.Size = New-Object System.Drawing.Size(160, 35)
$buttonRestartSpooler.Text = "Restart Print Spooler"
$buttonRestartSpooler.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 50)
$buttonRestartSpooler.ForeColor = [System.Drawing.Color]::White
$buttonRestartSpooler.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$buttonRestartSpooler.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(80, 80, 80)
$buttonRestartSpooler.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$buttonRestartSpooler.Cursor = [System.Windows.Forms.Cursors]::Hand
$leftPanel.Controls.Add($buttonRestartSpooler)

# Create Restart Windows Update button
$buttonRestartWU = New-Object System.Windows.Forms.Button
$buttonRestartWU.Location = New-Object System.Drawing.Point(10, 450)
$buttonRestartWU.Size = New-Object System.Drawing.Size(160, 35)
$buttonRestartWU.Text = "Restart Win Update"
$buttonRestartWU.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 50)
$buttonRestartWU.ForeColor = [System.Drawing.Color]::White
$buttonRestartWU.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$buttonRestartWU.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(80, 80, 80)
$buttonRestartWU.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$buttonRestartWU.Cursor = [System.Windows.Forms.Cursors]::Hand
$leftPanel.Controls.Add($buttonRestartWU)

# Create output text box
$textBoxOutput = New-Object System.Windows.Forms.TextBox
$textBoxOutput.Location = New-Object System.Drawing.Point(200, 10)
$textBoxOutput.Size = New-Object System.Drawing.Size(680, 525)
$textBoxOutput.Multiline = $true
$textBoxOutput.ReadOnly = $true
$textBoxOutput.ScrollBars = "Vertical"
$textBoxOutput.BackColor = [System.Drawing.Color]::FromArgb(40, 40, 40)
$textBoxOutput.ForeColor = [System.Drawing.Color]::FromArgb(220, 220, 220)
$textBoxOutput.Font = New-Object System.Drawing.Font("Consolas", 9)
$textBoxOutput.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
$textBoxOutput.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$form.Controls.Add($textBoxOutput)

# Create footer label
$labelFooter = New-Object System.Windows.Forms.Label
$labelFooter.Location = New-Object System.Drawing.Point(200, 540)
$labelFooter.Size = New-Object System.Drawing.Size(680, 25)
$labelFooter.Text = "Made by Louis Samosino"
$labelFooter.ForeColor = [System.Drawing.Color]::FromArgb(120, 120, 120)
$labelFooter.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Italic)
$labelFooter.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$labelFooter.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$labelFooter.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
$form.Controls.Add($labelFooter)

# Function to get System Info
function Get-SystemInfo {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $output = "=" * 60 + "`r`n"
    $output += "SYSTEM INFORMATION - $timestamp`r`n"
    $output += "=" * 60 + "`r`n`r`n"
    
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem
        
        $uptime = (Get-Date) - $os.LastBootUpTime
        $uptimeString = "{0} days, {1} hours, {2} minutes" -f $uptime.Days, $uptime.Hours, $uptime.Minutes
        
        $output += "OS Name:        $($os.Caption)`r`n"
        $output += "OS Version:     $($os.Version)`r`n"
        $output += "OS Build:       $($os.BuildNumber)`r`n"
        $output += "Computer Name:  $($cs.Name)`r`n"
        $output += "Uptime:         $uptimeString`r`n"
        $output += "System Type:    $($os.OSArchitecture)`r`n"
    }
    catch {
        $output += "Error retrieving system information: $($_.Exception.Message)`r`n"
    }
    
    $output += "`r`n"
    return $output
}

# Function to get CPU & Memory Info
function Get-CPUMemoryInfo {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $output = "=" * 60 + "`r`n"
    $output += "CPU & MEMORY INFORMATION - $timestamp`r`n"
    $output += "=" * 60 + "`r`n`r`n"
    
    try {
        $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        
        # Get CPU usage
        $cpuUsage = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples.CookedValue
        
        # Memory calculations
        $totalRAM = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        $freeRAM = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
        $usedRAM = [math]::Round($totalRAM - $freeRAM, 2)
        $memoryUsagePercent = [math]::Round(($usedRAM / $totalRAM) * 100, 2)
        
        $output += "CPU Model:      $($cpu.Name.Trim())`r`n"
        $output += "CPU Cores:      $($cpu.NumberOfCores)`r`n"
        $output += "CPU Threads:    $($cpu.NumberOfLogicalProcessors)`r`n"
        $output += "CPU Usage:      $([math]::Round($cpuUsage, 2))%`r`n"
        $output += "`r`n"
        $output += "Total RAM:      $totalRAM GB`r`n"
        $output += "Used RAM:       $usedRAM GB`r`n"
        $output += "Free RAM:       $freeRAM GB`r`n"
        $output += "Memory Usage:   $memoryUsagePercent%`r`n"
    }
    catch {
        $output += "Error retrieving CPU/Memory information: $($_.Exception.Message)`r`n"
    }
    
    $output += "`r`n"
    return $output
}

# Function to get Disk Info
function Get-DiskInfo {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $output = "=" * 60 + "`r`n"
    $output += "DISK INFORMATION - $timestamp`r`n"
    $output += "=" * 60 + "`r`n`r`n"
    
    try {
        $drives = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3"
        
        foreach ($drive in $drives) {
            $totalSpace = [math]::Round($drive.Size / 1GB, 2)
            $freeSpace = [math]::Round($drive.FreeSpace / 1GB, 2)
            $usedSpace = [math]::Round($totalSpace - $freeSpace, 2)
            $usedPercent = [math]::Round(($usedSpace / $totalSpace) * 100, 2)
            
            $output += "Drive:          $($drive.DeviceID)`r`n"
            $output += "Volume Name:    $($drive.VolumeName)`r`n"
            $output += "Total Space:    $totalSpace GB`r`n"
            $output += "Used Space:     $usedSpace GB ($usedPercent%)`r`n"
            $output += "Free Space:     $freeSpace GB`r`n"
            $output += "`r`n"
        }
    }
    catch {
        $output += "Error retrieving disk information: $($_.Exception.Message)`r`n"
    }
    
    return $output
}

# Function to get Network Info
function Get-NetworkInfo {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $output = "=" * 60 + "`r`n"
    $output += "NETWORK INFORMATION - $timestamp`r`n"
    $output += "=" * 60 + "`r`n`r`n"
    
    try {
        # Get network adapter configuration
        $adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
        
        foreach ($adapter in $adapters) {
            $output += "Adapter:        $($adapter.Description)`r`n"
            
            if ($adapter.IPAddress) {
                foreach ($ip in $adapter.IPAddress) {
                    if ($ip -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                        $output += "IP Address:     $ip`r`n"
                    }
                }
            }
            
            if ($adapter.DefaultIPGateway) {
                $output += "Gateway:        $($adapter.DefaultIPGateway -join ', ')`r`n"
            }
            
            if ($adapter.DNSServerSearchOrder) {
                $output += "DNS Servers:    $($adapter.DNSServerSearchOrder -join ', ')`r`n"
            }
            
            if ($adapter.MACAddress) {
                $output += "MAC Address:    $($adapter.MACAddress)`r`n"
            }
            
            $output += "`r`n"
        }
        
        # Ping test to 8.8.8.8
        $output += "---- Connectivity Test ----`r`n"
        $output += "Pinging 8.8.8.8 (Google DNS)...`r`n"
        
        try {
            $pingResult = Test-Connection -ComputerName 8.8.8.8 -Count 4 -ErrorAction Stop
            $avgTime = ($pingResult | Measure-Object -Property ResponseTime -Average).Average
            $output += "Status:         Success`r`n"
            $output += "Packets:        Sent = 4, Received = $($pingResult.Count)`r`n"
            $output += "Avg Response:   $([math]::Round($avgTime, 2)) ms`r`n"
        }
        catch {
            $output += "Status:         Failed`r`n"
            $output += "Error:          $($_.Exception.Message)`r`n"
        }
    }
    catch {
        $output += "Error retrieving network information: $($_.Exception.Message)`r`n"
    }
    
    $output += "`r`n"
    return $output
}

# Function to get Full System Snapshot
function Get-FullSnapshot {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $output = "=" * 60 + "`r`n"
    $output += "FULL SYSTEM SNAPSHOT - $timestamp`r`n"
    $output += "=" * 60 + "`r`n`r`n"
    
    $output += Get-SystemInfo
    $output += "`r`n"
    $output += Get-CPUMemoryInfo
    $output += "`r`n"
    $output += Get-DiskInfo
    $output += "`r`n"
    $output += Get-NetworkInfo
    
    return $output
}

# Function to log action to output
function Write-OutputLog {
    param([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $textBoxOutput.AppendText("[$timestamp] $message`r`n")
}

# Button click event
$buttonShowInfo.Add_Click({
    $textBoxOutput.Clear()
    $textBoxOutput.Text = "Loading information, please wait..."
    $form.Refresh()
    
    try {
        if ($radioSystemInfo.Checked) {
            $textBoxOutput.Text = Get-SystemInfo
        }
        elseif ($radioCPUMemory.Checked) {
            $textBoxOutput.Text = Get-CPUMemoryInfo
        }
        elseif ($radioDiskInfo.Checked) {
            $textBoxOutput.Text = Get-DiskInfo
        }
        elseif ($radioNetworkInfo.Checked) {
            $textBoxOutput.Text = Get-NetworkInfo
        }
        elseif ($radioFullSnapshot.Checked) {
            $textBoxOutput.Text = Get-FullSnapshot
        }
    }
    catch {
        $textBoxOutput.Text = "An error occurred: $($_.Exception.Message)"
    }
})

# Flush DNS button click event
$buttonFlushDNS.Add_Click({
    if (-not $isAdmin) {
        [System.Windows.Forms.MessageBox]::Show(
            "This action requires administrator privileges.`r`n`r`nPlease run the tool as Administrator.",
            "Administrator Required",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return
    }
    
    $textBoxOutput.Clear()
    Write-OutputLog "Flushing DNS cache..."
    
    try {
        $result = ipconfig /flushdns 2>&1
        Write-OutputLog "DNS cache flushed successfully!"
        Write-OutputLog $result
    }
    catch {
        Write-OutputLog "Error: $($_.Exception.Message)"
    }
})

# Clear Temp Files button click event
$buttonClearTemp.Add_Click({
    if (-not $isAdmin) {
        [System.Windows.Forms.MessageBox]::Show(
            "This action requires administrator privileges.`r`n`r`nPlease run the tool as Administrator.",
            "Administrator Required",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return
    }
    
    $textBoxOutput.Clear()
    Write-OutputLog "Clearing temporary files..."
    
    try {
        $tempPaths = @(
            $env:TEMP,
            "C:\Windows\Temp"
        )
        
        $totalDeleted = 0
        $totalSize = 0
        
        foreach ($path in $tempPaths) {
            if (Test-Path $path) {
                Write-OutputLog "Scanning: $path"
                $files = Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                
                foreach ($file in $files) {
                    try {
                        $size = $file.Length
                        Remove-Item -Path $file.FullName -Force -Recurse -ErrorAction SilentlyContinue
                        $totalDeleted++
                        $totalSize += $size
                    }
                    catch {
                        # Skip files in use
                    }
                }
            }
        }
        
        $sizeMB = [math]::Round($totalSize / 1MB, 2)
        Write-OutputLog "Completed! Deleted $totalDeleted files ($sizeMB MB)"
    }
    catch {
        Write-OutputLog "Error: $($_.Exception.Message)"
    }
})

# Restart Print Spooler button click event
$buttonRestartSpooler.Add_Click({
    if (-not $isAdmin) {
        [System.Windows.Forms.MessageBox]::Show(
            "This action requires administrator privileges.`r`n`r`nPlease run the tool as Administrator.",
            "Administrator Required",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return
    }
    
    $textBoxOutput.Clear()
    Write-OutputLog "Restarting Print Spooler service..."
    
    try {
        Stop-Service -Name Spooler -Force -ErrorAction Stop
        Write-OutputLog "Print Spooler stopped."
        Start-Sleep -Seconds 2
        Start-Service -Name Spooler -ErrorAction Stop
        Write-OutputLog "Print Spooler started successfully!"
        
        $service = Get-Service -Name Spooler
        Write-OutputLog "Service Status: $($service.Status)"
    }
    catch {
        Write-OutputLog "Error: $($_.Exception.Message)"
    }
})

# Restart Windows Update button click event
$buttonRestartWU.Add_Click({
    if (-not $isAdmin) {
        [System.Windows.Forms.MessageBox]::Show(
            "This action requires administrator privileges.`r`n`r`nPlease run the tool as Administrator.",
            "Administrator Required",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return
    }
    
    $textBoxOutput.Clear()
    Write-OutputLog "Restarting Windows Update service..."
    
    try {
        Stop-Service -Name wuauserv -Force -ErrorAction Stop
        Write-OutputLog "Windows Update service stopped."
        Start-Sleep -Seconds 2
        Start-Service -Name wuauserv -ErrorAction Stop
        Write-OutputLog "Windows Update service started successfully!"
        
        $service = Get-Service -Name wuauserv
        Write-OutputLog "Service Status: $($service.Status)"
    }
    catch {
        Write-OutputLog "Error: $($_.Exception.Message)"
    }
})

# Initial welcome message
$adminStatus = if ($isAdmin) { "Administrator" } else { "Standard User" }
$welcomeMessage = @"
============================================================
         Welcome to Wiz Utility Tool
============================================================

Running as: $adminStatus

Select an option from the left panel and click 'Show Info'
to display system information.

Information Options:
   System Info           - OS and computer details
   CPU & Memory          - Processor and RAM usage
   Disk Info             - Storage information
   Network Info          - IP, DNS, and connectivity
   Full System Snapshot  - Complete system overview

Quick Repairs:
   Flush DNS             - Clear DNS cache
   Clear Temp Files      - Remove temporary files
   Restart Print Spooler - Fix printing issues
   Restart Win Update    - Fix Windows Update

Note: Quick Repairs require Administrator privileges.

============================================================
"@

$textBoxOutput.Text = $welcomeMessage

# Show the form
[void]$form.ShowDialog()
