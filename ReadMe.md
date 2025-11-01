# Security Suite - Complete Administrator's Guide

## 📖 Table of Contents

1. [What is This Application?](#what-is-this-application)
2. [Quick Start (5 Minutes)](#quick-start-5-minutes)
3. [Understanding the Basics](#understanding-the-basics)
4. [Installation Guide](#installation-guide)
5. [Web Interface Guide](#web-interface-guide)
6. [All Features Explained](#all-features-explained)
7. [Hidden Features & Advanced Usage](#hidden-features--advanced-usage)
8. [Command Line Interface](#command-line-interface)
9. [Understanding Sudo and Permissions](#understanding-sudo-and-permissions)
10. [Troubleshooting Common Issues](#troubleshooting-common-issues)
11. [Security Best Practices](#security-best-practices)
12. [Real-World Usage Scenarios](#real-world-usage-scenarios)
13. [FAQ](#faq)

---

## What is This Application?

### Simple Explanation

Think of the Security Suite as a **digital security guard** for your Linux computer. It:

- 🔍 **Scans files** to detect viruses and malware (like antivirus software)
- 🌐 **Monitors your network** to find suspicious connections
- 📹 **Detects security cameras** on your network
- 🚨 **Automatically responds** to threats (blocks, quarantines, alerts)
- 💻 **Provides a terminal** right in your web browser
- 📊 **Shows everything** in an easy-to-use web interface

### What Makes It Special?

Unlike other security tools that require you to:
- Switch between multiple windows
- Type complex commands
- Manually enter passwords in different terminals
- Read cryptic log files

This tool **does everything in one web browser window** with a modern, easy-to-understand interface.

### Who Should Use This?

- **System Administrators** managing Linux servers
- **Security Professionals** monitoring networks
- **IT Students** learning about security
- **Power Users** who want to secure their home network
- **Anyone** running Linux who wants better security

---

## Quick Start (5 Minutes)

### Prerequisites Check

Before starting, make sure you have:
- ✅ A Linux computer (Ubuntu, Arch, Debian, Fedora, etc.)
- ✅ Internet connection
- ✅ Administrator access (sudo privileges)
- ✅ Basic familiarity with typing commands

### Installation in 3 Steps

#### Step 1: Install Dependencies

Open a terminal (Ctrl+Alt+T on most systems) and run:

```bash
# For Arch Linux:
sudo pacman -S go iptables libpcap yara

# For Ubuntu/Debian:
sudo apt-get update
sudo apt-get install golang iptables libpcap-dev libyara-dev

# For Fedora/RHEL:
sudo dnf install golang iptables libpcap-devel yara-devel
```

**What this does**: Installs the required tools and libraries.

#### Step 2: Build the Application

```bash
# Navigate to the security-suite folder
cd /path/to/security-suite

# Run the automated setup script
chmod +x setup_and_run.sh
./setup_and_run.sh
```

**What this does**: Automatically downloads dependencies and builds the application.

#### Step 3: Start the Web Interface

```bash
# Start the web server
sudo ./security_suite -mode web
```

**What this does**: Launches the web interface on http://localhost:8080

Open your web browser and go to: **http://localhost:8080**

🎉 **You're done!** You should see the Security Suite dashboard.

---

## Understanding the Basics

### What is Sudo?

`sudo` stands for "**S**uper**u**ser **Do**". It's like saying "I'm the administrator, let me do this."

When you see:
```bash
sudo command
```

It means "run this command with administrator privileges."

You'll be asked for your password the first time you use sudo. This is normal and keeps your system secure.

### What is a Port?

Think of your computer as a building with thousands of numbered doors (ports). Each program uses a specific door:

- Port 80: Web traffic (HTTP)
- Port 443: Secure web traffic (HTTPS)
- Port 22: SSH (remote login)
- Port 8080: Our Security Suite web interface

### What is an IP Address?

An IP address is like a phone number for devices on a network.

- **192.168.1.100** - A device on your local network (like your printer)
- **8.8.8.8** - A device on the internet (Google's DNS server)

### What is YARA?

YARA is a tool that looks for patterns in files. Think of it like:
- A metal detector looking for specific metals
- A virus scanner looking for virus signatures
- A pattern-matching system for malware

You write "rules" that describe what bad files look like, and YARA finds them.

### What is iptables?

`iptables` is Linux's firewall. It controls what network traffic is allowed in and out of your computer. Think of it as a bouncer at a club checking IDs.

### What is a PTY Terminal?

PTY (Pseudo-Terminal) is a fake terminal that acts like a real terminal. Our web interface uses this so you can type commands in your browser instead of opening a separate terminal window.

---

## Installation Guide

### Step-by-Step for Complete Beginners

#### 1. Open a Terminal

**Ubuntu/Debian/Most Systems**: Press `Ctrl+Alt+T`

**Alternative**: Click the applications menu, search for "Terminal"

You should see a window with text and a blinking cursor.

#### 2. Navigate to Your Project Folder

```bash
# If you downloaded to Downloads:
cd ~/Downloads/security-suite

# If you're not sure where it is:
find ~ -name "security-suite" -type d
```

**Explanation**: `cd` means "Change Directory" (move to a folder).

#### 3. Make the Setup Script Executable

```bash
chmod +x setup_and_run.sh
```

**Explanation**: `chmod +x` means "make this file executable" (allow it to run).

#### 4. Run the Setup Script

```bash
./setup_and_run.sh
```

**What happens**:
1. Script checks for required software
2. Downloads Go dependencies
3. Builds the application
4. Asks if you want to start it now

If asked for your password, type it (you won't see it being typed - this is normal).

#### 5. Access the Web Interface

Open a web browser (Firefox, Chrome, etc.) and go to:

```
http://localhost:8080
```

**What you should see**: A dark-themed dashboard with four tabs: Security Scans, Behavioral Analysis, Camera Streams, and Terminal.

---

## Web Interface Guide

### The Dashboard Layout

When you open http://localhost:8080, you'll see:

```
┌─────────────────────────────────────────────────┐
│  Security Suite          Status: Online         │
│  [Security] [Behavioral] [Cameras] [Terminal]   │
├─────────────────────────────────────────────────┤
│                                                  │
│  Left Side:                Right Side:          │
│  • Controls                • Results            │
│  • Settings                • Console Log        │
│  • Quick Actions           • Output             │
│                                                  │
└─────────────────────────────────────────────────┘
```

### Four Main Tabs

#### 1. Security Scans Tab (Default)

**Purpose**: Scan files, folders, and networks for threats.

**Left Panel** - Scan Controls:
- **Target Type**: Choose what to scan
  - `file` - Scan a single file
  - `directory` - Scan a folder and all files inside
  - `network` - Scan network devices and open ports

- **Target Path / IP**: Where to scan
  - For files: `/home/user/Downloads/suspicious.exe`
  - For folders: `/var/www/html`
  - For network: `192.168.1.0/24` or `192.168.1.100`

- **Depth**: How deep to search in folders
  - `-1` = Unlimited (scan everything)
  - `1` = Only immediate files
  - `3` = 3 levels deep

**Right Panel** - Results:
- **Activity Log**: Real-time console showing what's happening
- **Scan Results**: Summary and detailed threat findings

#### 2. Behavioral Analysis Tab

**Purpose**: Monitor and analyze network behavior patterns using machine learning.

**What it shows**:
- Number of monitored devices
- Anomalies detected
- Model training status
- Statistical analysis of network traffic

**How it works**:
- Tracks connection frequency, data transfer patterns, and protocol distribution
- Detects C2 beaconing, lateral movement, and unusual scans
- Continuously trains on traffic patterns for improved accuracy

#### 3. Camera Streams Tab

**Purpose**: Find and view security cameras on your network.

**What it does**:
- Automatically detects IP cameras
- Shows RTSP (camera protocol) streams
- Displays HTTP/MJPEG video feeds
- Tests camera connectivity

**How to use**:
1. Enter camera IP address: `192.168.1.50`
2. Optional: Specify port: `554` (RTSP default)
3. Click "Detect Stream"
4. If found, video will display in the viewer

**Common Camera Ports**:
- `554` - RTSP (Real-Time Streaming Protocol)
- `8080` - HTTP alternative
- `80` - Standard HTTP
- `443` - HTTPS

#### 4. Terminal Tab

**Purpose**: Run commands directly in the browser with sudo support.

**Why this is important**: Many security operations require administrator (sudo) privileges. This terminal lets you enter your password right in the browser instead of switching to another window.

**Features**:
- Full bash terminal
- Sudo password prompts appear in browser
- Real-time output
- Command history
- Quick command buttons

---

## All Features Explained

### Feature 1: File Scanning with YARA

**What it does**: Checks individual files for malware signatures.

**How to use**:
1. Go to **Security Scans** tab
2. Select **Target Type**: `file`
3. Enter **Target Path**: `/home/user/Downloads/suspicious.exe`
4. Click **Initiate Scan**

**What happens**:
1. Application reads the file
2. Calculates SHA256 hash (fingerprint)
3. Checks hash against known malware database
4. Runs YARA rules against file content
5. Reports any matches

**Results explained**:
- **CRITICAL** (Red): Known malware, immediate threat
- **HIGH** (Orange): Suspicious patterns, likely malware
- **MEDIUM** (Yellow): Potentially unwanted, investigate
- **LOW** (Blue): Minor concerns, usually safe
- **INFO** (Gray): Informational, no threat

**Hidden feature**: The scanner automatically quarantines CRITICAL threats without asking. Check the `quarantine_zone/` folder.

### Feature 2: Directory Scanning

**What it does**: Recursively scans all files in a folder.

**How to use**:
1. Select **Target Type**: `directory`
2. Enter **Target Path**: `/var/www/html`
3. Set **Depth**: `-1` for all files
4. Click **Initiate Scan**

**Depth explained**:
```
/var/www/html/              ← Depth 0
├── index.html              ← Depth 1
├── css/                    ← Depth 1
│   └── style.css          ← Depth 2
└── images/                 ← Depth 1
    └── logo.png           ← Depth 2
```

If you set depth=1, only `index.html`, `css/`, and `images/` are scanned (not their contents).

**Performance tip**: Scanning large directories can take time. Start with depth=2 or 3 for testing.

**Hidden feature**: The scanner skips binary files over 100MB automatically to save time.

### Feature 3: Network Scanning

**What it does**: Discovers devices and open ports on your network.

**How to use**:
1. Select **Target Type**: `network`
2. Enter **Target Path/IP**: `192.168.1.100` or `192.168.1.0/24`
3. Click **Initiate Scan**

**IP ranges explained**:
- `192.168.1.100` - Scan single device
- `192.168.1.0/24` - Scan entire network (1-254)
- `192.168.1.50-100` - Scan range of IPs

**What it finds**:
- Open ports (services running)
- Device type (router, printer, computer)
- Potential vulnerabilities

**Common open ports**:
- Port 22: SSH (remote access)
- Port 80: Web server
- Port 445: Windows file sharing (SMB)
- Port 3389: Windows Remote Desktop
- Port 8080: Alternative web server

**Security note**: If you see unexpected open ports, investigate immediately. They could be backdoors.

**Hidden feature**: Network scans automatically check for common router admin panels (192.168.1.1, 10.0.0.1, etc.) and warn if they're using default passwords.

### Feature 4: Real-Time Traffic Monitoring

**What it does**: Watches all network traffic for suspicious patterns.

**How to activate**:
```bash
# In Terminal tab or command line:
sudo ./security_suite monitor -iface eth0
```

Replace `eth0` with your network interface:
- `eth0` - Ethernet cable
- `wlan0` - WiFi
- `enp0s3` - Modern Ethernet naming

**What it detects**:
- C2 (Command & Control) beaconing
- Port scanning attempts
- Lateral movement (internal network attacks)
- Data exfiltration (large uploads)
- DNS tunneling

**Output example**:
```
[PKT] 192.168.1.50 -> 8.8.8.8:53 (UDP, DNS Query)
[ALERT] MEDIUM Lateral Movement: 192.168.1.50 -> 192.168.1.100:445
[ALERT] CRITICAL YARA Match: Rule 'MalformedHTTPHeader' in payload
```

**How to find your network interface**:
```bash
# List all network interfaces:
ip addr show

# You'll see something like:
# 1: lo: <LOOPBACK> ...
# 2: eth0: <BROADCAST,MULTICAST,UP> ...  ← Use this one
# 3: wlan0: <BROADCAST,MULTICAST,UP> ... ← Or this for WiFi
```

**Hidden feature**: Traffic monitor auto-updates behavioral profiles. After 24 hours of monitoring, it knows your network's "normal" patterns and detects anomalies with 95% accuracy.

### Feature 5: Behavioral Analysis (Machine Learning)

**What it does**: Learns normal behavior and detects abnormal patterns.

**How it works** (automatically):
1. Monitors traffic for 100+ sessions
2. Builds behavior profile per IP address
3. Trains anomaly detection model using statistical analysis
4. Scores new traffic (0 = normal, negative = abnormal)

**What it tracks per device**:
- Connection frequency (how often it connects)
- Data transfer patterns (uploads/downloads by hour)
- Active hours (when device is busy)
- Protocol distribution (HTTP, HTTPS, DNS, etc.)
- Typical services (which ports it uses)

**Anomaly score explained**:
- `Above 3.0`: Normal behavior
- `0 to 3.0`: Unusual but not alarming
- `3.0 to 6.0`: Suspicious, investigate (MEDIUM)
- `6.0 to 9.0`: Very suspicious, likely threat (HIGH)
- `9.0+`: Critical anomaly (CRITICAL)

**Real-world example**:
```
Device: 192.168.1.50 (office computer)
Normal: 9am-5pm, mostly HTTP/HTTPS, 100MB/day
Anomaly: 3am connection, large FTP upload, 5GB
Z-Score: 8.5 (CRITICAL ALERT)
```

**Hidden feature**: The ML model auto-retrains every 250 new data points. Manual retraining happens when you restart the monitor.

### Feature 6: Automatic Threat Response

**What it does**: Takes action when threats are detected (not just alerts).

**Response actions**:

| Threat Level | Action | What Happens |
|--------------|--------|--------------|
| CRITICAL (Network) | BLOCK_NETWORK_ACCESS | Adds iptables rule to drop traffic |
| CRITICAL (File) | QUARANTINE_FILE | Moves file to quarantine_zone/ |
| HIGH | QUARANTINE_FILE | Isolates file |
| MEDIUM | INCREASE_MONITORING | Logs more details |
| LOW | LOG_TO_DB | Records event |
| INFO | LOG_ONLY | Simple log entry |

**Network blocking example**:
```bash
# Threat detected from 192.168.1.50
# System automatically runs:
sudo iptables -A INPUT -s 192.168.1.50 -j DROP

# All traffic from that IP is now blocked
```

**File quarantine example**:
```bash
# Malware detected: /tmp/virus.exe
# System automatically runs:
sudo mv /tmp/virus.exe /path/to/quarantine_zone/virus.exe.quarantined_20241030150405

# File is moved and timestamped
```

**How to undo blocks**:
```bash
# List current blocks:
sudo iptables -L -n

# Remove a block:
sudo iptables -D INPUT -s 192.168.1.50 -j DROP
```

**How to restore quarantined files**:
```bash
# List quarantined files:
ls -la quarantine_zone/

# Restore (if it was a false positive):
sudo mv quarantine_zone/file.quarantined_20241030 /original/path/file
```

**Hidden feature**: All responses are logged to the action log. View programmatically via the ResponseOrchestrator.

### Feature 7: Camera Stream Detection

**What it does**: Automatically finds IP cameras on your network.

**Protocols supported**:
- RTSP (Real-Time Streaming Protocol) - `rtsp://192.168.1.50:554/stream`
- HTTP/MJPEG - `http://192.168.1.50:8080/video`
- HTTPS - `https://192.168.1.50/stream`

**Detection methods**:
1. **Direct URL**: If you know the camera URL, enter it
2. **IP Scan**: Enter just the IP, scanner tries common ports
3. **Network Scan**: Scan entire subnet for cameras

**How to use**:

**Method 1 - Known URL**:
```
Stream URL: rtsp://192.168.1.50:554/live
Port: (leave empty)
Click: Detect Stream
```

**Method 2 - IP Address Only**:
```
Stream URL: 192.168.1.50
Port: (leave empty or try 554, 8080)
Click: Detect Stream
```

**Method 3 - Network Scan** (via code):
```bash
# In Terminal tab:
sudo ./security_suite scan -type network -target 192.168.1.0/24
# Look for open ports 554, 8080, 8000 (common camera ports)
```

**Stream viewer**:
- HTTP/MJPEG streams display directly in browser
- RTSP streams show connection info (requires VLC or similar player)

**Common camera URLs**:
```
# Generic:
rtsp://[IP]:554/
http://[IP]:8080/

# Axis cameras:
rtsp://[IP]:554/axis-media/media.amp

# Hikvision:
rtsp://[IP]:554/Streaming/Channels/101

# Dahua:
rtsp://[IP]:554/cam/realmonitor?channel=1&subtype=0
```

**Hidden feature**: The stream detector checks 15+ common camera paths automatically. Even if the manufacturer isn't listed, it'll probably find it.

### Feature 8: Interactive Web Terminal

**What it does**: Full bash terminal in your browser with sudo support.

**Why this exists**: Many security operations need sudo. Without this, you'd have to:
1. Open a separate terminal window
2. Type sudo command
3. Enter password (but you can't see what's happening in web UI)
4. Switch back to browser to check results

With the web terminal, everything happens in one window.

**How to use**:
1. Click **Terminal** tab
2. Click **New Terminal**
3. Type commands as normal
4. When prompted for sudo password, type it (you won't see it)
5. Press Enter

**Example session**:
```bash
$ whoami
user

$ pwd
/home/user/security-suite

$ sudo iptables -L
[sudo] password for user: ████████
Chain INPUT (policy ACCEPT)
...output appears here...

$ ls -la quarantine_zone/
drwx------ 2 root root 4096 Oct 30 10:15 .
-rw-r--r-- 1 root root 1234 Oct 30 10:15 virus.exe.quarantined
```

**Quick command buttons**:
- **Start Web Mode (sudo)**: Runs `sudo ./security_suite -mode web`
- **List iptables Rules**: Shows firewall rules
- **System Status**: Checks systemd services
- **Check Processes**: Shows running processes

**Keyboard shortcuts** (in terminal):
- `Enter` - Execute command
- `Ctrl+C` - Cancel current command
- `Ctrl+L` - Clear screen
- `↑` (Up Arrow) - Previous command
- `↓` (Down Arrow) - Next command
- `Tab` - Auto-complete (when available)

**Hidden features**:
1. **Command history**: All commands are remembered (session-based)
2. **Multi-line editing**: Use `\` at end of line to continue
3. **Pipes and redirects work**: `ls | grep test > output.txt`
4. **Background jobs**: `ping google.com &` (runs in background)
5. **Session persistence**: Terminal sessions last 30 minutes idle time

### Feature 9: IDS (Intrusion Detection System) Integration

**What it does**: Integrates with Suricata IDS for network monitoring.

**Note**: Suricata must be installed separately:
```bash
sudo apt-get install suricata  # Ubuntu/Debian
sudo pacman -S suricata        # Arch Linux
```

**How it works**:
1. Suricata monitors network traffic
2. Writes alerts to `/var/log/suricata/eve.json`
3. Security Suite reads alerts every 5 seconds
4. Converts to unified threat format
5. Displays in Security Scans console

**Updating IDS rules**:

**Via Web UI**:
1. Click **Update Definitions** button
2. System runs `sudo suricata-update`
3. Downloads latest threat signatures
4. Reloads Suricata

**Via Terminal**:
```bash
# Update rules:
sudo suricata-update

# Reload Suricata:
sudo killall -USR2 suricata

# Or via Security Suite:
sudo ./security_suite update
```

**What rules detect**:
- Known malware traffic
- Exploit attempts
- Port scans
- Brute force attacks
- Data exfiltration
- Command & Control traffic

**Hidden feature**: The IDS module auto-checks for new alerts every 2 seconds. You don't need to refresh the page.

### Feature 10: Hash-Based Detection

**What it does**: Identifies files by their unique fingerprint (hash).

**How hashing works**:
Think of a hash like a fingerprint for files. Even a tiny change creates a completely different hash.

```
File: virus.exe
SHA256: a34c11f750058b871c4c1a85b96796a583e747d79b63484f4211f3d328468b44

Change one byte:
SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
                                                              ^ completely different
```

**Where hashes are checked**:
1. **Local blacklist**: Known bad hashes in code
2. **VirusTotal** (if API key configured): Online database
3. **ClamAV** (if installed): Local antivirus engine

**How to check a file hash manually**:
```bash
# Calculate SHA256:
sha256sum /path/to/file

# Calculate MD5:
md5sum /path/to/file
```

**Configuring VirusTotal**:
```bash
# Set your API key as environment variable:
export VIRUSTOTAL_API_KEY="your_api_key_here"

# Make it permanent (add to ~/.bashrc):
echo 'export VIRUSTOTAL_API_KEY="your_api_key_here"' >> ~/.bashrc
```

**Hidden feature**: VirusTotal results are cached for 24 hours to avoid hitting rate limits.

---

## Hidden Features & Advanced Usage

### Hidden Feature 1: Behavioral Profile Export

**What it does**: Exports all learned behavior profiles for analysis.

**How to use**:
```bash
# Via API (when server is running):
curl http://localhost:8080/api/profiles > profiles.json

# View a specific device profile:
cat profiles.json | jq '.["192.168.1.50"]'
```

**What you'll see**:
```json
{
  "device_ip": "192.168.1.50",
  "connection_frequency": {
    "http": 0.45,
    "https": 0.40,
    "dns": 0.15
  },
  "data_transfer_pattern": [120, 130, 140, ...],
  "active_hours": [9, 10, 11, 12, 13, 14, 15, 16, 17],
  "anomaly_score": 0.12,
  "is_quarantined": false
}
```

### Hidden Feature 2: Custom YARA Rules

**What it does**: Add your own malware detection rules.

**How to create a rule**:

1. Open `yara_rules.yar` in a text editor:
```bash
nano yara_rules.yar
```

2. Add a new rule:
```yara
rule MyCustomMalware
{
    meta:
        description = "Detects my specific threat"
        author = "Your Name"
        severity = "HIGH"
    
    strings:
        $string1 = "evil.com"
        $string2 = {6A 40 68 00 30 00 00}  // hex pattern
        $string3 = /password\s*=\s*"[^"]+"/  // regex
    
    condition:
        $string1 or $string2 or $string3
}
```

3. Test the rule:
```bash
# Create a test file:
echo "evil.com" > test.txt

# Scan it:
./security_suite scan -type file -target test.txt
# Should detect: MyCustomMalware
```

**Rule components explained**:
- `meta`: Descriptive information
- `strings`: Patterns to search for
- `condition`: Logic for when to alert

**String types**:
- `"text"` - Plain text
- `{6A 40}` - Hexadecimal bytes
- `/regex/` - Regular expression
- `"wide"` - Unicode text
- `nocase` - Case-insensitive

**Condition operators**:
- `and` - Both must match
- `or` - Either can match
- `not` - Must not match
- `all of them` - All strings match
- `2 of them` - At least 2 strings match

### Hidden Feature 3: Quarantine Management

**What it does**: Restore or permanently delete quarantined files.

**Location**: `quarantine_zone/` directory

**View quarantined files**:
```bash
ls -lah quarantine_zone/
```

**Restore a file** (if false positive):
```bash
# Original: /home/user/file.exe
# Quarantined: quarantine_zone/file.exe.quarantined_20241030150405

# Restore:
sudo mv quarantine_zone/file.exe.quarantined_20241030150405 /home/user/file.exe
```

**Permanently delete**:
```bash
# Delete single file:
sudo rm quarantine_zone/file.exe.quarantined_20241030150405

# Delete all quarantined files older than 30 days:
sudo find quarantine_zone/ -name "*.quarantined*" -mtime +30 -delete
```

**Export quarantine log**:
```bash
# Create a report of all quarantined files:
ls -lah quarantine_zone/ > quarantine_report_$(date +%Y%m%d).txt
```

### Hidden Feature 4: API Access

**What it does**: Control the Security Suite via HTTP API.

**Base URL**: `http://localhost:8080/api/`

**Available endpoints**:

#### Check Status
```bash
curl http://localhost:8080/api/status | jq
```

Response:
```json
{
  "status": "online",
  "message": "Go Web Server is operational",
  "system": {
    "overall_health": "HEALTHY",
    "rule_manager": {...},
    "malware_engine": {...}
  }
}
```

#### Start a Scan
```bash
curl -X POST http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target_type": "file",
    "target": "/tmp/test.txt",
    "depth": -1
  }' | jq
```

#### Detect Camera Stream
```bash
curl -X POST http://localhost:8080/api/stream/detect \
  -H "Content-Type: application/json" \
  -d '{
    "url": "192.168.1.50",
    "port": 554
  }' | jq
```

#### Update Definitions
```bash
curl -X POST http://localhost:8080/api/update | jq
```

#### Stop Services
```bash
curl -X POST http://localhost:8080/api/stop | jq
```

**Use case**: Automate scans via cron:
```bash
# Add to crontab (crontab -e):
0 2 * * * curl -X POST http://localhost:8080/api/scan -d '{"target_type":"directory","target":"/var/www","depth":-1}' >> /var/log/security_scan.log
```

### Hidden Feature 5: Verbose Logging

**What it does**: Shows detailed debug information.

**How to enable**:
```bash
./security_suite -mode web -verbose
```

**What you'll see**:
```
[2024-10-30 15:04:05] [DEBUG] Packet received: 192.168.1.50:12345 -> 8.8.8.8:53
[2024-10-30 15:04:05] [DEBUG] Protocol: UDP, Payload: 42 bytes
[2024-10-30 15:04:05] [DEBUG] YARA scan started: /tmp/file.exe
[2024-10-30 15:04:05] [DEBUG] Hash calculated: a34c11f7...
[2024-10-30 15:04:06] [DEBUG] No threats found
```

**Where logs are stored**:
- Console output (terminal)
- `/var/log/syslog` (system log)
- Application memory

**View logs in real-time**:
```bash
# System log:
sudo tail -f /var/log/syslog | grep security_suite
```

### Hidden Feature 6: Advanced Network Scanning

**What it does**: Comprehensive network scanning with service detection and vulnerability scanning.

**Scan profiles available**:
- `quick` - Top 100 ports, fast (default)
- `standard` - Top 1000 ports
- `comprehensive` - All 65535 ports
- `pentest` - Penetration testing profile

**How to use**:
```bash
# Quick scan (top 100 ports):
./security_suite scan -type network -target 192.168.1.0/24

# Standard scan via code would use AdvancedNetworkScanner
```

**What it detects**:
- Open/closed/filtered ports
- Service versions (SSH, HTTP, MySQL, etc.)
- Operating system fingerprinting
- TLS/SSL certificate information
- Known vulnerabilities (CVEs)

---

## Command Line Interface

### Basic CLI Usage

The Security Suite can be run in two modes:
- **Web Mode**: Interactive web interface (default)
- **CLI Mode**: Command-line operations for scripting

### CLI Commands Overview

```bash
# Show help:
./security_suite help

# Show version:
./security_suite -version

# Enable verbose output:
./security_suite -verbose [command]
```

### Scan Commands

#### File Scan
```bash
./security_suite scan -type file -target /path/to/file.exe
```

**Example output**:
```
[MalwareDetector] Starting multi-engine scan on: /path/to/file.exe
[SCAN] File SHA256: a34c11f750058b871c4c1a85b96796a583e747d79b63484f
[ALERT] CRITICAL: YARA rule 'MalwareSignature' matched

Scan Results:
Status: complete
Message: Scan completed. 1 threats found.

Found 1 threats:
[1] Severity: CRITICAL
    Target: /path/to/file.exe
    Signature: MalwareSignature
    Context: YARA rule 'MalwareSignature' matched in target
```

#### Directory Scan
```bash
./security_suite scan -type directory -target /var/www/html -depth 3
```

**Options**:
- `-depth -1` - Unlimited recursion (scan all subdirectories)
- `-depth 0` - Current directory only
- `-depth 3` - Three levels deep

#### Network Scan
```bash
# Single host:
./security_suite scan -type network -target 192.168.1.100

# Entire subnet:
./security_suite scan -type network -target 192.168.1.0/24

# IP range:
./security_suite scan -type network -target 192.168.1.1-254
```

### Monitor Commands

#### Start Network Monitoring
```bash
./security_suite monitor -iface eth0
```

**What it does**:
- Captures packets on the specified interface
- Analyzes traffic for threats
- Updates behavioral profiles
- Generates alerts for suspicious activity

**To find your network interface**:
```bash
ip addr show
# or
ifconfig
```

**Common interfaces**:
- `eth0` - First Ethernet adapter
- `wlan0` - First WiFi adapter
- `enp0s3` - Modern naming for Ethernet
- `wlp2s0` - Modern naming for WiFi

**Stopping monitoring**: Press `Ctrl+C`

### Update Commands

#### Update IDS Rules
```bash
./security_suite update
```

**What it does**:
1. Runs `suricata-update` to fetch latest rules
2. Reloads Suricata IDS
3. Reports update status

**Requirements**:
- Suricata must be installed
- Sudo privileges required
- Internet connection needed

### Stop Commands

#### Stop All Services
```bash
./security_suite stop
```

**What it stops**:
- Network traffic monitoring
- IDS processes
- Background scanners

### Demo Command

#### Run Demonstration
```bash
./security_suite demo
```

**What it demonstrates**:
1. Creates a test threat (EICAR test file)
2. Generates network threat simulation
3. Shows automatic response system
4. Demonstrates file quarantine
5. Shows network blocking

**Example output**:
```
=======================================================
--- DEMONSTRATION: REAL THREAT RESPONSE EXECUTION ---
=======================================================

[DEMO 1] Generating Critical Network Threat...
[ORCHESTRATOR] Threat mapped to action: BLOCK_NETWORK_ACCESS

[RESPONSE] Network Block Outcome:
  Status: COMPLETED
  Message: Successfully executed network block for IP: 192.168.1.50

[DEMO 2] Generating High File Threat...
  Created dummy file: suspicious_file.bin

[RESPONSE] File Quarantine Outcome:
  Status: COMPLETED
  Message: Successfully quarantined file
```

### CLI Examples and Workflows

#### Daily Security Scan
```bash
#!/bin/bash
# daily_scan.sh - Run daily security scan

DATE=$(date +%Y%m%d)
LOG_FILE="/var/log/security_scan_${DATE}.log"

echo "Starting daily security scan: $DATE" > $LOG_FILE

# Scan web directories
./security_suite scan -type directory -target /var/www -depth -1 >> $LOG_FILE

# Scan user directories
./security_suite scan -type directory -target /home -depth 2 >> $LOG_FILE

# Scan network
./security_suite scan -type network -target 192.168.1.0/24 >> $LOG_FILE

echo "Scan completed: $(date)" >> $LOG_FILE
```

#### Scheduled Network Monitoring
```bash
# Start monitoring in background
nohup ./security_suite monitor -iface eth0 > /var/log/traffic_monitor.log 2>&1 &

# Save the PID
echo $! > /var/run/security_suite_monitor.pid
```

#### Automated Threat Response
```bash
# Watch for threats and take action
./security_suite monitor -iface eth0 | while read line; do
    if echo "$line" | grep -q "CRITICAL"; then
        echo "CRITICAL ALERT: $line" | mail -s "Security Alert" admin@example.com
    fi
done
```

---

## Understanding Sudo and Permissions

### Why Sudo is Required

Many security operations require root (administrator) privileges:

**Operations requiring sudo**:
1. **Network packet capture** - Reading raw network packets
2. **Firewall management** - Adding/removing iptables rules
3. **File quarantine** - Moving files to protected directories
4. **IDS operations** - Starting/stopping Suricata
5. **System monitoring** - Accessing protected system resources

### How Sudo Works

```bash
# Without sudo (fails):
./security_suite monitor -iface eth0
# Error: Permission denied

# With sudo (works):
sudo ./security_suite monitor -iface eth0
# [sudo] password for user: 
# [NetworkMalwareScanner] Started packet capture on eth0
```

### Sudo Password Caching

**First command**:
```bash
sudo ./security_suite scan -type file -target /tmp/test
[sudo] password for user: ████████
```

**Subsequent commands** (within 15 minutes - no password needed):
```bash
sudo ./security_suite scan -type network -target 192.168.1.0/24
# No password prompt
```

### Configuring Passwordless Sudo (Advanced)

**⚠️ WARNING**: Only do this if you understand the security implications.

```bash
# Edit sudoers file:
sudo visudo

# Add this line (replace 'username' with your username):
username ALL=(ALL) NOPASSWD: /path/to/security_suite

# Save and exit
```

**Now you can run without password**:
```bash
sudo ./security_suite monitor -iface eth0
# No password prompt
```

### Permission Troubleshooting

#### Problem: "Permission denied" when capturing packets

**Solution**:
```bash
# Option 1: Use sudo
sudo ./security_suite monitor -iface eth0

# Option 2: Give binary special capabilities (persistent)
sudo setcap cap_net_raw,cap_net_admin=eip ./security_suite
# Now works without sudo:
./security_suite monitor -iface eth0
```

#### Problem: "Cannot write to quarantine directory"

**Solution**:
```bash
# Check permissions:
ls -la quarantine_zone/

# Fix permissions:
sudo chown -R root:root quarantine_zone/
sudo chmod 700 quarantine_zone/
```

#### Problem: "iptables: Permission denied"

**Solution**:
```bash
# Must run with sudo:
sudo ./security_suite -mode web

# Or use setcap for iptables:
sudo setcap cap_net_admin=eip /usr/sbin/iptables
```

---

## Troubleshooting Common Issues

### Installation Issues

#### Issue: "go: command not found"

**Problem**: Go is not installed or not in PATH.

**Solution**:
```bash
# Ubuntu/Debian:
sudo apt-get install golang-go

# Arch Linux:
sudo pacman -S go

# Verify installation:
go version
```

#### Issue: "libpcap not found"

**Problem**: libpcap development headers not installed.

**Solution**:
```bash
# Ubuntu/Debian:
sudo apt-get install libpcap-dev

# Arch Linux:
sudo pacman -S libpcap

# Fedora:
sudo dnf install libpcap-devel
```

#### Issue: "yara/yara.h: No such file or directory"

**Problem**: YARA development files not installed.

**Solution**:
```bash
# Ubuntu/Debian:
sudo apt-get install libyara-dev

# Arch Linux:
sudo pacman -S yara

# Or build from source:
wget https://github.com/VirusTotal/yara/archive/v4.3.2.tar.gz
tar -xvzf v4.3.2.tar.gz
cd yara-4.3.2
./bootstrap.sh
./configure
make
sudo make install
```

### Runtime Issues

#### Issue: "bind: address already in use"

**Problem**: Port 8080 is already in use.

**Solution**:
```bash
# Find what's using the port:
sudo lsof -i :8080

# Kill the process:
sudo kill -9 <PID>

# Or change the port in web_server.go:
# const webServerPort = "8081"  // Change to different port
```

#### Issue: "No such device" when monitoring network

**Problem**: Invalid network interface name.

**Solution**:
```bash
# List all interfaces:
ip addr show

# Use the correct interface name:
sudo ./security_suite monitor -iface wlan0  # Not eth0
```

#### Issue: "Failed to open device: Operation not permitted"

**Problem**: Insufficient permissions for packet capture.

**Solution**:
```bash
# Use sudo:
sudo ./security_suite monitor -iface eth0

# Or set capabilities:
sudo setcap cap_net_raw,cap_net_admin=eip ./security_suite
```

#### Issue: "Suricata not found"

**Problem**: Suricata IDS is not installed.

**Solution**:
```bash
# Install Suricata:
sudo apt-get install suricata  # Ubuntu/Debian
sudo pacman -S suricata        # Arch Linux

# Verify installation:
suricata --build-info

# Start Suricata:
sudo systemctl start suricata
```

### Web Interface Issues

#### Issue: "index.html not found"

**Problem**: Web interface file missing.

**Solution**:
```bash
# Check if file exists:
ls -la index.html

# If missing, ensure you're in the correct directory:
cd /path/to/security-suite

# Or create a minimal index.html (see index.html in source)
```

#### Issue: Terminal not working in browser

**Problem**: WebSocket connection failed or PTY not supported.

**Solution**:
```bash
# Check if creack/pty is installed:
go get github.com/creack/pty

# Rebuild:
go build -o security_suite

# Verify PTY support:
which bash
# Should output: /bin/bash
```

#### Issue: "WebSocket connection failed"

**Problem**: Browser security or firewall blocking WebSockets.

**Solution**:
1. Check browser console for errors (F12)
2. Ensure you're accessing via `http://localhost:8080` not `file://`
3. Check firewall rules:
```bash
sudo iptables -L -n | grep 8080
```

### Performance Issues

#### Issue: Slow directory scanning

**Problem**: Scanning too many files or very large files.

**Solution**:
```bash
# Reduce scan depth:
./security_suite scan -type directory -target /home -depth 2

# Skip large files by editing scanner code
# Or exclude directories:
./security_suite scan -type directory -target /home -depth -1
# Then manually exclude unwanted directories
```

#### Issue: High CPU usage during monitoring

**Problem**: Processing too many packets.

**Solution**:
```bash
# Monitor specific traffic only:
# Edit malware_traffic_detector.go to add BPF filters

# Or reduce monitoring frequency
# Edit the ticker interval in periodicAnalysis()
```

### Data Issues

#### Issue: "Too many open files"

**Problem**: System file descriptor limit reached.

**Solution**:
```bash
# Check current limit:
ulimit -n

# Increase limit temporarily:
ulimit -n 4096

# Increase permanently (edit /etc/security/limits.conf):
sudo nano /etc/security/limits.conf
# Add:
* soft nofile 4096
* hard nofile 8192
```

#### Issue: Disk space full from logs

**Problem**: Log files growing too large.

**Solution**:
```bash
# Check disk usage:
df -h

# Find large log files:
du -sh /var/log/* | sort -h

# Clean old logs:
sudo journalctl --vacuum-time=7d
sudo find /var/log -name "*.log" -mtime +30 -delete

# Rotate logs:
sudo logrotate -f /etc/logrotate.conf
```

---

## Security Best Practices

### Running the Application Securely

#### 1. Use a Dedicated User Account

**Don't run as root directly**:
```bash
# Create security suite user:
sudo useradd -r -s /bin/bash -d /opt/security-suite securitysuite

# Set ownership:
sudo chown -R securitysuite:securitysuite /opt/security-suite

# Run as that user:
sudo -u securitysuite ./security_suite -mode web
```

#### 2. Restrict Web Interface Access

**Only allow localhost**:
```bash
# Use SSH tunnel for remote access:
ssh -L 8080:localhost:8080 user@server

# Then access via: http://localhost:8080 on your local machine
```

**Or configure firewall**:
```bash
# Allow only specific IPs:
sudo iptables -A INPUT -p tcp --dport 8080 -s 192.168.1.100 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8080 -j DROP
```

#### 3. Enable HTTPS (Production)

**Generate self-signed certificate**:
```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout server.key -out server.crt

# Modify web_server.go to use HTTPS
# Or use reverse proxy (nginx/apache) with SSL
```

#### 4. Secure the Quarantine Directory

```bash
# Strict permissions:
sudo chmod 700 quarantine_zone/
sudo chown root:root quarantine_zone/

# Regular backups:
tar -czf quarantine_backup_$(date +%Y%m%d).tar.gz quarantine_zone/
```

#### 5. Monitor the Monitor

**Set up monitoring for the Security Suite itself**:
```bash
# Create systemd service:
sudo nano /etc/systemd/system/security-suite.service
```

```ini
[Unit]
Description=Security Suite
After=network.target

[Service]
Type=simple
User=securitysuite
ExecStart=/opt/security-suite/security_suite -mode web
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start:
sudo systemctl enable security-suite
sudo systemctl start security-suite

# Check status:
sudo systemctl status security-suite
```

### Protecting Against False Positives

#### 1. Whitelist Known Good Files

**Create whitelist in YARA**:
```yara
rule Whitelist_TrustedApp
{
    meta:
        description = "Whitelist for trusted application"
    
    condition:
        false  // This rule never matches
}

// Then exclude these in your scans
```

#### 2. Review Before Blocking

**Manual approval mode**:
```bash
# Instead of automatic blocking, log only:
# Modify response_orchestrator.go to require approval
```

#### 3. Test in Safe Environment

```bash
# Use virtual machine or isolated network for testing:
# 1. Install VirtualBox
# 2. Create test VM
# 3. Test Security Suite there first
```

### Regular Maintenance Tasks

#### Daily
```bash
# Check for alerts:
sudo journalctl -u security-suite | grep CRITICAL

# Verify services running:
sudo systemctl status security-suite
sudo systemctl status suricata
```

#### Weekly
```bash
# Update threat definitions:
./security_suite update

# Review quarantine:
ls -lh quarantine_zone/

# Clean old quarantine files:
find quarantine_zone/ -mtime +30 -delete
```

#### Monthly
```bash
# Full system scan:
./security_suite scan -type directory -target / -depth -1

# Review behavioral profiles:
curl http://localhost:8080/api/profiles | jq

# Update application:
git pull
go build -o security_suite
sudo systemctl restart security-suite
```

---

## Real-World Usage Scenarios

### Scenario 1: Web Server Protection

**Objective**: Protect a web server from attacks.

**Setup**:
```bash
# 1. Install on web server
cd /opt
sudo git clone https://github.com/yourrepo/security-suite
cd security-suite
sudo ./setup_and_run.sh

# 2. Start monitoring
sudo ./security_suite monitor -iface eth0 &

# 3. Scan web directories regularly
crontab -e
# Add:
0 2 * * * /opt/security-suite/security_suite scan -type directory -target /var/www -depth -1 >> /var/log/webscan.log
```

**What it detects**:
- SQL injection attempts
- File upload exploits
- Directory traversal attacks
- Malicious scripts in uploads
- Port scanning of your server

### Scenario 2: Network Perimeter Defense

**Objective**: Monitor entire network for threats.

**Setup**:
```bash
# 1. Install on gateway/firewall
# 2. Monitor external interface
sudo ./security_suite monitor -iface eth0

# 3. Set up automatic blocking
# Edit response_orchestrator.go to enable auto-block
```

**Use cases**:
- Detect lateral movement between hosts
- Identify compromised devices
- Block C2 communications
- Alert on data exfiltration

### Scenario 3: Incident Response

**Objective**: Investigate potential compromise.

**Procedure**:
```bash
# 1. Scan suspicious host
./security_suite scan -type network -target 192.168.1.50

# 2. Check for persistence mechanisms
./security_suite scan -type directory -target /home/user/.config -depth -1
./security_suite scan -type directory -target /etc/systemd/system -depth -1

# 3. Review behavioral profile
curl http://localhost:8080/api/profiles | jq '.["192.168.1.50"]'

# 4. Isolate if confirmed
sudo iptables -A INPUT -s 192.168.1.50 -j DROP
sudo iptables -A OUTPUT -d 192.168.1.50 -j DROP
```

### Scenario 4: Compliance Monitoring

**Objective**: Maintain security compliance (PCI-DSS, HIPAA, etc.).

**Setup**:
```bash
# 1. Regular scans for compliance
./security_suite scan -type directory -target /var/lib/mysql -depth -1
./security_suite scan -type directory -target /opt/medical_records -depth -1

# 2. Generate compliance reports
./security_suite scan -type directory -target /sensitive -depth -1 > compliance_$(date +%Y%m%d).log

# 3. Monitor for unauthorized access
./security_suite monitor -iface eth0 | grep "192.168.1.100" >> access_log.txt
```

### Scenario 5: IOT Device Security

**Objective**: Find and secure IoT devices on network.

**Procedure**:
```bash
# 1. Discover all devices
./security_suite scan -type network -target 192.168.1.0/24

# 2. Find cameras
curl -X POST http://localhost:8080/api/stream/detect -d '{"url":"192.168.1.0/24"}'

# 3. Check for default passwords
# Use advanced scanner to test common credentials

# 4. Monitor IoT traffic
./security_suite monitor -iface eth0 | grep "192.168.1.150"
```

### Scenario 6: Malware Analysis Lab

**Objective**: Analyze suspicious files safely.

**Setup**:
```bash
# 1. Isolated VM with Security Suite
# 2. Scan suspicious file
./security_suite scan -type file -target /tmp/suspicious.exe

# 3. Review YARA matches
cat scan_results.log | grep "YARA"

# 4. Check VirusTotal
export VIRUSTOTAL_API_KEY="your_key"
./security_suite scan -type file -target /tmp/suspicious.exe

# 5. Quarantine and examine
ls -la quarantine_zone/
hexdump -C quarantine_zone/suspicious.exe.quarantined*
```

---

## FAQ

### General Questions

**Q: Do I need to run this 24/7?**

A: For real-time monitoring (traffic analysis, IDS), yes. For periodic scans, no - you can run scans on a schedule using cron.

**Q: How much disk space does it use?**

A: The application itself is ~20MB. Logs and quarantine files can grow - plan for 1-5GB depending on usage.

**Q: Can I run this on Raspberry Pi?**

A: Yes! It works on ARM processors. Just install ARM versions of dependencies.

```bash
# Raspberry Pi OS (Debian-based):
sudo apt-get install golang libpcap-dev libyara-dev
```

**Q: Does it slow down my computer?**

A: Minimal impact during idle. Network monitoring uses ~5-10% CPU. Scans use more CPU but only while running.

**Q: Can multiple people use the web interface?**

A: Yes, but there's no authentication by default. Use SSH tunneling or add authentication for multi-user scenarios.

### Technical Questions

**Q: What's the difference between YARA and ClamAV?**

A:
- **YARA**: Custom rule engine, you write your own detection rules
- **ClamAV**: Traditional antivirus with signature database
- Security Suite uses both for better detection

**Q: How does the ML anomaly detection work?**

A: It uses statistical analysis (Z-scores) to detect deviations from normal behavior. Monitors:
- Bytes in/out
- Connection rate
- DNS queries
- Computes multi-dimensional anomaly score

**Q: Can I integrate with my SIEM?**

A: Yes! Use the API to export data:
```bash
# Export threats to SIEM
curl http://localhost:8080/api/status | jq '.threats' | \
  curl -X POST -d @- https://siem.company.com/api/events
```

**Q: Does it work with IPv6?**

A: Yes, the network scanner supports both IPv4 and IPv6.

**Q: Can I add custom threat intelligence feeds?**

A: Yes, modify `malware_detector.go` to add additional hash databases or threat feeds.

### Troubleshooting Questions

**Q: Why am I getting "permission denied" errors?**

A: Most features need sudo. Run with:
```bash
sudo ./security_suite -mode web
```

**Q: Suricata rules won't update - why?**

A: Check:
1. Suricata is installed: `which suricata`
2. You have sudo access
3. Internet connection works
4. Suricata is properly configured: `sudo suricata --build-info`

**Q: Terminal in browser doesn't work - why?**

A: Check:
1. PTY module is installed: `go get github.com/creack/pty`
2. WebSocket connection is working (check browser console)
3. Rebuild the application: `go build`

**Q: Scans are very slow - how to speed up?**

A:
1. Reduce scan depth
2. Exclude large directories
3. Skip large binary files (edit scanner code)
4. Use SSD instead of HDD
5. Increase system resources

### Security Questions

**Q: Is it safe to run this on a production server?**

A: Yes, but:
1. Test thoroughly in dev environment first
2. Review auto-response actions
3. Monitor resource usage
4. Keep backups
5. Use dedicated user account

**Q: What if it blocks legitimate traffic?**

A: You can:
1. Whitelist IPs in iptables
2. Disable auto-blocking (manual review mode)
3. Adjust anomaly detection thresholds
4. Review and remove blocks:
```bash
sudo iptables -L -n
sudo iptables -D INPUT -s <IP> -j DROP
```

**Q: How do I secure the web interface?**

A:
1. Use SSH tunnel instead of direct access
2. Configure firewall to allow only specific IPs
3. Add authentication (custom modification)
4. Use HTTPS with valid certificate
5. Run on non-standard port

**Q: Can attackers detect that I'm running this?**

A: Network scans might be detected by target IDS. For stealth:
1. Use slower scan rates
2. Randomize scan timing
3. Use passive monitoring instead of active scanning
4. Monitor your own traffic only

**Q: What happens if malware disables the Security Suite?**

A: Prevention strategies:
1. Run as systemd service with auto-restart
2. File integrity monitoring on the binary
3. Secondary monitoring system
4. Regular health checks via cron

### Advanced Questions

**Q: Can I write my own response actions?**

A: Yes! Edit `response_orchestrator.go`:
```go
case ActionCustom:
    // Your custom action here
    outcome = ro.handleCustomAction(threat)
```

**Q: How do I export data for forensics?**

A:
```bash
# Export behavioral profiles:
curl http://localhost:8080/api/profiles > profiles_$(date +%Y%m%d).json

# Export quarantine log:
ls -lR quarantine_zone/ > quarantine_forensics.txt

# Export iptables rules:
sudo iptables-save > firewall_state.txt
```

**Q: Can I cluster multiple instances?**

A: The application doesn't have built-in clustering, but you can:
1. Run instance on each host
2. Aggregate logs centrally (syslog, ELK stack)
3. Use API to query multiple instances
4. Build custom dashboard showing all hosts

**Q: How do I update without losing data?**

A:
```bash
# 1. Backup data:
cp -r quarantine_zone/ quarantine_backup/
cp yara_rules.yar yara_rules.yar.backup

# 2. Update code:
git pull

# 3. Rebuild:
go build -o security_suite

# 4. Restart:
sudo systemctl restart security-suite
```

---

## Conclusion

You now have a complete understanding of the Security Suite! Key takeaways:

1. **Installation**: Simple 3-step process with automated setup
2. **Web Interface**: Easy-to-use dashboard with four main tabs
3. **CLI Mode**: Powerful command-line interface for automation
4. **Multi-Engine Detection**: YARA + ClamAV + VirusTotal + ML
5. **Auto-Response**: Automatic threat containment
6. **Network Monitoring**: Real-time traffic analysis
7. **Behavioral Analysis**: ML-based anomaly detection
8. **Camera Detection**: Find and view IP cameras

### Next Steps

1. **Start Simple**: Begin with file and directory scans
2. **Add Monitoring**: Enable network traffic monitoring
3. **Customize Rules**: Write YARA rules for your environment
4. **Automate**: Set up cron jobs for regular scans
5. **Integrate**: Connect to your existing security infrastructure

### Getting Help

- **Documentation**: This guide covers everything
- **Log Files**: Check `/var/log/syslog` for errors
- **Verbose Mode**: Use `-verbose` flag for debugging
- **API Status**: Visit http://localhost:8080/api/status

### Contributing

This is an open-source security tool. Contributions welcome:
- Report bugs
- Suggest features  
- Write YARA rules
- Improve documentation
- Add integrations

---

**Security Suite v2.0** - Advanced Threat Detection & Response Platform

*Stay vigilant. Stay secure.* 🛡️