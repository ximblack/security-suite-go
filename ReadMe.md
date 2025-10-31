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

**What you should see**: A dark-themed dashboard with three tabs: Security Scans, Camera Streams, and Terminal.

---

## Web Interface Guide

### The Dashboard Layout

When you open http://localhost:8080, you'll see:

```
┌─────────────────────────────────────────────────────┐
│  Security Suite          Status: Online             │
│  [Security Scans] [Camera Streams] [Terminal]       │
├─────────────────────────────────────────────────────┤
│                                                     │
│  Left Side:                Right Side:              │
│  • Controls                • Results                │
│  • Settings                • Console Log            │
│  • Quick Actions           • Output                 │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### Three Main Tabs

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

#### 2. Camera Streams Tab

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

#### 3. Terminal Tab

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
3. Trains anomaly detection model
4. Scores new traffic (0 = normal, -1 = very abnormal)

**What it tracks per device**:
- Connection frequency (how often it connects)
- Data transfer patterns (uploads/downloads by hour)
- Active hours (when device is busy)
- Protocol distribution (HTTP, HTTPS, DNS, etc.)
- Typical services (which ports it uses)

**Anomaly score explained**:
- `0.5 to 0`: Normal behavior
- `0 to -0.5`: Unusual but not alarming
- `-0.5 to -1`: Very suspicious, investigate
- `-1 or lower`: Critical anomaly, likely threat

**Real-world example**:
```
Device: 192.168.1.50 (office computer)
Normal: 9am-5pm, mostly HTTP/HTTPS, 100MB/day
Anomaly: 3am connection, large FTP upload, 5GB
Score: -0.85 (ALERT)
```

**Hidden feature**: The ML model auto-retrains every 250 new data points. You can trigger manual retraining by restarting the monitor.

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

**Hidden feature**: All responses are logged to `action_log`. View with:
```bash
# In Terminal tab:
cat action_log | grep QUARANTINE
```

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

**Method 3 - Network Scan**:
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

**Keyboard shortcuts**:
- `Enter` - Execute command
- `Ctrl+C` - Cancel current command
- `Ctrl+L` - Clear screen
- `↑` (Up Arrow) - Previous command
- `↓` (Down Arrow) - Next command
- `Tab` - Auto-complete (when available)

**Hidden features**:
1. **Command history**: All commands are remembered (up to 1000)
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
3. Security Suite reads alerts
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

**Hidden feature**: The IDS module auto-checks for new alerts every 5 seconds. You don't need to refresh the page.

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
3. **NSRL** (if database downloaded): Known good files

**How to check a file hash manually**:
```bash
# Calculate SHA256:
sha256sum /path/to/file

# Calculate MD5:
md5sum /path/to/file
```

**Hidden feature**: Every scanned file's hash is logged to `scan_history.json`. You can review past scans:
```bash
cat scan_history.json | jq '.[] | select(.hash == "a34c11...")'
```

---

## Hidden Features & Advanced Usage

### Hidden Feature 1: Behavioral Profile Export

**What it does**: Exports all learned behavior profiles for analysis.

**How to use**:
```bash
# In Terminal tab:
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
- `security_suite.log` (if file logging enabled)

**View logs in real-time**:
```bash
# System log:
sudo tail -f /var/log/syslog | grep security_suite

# Application log (if exists):
tail -f security_suite.log
```

### Hidden Feature 6: Configuration File

**What it does**: Customize default settings.

**Location**: `config.json` (create if doesn't exist)

**Example configuration**:
```json
{
  "web_server": {
    "port": 8080,
    "enable_https": false,
    "cert_file": "/etc/ssl/cert.pem",
    "key_file": "/etc/ssl/key.pem"
  },
  "scanner": {
    "max_file_size_mb": 100,
    "skip_extensions": [".jpg", ".png", ".mp4"],
    "scan_timeout_seconds": 300
  },
  "network": {
    "default_interface": "eth0",
    "monitor_pcap_buffer_mb": 10
  },
  "quarantine": {
    "directory": "/opt/security-suite/quarantine",
    "auto_delete_days": 30
  },
  "notifications": {
    "email_enabled": false,
    "email_to": "admin@example.com",
    "slack_webhook": ""
  }
}
```

**How to use**:
1. Create `config.json` in the application directory
2. Add your settings
3. Restart the application
4. Settings are applied automatically

###