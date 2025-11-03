
⚖️ Legal Disclaimer
IMPORTANT - READ CAREFULLY BEFORE USE:
This software is provided "AS IS" WITHOUT WARRANTY OF ANY KIND, either express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement. In no event shall the authors, copyright holders, or contributors be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.
Educational and Research Purpose: This Security Suite is designed for educational purposes, security research, authorized penetration testing, and legitimate system administration on networks and systems you own or have explicit written permission to test.
Unauthorized Use Prohibited: Unauthorized access to computer systems is illegal under the Computer Fraud and Abuse Act (CFAA) in the United States and similar laws in other jurisdictions. The authors and contributors of this software:

Do NOT authorize or condone any unauthorized use of this software
Are NOT responsible for any misuse, damage, or illegal activity conducted with this software
Accept NO liability for actions taken by users of this software
Provide NO support, warranty, or guarantee of functionality

User Responsibility: By downloading, installing, or using this software, you acknowledge that:

You are solely responsible for compliance with all applicable laws and regulations
You will only use this software on systems you own or have explicit written authorization to test
You understand the tools included can cause system disruption if misused
You accept all risks associated with the use of this software

No Support Provided: This software is provided as-is without any form of technical support, maintenance, or updates. Use at your own risk.

Prerequisites & Installation
System Requirements

Operating System: Linux (Arch, Ubuntu 20.04+, Debian, RHEL 8+, Fedora)
Architecture: x86_64 or ARM64
Go Version: 1.19 or higher
RAM: Minimum 4GB (8GB+ recommended for network monitoring)
Disk: 50GB available space (for logs, quarantine, wordlists)
Privileges: Root access required for packet capture and iptables

Required Dependencies
Core Dependencies
bash# Arch Linux
sudo pacman -S go iptables libpcap yara base-devel

# Ubuntu/Debian
sudo apt-get update
sudo apt-get install golang iptables libpcap-dev libyara-dev build-essential

# Fedora/RHEL
sudo dnf install golang iptables libpcap-devel yara-devel gcc make
Optional Dependencies
bash# ClamAV (for antivirus scanning)
sudo pacman -S clamav          # Arch
sudo apt-get install clamav    # Ubuntu/Debian
sudo dnf install clamav        # Fedora

# Suricata (for IDS functionality)
sudo pacman -S suricata        # Arch
sudo apt-get install suricata  # Ubuntu/Debian
sudo dnf install suricata      # Fedora

# Hashcat (for advanced hash cracking)
sudo pacman -S hashcat         # Arch
sudo apt-get install hashcat   # Ubuntu/Debian
sudo dnf install hashcat       # Fedora

# GeoIP Database and Libraries
# The application uses github.com/oschwald/geoip2-golang for IP geolocation
# This is automatically installed via Go modules, but you need the database files

# Download MaxMind GeoLite2 Database (Free):
# 1. Create account at https://www.maxmind.com/en/geolite2/signup
# 2. Download GeoLite2-City database
# 3. Extract and place in standard location

# Example installation:
sudo mkdir -p /usr/local/share/GeoIP
cd /tmp
wget https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=YOUR_LICENSE_KEY&suffix=tar.gz -O GeoLite2-City.tar.gz
tar -xzf GeoLite2-City.tar.gz
sudo cp GeoLite2-City_*/GeoLite2-City.mmdb /usr/local/share/GeoIP/

# Or use package manager (if available):
sudo apt-get install geoipupdate  # Ubuntu/Debian
sudo pacman -S geoipupdate        # Arch
GeoIP Configuration
The application uses the MaxMind GeoIP2 database via the github.com/oschwald/geoip2-golang package for IP geolocation features in network forensics.
Default Database Path: /usr/local/share/GeoIP/GeoLite2-City.mmdb
Configure Custom Path:
Edit config.json:
json{
  "selected_nic": "eth0",
  "geoip_path": "/path/to/your/GeoLite2-City.mmdb",
  "api_keys": {}
}
MaxMind GeoLite2 Setup (Free Database):

Create MaxMind Account:

bash   # Visit: https://www.maxmind.com/en/geolite2/signup
   # Sign up for a free account

Generate License Key:

bash   # Visit: https://www.maxmind.com/en/accounts/current/license-key
   # Generate a new license key

Download Database:

bash   # Manual download
   wget "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=YOUR_LICENSE_KEY&suffix=tar.gz" -O GeoLite2-City.tar.gz
   
   tar -xzf GeoLite2-City.tar.gz
   sudo mkdir -p /usr/local/share/GeoIP
   sudo cp GeoLite2-City_*/GeoLite2-City.mmdb /usr/local/share/GeoIP/

Verify Installation:

bash   ls -lh /usr/local/share/GeoIP/GeoLite2-City.mmdb
Automated Updates with geoipupdate:
bash# Install geoipupdate
sudo apt-get install geoipupdate  # Ubuntu/Debian
sudo pacman -S geoipupdate        # Arch

# Configure geoipupdate
sudo nano /etc/GeoIP.conf
Add your configuration:
ini# GeoIP.conf file
AccountID YOUR_ACCOUNT_ID
LicenseKey YOUR_LICENSE_KEY
EditionIDs GeoLite2-City GeoLite2-Country

DatabaseDirectory /usr/local/share/GeoIP
Setup automatic updates:
bash# Test update
sudo geoipupdate -v

# Add to crontab for weekly updates
sudo crontab -e

# Add this line:
0 2 * * 0 /usr/bin/geoipupdate
GeoIP Features in Security Suite
The GeoIP functionality is used in the Forensic Toolkit module for:

Network Session Analysis - PCAP file analysis with geolocation
IP Attribution - Automatic geolocation of source/destination IPs
Threat Intelligence - Geographic context for security events

Example Usage:
bash# PCAP analysis with GeoIP (requires code support or future CLI)
# The ForensicToolkit.AnalyzePCAPFile() method automatically:
# - Extracts network sessions from PCAP files
# - Resolves geographic location for each IP
# - Provides country, city, coordinates, and timezone
GeoIP Data Included:

Country name
City name
Latitude/Longitude coordinates
Time zone
Automatically filters private/local IPs (no lookup needed)

Testing GeoIP Installation
Create a test script:
bashcat > test_geoip.sh << 'EOF'
#!/bin/bash
# Test if GeoIP database is accessible

GEOIP_DB="/usr/local/share/GeoIP/GeoLite2-City.mmdb"

if [ -f "$GEOIP_DB" ]; then
    echo "✓ GeoIP database found at: $GEOIP_DB"
    echo "  Size: $(du -h $GEOIP_DB | cut -f1)"
    echo "  Modified: $(stat -c %y $GEOIP_DB | cut -d' ' -f1)"
else
    echo "✗ GeoIP database NOT found at: $GEOIP_DB"
    echo "  Please download from MaxMind (see README)"
fi
EOF

chmod +x test_geoip.sh
./test_geoip.sh
```

**Expected Output:**
```
✓ GeoIP database found at: /usr/local/share/GeoIP/GeoLite2-City.mmdb
  Size: 65M
  Modified: 2024-10-15
The GeoIP package (github.com/oschwald/geoip2-golang v1.11.0) is automatically installed when you run go mod tidy during the build process, but the database file must be downloaded separately from MaxMind.RetryCPlease complete this action, and place MaxMind up with the other external dependencies  such as suricata and clamAV. And then regenerate this complete comprehensive read me users guide in a downloadable ReadMe.md file in the canvas. This direct response format is of literally no use to me.I'll create a complete, comprehensive README.md file with MaxMind GeoIP properly organized with the other external dependencies.
markdown# Security Suite v2.0 - Advanced Threat Detection & Response Platform

## 📖 Table of Contents

1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [Prerequisites & Installation](#prerequisites--installation)
4. [Command Line Interface Guide](#command-line-interface-guide)
5. [Core Security Modules](#core-security-modules)
6. [Advanced Features](#advanced-features)
7. [Configuration & Settings](#configuration--settings)
8. [Security Hardening](#security-hardening)
9. [Troubleshooting](#troubleshooting)
10. [Production Deployment](#production-deployment)
11. [Appendix](#appendix)

---

## Overview

### What is Security Suite?

Security Suite v2.0 is an enterprise-grade, command-line-focused security analysis platform written in Go. It provides comprehensive threat detection, behavioral analysis, network scanning, and automated response capabilities designed for security professionals operating in hardened environments where GUI access may be limited or unavailable.

### Key Capabilities

- **Multi-Engine Malware Detection**: YARA rules, ClamAV integration, VirusTotal API, hash-based detection
- **Behavioral Analysis**: Machine learning-based anomaly detection using Isolation Forest algorithm
- **Network Security**: Port scanning, OS fingerprinting, service detection, vulnerability assessment
- **Intrusion Detection**: Suricata IDS integration with automated rule management
- **Digital Forensics**: Hash extraction, process analysis, PCAP analysis with GeoIP, sensitive file discovery
- **Hash Cracking**: Dictionary attacks with support for MD5, SHA256, NTLM, bcrypt (via Hashcat)
- **Web Security Scanning**: SQL injection, XSS, LFI, RCE, SSRF, XXE detection
- **Automated Response**: File quarantine, network blocking via iptables, threat orchestration

### Design Philosophy

This tool is built for **command-line operation** in security-hardened environments where:
- GUI access is restricted or unavailable
- All operations must be scriptable and auditable
- Performance and resource efficiency are critical
- Integration with existing security infrastructure is required

---

## System Architecture

### Core Components
```
┌─────────────────────────────────────────────────────────┐
│                   CoreController                         │
│  (Central orchestration and module coordination)        │
└──────────────┬──────────────────────────────────────────┘
               │
      ┌────────┴────────┐
      │                 │
┌─────▼─────┐    ┌─────▼──────┐
│  Scanner  │    │  Response  │
│  Modules  │    │Orchestrator│
└─────┬─────┘    └─────┬──────┘
      │                │
      │                │
┌─────▼────────────────▼─────────────────────────────────┐
│                                                          │
│  ┌──────────────┐  ┌─────────────┐  ┌───────────────┐ │
│  │   Malware    │  │  Behavioral │  │   Network     │ │
│  │   Detector   │  │   Analyzer  │  │   Scanner     │ │
│  └──────────────┘  └─────────────┘  └───────────────┘ │
│                                                          │
│  ┌──────────────┐  ┌─────────────┐  ┌───────────────┐ │
│  │     IDS      │  │  Forensic   │  │     Web       │ │
│  │   Module     │  │   Toolkit   │  │   Scanner     │ │
│  └──────────────┘  └─────────────┘  └───────────────┘ │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

### Module Descriptions

- **MalwareDetector**: Multi-engine scanning (YARA, ClamAV, VirusTotal, hash databases)
- **BehavioralAnalyzer**: ML-based anomaly detection with Isolation Forest algorithm
- **NetworkMalwareScanner**: Real-time packet capture and traffic analysis
- **IntrusionDetector**: Suricata IDS integration with automated rule updates
- **AdvancedNetworkScanner**: Port scanning, service detection, OS fingerprinting
- **VulnerabilityScanner**: CVE detection including EternalBlue, BlueKeep, Log4Shell
- **ForensicToolkit**: Hash extraction, process analysis, PCAP analysis with GeoIP, sensitive file discovery
- **HashCracker**: High-speed dictionary attacks with Hashcat integration
- **WebSecurityScanner**: Comprehensive web application vulnerability scanning
- **ResponseOrchestrator**: Automated threat response (quarantine, blocking)

---

## Prerequisites & Installation

### System Requirements

- **Operating System**: Linux (Arch, Ubuntu 20.04+, Debian, RHEL 8+, Fedora)
- **Architecture**: x86_64 or ARM64
- **Go Version**: 1.19 or higher
- **RAM**: Minimum 4GB (8GB+ recommended for network monitoring)
- **Disk**: 50GB available space (for logs, quarantine, wordlists)
- **Privileges**: Root access required for packet capture and iptables

### Required Dependencies

#### Core Dependencies

These are essential for basic functionality:
```bash
# Arch Linux
sudo pacman -S go iptables libpcap yara base-devel

# Ubuntu/Debian
sudo apt-get update
sudo apt-get install golang iptables libpcap-dev libyara-dev build-essential

# Fedora/RHEL
sudo dnf install golang iptables libpcap-devel yara-devel gcc make
```

**Dependency Details:**
- `go` - Go programming language (v1.19+)
- `iptables` - Firewall management for automated blocking
- `libpcap` - Packet capture library for network monitoring
- `yara` - Pattern matching engine for malware detection
- `build-essential` / `base-devel` - Compilation tools

### Optional External Dependencies

These enhance functionality but are not required for basic operation:

#### ClamAV (Antivirus Engine)

Provides additional malware scanning capabilities.
```bash
# Arch Linux
sudo pacman -S clamav
sudo systemctl enable clamav-daemon
sudo systemctl start clamav-daemon

# Ubuntu/Debian
sudo apt-get install clamav clamav-daemon
sudo systemctl enable clamav-daemon
sudo systemctl start clamav-daemon

# Fedora/RHEL
sudo dnf install clamav clamav-update
sudo systemctl enable clamd@scan
sudo systemctl start clamd@scan

# Update virus definitions
sudo freshclam
```

**Configuration:**
```bash
# Check ClamAV socket location
sudo ss -lx | grep clam
```

**Testing:**
```bash
# Test ClamAV is working
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.txt
clamscan eicar.txt
# Should detect: Eicar-Test-Signature
```

#### Suricata (Intrusion Detection System)

Provides real-time network intrusion detection.
```bash
# Arch Linux
sudo pacman -S suricata
sudo systemctl enable suricata
sudo systemctl start suricata

# Ubuntu/Debian
sudo apt-get install suricata
sudo systemctl enable suricata
sudo systemctl start suricata

# Fedora/RHEL
sudo dnf install suricata
sudo systemctl enable suricata
sudo systemctl start suricata

# Update IDS rules
sudo suricata-update
```

**Configuration:**
```bash
# Configure network interface
sudo nano /etc/suricata/suricata.yaml

# Find and update:
af-packet:
  - interface: eth0  # Change to your interface

# Test configuration
sudo suricata -T -c /etc/suricata/suricata.yaml

# View alerts
sudo tail -f /var/log/suricata/eve.json
```

**Rule Management:**
```bash
# Enable rule sources
sudo suricata-update list-sources
sudo suricata-update enable-source et/open

# Update rules
sudo suricata-update

# Reload Suricata (no restart needed)
sudo killall -USR2 suricata
```

#### Hashcat (Advanced Hash Cracking)

Required for cracking complex hash types (NTLM, bcrypt, SHA512-crypt).
```bash
# Arch Linux
sudo pacman -S hashcat

# Ubuntu/Debian
sudo apt-get install hashcat

# Fedora/RHEL
sudo dnf install hashcat

# Verify installation
hashcat --version
```

**Testing:**
```bash
# Test Hashcat with simple MD5
echo -n "password" | md5sum
# Output: 5f4dcc3b5aa765d61d8327deb882cf99

# Create hash file
echo '5f4dcc3b5aa765d61d8327deb882cf99' > test_hash.txt

# Crack with small wordlist
echo -e "password\ntest\nadmin" > test_wordlist.txt
hashcat -m 0 -a 0 test_hash.txt test_wordlist.txt

# Clean up
rm test_hash.txt test_wordlist.txt
```

#### MaxMind GeoIP (IP Geolocation)

Provides geographic context for network forensics and threat intelligence.

**Purpose:**
- Geographic attribution of IP addresses in PCAP analysis
- Threat intelligence enrichment with location data
- Network forensics with country/city/timezone context

**Installation Steps:**

1. **Create MaxMind Account (Free):**
   - Visit: https://www.maxmind.com/en/geolite2/signup
   - Sign up for a free GeoLite2 account
   - Confirm your email address

2. **Generate License Key:**
   - Login to: https://www.maxmind.com/en/account/login
   - Navigate to: Account → Manage License Keys
   - Click "Generate new license key"
   - Name it (e.g., "SecuritySuite")
   - Answer "No" to "Will this key be used for GeoIP Update?"
   - Save the license key securely

3. **Download Database Manually:**
```bash
   # Create directory
   sudo mkdir -p /usr/local/share/GeoIP
   
   # Download (replace YOUR_LICENSE_KEY with your actual key)
   cd /tmp
   wget "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=YOUR_LICENSE_KEY&suffix=tar.gz" -O GeoLite2-City.tar.gz
   
   # Extract
   tar -xzf GeoLite2-City.tar.gz
   
   # Copy database file
   sudo cp GeoLite2-City_*/GeoLite2-City.mmdb /usr/local/share/GeoIP/
   
   # Verify
   ls -lh /usr/local/share/GeoIP/GeoLite2-City.mmdb
   
   # Clean up
   rm -rf GeoLite2-City_* GeoLite2-City.tar.gz
```

4. **Install geoipupdate (Automated Updates - Recommended):**
```bash
   # Install package
   # Arch Linux
   sudo pacman -S geoipupdate
   
   # Ubuntu/Debian
   sudo apt-get install geoipupdate
   
   # Fedora/RHEL
   sudo dnf install geoipupdate
```

5. **Configure geoipupdate:**
```bash
   # Edit configuration file
   sudo nano /etc/GeoIP.conf
```
   
   Add your credentials:
```ini
   # GeoIP.conf file for geoipupdate
   
   # Your MaxMind account ID and license key
   AccountID YOUR_ACCOUNT_ID
   LicenseKey YOUR_LICENSE_KEY
   
   # Database editions to download
   EditionIDs GeoLite2-City GeoLite2-Country
   
   # Database directory
   DatabaseDirectory /usr/local/share/GeoIP
```

6. **Test Manual Update:**
```bash
   # Run update manually
   sudo geoipupdate -v
   
   # Verify database was updated
   ls -lh /usr/local/share/GeoIP/
```

7. **Setup Automatic Updates:**
```bash
   # Add to root's crontab for weekly updates
   sudo crontab -e
   
   # Add this line (updates every Sunday at 2 AM):
   0 2 * * 0 /usr/bin/geoipupdate
```

**Configuration in Security Suite:**

Edit `config.json`:
```json
{
  "selected_nic": "eth0",
  "geoip_path": "/usr/local/share/GeoIP/GeoLite2-City.mmdb",
  "api_keys": {}
}
```

**Testing GeoIP Integration:**

Create a test script:
```bash
cat > test_geoip.sh << 'EOF'
#!/bin/bash
# Test GeoIP database installation

GEOIP_DB="/usr/local/share/GeoIP/GeoLite2-City.mmdb"

echo "=== GeoIP Database Status ==="
if [ -f "$GEOIP_DB" ]; then
    echo "✓ Database found: $GEOIP_DB"
    echo "  Size: $(du -h $GEOIP_DB | cut -f1)"
    echo "  Modified: $(stat -c %y $GEOIP_DB 2>/dev/null | cut -d' ' -f1 || stat -f %Sm -t %Y-%m-%d $GEOIP_DB 2>/dev/null)"
    echo ""
    echo "✓ GeoIP is ready for use"
else
    echo "✗ Database NOT found: $GEOIP_DB"
    echo ""
    echo "Please install using the instructions in README.md"
    echo "Quick install:"
    echo "  1. Sign up at: https://www.maxmind.com/en/geolite2/signup"
    echo "  2. Get license key from: https://www.maxmind.com/en/accounts/current/license-key"
    echo "  3. Download database"
fi
EOF

chmod +x test_geoip.sh
./test_geoip.sh
```

**Expected Output:**
```
=== GeoIP Database Status ===
✓ Database found: /usr/local/share/GeoIP/GeoLite2-City.mmdb
  Size: 65M
  Modified: 2024-10-15

✓ GeoIP is ready for use
```

**GeoIP Features in Security Suite:**

The GeoIP functionality is integrated into the **Forensic Toolkit** module:

- **PCAP Analysis**: Automatic geolocation of all IP addresses in network captures
- **Threat Intelligence**: Geographic context for security events
- **Network Forensics**: Country, city, coordinates, and timezone data
- **Smart Filtering**: Automatically skips private/local IPs (no unnecessary lookups)

**Data Provided:**
```
GeoLocationData {
  CountryName: "United States"
  CityName: "Mountain View"
  Latitude: 37.4056
  Longitude: -122.0775
  TimeZone: "America/Los_Angeles"
}
```

### Installation Steps

#### 1. Clone or Extract Repository
```bash
cd ~
# If using git:
git clone https://github.com/yourusername/security-suite
cd security-suite

# Or extract from archive:
tar -xzf security-suite.tar.gz
cd security-suite
```

#### 2. Automated Build
```bash
chmod +x setup_and_run.sh
./setup_and_run.sh
```

This script will:
- Verify all dependencies
- Initialize Go modules
- Download required Go packages (including GeoIP library)
- Create necessary directories
- Generate default YARA rules
- Build the executable
- Set packet capture capabilities (if root)

#### 3. Manual Build (Alternative)
```bash
# Initialize Go module
go mod init security_suite
go mod tidy

# Create required directories
mkdir -p ids_rules quarantine_zone logs

# Build the application
go build -ldflags="-s -w" -o security_suite .

# Set capabilities (allows non-root packet capture)
sudo setcap cap_net_raw,cap_net_admin=eip ./security_suite
```

#### 4. Verify Installation
```bash
./security_suite -version
```

Expected output:
```
Security Suite v2.0.0
```

#### 5. Verify All Dependencies
```bash
cat > verify_deps.sh << 'EOF'
#!/bin/bash
echo "=== Security Suite Dependency Check ==="
echo ""

# Check Go
if command -v go &> /dev/null; then
    echo "✓ Go: $(go version | awk '{print $3}')"
else
    echo "✗ Go: NOT FOUND"
fi

# Check iptables
if command -v iptables &> /dev/null; then
    echo "✓ iptables: $(iptables --version | head -1)"
else
    echo "✗ iptables: NOT FOUND"
fi

# Check libpcap
if ldconfig -p 2>/dev/null | grep -q libpcap; then
    echo "✓ libpcap: FOUND"
else
    echo "✗ libpcap: NOT FOUND"
fi

# Check YARA
if command -v yara &> /dev/null; then
    echo "✓ YARA: $(yara --version)"
else
    echo "✗ YARA: NOT FOUND"
fi

echo ""
echo "=== Optional Dependencies ==="
echo ""

# Check ClamAV
if command -v clamscan &> /dev/null; then
    echo "✓ ClamAV: $(clamscan --version | head -1)"
else
    echo "○ ClamAV: Not installed (optional)"
fi

# Check Suricata
if command -v suricata &> /dev/null; then
    echo "✓ Suricata: $(suricata --version | head -1)"
else
    echo "○ Suricata: Not installed (optional)"
fi

# Check Hashcat
if command -v hashcat &> /dev/null; then
    echo "✓ Hashcat: $(hashcat --version | head -1)"
else
    echo "○ Hashcat: Not installed (optional)"
fi

# Check GeoIP
if [ -f "/usr/local/share/GeoIP/GeoLite2-City.mmdb" ]; then
    echo "✓ GeoIP: Database found"
else
    echo "○ GeoIP: Database not found (optional)"
fi

echo ""
echo "=== Security Suite Binary ==="
echo ""

if [ -f "./security_suite" ]; then
    echo "✓ Binary: ./security_suite"
    echo "  Size: $(du -h ./security_suite | cut -f1)"
else
    echo "✗ Binary: NOT FOUND - Run ./setup_and_run.sh"
fi
EOF

chmod +x verify_deps.sh
./verify_deps.sh
```

---

## Command Line Interface Guide

### Basic Command Structure
```bash
./security_suite [global-options]  [command-options]
```

### Global Options
```bash
-mode      # Operation mode (default: web)
-version            # Display version and exit
-verbose            # Enable detailed output
```

### Available Commands

| Command | Purpose | Example |
|---------|---------|---------|
| `scan` | File, directory, or network scanning | `./security_suite scan -type file -target /path/to/file` |
| `monitor` | Real-time network traffic monitoring | `sudo ./security_suite monitor -iface eth0` |
| `update` | Update threat definitions (YARA, Suricata, ClamAV) | `sudo ./security_suite update` |
| `stop` | Stop all active processes | `./security_suite stop` |
| `demo` | Run demonstration of capabilities | `./security_suite demo` |
| `forensic` | Digital forensics operations | `sudo ./security_suite forensic -os linux -target /home` |
| `crack` | Hash cracking operations | `./security_suite crack -type MD5 -wordlist wordlist.txt -hashes hash1,hash2` |
| `webscan` | Web application security scanning | `./security_suite webscan -url https://example.com -type quick` |
| `help` | Display help information | `./security_suite help` |

### Getting Help
```bash
# General help
./security_suite help

# Command-specific help
./security_suite scan --help
./security_suite monitor --help
./security_suite forensic --help
```

---

## Core Security Modules

### 1. File & Directory Scanning

#### Scan Single File

Performs comprehensive malware analysis on a single file using multiple detection engines.
```bash
./security_suite scan -type file -target /path/to/suspicious.exe
```

**Detection Engines Used:**
1. **SHA256 Hash Check** - Against known malware database
2. **VirusTotal API** - Online multi-engine scanning (if API key configured)
3. **ClamAV** - Local antivirus engine (if installed)
4. **YARA Rules** - Pattern-based detection
5. **Behavioral Heuristics** - Suspicious file characteristics

**Output Example:**
```
[MalwareDetector] Starting multi-engine scan on: /path/to/suspicious.exe
[SCAN] File SHA256: a34c11f750058b871c4c1a85b96796a583e747d79b63484f
[VirusTotal] Checking hash against database...
[VirusTotal] Detection: 45/70 vendors flagged as malicious
[ClamAV] Scanning with local database...
[ClamAV] Win.Trojan.Generic detected
[YARA] Applying detection rules...
[ALERT] CRITICAL: YARA rule 'MalwareSignature' matched

Scan Results:
Status: complete
Message: Scan completed. 1 threats found.

Found 1 threats:
[1] Severity: CRITICAL
    Target: /path/to/suspicious.exe
    Signature: MalwareSignature
    Context: YARA rule 'MalwareSignature' matched in target
    Hash: a34c11f750058b871c4c1a85b96796a583e747d79b63484f
    Action: QUARANTINE_FILE

File has been automatically quarantined to: quarantine_zone/suspicious.exe.quarantined_20241103150405
```

**Advanced File Scanning:**
```bash
# Scan with verbose output
./security_suite -verbose scan -type file -target /tmp/sample.bin

# Scan multiple files using shell loop
for file in /tmp/samples/*; do
    echo "Scanning: $file"
    ./security_suite scan -type file -target "$file"
    echo "---"
done

# Scan files modified in last 24 hours
find /var/www -type f -mtime -1 -exec ./security_suite scan -type file -target {} \;

# Scan only executable files
find /home -type f -executable -exec ./security_suite scan -type file -target {} \;
```

#### Scan Directory (Recursive)

Recursively scans all files in a directory tree.
```bash
./security_suite scan -type directory -target /var/www/html -depth -1
```

**Depth Options:**
- `-1` - Unlimited depth (scan all subdirectories recursively)
- `0` - Current directory only (no subdirectories)
- `1` - One level deep
- `2` - Two levels deep
- `3` - Three levels deep (recommended for large directories)

**Examples:**
```bash
# Scan entire web server directory
./security_suite scan -type directory -target /var/www/html -depth -1

# Scan user home directory (2 levels deep for performance)
./security_suite scan -type directory -target /home/user -depth 2

# Scan system binaries (careful - this takes time)
sudo ./security_suite scan -type directory -target /usr/bin -depth 1

# Scan tmp directory (common malware location)
sudo ./security_suite scan -type directory -target /tmp -depth -1
```

**Output Example:**
```
[2024-11-03 15:04:05] ScannerWrapper: Starting extensive directory scan of '/var/www/html' (Depth: -1).
[SCAN] Processing: /var/www/html/index.php
[SCAN] Processing: /var/www/html/uploads/image.jpg
[SCAN] Processing: /var/www/html/uploads/shell.php
[SCAN ALERT] Threat detected in: /var/www/html/uploads/shell.php
[YARA] Rule 'Webshell_Detection' matched
[SCAN] Processed 247 files in 35 subdirectories
[SCAN] Skipped 12 files (too large or binary)

Directory scan complete. Scanned 247 files, found 1 threats.

Threat Summary:
[1] CRITICAL: /var/www/html/uploads/shell.php
    Signature: Webshell_Detection
    Action: File quarantined
```

**Performance Optimization:**
```bash
# Skip large files using find
find /data -type f -size -10M -exec ./security_suite scan -type file -target {} \;

# Parallel scanning using GNU parallel (4 concurrent scans)
find /var/www -type f | parallel -j 4 ./security_suite scan -type file -target {}

# Scan only specific file types
find /home -type f \( -name "*.exe" -o -name "*.dll" -o -name "*.so" \) -exec ./security_suite scan -type file -target {} \;

# Scan and log results
./security_suite scan -type directory -target /opt -depth 3 > scan_$(date +%Y%m%d_%H%M%S).log 2>&1
```

#### Understanding Scan Results

**Threat Severity Levels:**

| Level | Description | Automatic Action | Example |
|-------|-------------|------------------|---------|
| `CRITICAL` | Confirmed malware, immediate threat | Automatic quarantine + network block (if applicable) | Known ransomware, backdoors |
| `HIGH` | Strong indicators of malicious activity | Quarantine + alert | Webshells, suspicious scripts |
| `MEDIUM` | Suspicious patterns detected | Log + monitor | Obfuscated code, packed binaries |
| `LOW` | Minor concerns, likely false positive | Log only | Unusual file headers |
| `INFO` | Informational, no threat | Log only | File metadata |

**Automatic Response Actions:**

The ResponseOrchestrator automatically handles threats:
```bash
# View quarantined files
ls -lh quarantine_zone/

# Restore a false positive
sudo mv quarantine_zone/file.quarantined_TIMESTAMP /original/path/file

# View blocked IPs (from network threats)
sudo iptables -L -n | grep DROP

# Remove a block
sudo iptables -D INPUT -s 192.168.1.50 -j DROP
```

### 2. Network Scanning

#### Basic Network Scan

Performs comprehensive network reconnaissance and security assessment.
```bash
# Scan single host
./security_suite scan -type network -target 192.168.1.100

# Scan entire subnet (Class C)
./security_suite scan -type network -target 192.168.1.0/24

# Scan IP range
./security_suite scan -type network -target 192.168.1.1-254

# Scan specific hosts
./security_suite scan -type network -target 192.168.1.1,192.168.1.10,192.168.1.50
```

**What Gets Scanned:**

1. **Host Discovery** - Identifies live hosts
2. **Port Scanning** - Detects open ports (top 1000 by default)
3. **Service Detection** - Identifies running services and versions
4. **OS Fingerprinting** - Determines operating system
5. **Vulnerability Scanning** - Checks for known CVEs
6. **Behavioral Analysis** - Integrates with traffic profiles

**Output Example:**
```
[NETWORK SCANNER] Starting tcp scan with profile: quick
[NETWORK SCANNER] Scanning 254 potential targets
[NETWORK SCANNER] Discovered 12 live hosts
[NETWORK SCANNER] Found 12 active hosts. Starting in-depth analysis...

[HOST:192.168.1.1] Router/Gateway
  Hostname: gateway.local
  OS: Linux 3.10.x (Accuracy: 75%)
  Open Ports: 22 (SSH), 80 (HTTP), 443 (HTTPS)

[HOST:192.168.1.50] Workstation
  Hostname: desktop-01.local
  OS: Ubuntu Linux (Accuracy: 85%)
  Open Ports: 
    22/TCP  SSH      OpenSSH 8.9p1
    80/TCP  HTTP     nginx 1.18.0
    445/TCP SMB      Samba 4.13.3
  
  [VULN] Scanning 192.168.1.50:445 for CVE-2017-0144 (EternalBlue)...
  [ALERT] CRITICAL: SMBv1 negotiated. The host is likely susceptible to MS17-010 if unpatched.

[HOST:192.168.1.100] Server
  Hostname: webserver.local
  OS: Windows Server 2019 (Accuracy: 90%)
  Open Ports:
    3389/TCP RDP     Microsoft Terminal Services
  
  [VULN] Scanning 192.168.1.100:3389 for CVE-2019-0708 (BlueKeep)...
  [INFO] RDP service detected. Unable to confirm BlueKeep vulnerability without deeper probe.

Network scan complete. Analyzed 12 hosts, found 3 security findings.

Summary:
  Total Hosts: 12
  Total Open Ports: 47
  Critical Vulnerabilities: 1
  High Vulnerabilities: 0
  Medium Vulnerabilities: 2
```

**Scan Results Interpretation:**
```bash
# Export results for further analysis
./security_suite scan -type network -target 192.168.1.0/24 > network_scan_$(date +%Y%m%d).txt

# Filter for critical findings only
./security_suite scan -type network -target 192.168.1.0/24 | grep -A 5 "CRITICAL"

# Extract vulnerable hosts
./security_suite scan -type network -target 192.168.1.0/24 | grep -B 2 "VULN" | grep "HOST:"
```

#### Advanced Network Scanning

**Targeted Port Scanning:**

The scanner uses intelligent port selection:
- **Quick Scan** (default): Top 100 most common ports
- **Standard Scan**: Top 1000 ports
- **Comprehensive Scan**: All 65535 ports (very slow)

**Service-Specific Scans:**
```bash
# Scan for web servers
./security_suite scan -type network -target 192.168.1.0/24 | grep -E "80/TCP|443/TCP|8080/TCP"

# Scan for SSH servers
./security_suite scan -type network -target 192.168.1.0/24 | grep "22/TCP"

# Scan for Windows file sharing
./security_suite scan -type network -target 192.168.1.0/24 | grep "445/TCP"

# Scan for databases
./security_suite scan -type network -target 192.168.1.0/24 | grep -E "3306/TCP|5432/TCP|1433/TCP|27017/TCP"
```

**Vulnerability Detection:**

The scanner automatically checks for:

| Vulnerability | CVE | Service | Severity |
|--------------|-----|---------|----------|
| EternalBlue | CVE-2017-0144 | SMB (445) | CRITICAL |
| BlueKeep | CVE-2019-0708 | RDP (3389) | CRITICAL |
| Heartbleed | CVE-2014-0160 | HTTPS (443) | HIGH |
| Log4Shell |
