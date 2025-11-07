
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

# Security Suite - Complete Documentation

## Table of Contents
1. [Alert and Response Monitoring](#alert-and-response-monitoring)
2. [Update Command](#update-command)
3. [Stop Command](#stop-command)
4. [Demo Command](#demo-command)
5. [Forensic Command](#forensic-command)
6. [Crack Command](#crack-command)
7. [WebScan Command](#webscan-command)
8. [Complete Feature Reference](#complete-feature-reference)
9. [Real-World Usage Scenarios](#real-world-usage-scenarios)
10. [Troubleshooting Guide](#troubleshooting-guide)
11. [Security Best Practices](#security-best-practices)
12. [Performance Benchmarks](#performance-benchmarks)

---

## Alert and Response Monitoring

```
- `[ALERT]` - Detected threats with severity level
- `[RESPONSE]` - Automated response actions taken
```

**Stopping Monitoring:**
Press `Ctrl+C` to gracefully stop packet capture.

**Example 2: Monitor WiFi with Verbose Output**
```bash
sudo ./security_suite -verbose monitor -iface wlan0
```

**Output (Verbose):**
```
[NetworkMalwareScanner] Started packet capture on wlan0
[DEBUG] Packet received: 192.168.1.75:54321 -> 8.8.8.8:53
[DEBUG] Protocol: UDP, Payload: 42 bytes
[DEBUG] DNS Query for: api.example.com
[PKT] 192.168.1.75 -> 8.8.8.8:53 (UDP, DNS Query)

[DEBUG] Behavioral Profile Update: 192.168.1.75
[DEBUG]   Connections: 15
[DEBUG]   Bytes In: 4520
[DEBUG]   Bytes Out: 2340
[DEBUG]   Anomaly Score: 0.12 (NORMAL)

[ALERT] HIGH Behavioral anomaly: Connection frequency exceeds baseline
  Source: 192.168.1.75
  Z-Score: 4.2
  Pattern: High-frequency connections (C2 Beaconing suspected)
```

---

## Update Command

**Purpose:** Update threat definitions and IDS rules

**Syntax:**
```bash
./security_suite update
```

**No options required** - updates all components automatically.

**Example:**
```bash
./security_suite update
```

**Output:**
```
[RuleManager] Executing Suricata rule update: suricata-update
[RuleManager] Rules updated successfully at 2024-11-02T15:30:12Z
[MalwareDetector] Updating malware definitions...
[MalwareDetector] YARA rules updated
[MalwareDetector] ClamAV signatures updated
[BehavioralAnalyzer] Remote behavior profiles loaded (simulated)

Update Status: Malware: Updated | IDS: Updated | Behavioral: Updated
```

**What Gets Updated:**
- ✅ Suricata IDS rules (via suricata-update)
- ✅ YARA malware signatures
- ✅ ClamAV virus database (if installed)
- ✅ Behavioral analysis models
- ✅ Vulnerability signatures

**Recommended Frequency:**
- **Daily** for production systems
- **Weekly** for test environments
- **Before major scans** for best accuracy

---

## Stop Command

**Purpose:** Stop all running security processes

**Syntax:**
```bash
./security_suite stop
```

**Example:**
```bash
./security_suite stop
```

**Output:**
```
[CoreController] Stop all services requested
[INFO] Stopped process: network_monitor
[INFO] Stopped process: ids_monitor
[INFO] Stopped process: behavioral_analyzer
All scanners stopped
```

**What Gets Stopped:**
- Network traffic monitoring
- IDS alert monitoring
- Background behavioral analysis
- Active hash cracking jobs
- Running web scans

**Note:** This does NOT stop the web server itself, only background processes.

---

## Demo Command

**Purpose:** Run demonstration of threat detection and response

**Syntax:**
```bash
./security_suite demo
```

**Example:**
```bash
./security_suite demo
```

**Output:**
```
============================================================
SECURITY SUITE DEMONSTRATION
============================================================

--- 1. FILE SCAN & QUARANTINE DEMO (EICAR) ---
[DEMO] Created dummy file: eicar_test_file.txt
[DEMO] Scan Result: Scan complete. Found 1 threats

[RESPONSE] File Quarantine Outcome (Action: QUARANTINE_FILE):
  Status: COMPLETED
  Message: Successfully quarantined file: sudo mv eicar_test_file.txt quarantine_zone/eicar_test_file.txt.quarantined_20241102153045

=======================================================
```

**What the Demo Does:**
1. Creates EICAR test file (harmless malware test signature)
2. Scans the file
3. Detects the threat
4. Automatically quarantines the file
5. Shows the complete response workflow

**Safe to Run:** The EICAR test file is industry-standard and completely harmless.

---

## Forensic Command

**Purpose:** Extract hashes from forensic images/systems

**Syntax:**
```bash
sudo ./security_suite forensic -os <OS_TYPE> -target <TARGET_PATH>
```

**Options:**
- `-os` - Target OS: `windows`, `linux` (required)
- `-target` - Path to forensic image or system root (required)

### Forensic Examples

**Example 1: Extract Linux Hashes**
```bash
sudo ./security_suite forensic -os linux -target /
```

**Output:**
```
[FORENSIC] Starting hash extraction from target: / (OS: linux)...
[ForensicToolkit] Starting unified hash extraction for OS: linux, Path: /
[ForensicToolkit] Starting sensitive file search at: /
[ForensicToolkit] Starting hash extraction from 3 files (OS: linux)...
[ForensicToolkit] Completed extraction, 23 hashes found.

[SUCCESS] Extracted 23 hashes:

[1] Type: SHA512-Crypt | User: root
    Hash: $6$rounds=5000$saltsaltsal$hash...
    Source: /etc/shadow

[2] Type: SHA512-Crypt | User: admin
    Hash: $6$rounds=5000$saltsaltsal$hash...
    Source: /etc/shadow

[3] Type: MD5 | User: user1
    Hash: 5f4dcc3b5aa765d61d8327deb882cf99
    Source: /var/backup/passwords.txt

[... additional hashes ...]
```

**Example 2: Extract Hashes from Mounted Forensic Image**
```bash
# First mount the forensic image
sudo mkdir /mnt/forensic
sudo mount -o ro,loop evidence.dd /mnt/forensic

# Extract hashes
sudo ./security_suite forensic -os linux -target /mnt/forensic

# Unmount when done
sudo umount /mnt/forensic
```

**Example 3: Target Specific Directory**
```bash
sudo ./security_suite forensic -os linux -target /home
```

**Output:**
```
[FORENSIC] Starting hash extraction from target: /home (OS: linux)...
[ForensicToolkit] Found sensitive files:
  /home/user/.ssh/id_rsa
  /home/user/.bash_history
  /home/user/passwords.txt
  /home/admin/.mysql_history

[SUCCESS] Extracted 8 hashes from user files.
```

---

## Crack Command

**Purpose:** Dictionary attack on password hashes

**Syntax:**
```bash
./security_suite crack -type <HASH_TYPE> -wordlist <WORDLIST_PATH> -hashes <HASH_LIST>
```

**Options:**
- `-type` - Hash type: `MD5`, `SHA256`, `NTLM`, `SHA512-Crypt` (required)
- `-wordlist` - Path to wordlist file (required)
- `-hashes` - Comma-separated list of hashes (required)

**Supported Hash Types:**
- `MD5` - Native Go implementation (fast)
- `SHA256` - Native Go implementation (fast)
- `NTLM` - Requires Hashcat (external)
- `Bcrypt` - Requires Hashcat (external)
- `SHA512-Crypt` - Requires Hashcat (external)

### Crack Examples

**Example 1: Crack MD5 Hashes**
```bash
./security_suite crack \
  -type MD5 \
  -wordlist /usr/share/wordlists/rockyou.txt \
  -hashes "5f4dcc3b5aa765d61d8327deb882cf99,098f6bcd4621d373cade4e832627b4f6"
```

**Output:**
```
[CRACKER] Session CRACK-1730568345: Starting crack job on 2 hashes (Type: MD5) with wordlist: /usr/share/wordlists/rockyou.txt

[HashCracker] Session CRACK-1730568345 Progress: 0/2 cracked (0.00%)
[HashCracker] Session CRACK-1730568345 Progress: 1/2 cracked (50.00%)
[CRACKED] 5f4dcc3b5aa765d61d8327deb882cf99 = password
[HashCracker] Session CRACK-1730568345 Progress: 2/2 cracked (100.00%)
[CRACKED] 098f6bcd4621d373cade4e832627b4f6 = test

[HashCracker] Session CRACK-1730568345 FINAL Progress: 2/2 cracked (100.00%). Done.

Cracking Results:
Hash: 5f4dcc3b5aa765d61d8327deb882cf99
Plaintext: password

Hash: 098f6bcd4621d373cade4e832627b4f6
Plaintext: test
```

**Example 2: Crack NTLM with Hashcat**
```bash
# Requires Hashcat installed: sudo pacman -S hashcat (Arch) or sudo apt install hashcat (Ubuntu)
./security_suite crack \
  -type NTLM \
  -wordlist /usr/share/wordlists/rockyou.txt \
  -hashes "8846f7eaee8fb117ad06bdd830b7586c"
```

**Output:**
```
[HashCracker: Hashcat] Using external tool for NTLM. Hashcat must be installed.
[HashCracker: Hashcat] Calling hashcat with mode 1000 on /tmp/hashes-1730568450.txt...
[HashCracker: Hashcat] Hashcat completed successfully. Output:
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1000 (NTLM)
Hash.Target......: 8846f7eaee8fb117ad06bdd830b7586c
Time.Started.....: Sat Nov 02 15:45:50 2024
...

[CRACKED] 8846f7eaee8fb117ad06bdd830b7586c = password123

[HashCracker] Session CRACK-1730568450: Cracking job finished.
```

**Example 3: Background Cracking Job**
```bash
# Start cracking in background
./security_suite crack -type MD5 -wordlist rockyou.txt -hashes "hash1,hash2,hash3" &

# Check progress
ps aux | grep security_suite

# Results are logged to console output
```

**Wordlist Recommendations:**
- **Small (fast testing):** `/usr/share/wordlists/fasttrack.txt`
- **Medium:** `/usr/share/wordlists/dirb/common.txt`
- **Large (comprehensive):** `/usr/share/wordlists/rockyou.txt` (14 million passwords)
- **Custom:** Create your own based on target organization

---

## WebScan Command

**Purpose:** Web application vulnerability scanning

**Syntax:**
```bash
./security_suite webscan -url <TARGET_URL> [-type <SCAN_TYPE>] [-depth <DEPTH>] [-format <FORMAT>]
```

**Options:**
- `-url` - Target URL to scan (required)
- `-type` - Scan type: `quick`, `full`, `custom` (default: quick)
- `-depth` - Crawl depth for URL discovery (default: 2)
- `-format` - Report format: `text`, `json`, `html` (default: text)

### WebScan Examples

**Example 1: Quick Web Scan**
```bash
./security_suite webscan -url https://example.com -type quick
```

**Output:**
```
Starting web security scan of: https://example.com

[WebScanner] Starting comprehensive scan of https://example.com
[WebScanner] Phase 1: Information Gathering
[WebScanner] Phase 2: Endpoint Discovery
[Crawler] Starting production-level crawling of example.com (Depth: 1)
[Crawler] Processing 5 URLs at Depth 0
[WebScanner] Phase 3: Vulnerability Testing

[VULNERABILITY FOUND]
Type: Missing X-Content-Type-Options Header
Severity: LOW
URL: https://example.com
Remediation: Set the X-Content-Type-Options header to 'nosniff'.

[VULNERABILITY FOUND]
Type: Cross-Site Scripting (XSS) - Reflected
Severity: HIGH
URL: https://example.com/search?q=test
Parameter: q
Payload: <script>alert('XSS-TEST')</script>
Remediation: Implement proper input validation and output encoding.

[WebScanner] Scan completed. Found 2 vulnerabilities.

Web scan complete. Found 2 vulnerabilities (Critical: 0, High: 1, Medium: 0, Low: 1)

============================================
WEB SECURITY SCAN REPORT
============================================
Timestamp: Saturday, 02-Nov-24 15:50:30 UTC
Target: https://example.com

SUMMARY OF FINDINGS
--------------------------------------------
Total Vulnerabilities: 2
  CRITICAL: 0
  HIGH:     1
  MEDIUM:   0
  LOW:      1

============================================
DETAILED FINDINGS
============================================

[1] HIGH - Cross-Site Scripting (XSS) - Reflected
URL: https://example.com/search?q=test
Parameter: q
Payload: <script>alert('XSS-TEST')</script>
Description: Reflected XSS vulnerability detected in GET parameter. Payload was found unescaped in the response.
CVSS: 7.5 | CWE: CWE-79 | OWASP: A03:2021 - Injection
Remediation: Implement proper input validation and output encoding on all user-controlled data.

---

[2] LOW - Missing X-Content-Type-Options Header
URL: https://example.com
Description: The X-Content-Type-Options header is missing, which can allow MIME-type sniffing.
CVSS: 4.3 | CWE: CWE-200 | OWASP: A05:2021 - Security Misconfiguration
Remediation: Set the X-Content-Type-Options header to 'nosniff'.
```

**Example 2: Full Web Scan with HTML Report**
```bash
./security_suite webscan -url https://testphp.vulnweb.com -type full -format html > report.html
```

**Example 3: Custom Scan Configuration**
```bash
./security_suite webscan \
  -url https://example.com \
  -type custom \
  -depth 3 \
  -format json > scan_results.json
```

**⚠️ CRITICAL WARNING:**
- Only scan websites you own or have written authorization to test
- Unauthorized scanning may be illegal in your jurisdiction
- Some scans may be detected as attacks by WAFs/IDS
- Always obtain permission before testing

---

## Complete Feature Reference

### 1. Malware Detection Engine

**Capabilities:**
- YARA rule-based signature matching
- SHA256 hash blacklist checking
- ClamAV antivirus integration
- VirusTotal API lookup
- Multi-threaded file scanning
- Automatic file quarantine

**Detection Methods:**
```
┌─────────────────────────────────────────┐
│         Malware Detection Flow          │
├─────────────────────────────────────────┤
│                                         │
│  File Submitted                         │
│      ↓                                  │
│  Calculate SHA256 Hash                  │
│      ↓                                  │
│  Check Hash Blacklist ────→ MATCH → CRITICAL
│      ↓ NO MATCH                        │
│  Query VirusTotal API ────→ MATCH → HIGH
│      ↓ NO MATCH                        │
│  Scan with ClamAV ────────→ MATCH → HIGH
│      ↓ NO MATCH                        │
│  Execute YARA Rules ───────→ MATCH → VARIABLE
│      ↓ NO MATCH                        │
│  File Clean                             │
│                                         │
└─────────────────────────────────────────┘
```

**Supported File Types:**
- PE executables (.exe, .dll)
- Scripts (.sh, .py, .php, .js)
- Documents (.pdf, .doc, .xls)
- Archives (.zip, .tar, .gz)
- Binary files
- All text formats

**YARA Rule Example:**
```yara
rule WebShell_Detection {
    meta:
        description = "Detects PHP webshell patterns"
        severity = "CRITICAL"
        author = "Security Suite"
    
    strings:
        $php = "<?php" nocase
        $exec1 = "exec(" nocase
        $exec2 = "shell_exec(" nocase
        $eval = "eval(" nocase
        $base64 = "base64_decode"
    
    condition:
        $php and (2 of ($exec*) or ($eval and $base64))
}
```

**Custom YARA Rules:**
- Located in: `yara_rules.yar`
- Automatically loaded on startup
- Can be updated without restarting (use Update Definitions)

---

### 2. Network Scanning Engine

**Capabilities:**
- TCP/UDP port scanning
- Service version detection (50+ signatures)
- OS fingerprinting (TTL, Window Size, TCP options)
- Vulnerability scanning (EternalBlue, BlueKeep, etc.)
- SSL/TLS certificate analysis
- Banner grabbing

**Scan Profiles:**
- **Quick:** Top 100 ports (~1 minute)
- **Standard:** Top 1,000 ports (~5 minutes)
- **Comprehensive:** All 65,535 ports (~30 minutes)
- **PenTest:** Security-focused port selection

**Service Detection Examples:**
```
Port 22/TCP:
  Service: ssh
  Product: OpenSSH
  Version: 8.9p1 Ubuntu-3ubuntu0.1
  Banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1

Port 445/TCP:
  Service: microsoft-ds
  Product: SMB/CIFS
  Version: SMBv1 (NT LM 0.12)
  Extra: Potentially Vulnerable (MS17-010)
```

**Vulnerability Database:**
- CVE-2017-0144 (EternalBlue) - SMBv1 RCE
- CVE-2019-0708 (BlueKeep) - RDP RCE
- CVE-2014-0160 (Heartbleed) - OpenSSL Info Disclosure
- CVE-2021-44228 (Log4Shell) - Apache Log4j RCE
- 20+ additional critical vulnerabilities

**OS Fingerprinting Accuracy:**
```
Detection Method: Multi-factor analysis
Factors Analyzed:
  - Initial TTL (32, 64, 128, 255)
  - TCP Window Size
  - TCP Options (MSS, SACK, Timestamps)
  - Service banners
  - HTTP headers

Accuracy Rates:
  Windows: 85-95%
  Linux: 80-90%
  Network Devices: 90-98%
```

---

### 3. Behavioral Analysis (Machine Learning)

**Algorithm:** Isolation Forest (Anomaly Detection)

**How It Works:**
```
┌─────────────────────────────────────────────────┐
│        Behavioral Analysis Pipeline             │
├─────────────────────────────────────────────────┤
│                                                 │
│  Network Traffic                                │
│       ↓                                         │
│  Feature Extraction                             │
│    • Connection Rate                            │
│    • Bytes In/Out                               │
│    • Protocol Distribution                      │
│    • Active Hours                               │
│       ↓                                         │
│  Profile Building (per IP)                      │
│       ↓                                         │
│  Isolation Forest Training                      │
│    (100 trees, 256 sample size)                │
│       ↓                                         │
│  Anomaly Scoring (0-1 scale)                   │
│    0.0-0.3: Normal                             │
│    0.3-0.6: Suspicious                         │
│    0.6-0.8: High Anomaly                       │
│    0.8-1.0: Critical Anomaly                   │
│       ↓                                         │
│  Threat Indicator Generation                    │
│                                                 │
└─────────────────────────────────────────────────┘
```

**Detected Behaviors:**
- **C2 Beaconing:** Regular periodic connections to external hosts
- **Data Exfiltration:** Unusually large uploads
- **Lateral Movement:** Internal network scanning
- **Port Scanning:** High connection frequency to multiple ports
- **DNS Tunneling:** Excessive DNS queries with large payloads
- **Off-hours Activity:** Activity during unusual times

**Statistical Baseline:**
- Mean connection rate per IP
- Standard deviation for traffic patterns
- Z-score calculation for anomaly detection
- Adaptive learning (model retrains every 15 minutes)

**Indicators of Behavior (IOB):**
```
IOB: C2-Beaconing
Pattern: high_freq_connections + small_periodic_data
Ports: 8080, 443, 53
Severity: CRITICAL

IOB: Exfiltration-LargeTransfer
Pattern: large_data_transfer + high_bytes_out
Ports: 80, 443, 21
Severity: HIGH

IOB: Lateral-Movement-Scan
Pattern: high_freq_connections + short_duration
Ports: 22, 23, 445, 3389
Severity: HIGH
```

---

### 4. Intrusion Detection System (IDS)

**Engine:** Suricata Integration

**Capabilities:**
- Real-time packet inspection
- Protocol analysis (HTTP, DNS, TLS, SMB, etc.)
- Signature-based detection
- Anomaly detection
- File extraction from traffic
- Alert correlation

**Rule Format:**
```
alert tcp any any -> $HOME_NET 445 (
    msg:"SECURITY_SUITE Potential Lateral Movement via SMB";
    flow:to_server,established;
    threshold:type threshold, track by_src, count 10, seconds 60;
    sid:1000004;
    rev:1;
)
```

**Custom Rules:**
- Located in: `ids_rules/security_suite_local.rules`
- Automatically loaded on Suricata start/reload
- Update with: `./security_suite update`

**Alert Processing:**
```
Suricata → eve.json → Security Suite → Threat Indicator → Response Orchestrator
```

**Example Alert Flow:**
```
1. Suricata detects port scan
2. Writes to /var/log/suricata/eve.json
3. Security Suite reads alert (every 2 seconds)
4. Converts to ThreatIndicator
5. Evaluates severity (1=Critical, 3=Medium)
6. Triggers automated response
7. Blocks attacker IP via iptables
```

---

### 5. Automated Threat Response

**Response Orchestrator:** Centralized action dispatcher

**Response Matrix:**
```
┌───────────┬──────────────────────────────────┐
│ Severity  │ Automatic Action                  │
├───────────┼──────────────────────────────────┤
│ CRITICAL  │ • File: QUARANTINE_FILE           │
│           │ • Network: BLOCK_NETWORK_ACCESS   │
├───────────┼──────────────────────────────────┤
│ HIGH      │ • QUARANTINE_FILE                 │
├───────────┼──────────────────────────────────┤
│ MEDIUM    │ • INCREASE_MONITORING             │
│           │ • LOG_TO_DB                       │
├───────────┼──────────────────────────────────┤
│ LOW       │ • LOG_ONLY                        │
├───────────┼──────────────────────────────────┤
│ INFO      │ • LOG_ONLY                        │
└───────────┴──────────────────────────────────┘
```

**File Quarantine Process:**
```bash
# Threat Detected: /tmp/malware.exe
# Automatic execution:
sudo mv /tmp/malware.exe quarantine_zone/malware.exe.quarantined_20241102153045

# File is:
# - Moved to secure location
# - Timestamped
# - Permissions set to 000 (no access)
# - Logged in action history
```

**Network Block Process:**
```bash
# Threat Detected from: 192.168.1.50
# Automatic execution:
sudo iptables -A INPUT -s 192.168.1.50 -j DROP

# Traffic from that IP is:
# - Immediately blocked
# - Logged in action history
# - Persists until manual removal
```

**Viewing Active Blocks:**
```bash
# List all iptables rules
sudo iptables -L -n -v

# Remove a block
sudo iptables -D INPUT -s 192.168.1.50 -j DROP

# Clear all blocks
sudo iptables -F
```

**Restoring Quarantined Files:**
```bash
# List quarantined files
ls -la quarantine_zone/

# Restore a file (if false positive)
sudo mv quarantine_zone/file.quarantined_20241102 /original/path/file

# Delete permanently
sudo rm quarantine_zone/file.quarantined_20241102
```

---

### 6. Web Application Scanner

**OWASP Top 10 Coverage:**
```
✓ A01:2021 - Broken Access Control
  • Path Traversal
  • LFI (Local File Inclusion)
  • Open Redirect

✓ A02:2021 - Cryptographic Failures
  • Weak SSL/TLS protocols
  • Insecure cookies

✓ A03:2021 - Injection
  • SQL Injection (Error, Boolean, Time-based)
  • XSS (Reflected, Stored)
  • Command Injection (RCE)
  • LDAP Injection

✓ A04:2021 - Insecure Design
  • CSRF (Cross-Site Request Forgery)

✓ A05:2021 - Security Misconfiguration
  • Missing security headers
  • Default credentials
  • XXE (XML External Entity)

✓ A07:2021 - Identification and Authentication Failures
  • Weak authentication testing
  • Session management flaws

✓ A10:2021 - Server-Side Request Forgery (SSRF)
  • Internal network access
  • Metadata endpoint access
```

**Attack Techniques:**
- **Active Testing:** Actual exploit attempts
- **Passive Analysis:** Header inspection, cookie analysis
- **Behavioral Testing:** Authentication workflow analysis

**Payloads Database:**
```
SQL Injection:
  ' AND 1=1 --
  ' OR 'a'='a
  '; DROP TABLE users--

XSS:
  <script>alert('XSS')</script>
  " onmouseover=alert('XSS') x="

LFI:
  ../../../etc/passwd
  ....//....//etc/passwd

RCE:
  ; echo VULNTEST999
  | whoami
```

---

### 7. Digital Forensics Toolkit

**Capabilities:**
- Hash extraction (Linux: /etc/shadow, Windows: SAM)
- Running process analysis
- Sensitive file discovery
- PCAP analysis (network forensics)
- Geo-location lookups (MaxMind GeoIP2)

**Hash Extraction Targets:**
```
Linux:
  /etc/shadow           (user password hashes)
  /etc/passwd           (user info)
  /root/.bash_history   (command history)
  /home/*/.ssh/id_rsa   (SSH keys)
  /var/www/.htpasswd    (web authentication)

Windows (when mounted):
  Windows/System32/config/SAM
  Windows/System32/config/SECURITY
```

**Process Analysis:**
```bash
# Analyzes output of: ps aux
# Extracts:
  - PID (Process ID)
  - User (owner)
  - CPU usage
  - Memory usage
  - Full command line
```

**PCAP Analysis:**
```
Capabilities:
  - Session reconstruction
  - Protocol identification (HTTP, TLS, SSH, DNS)
  - Payload extraction
  - Geo-location tagging
  - Deep packet inspection

Example Output:
  Session: 192.168.1.50:54321 -> 8.8.8.8:53
  Protocol: DNS
  Packets: 24
  Payload: [DNS Query for api.malware.com]
  GeoLocation: United States, Mountain View, CA
```

---

### 8. Hash Cracking Engine

**Supported Algorithms:**
- **Native (Fast):** MD5, SHA256
- **Hashcat (Comprehensive):** NTLM, Bcrypt, SHA512-Crypt

**Concurrency:** Multi-threaded (4-8 cores recommended)

**Attack Modes:**
- **Dictionary:** Wordlist-based (rockyou.txt, etc.)
- **Hashcat Extended:** Mask attacks, combinator attacks

**Performance:**
```
MD5 (Native Go):
  ~100,000 hashes/second per core
  4-core system: ~400,000 h/s

SHA256 (Native Go):
  ~50,000 hashes/second per core
  4-core system: ~200,000 h/s

NTLM (Hashcat + GPU):
  ~1-10 billion hashes/second (GPU-dependent)
```

**Wordlist Recommendations:**
```
Small (Testing):
  /usr/share/wordlists/fasttrack.txt (222 passwords)

Medium (Targeted):
  /usr/share/wordlists/dirb/common.txt (4,614 passwords)

Large (Comprehensive):
  /usr/share/wordlists/rockyou.txt (14,344,391 passwords)
  
Custom:
  Create organization-specific wordlists using:
  - Company name variations
  - Product names
  - Common password patterns
  - Previous breach data
```

---

### 9. Interactive Terminal

**Technology:** PTY (Pseudo-Terminal) with WebSocket streaming

**Features:**
- Full bash compatibility
- Real-time I/O
- Sudo password prompts in browser
- Command history
- Color support (xterm-256color)
- Session persistence (30 minute idle timeout)

**Architecture:**
```
Browser ←→ WebSocket ←→ Go Server ←→ PTY ←→ Bash Process
```

**Session Management:**
```
1. User clicks "New Session"
2. Server creates PTY
3. Spawns /bin/bash inside PTY
4. WebSocket connects browser ↔ PTY
5. Bidirectional streaming begins
6. User types commands → PTY → bash
7. Bash output → PTY → WebSocket → Browser
```

**Security Features:**
- Sessions are user-isolated
- Automatic cleanup after 30 minutes idle
- Graceful shutdown on disconnect
- No command injection vulnerabilities

---

### 10. Camera Stream Detection

**Supported Protocols:**
- RTSP (Real-Time Streaming Protocol)
- HTTP/MJPEG
- HTTPS

**Detection Method:**
```
1. User provides IP or URL
2. System attempts multiple protocols:
   - RTSP: rtsp://IP:554/path
   - HTTP: http://IP:8080/path
   - HTTPS: https://IP/path
3. Tests 15+ common camera paths
4. Returns first working stream
```

**Common Camera Manufacturers:**
```
Axis:
  rtsp://IP:554/axis-media/media.amp
  
Hikvision:
  rtsp://IP:554/Streaming/Channels/101

Dahua:
  rtsp://IP:554/cam/realmonitor?channel=1&subtype=0

Generic:
  rtsp://IP:554/
  http://IP:8080/video
```

---

## Real-World Usage Scenarios

### Scenario 1: Compromised Web Server Investigation

**Situation:** Web server showing unusual activity

**Investigation Steps:**

1. **Initial Assessment**
```bash
# Start network monitoring to capture ongoing activity
sudo ./security_suite -verbose monitor -iface eth0
```

2. **Scan for Malware**
```bash
# Scan web root for backdoors/webshells
sudo ./security_suite scan -path /var/www/html -recursive
```

3. **Check for Active Threats**
```bash
# Look for suspicious processes and connections
sudo ./security_suite forensic -os linux -target /var/www
```

4. **Web Application Analysis**
```bash
# Scan the web application for vulnerabilities
./security_suite webscan -url https://yourserver.com -type full
```

5. **Review Findings**
- Check quarantine_zone/ for isolated files
- Review behavioral alerts for C2 beaconing
- Examine IDS alerts for exploit attempts
- Analyze extracted hashes for weak passwords

**Expected Results:**
- Webshell detection in uploads directory
- Suspicious outbound connections (C2 beaconing)
- SQL injection vulnerabilities in login form
- Weak admin credentials cracked

**Remediation:**
- Quarantine malicious files (automatic)
- Block attacker IPs (automatic)
- Patch web application vulnerabilities
- Reset compromised passwords
- Update all definitions

---

### Scenario 2: Internal Network Threat Hunt

**Situation:** Suspected lateral movement in corporate network

**Hunt Procedure:**

1. **Network Reconnaissance**
```bash
# Scan internal network for vulnerabilities
./security_suite netscan -target 192.168.1.0/24 -profile pentest
```

2. **Continuous Monitoring**
```bash
# Monitor for lateral movement indicators
sudo ./security_suite -verbose monitor -iface eth0
```

3. **Behavioral Analysis**
- Watch for high-frequency internal scanning
- Detect SMB/RDP brute force attempts
- Identify data exfiltration patterns
- Track anomalous authentication patterns

4. **Forensic Collection**
```bash
# Extract hashes from suspected compromised systems
sudo ./security_suite forensic -os linux -target /mnt/suspect1
```

5. **Credential Analysis**
```bash
# Attempt to crack extracted hashes
./security_suite crack \
  -type SHA512-Crypt \
  -wordlist /usr/share/wordlists/rockyou.txt \
  -hashes "extracted_hashes_here"
```

**Indicators to Watch:**
- Multiple failed authentication attempts
- Port scanning activity (ports 22, 445, 3389)
- Unusual service usage patterns
- Off-hours network activity
- Large internal data transfers

**Response Actions:**
- Automatic IP blocking for scanning hosts
- Quarantine suspected malware samples
- Increase monitoring on compromised segments
- Force password resets for cracked credentials

---

### Scenario 3: Incident Response Workflow

**Situation:** Security incident requiring full investigation

**Complete Workflow:**

```bash
# Phase 1: Containment
sudo ./security_suite monitor -iface eth0  # Background monitoring
# Automatically blocks malicious IPs

# Phase 2: Evidence Collection
sudo ./security_suite scan -path / -recursive  # Full system scan
sudo ./security_suite forensic -os linux -target /  # Hash extraction
./security_suite netscan -target <attacker_ip> -profile quick  # Attacker profiling

# Phase 3: Analysis
./security_suite crack -type MD5 -wordlist rockyou.txt -hashes "found_hashes"
./security_suite webscan -url https://targetsite.com -type full

# Phase 4: Update Defenses
./security_suite update  # Latest threat definitions

# Phase 5: Reporting
# Review dashboard at http://localhost:8080
# Export findings from web interface
```

**Generated Artifacts:**
- Malware samples in quarantine_zone/
- Network traffic logs
- Cracked credentials
- Vulnerability assessment reports
- IDS alert logs
- Behavioral analysis data

---

### Scenario 4: Penetration Testing Engagement

**Situation:** Authorized security assessment of client infrastructure

**Testing Methodology:**

1. **Reconnaissance**
```bash
# Network discovery
./security_suite netscan -target client-network.com -profile comprehensive

# Web application mapping
./security_suite webscan -url https://client-webapp.com -type full -depth 3
```

2. **Vulnerability Assessment**
- Review scan results for critical vulnerabilities
- Prioritize findings by CVSS score
- Document exploitation paths

3. **Exploitation (Simulated)**
```bash
# Test weak credentials
./security_suite crack \
  -type NTLM \
  -wordlist /usr/share/wordlists/rockyou.txt \
  -hashes "target_hashes"
```

4. **Post-Exploitation Analysis**
```bash
# Analyze what attacker could access
sudo ./security_suite forensic -os linux -target /target/mount
```

5. **Report Generation**
- Export findings from web dashboard
- Include CVSS scores, CWE mappings, OWASP categories
- Provide remediation recommendations
- Document automated response effectiveness

**Deliverables:**
- Comprehensive vulnerability report
- Risk assessment matrix
- Proof-of-concept exploits
- Remediation priority roadmap

---

## Troubleshooting Guide

### Common Issues

**Issue: "Permission denied" errors**
```bash
# Solution: Run with sudo for privileged operations
sudo ./security_suite monitor -iface eth0
sudo ./security_suite scan -path /root -recursive
```

**Issue: Suricata not starting**
```bash
# Check if already running
sudo systemctl status suricata

# Stop existing instance
sudo systemctl stop suricata

# Verify configuration
sudo suricata -T -c /etc/suricata/suricata.yaml
```

**Issue: Web interface not accessible**
```bash
# Check if port 8080 is in use
sudo netstat -tlnp | grep 8080

# Try alternative port
./security_suite -port 8081
```

**Issue: Network monitoring shows no packets**
```bash
# List available interfaces
ip link show

# Verify interface is up
sudo ip link set eth0 up

# Check permissions
sudo setcap cap_net_raw,cap_net_admin=eip ./security_suite
```

**Issue: Hashcat not found**
```bash
# Install Hashcat
# Arch Linux:
sudo pacman -S hashcat

# Ubuntu/Debian:
sudo apt install hashcat

# Verify installation:
which hashcat
```

**Issue: High CPU usage during scanning**
```bash
# Reduce scan speed with nice
nice -n 19 ./security_suite scan -path /large/directory

# Limit concurrent goroutines (edit source code)
# Adjust: numWorkers := 4  // Instead of 8
```

**Issue: False positive malware detections**
```bash
# Review YARA rules
nano yara_rules.yar

# Restore quarantined file
sudo mv quarantine_zone/false_positive.quarantined /original/path

# Whitelist hash (add to code or config)
```

---

## Security Best Practices

### For Production Deployments

1. **Access Control**
   - Run web interface on internal network only
   - Use HTTPS with valid certificates
   - Implement authentication (add reverse proxy with auth)
   - Restrict sudo access to security team

2. **Update Frequency**
   ```bash
   # Daily automated updates
   0 2 * * * /path/to/security_suite update >> /var/log/security_suite_update.log 2>&1
   ```

3. **Log Management**
   - Rotate logs regularly
   - Export to SIEM (Splunk, ELK)
   - Retain logs per compliance requirements
   - Monitor disk space

4. **Response Validation**
   - Review quarantined files weekly
   - Audit blocked IPs monthly
   - Test restore procedures
   - Document false positives

5. **Performance Tuning**
   - Adjust scan schedules during off-hours
   - Limit concurrent operations
   - Use quick scans for frequent checks
   - Reserve comprehensive scans for monthly audits

### Legal and Ethical Considerations

⚠️ **CRITICAL WARNINGS:**

1. **Authorization Required**
   - Only scan systems you own or have written permission to test
   - Obtain client authorization for penetration testing
   - Document scope and limitations
   - Respect rules of engagement

2. **Data Privacy**
   - Handle extracted credentials securely
   - Follow data protection regulations (GDPR, CCPA)
   - Encrypt sensitive findings
   - Secure deletion of forensic evidence when complete

3. **Responsible Disclosure**
   - Report vulnerabilities to vendors privately
   - Allow reasonable time for patching (90 days standard)
   - Follow coordinated disclosure practices
   - Do not exploit vulnerabilities for personal gain

4. **Compliance**
   - Verify tools comply with organizational policies
   - Document all security testing activities
   - Maintain audit trails
   - Follow industry standards (PCI-DSS, HIPAA, SOC2)

---

## Performance Benchmarks

### System Requirements

**Minimum:**
- CPU: 2 cores, 2.0 GHz
- RAM: 4 GB
- Disk: 10 GB free space
- Network: 100 Mbps

**Recommended:**
- CPU: 4+ cores, 3.0+ GHz
- RAM: 8+ GB
- Disk: 50+ GB SSD
- Network: 1 Gbps

**Optimal (Large Deployments):**
- CPU: 8+ cores, 3.5+ GHz
- RAM: 16+ GB
- Disk: 100+ GB NVMe SSD
- Network: 10 Gbps
- GPU: CUDA-capable (for hash cracking)

### Performance Metrics

**File Scanning:**
```
Single File: ~10-50ms (average)
Directory (1,000 files): ~30-60 seconds
Full System Scan: ~10-30 minutes (varies by size)
```

**Network Scanning:**
```
Quick Scan (100 ports, 1 host): ~30-60 seconds
Standard Scan (1,000 ports, 1 host): ~5-10 minutes
Comprehensive (65,535 ports, 1 host): ~30-60 minutes
Class C Network (/24, quick): ~10-20 minutes
```

**Web Scanning:**
```
Quick Scan: ~2-5 minutes
Full Scan (depth 2): ~10-20 minutes
Full Scan (depth 3): ~30-60 minutes
```

**Hash Cracking:**
```
MD5 (10,000 hashes, rockyou.txt):
  4-core CPU: ~5-10 minutes
  8-core CPU: ~3-5 minutes

NTLM (10,000 hashes, rockyou.txt):
  Hashcat + GTX 1060: ~1-2 minutes
  Hashcat + RTX 3080: ~10-30 seconds
```

**Network Monitoring:**
```
Packet Processing: ~10,000-50,000 packets/second
Memory Usage: ~200-500 MB (base)
CPU Usage: ~10-30% (1 core)
```

### Optimization Tips

1. **For Large File Scans:**
   - Use SSD storage
   - Exclude known safe directories (/usr, /lib)
   - Schedule during off-peak hours
   - Use `-recursive` flag efficiently

2. **For Network Scans:**
   - Start with quick profiles
   - Use targeted port lists
   - Scan smaller subnets in parallel
   - Adjust timeout values for faster networks

3. **For Hash Cracking:**
   - Use GPU acceleration when available
   - Start with smaller wordlists
   - Use rule-based attacks for efficiency
   - Consider distributed cracking for large jobs

4. **For Web Scans:**
   - Limit crawl depth initially
   - Use quick scans for initial assessment
   - Target specific endpoints for deep testing
   - Run during maintenance windows

---

## Advanced Configuration

### Custom YARA Rules

Create custom detection rules in `yara_rules.yar`:

```yara
rule Advanced_Backdoor {
    meta:
        description = "Advanced persistent backdoor detection"
        severity = "CRITICAL"
        author = "Your Name"
        date = "2024-11-02"
    
    strings:
        $net1 = "socket" nocase
        $net2 = "connect" nocase
        $exec = "exec" nocase
        $base64 = "base64" nocase
        $crypto = { 6A 40 68 00 30 00 00 }  // Hex pattern
    
    condition:
        2 of ($net*) and ($exec or $base64) and $crypto
}
```

### Custom IDS Rules

Add rules to `ids_rules/security_suite_local.rules`:

```
alert tcp any any -> $HOME_NET any (
    msg:"CUSTOM Suspicious PowerShell Download";
    flow:to_server,established;
    content:"powershell"; nocase;
    content:"DownloadFile"; nocase; distance:0;
    classtype:trojan-activity;
    sid:2000001;
    rev:1;
)

alert dns any any -> any any (
    msg:"CUSTOM Possible DNS Tunneling";
    dns_query; content:".tunnel."; nocase;
    threshold:type threshold, track by_src, count 10, seconds 60;
    classtype:policy-violation;
    sid:2000002;
    rev:1;
)
```

### Environment Variables

```bash
# Configure VirusTotal API
export VT_API_KEY="your_api_key_here"

# Set custom quarantine location
export QUARANTINE_DIR="/secure/quarantine"

# Adjust worker threads
export MAX_WORKERS=8

# Custom Suricata config
export SURICATA_CONFIG="/etc/suricata/custom.yaml"
```

### Integration with External Tools

**SIEM Integration (Syslog):**
```bash
# Configure rsyslog to forward alerts
echo "*.* @@siem.company.com:514" >> /etc/rsyslog.conf
systemctl restart rsyslog
```

**Slack Notifications:**
```bash
# Add webhook to send critical alerts
SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/WEBHOOK"
# Integrate in response orchestrator
```

**Email Alerts:**
```bash
# Configure mail client
sudo apt install mailutils
# Send critical alerts via email
echo "Critical threat detected" | mail -s "Security Alert" admin@company.com
```

---

## API Reference (Future Feature)

### REST API Endpoints (Planned)

```
POST   /api/v1/scan
GET    /api/v1/scan/:id/status
GET    /api/v1/scan/:id/results
POST   /api/v1/monitor/start
POST   /api/v1/monitor/stop
GET    /api/v1/threats
POST   /api/v1/response/:action
GET    /api/v1/quarantine
DELETE /api/v1/quarantine/:id
POST   /api/v1/update
GET    /api/v1/stats
```

### Example API Usage (Future)

```bash
# Start a scan
curl -X POST http://localhost:8080/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"path": "/var/www", "recursive": true}'

# Check scan status
curl http://localhost:8080/api/v1/scan/12345/status

# Get results
curl http://localhost:8080/api/v1/scan/12345/results
```

---

## Contributing

### Reporting Issues

1. Check existing issues on project repository
2. Provide detailed reproduction steps
3. Include system information (OS, version, hardware)
4. Attach relevant logs (redact sensitive data)

### Feature Requests

1. Describe the use case
2. Explain expected behavior
3. Provide examples if applicable
4. Consider security implications

### Development Setup

```bash
# Clone repository
git clone https://github.com/yourusername/security_suite.git
cd security_suite

# Install dependencies
go mod download

# Build
go build -o security_suite

# Run tests
go test ./...

# Run with race detection
go run -race main.go
```

**Use at your own risk. The authors assume no liability for misuse or damage.**

---

## Acknowledgments

- **Suricata** - Open-source IDS/IPS engine
- **YARA** - Pattern matching for malware research
- **ClamAV** - Open-source antivirus engine
- **Hashcat** - Advanced password recovery
- **VirusTotal** - File and URL analysis service
- **OWASP** - Web application security standards
- **Go Community** - Excellent libraries and tools

---

## Changelog

### Version 1.0.0 (Current)
- Initial release
- Malware scanning with YARA/ClamAV
- Network vulnerability scanning
- Behavioral analysis (ML)
- IDS integration (Suricata)
- Automated response orchestration
- Web application scanning
- Digital forensics toolkit
- Hash cracking engine
- Interactive web terminal
- Camera stream detection

### Planned Features (v1.1.0)
- REST API endpoints
- Email/Slack notifications
- Machine learning model improvements
- Additional vulnerability signatures
- Enhanced reporting formats
- Multi-language support
- Container security scanning
- Cloud infrastructure scanning

---

**End of Documentation**

