Process Notes: Security Suite v2.0.0

1. Project Overview and Core Features

The Security Suite v2.0.0 is an Advanced Threat Detection & Response Platform written in Go with a modern web interface. It is designed to be production-ready and includes a comprehensive set of security capabilities:

Module

Core Functionality

Malware Detection

YARA rule-based signature scanning, SHA256 detection, and ClamAV integration.

Behavioral Analyzer

Machine learning (Isolation Forest simulation) for anomaly detection, network traffic profiling, and C2 beaconing identification.

Intrusion Detection (IDS)

Real Suricata integration for real-time alert monitoring and custom rule management.

Network Scanner

Comprehensive port scanning (TCP/UDP), OS fingerprinting, service version detection, and vulnerability scanning.

Response Orchestrator

Automated threat response, including file quarantine and network access blocking via iptables.

Interactive Terminal

Fully functional web-based PTY terminal with real-time I/O, supporting interactive sudo command execution.

2. Deployment and Installation Guide

System Requirements

OS: Linux (Arch Linux, Ubuntu 20.04+, Debian, RHEL 8+).

Go Version: 1.19 or higher.

Minimum Specs: 4 cores CPU, 8GB RAM, 50GB Disk.

Required Privileges: Root access is mandatory for packet capture, iptables modifications, and daemon management (ClamAV, Suricata).

Dependency Installation (Arch Linux)

Since you are working on Arch Linux, the system dependencies can be installed using pacman:

# Update package manager and install core dependencies
sudo pacman -S go libpcap yara iptables clamav suricata base-devel


(Note: As this is a Go project, dependencies are managed via go mod tidy and not pip install inside of a venv, which is typically for Python projects.)

Quick Build and Run

Download Files: Clone or download all files into a directory (e.g., ~/security-suite).

Make Scripts Executable: chmod +x setup_and_run.sh check_compilation.sh.

Build and Run Setup: Use the unified setup script, which builds the application and handles dependencies:

./setup_and_run.sh


OR, if running manually:

go build -o security_suite .


Start Web Interface: Running with sudo is required for full functionality:

sudo ./security_suite -mode web


Access: Open your browser to http://localhost:8080.

3. Key Functional Highlights

Advanced Network Scanning

The new scanner is a comprehensive, professional-grade tool.

Capabilities: Includes multiple scan types (TCP, SYN, UDP, aggressive), host discovery (ping, ARP), and results export.

Detection: Features dedicated modules for service version detection (50+ signatures, e.g., SSH, MySQL) and OS fingerprinting.

Vulnerabilities: Detects critical vulnerabilities like EternalBlue, BlueKeep, and Log4Shell.

Profiles: Supports different scan profiles: Quick, Standard, Comprehensive, and PenTest.

Interactive Terminal Integration

The web UI now includes a full PTY terminal interface.

Problem Solved: It eliminates issues where privileged commands (e.g., sudo suricata-update) would hang because the password prompt was invisible.

Mechanism: The terminal provides a real bash shell that correctly handles the sudo password prompt directly in the browser using WebSocket for real-time I/O streaming.

Key Benefit: Run privileged commands, view real-time output, and manage the entire security platform from a single, unified interface.

4. Production Readiness and Maintenance

Essential Production Checklist Items

All system dependencies (libpcap, yara, iptables, clamav, suricata) are installed.

ClamAV daemon is running and updated (sudo freshclam).

Suricata daemon is running and rules are updated (sudo suricata-update).

Network interface is identified and configured.

Permissions are correctly configured (binary capabilities set OR running as root).

VirusTotal API key is configured as an environment variable (optional).

Log File Locations

Security Suite Logs: ./logs/security_suite.log

Suricata Logs: /var/log/suricata/eve.json

ClamAV Logs: sudo journalctl -u clamav-daemon -f

Maintenance Tasks (Weekly/Monthly)

Update ClamAV signatures: sudo freshclam.

Update Suricata rules: sudo suricata-update.

Review and tune ML baselines for the Behavioral Analyzer.

Monitor disk space in the ./quarantine_zone/ directory.
