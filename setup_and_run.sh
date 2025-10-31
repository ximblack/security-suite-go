#!/bin/bash
# Security Suite - Complete Build and Setup Script
# This script compiles all Go files into a single executable

set -e  # Exit on error

echo "=========================================="
echo "Security Suite - Complete Build"
echo "Version 2.0.0"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    echo -e "${YELLOW}Warning: Running as root. This is required for full functionality.${NC}"
else
    echo -e "${YELLOW}Note: Not running as root. Some features will be limited.${NC}"
    echo -e "${YELLOW}      Run with 'sudo' for full functionality.${NC}"
fi
echo ""

# Step 1: Check dependencies
echo -e "${BLUE}Step 1: Checking dependencies...${NC}"

check_command() {
    if command -v $1 &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} $1 found"
        return 0
    else
        echo -e "  ${RED}✗${NC} $1 not found"
        return 1
    fi
}

MISSING_DEPS=0

check_command go || MISSING_DEPS=1
check_command iptables || MISSING_DEPS=1

# Check for libpcap
if ldconfig -p 2>/dev/null | grep -q libpcap; then
    echo -e "  ${GREEN}✓${NC} libpcap found"
else
    echo -e "  ${RED}✗${NC} libpcap not found"
    MISSING_DEPS=1
fi

# Check for YARA
if ldconfig -p 2>/dev/null | grep -q libyara; then
    echo -e "  ${GREEN}✓${NC} libyara found"
else
    echo -e "  ${RED}✗${NC} libyara not found"
    MISSING_DEPS=1
fi

if [ $MISSING_DEPS -eq 1 ]; then
    echo ""
    echo -e "${RED}Missing dependencies detected!${NC}"
    echo ""
    echo "Install missing dependencies with:"
    echo ""
    echo "  # Arch Linux:"
    echo "  sudo pacman -S go iptables libpcap yara"
    echo ""
    echo "  # Ubuntu/Debian:"
    echo "  sudo apt-get install golang iptables libpcap-dev libyara-dev"
    echo ""
    echo "  # Fedora/RHEL:"
    echo "  sudo dnf install golang iptables libpcap-devel yara-devel"
    echo ""
    exit 1
fi

echo ""

# Step 2: Initialize Go module if needed
echo -e "${BLUE}Step 2: Initializing Go module...${NC}"
if [ ! -f "go.mod" ]; then
    go mod init security-suite
    echo -e "  ${GREEN}✓${NC} go.mod created"
else
    echo -e "  ${GREEN}✓${NC} go.mod already exists"
fi

# Step 3: Add required dependencies
echo -e "${BLUE}Step 3: Adding Go dependencies...${NC}"
go get github.com/hillu/go-yara/v4
go get github.com/creack/pty
go get github.com/gorilla/websocket
go get github.com/google/gopacket
go get gonum.org/v1/gonum/stat
go get fyne.io/fyne/v2
echo -e "  ${GREEN}✓${NC} Dependencies added"

# Step 4: Download and tidy dependencies
echo ""
echo -e "${BLUE}Step 4: Downloading Go dependencies...${NC}"
go mod tidy
echo -e "  ${GREEN}✓${NC} Dependencies downloaded"
echo ""

# Step 5: Create default YARA rules if not exists
echo -e "${BLUE}Step 5: Setting up YARA rules...${NC}"
if [ ! -f "yara_rules.yar" ]; then
    cat > yara_rules.yar << 'EOF'
rule EICAR_Test_File
{
    meta:
        description = "EICAR antivirus test file"
        severity = "MEDIUM"
        author = "Security Suite"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Suspicious_PE_File
{
    meta:
        description = "Detects suspicious PE executable patterns"
        severity = "HIGH"
        author = "Security Suite"
    strings:
        $mz = "MZ"
        $suspicious1 = "CreateRemoteThread" ascii wide
        $suspicious2 = "VirtualAllocEx" ascii wide
        $suspicious3 = "WriteProcessMemory" ascii wide
    condition:
        $mz at 0 and 2 of ($suspicious*)
}

rule Potential_Credential_Harvesting
{
    meta:
        description = "Detects potential credential harvesting code"
        severity = "HIGH"
        author = "Security Suite"
    strings:
        $cred1 = "password" nocase
        $cred2 = "credential" nocase
        $cred3 = /user(name)?[:=]/ nocase
        $net1 = "http" nocase
        $net2 = "POST" nocase
    condition:
        2 of ($cred*) and 1 of ($net*)
}

rule Potential_C2_Communication
{
    meta:
        description = "Detects potential C2 communication patterns"
        severity = "CRITICAL"
        author = "Security Suite"
    strings:
        $beacon1 = "beacon" nocase
        $beacon2 = "callback" nocase
        $c2_1 = "command" nocase
        $c2_2 = "control" nocase
        $net = /https?:\/\// nocase
    condition:
        1 of ($beacon*) and 1 of ($c2_*) and $net
}

rule Webshell_Detection
{
    meta:
        description = "Detects common webshell patterns"
        severity = "CRITICAL"
        author = "Security Suite"
    strings:
        $php1 = "<?php" nocase
        $exec1 = "exec(" nocase
        $exec2 = "shell_exec(" nocase
        $exec3 = "system(" nocase
        $exec4 = "passthru(" nocase
        $eval = "eval(" nocase
        $base64 = "base64_decode" nocase
    condition:
        $php1 and (2 of ($exec*) or ($eval and $base64))
}
EOF
    echo -e "  ${GREEN}✓${NC} Default YARA rules created"
else
    echo -e "  ${GREEN}✓${NC} YARA rules file already exists"
fi
echo ""

# Step 6: Create necessary directories
echo -e "${BLUE}Step 6: Creating necessary directories...${NC}"
mkdir -p ids_rules
mkdir -p quarantine_zone
mkdir -p logs
echo -e "  ${GREEN}✓${NC} Directories created"
echo ""

# Step 7: Build the application
echo -e "${BLUE}Step 7: Building Security Suite...${NC}"
echo "This may take a few moments..."
go build -ldflags="-s -w" -o security_suite .
if [ $? -eq 0 ]; then
    echo -e "  ${GREEN}✓${NC} Build successful"
    echo -e "  ${GREEN}✓${NC} Executable: ./security_suite"
else
    echo -e "  ${RED}✗${NC} Build failed"
    exit 1
fi
echo ""

# Step 8: Set capabilities for non-root packet capture (optional)
if [ "$EUID" -eq 0 ]; then
    echo -e "${BLUE}Step 8: Setting packet capture capabilities...${NC}"
    setcap cap_net_raw,cap_net_admin=eip ./security_suite 2>/dev/null
    if [ $? -eq 0 ]; then
        echo -e "  ${GREEN}✓${NC} Capabilities set (packet capture will work without sudo)"
    else
        echo -e "  ${YELLOW}!${NC} Failed to set capabilities (not critical)"
    fi
    echo ""
else
    echo -e "${YELLOW}Step 8: Skipping capability setup (requires root)${NC}"
    echo -e "  To enable packet capture without sudo, run:"
    echo -e "  ${BLUE}sudo setcap cap_net_raw,cap_net_admin=eip ./security_suite${NC}"
    echo ""
fi

# Step 9: Display file structure
echo -e "${BLUE}Step 9: Verifying file structure...${NC}"
echo "Core files:"
ls -lh security_suite index.html yara_rules.yar 2>/dev/null | awk '{print "  " $9 " (" $5 ")"}'
echo ""
echo "Directories:"
ls -ld ids_rules quarantine_zone logs 2>/dev/null | awk '{print "  " $9 "/"}'
echo ""

# Step 10: Display completion message
echo -e "${GREEN}=========================================="
echo "Build Complete!"
echo "==========================================${NC}"
echo ""
echo -e "${BLUE}Quick Start Guide:${NC}"
echo ""
echo -e "${GREEN}1. Web Interface (Recommended):${NC}"
echo "   ./security_suite -mode web"
echo "   Then open: http://localhost:8080"
echo ""
echo -e "${GREEN}2. CLI Mode:${NC}"
echo "   ./security_suite scan -type file -target /path/to/file"
echo "   ./security_suite scan -type directory -target /var/www -depth 3"
echo "   ./security_suite scan -type network -target 192.168.1.0/24"
echo ""
echo -e "${GREEN}3. Network Monitoring:${NC}"
echo "   sudo ./security_suite monitor -iface eth0"
echo ""
echo -e "${GREEN}4. Run Demonstration:${NC}"
echo "   ./security_suite demo"
echo ""
echo -e "${YELLOW}Note: For full functionality (packet capture, iptables), run with sudo:${NC}"
echo "   sudo ./security_suite -mode web"
echo ""
echo -e "${BLUE}Features Available:${NC}"
echo "  ✓ File and directory scanning with YARA rules"
echo "  ✓ Network port scanning and service detection"
echo "  ✓ Behavioral analysis with ML anomaly detection"
echo "  ✓ Intrusion detection system (IDS) integration"
echo "  ✓ Camera stream detection and viewing"
echo "  ✓ Interactive terminal with sudo support"
echo "  ✓ Automated threat response (quarantine, block)"
echo "  ✓ Web-based control panel"
echo ""

# Ask if user wants to run now
read -p "Do you want to start the web interface now? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo -e "${GREEN}Starting Security Suite Web Interface...${NC}"
    echo -e "${YELLOW}Press Ctrl+C to stop${NC}"
    echo ""
    
    if [ "$EUID" -eq 0 ]; then
        ./security_suite -mode web
    else
        echo -e "${YELLOW}Running without root privileges. Some features will be limited.${NC}"
        echo -e "${YELLOW}For full functionality, press Ctrl+C and run: sudo ./security_suite -mode web${NC}"
        echo ""
        ./security_suite -mode web
    fi
fi
