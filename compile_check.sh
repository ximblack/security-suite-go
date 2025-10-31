#!/bin/bash
# Pre-compilation checker for Security Suite
# Verifies all files are correct before building

set -e

echo "=========================================="
echo "Security Suite - Pre-Build Verification"
echo "=========================================="
echo ""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

ERRORS=0
WARNINGS=0

# Check required files
echo -e "${BLUE}Checking required files...${NC}"
REQUIRED_FILES=(
    "main.go"
    "behavioral_analyzer.go"
    "core_controller.go"
    "ids_module.go"
    "malware_detector.go"
    "malware_traffic_detector.go"
    "network_scanner_advanced.go"
    "os_detector.go"
    "response_orchestrator.go"
    "scanner_wrapper.go"
    "security_suite.go"
    "security_suite_gui.go"
    "service_detector.go"
    "stream_detector.go"
    "terminal_handler.go"
    "types.go"
    "vuln_scanner.go"
    "web_server.go"
    "index.html"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo -e "  ${GREEN}✓${NC} $file"
    else
        echo -e "  ${RED}✗${NC} $file (MISSING)"
        ERRORS=$((ERRORS + 1))
    fi
done

echo ""

# Check for duplicate main functions
echo -e "${BLUE}Checking for duplicate main() functions...${NC}"
MAIN_COUNT=$(grep -r "^func main()" *.go 2>/dev/null | wc -l)
if [ "$MAIN_COUNT" -eq 1 ]; then
    echo -e "  ${GREEN}✓${NC} Single main() function found"
else
    echo -e "  ${RED}✗${NC} Found $MAIN_COUNT main() functions (should be 1)"
    grep -r "^func main()" *.go 2>/dev/null
    ERRORS=$((ERRORS + 1))
fi

echo ""

# Check for duplicate type definitions
echo -e "${BLUE}Checking for duplicate type definitions...${NC}"

check_duplicate_type() {
    TYPE_NAME=$1
    COUNT=$(grep -r "^type $TYPE_NAME " *.go 2>/dev/null | wc -l)
    if [ "$COUNT" -gt 1 ]; then
        echo -e "  ${RED}✗${NC} Duplicate type: $TYPE_NAME (found $COUNT times)"
        grep -r "^type $TYPE_NAME " *.go 2>/dev/null | head -5
        ERRORS=$((ERRORS + 1))
        return 1
    else
        echo -e "  ${GREEN}✓${NC} $TYPE_NAME (unique)"
        return 0
    fi
}

check_duplicate_type "MalwareBehavior"
check_duplicate_type "StreamInfo"
check_duplicate_type "LogMessage"

echo ""

# Check for duplicate function definitions
echo -e "${BLUE}Checking for duplicate function definitions...${NC}"

check_duplicate_func() {
    FUNC_NAME=$1
    COUNT=$(grep -r "^func $FUNC_NAME(" *.go 2>/dev/null | wc -l)
    if [ "$COUNT" -gt 1 ]; then
        echo -e "  ${YELLOW}⚠${NC} Duplicate function: $FUNC_NAME (found $COUNT times)"
        grep -r "^func $FUNC_NAME(" *.go 2>/dev/null
        WARNINGS=$((WARNINGS + 1))
        return 1
    fi
    return 0
}

check_duplicate_func "contains"
check_duplicate_func "isPrivateIP"

echo ""

# Check for correct package declarations
echo -e "${BLUE}Checking package declarations...${NC}"
WRONG_PACKAGE=$(grep -r "^package " *.go 2>/dev/null | grep -v "package main" | wc -l)
if [ "$WRONG_PACKAGE" -eq 0 ]; then
    echo -e "  ${GREEN}✓${NC} All Go files use 'package main'"
else
    echo -e "  ${RED}✗${NC} Found files with wrong package declaration:"
    grep -r "^package " *.go 2>/dev/null | grep -v "package main"
    ERRORS=$((ERRORS + 1))
fi

echo ""

# Check Go module
echo -e "${BLUE}Checking Go module...${NC}"
if [ -f "go.mod" ]; then
    echo -e "  ${GREEN}✓${NC} go.mod exists"
    
    # Check required dependencies
    REQUIRED_DEPS=(
        "github.com/hillu/go-yara/v4"
        "github.com/creack/pty"
        "github.com/gorilla/websocket"
        "github.com/google/gopacket"
        "gonum.org/v1/gonum"
    )
    
    for dep in "${REQUIRED_DEPS[@]}"; do
        if grep -q "$dep" go.mod; then
            echo -e "    ${GREEN}✓${NC} $dep"
        else
            echo -e "    ${YELLOW}⚠${NC} $dep (missing, will be added during build)"
            WARNINGS=$((WARNINGS + 1))
        fi
    done
else
    echo -e "  ${YELLOW}⚠${NC} go.mod not found (will be created during build)"
    WARNINGS=$((WARNINGS + 1))
fi

echo ""

# Try a dry-run compilation check
echo -e "${BLUE}Attempting syntax check...${NC}"
if command -v go &> /dev/null; then
    if go build -o /dev/null . 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} Syntax check passed"
    else
        echo -e "  ${RED}✗${NC} Compilation errors found:"
        go build -o /dev/null . 2>&1 | head -20
        ERRORS=$((ERRORS + 1))
    fi
else
    echo -e "  ${YELLOW}⚠${NC} Go compiler not found, skipping syntax check"
    WARNINGS=$((WARNINGS + 1))
fi

echo ""

# Summary
echo "=========================================="
echo "Verification Summary"
echo "=========================================="

if [ "$ERRORS" -eq 0 ] && [ "$WARNINGS" -eq 0 ]; then
    echo -e "${GREEN}✓ All checks passed! Ready to build.${NC}"
    echo ""
    echo "Run: ./build.sh"
    exit 0
elif [ "$ERRORS" -eq 0 ]; then
    echo -e "${YELLOW}⚠ Passed with $WARNINGS warning(s)${NC}"
    echo "You can proceed with the build, but review warnings above."
    echo ""
    echo "Run: ./build.sh"
    exit 0
else
    echo -e "${RED}✗ Found $ERRORS error(s) and $WARNINGS warning(s)${NC}"
    echo "Please fix the errors above before building."
    exit 1
fi
