package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// --- Internal YARA Rule for Compiler Initialization ---
// This rule is used as a fallback if the primary rule file is missing or corrupted,
// ensuring yara.compile() has a valid input to initialize the engine.
const YARA_INIT_RULE_WRAPPER = `
rule InitializationRule_Core
{
  meta:
    description = "A basic rule required for YARA compiler initialization."
    author = "Security Suite Core"
    version = "1.0"
  strings:
    $init_string = "SECURITY-SUITE-YARA-INIT" wide ascii
  condition:
    filesize < 1MB and $init_string
}
`

// SecurityScannerWrapper manages file, directory, and network scanning operations.
type SecurityScannerWrapper struct {
	Verbose              bool
	RuleManager          *RuleManager
	MalwareDetector      *MalwareDetector
	ResponseOrchestrator *ResponseOrchestrator
	yaraRulesCompiled    interface{} // Placeholder for *yara.Rules or similar
}

// NewSecurityScannerWrapper initializes the scanner wrapper with its dependencies.
func NewSecurityScannerWrapper(rm *RuleManager, md *MalwareDetector, ro *ResponseOrchestrator) *SecurityScannerWrapper {
	wrapper := &SecurityScannerWrapper{
		Verbose:              false,
		RuleManager:          rm,
		MalwareDetector:      md,
		ResponseOrchestrator: ro,
	}

	fmt.Println("[ScannerWrapper] Initialized successfully.")
	return wrapper
}

// ScanDirectory performs a recursive file scan on a target path.
func (ssw *SecurityScannerWrapper) ScanDirectory(targetPath string, depthStr string) ([]ThreatIndicator, string) {
	fmt.Printf("[%s] ScannerWrapper: Starting directory scan of '%s' (Depth: %s).\n", time.Now().Format("15:04:05"), targetPath, depthStr)

	var results []ThreatIndicator
	var mu sync.Mutex // Mutex to protect the results slice from concurrent writes
	totalScanned := 0

	// Parse depth
	depth, err := strconv.Atoi(depthStr)
	if err != nil || depth == 0 {
		// Default to infinite recursion (-1) if parsing fails or depth is 0
		depth = -1
	}

	// The walk function to traverse the directory
	err = filepath.Walk(targetPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Printf("[SCAN ERROR] Prevented from accessing path %s: %v\n", path, err)
			return nil // Continue walking
		}

		// Skip directories and device files
		if info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}

		totalScanned++
		// Read file content
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			fmt.Printf("[SCAN ERROR] Could not read file %s: %v\n", path, readErr)
			return nil
		}

		// Call the malware detection engine
		indicators, found := ssw.MalwareDetector.ScanData(data, path, "local_host", "file")

		if found {
			mu.Lock()
			results = append(results, indicators...)
			mu.Unlock()
		}

		return nil
	})

	if err != nil {
		fmt.Printf("[SCAN FATAL ERROR] Error during directory walk: %v\n", err)
	}

	message := fmt.Sprintf("Scanned %d files, found %d threats", totalScanned, len(results))
	return results, message
}

// ScanFile performs a hash and signature scan on a single file.
func (ssw *SecurityScannerWrapper) ScanFile(filePath string) ([]ThreatIndicator, string) {
	fmt.Printf("[%s] ScannerWrapper: Starting file scan of '%s'.\n", time.Now().Format("15:04:05"), filePath)
	var results []ThreatIndicator

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Sprintf("Failed to read file: %v", err)
	}

	// Hash the file (hash matching is internal to MalwareDetector, but we can log the hash)
	hasher := sha256.New()
	hasher.Write(data)
	hash := hex.EncodeToString(hasher.Sum(nil))
	fmt.Printf("[SCAN] File SHA256: %s\n", hash)

	// Call the malware detection engine
	indicators, found := ssw.MalwareDetector.ScanData(data, filePath, "local_host", "file")

	if found {
		results = append(results, indicators...)
	}

	// Add hash to details for reporting
	for i := range results {
		if results[i].Details == nil {
			results[i].Details = make(map[string]interface{})
		}
		results[i].Details["file_hash_sha256"] = hash
	}

	message := fmt.Sprintf("Scan complete. Found %d threats", len(results))
	return results, message
}

// ScanNetwork performs a network port scan on a target IP/range.
func (ssw *SecurityScannerWrapper) ScanNetwork(target string, scanType string) ([]ThreatIndicator, string) {
	fmt.Printf("[%s] ScannerWrapper: Starting network scan of '%s' (Type: %s).\n", time.Now().Format("15:04:05"), target, scanType)

	var ports []int
	switch scanType {
	case "quick":
		ports = []int{22, 80, 443, 445, 3389}
	case "common":
		ports = []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443}
	case "full":
		// Full scan would be 1-65535, but that's too slow for demo
		ports = make([]int, 1000)
		for i := 0; i < 1000; i++ {
			ports[i] = i + 1
		}
	default:
		ports = []int{22, 80, 443}
	}

	results := ssw.scanNetworkPorts(target, ports)

	var indicators []ThreatIndicator
	for port, isOpen := range results {
		if isOpen {
			indicators = append(indicators, ThreatIndicator{
				Timestamp: time.Now(),
				SourceID:  "PORT-SCAN",
				Target:    net.JoinHostPort(target, strconv.Itoa(port)),
				Severity:  ThreatLevelInfo,
				Signature: fmt.Sprintf("Open Port %d", port),
				Context:   fmt.Sprintf("Port %d is open on %s", port, target),
				Action:    ActionLog,
			})
		}
	}

	message := fmt.Sprintf("Network scan complete. Found %d open ports", len(indicators))
	return indicators, message
}

// scanNetworkPorts simulates a quick port scan.
func (ssw *SecurityScannerWrapper) scanNetworkPorts(target string, ports []int) map[int]bool {
	results := make(map[int]bool)
	timeout := 100 * time.Millisecond // Quick timeout

	fmt.Printf("[%s] ScannerWrapper: Starting network scan of '%s' on %d ports.\n", time.Now().Format("15:04:05"), target, len(ports))

	for _, port := range ports {
		address := net.JoinHostPort(target, strconv.Itoa(port))
		conn, err := net.DialTimeout("tcp", address, timeout)

		if err == nil {
			conn.Close()
			results[port] = true
		}
	}

	fmt.Printf("[SCAN] Network scan on %s complete. Found %d open ports.\n", target, len(results))
	return results
}

// UpdateIDSRules calls the RuleManager to update IDS rules.
func (ssw *SecurityScannerWrapper) UpdateIDSRules() bool {
	fmt.Printf("[%s] ScannerWrapper: Starting IDS rule update via RuleManager.\n", time.Now().Format("15:04:05"))
	// RuleManager handles the privileged execution and download logic
	success := ssw.RuleManager.UpdateRules()
	if success {
		fmt.Println("[ScannerWrapper] IDS rules updated successfully.")
	} else {
		fmt.Println("[ScannerWrapper] IDS rule update FAILED.")
	}
	return success
}
