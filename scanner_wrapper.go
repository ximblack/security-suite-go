// scanner_wrapper_prod.go
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// --- SHARED TYPES (Re-introduced for production compilation) ---

// OpenPortResult (Simplified for compilation)
type OpenPortResult struct {
	Port         int
	Protocol     string
	Service      string
	Version      string
	Banner       string
	ResponseTime time.Duration
}

// --- DEPENDENCIES (Production Stubs for Compilation) ---
// These structs and methods must be present for the wrapper to compile and use them.

// --- SecurityScannerWrapper Implementation ---

// SecurityScannerWrapper manages file, directory, and network scanning operations
type SecurityScannerWrapper struct {
	Verbose              bool
	RuleManager          *RuleManager
	MalwareDetector      *MalwareDetector
	ResponseOrchestrator *ResponseOrchestrator

	// CORE MODULES: Fully integrated dependencies
	NetworkScanner   *AdvancedNetworkScanner
	OSDetector       *OSDetector
	VulnScanner      *VulnerabilityScanner
	BehaviorAnalyzer *BehavioralAnalyzer
}

// NewSecurityScannerWrapper initializes the scanner wrapper with its production dependencies
func NewSecurityScannerWrapper(rm *RuleManager, md *MalwareDetector, ro *ResponseOrchestrator) *SecurityScannerWrapper {
	wrapper := &SecurityScannerWrapper{
		Verbose:              false,
		RuleManager:          rm,
		MalwareDetector:      md,
		ResponseOrchestrator: ro,

		// Initialize ALL production modules
		NetworkScanner:   NewAdvancedNetworkScanner(),
		OSDetector:       NewOSDetector(),
		VulnScanner:      NewVulnerabilityScanner(),
		BehaviorAnalyzer: NewBehavioralAnalyzer(),
	}

	fmt.Println("[ScannerWrapper] Initialized with production orchestration modules.")
	return wrapper
}

// ScanDirectory performs a recursive file scan on a target path using concurrent, depth-controlled logic
func (ssw *SecurityScannerWrapper) ScanDirectory(targetPath string, depthStr string) ([]ThreatIndicator, string) {
	fmt.Printf("[%s] ScannerWrapper: Starting extensive directory scan of '%s' (Depth: %s).\n", time.Now().Format("15:04:05"), targetPath, depthStr)

	var results []ThreatIndicator
	var mu sync.Mutex
	var wg sync.WaitGroup
	totalScanned := 0

	// Parse depth - Conclusive error handling
	depth, err := strconv.Atoi(depthStr)
	if err != nil || depth < 0 {
		depth = 100 // Default to a reasonable depth limit
		fmt.Printf("[SCAN] Warning: Invalid depth '%s', defaulting to %d.\n", depthStr, depth)
	}

	// Use filepath.WalkDir for robust, efficient traversal
	err = filepath.WalkDir(targetPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			fmt.Printf("Error accessing path %q: %v\n", path, err)
			return nil // Continue walking
		}

		// Calculate current depth relative to targetPath
		currentDepth := strings.Count(path, string(os.PathSeparator)) - strings.Count(targetPath, string(os.PathSeparator))
		if currentDepth > depth {
			if d.IsDir() {
				return filepath.SkipDir // Skip directory if depth limit reached
			}
			return nil
		}

		if d.IsDir() || !d.Type().IsRegular() {
			return nil // Skip directories and non-regular files
		}

		// Conclusive check for size before concurrent processing
		info, err := d.Info()
		if err != nil || info.Size() > 100*1024*1024 {
			// Skip files larger than 100MB
			if err == nil {
				fmt.Printf("[SCAN] Skipping large file: %s (%d bytes)\n", path, info.Size())
			}
			return nil
		}

		totalScanned++
		wg.Add(1)

		// Process file concurrently (production feature)
		go func(filePath string) {
			defer wg.Done()

			indicators, found := ssw.MalwareDetector.ScanFile(filePath)
			if found {
				mu.Lock()
				results = append(results, indicators...)
				mu.Unlock()

				if ssw.Verbose {
					fmt.Printf("[SCAN ALERT] Threat detected in: %s\n", filePath)
				}
			}
		}(path)

		return nil
	})

	wg.Wait() // Wait for all file scans to complete

	if err != nil {
		return nil, fmt.Sprintf("Error during directory traversal: %v", err)
	}

	message := fmt.Sprintf("Directory scan complete. Scanned %d files, found %d threats.",
		totalScanned, len(results))

	return results, message
}

// ScanFile performs a comprehensive scan on a single file (re-used from previous logic)
func (ssw *SecurityScannerWrapper) ScanFile(filePath string) ([]ThreatIndicator, string) {
	fmt.Printf("[%s] ScannerWrapper: Starting file scan of '%s'.\n", time.Now().Format("15:04:05"), filePath)

	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Sprintf("Failed to access file: %v", err)
	}
	if info.IsDir() {
		return nil, "Target is a directory, not a file"
	}

	indicators, found := ssw.MalwareDetector.ScanFile(filePath)

	// Calculate and add hash to results
	data, err := os.ReadFile(filePath)
	if err == nil {
		hasher := sha256.New()
		hasher.Write(data)
		hash := hex.EncodeToString(hasher.Sum(nil))

		if ssw.Verbose {
			fmt.Printf("[SCAN] File SHA256: %s\n", hash)
		}

		// Add hash to all indicators
		for i := range indicators {
			if indicators[i].Details == nil {
				indicators[i].Details = make(map[string]interface{})
			}
			indicators[i].Details["file_hash_sha256"] = hash
			indicators[i].Details["file_size"] = info.Size()
		}
	}

	var message string
	if found {
		message = fmt.Sprintf("Scan complete. Found %d threats", len(indicators))
	} else {
		message = "Scan complete. No threats detected"
	}

	return indicators, message
}

// ScanNetwork performs a coordinated, multi-stage network discovery and analysis (Fully functional orchestration)
func (ssw *SecurityScannerWrapper) ScanNetwork(networkCIDR string, scanType string) ([]ThreatIndicator, string) {
	fmt.Printf("[%s] ScannerWrapper: Starting multi-stage network scan of '%s' (Type: %s).\n", time.Now().Format("15:04:05"), networkCIDR, scanType)

	// Stage 1: Host and Port Discovery (Abstraction of NetworkScanner complexity)
	opts := ScanOptions{
		Targets:          []string{networkCIDR},
		ScanType:         NetworkScanType(scanType),
		ServiceDetection: true,
		OSDetection:      true,
		VulnScanning:     true,
	}
	discoveryResults, err := ssw.NetworkScanner.ScanNetwork(opts)
	if err != nil {
		return nil, fmt.Sprintf("Network scan failed: %v", err)
	}

	if len(discoveryResults) == 0 {
		return nil, "Network scan complete. No active hosts found."
	}
	fmt.Printf("[SCAN] Found %d active hosts. Starting in-depth analysis...\n", len(discoveryResults))

	var allIndicators []ThreatIndicator
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Stage 2: In-depth Analysis (Concurrent processing of all discovered hosts)
	for ip, hostResult := range discoveryResults {
		if !hostResult.IsAlive {
			continue
		}

		wg.Add(1)
		go func(ip string, hostResult *HostScanResult) {
			defer wg.Done()

			// Conclusive Orchestration Step: Analyze the host using all core modules
			var openPorts []int
			for _, port := range hostResult.OpenPorts {
				openPorts = append(openPorts, port.Port)
			}
			hostIndicators := ssw.analyzeHost(ip, openPorts)

			mu.Lock()
			allIndicators = append(allIndicators, hostIndicators...)
			mu.Unlock()
		}(ip, hostResult)
	}

	wg.Wait()

	message := fmt.Sprintf("Network scan complete. Analyzed %d hosts, found %d security findings.",
		len(discoveryResults), len(allIndicators))

	return allIndicators, message
}

// analyzeHost runs all security modules against a single target IP (Core Orchestration Logic)
func (ssw *SecurityScannerWrapper) analyzeHost(ip string, openPorts []int) []ThreatIndicator {
	var indicators []ThreatIndicator

	// A. OS and Service Detection (OSDetector)
	// Gets the OS, as well as a map of open port -> ServiceInfo
	var port int
	if len(openPorts) > 0 {
		port = openPorts[0]
	}
	osFP := ssw.OSDetector.DetectOS(ip, port)

	if ssw.Verbose && osFP.OS != "Unknown" {
		fmt.Printf("[HOST:%s] OS: %s (Accuracy: %d%%)\n", ip, osFP.OS, osFP.Accuracy)
	}

	// B. Active Vulnerability Scan (VulnerabilityScanner)
	// Iterate through every service detected on the host
	for port, service := range osFP.Services {
		vulns := ssw.VulnScanner.ScanService(ip, port, service)

		for _, vuln := range vulns {
			// Convert Vulnerability findings into ThreatIndicators
			indicator := ThreatIndicator{
				Timestamp: time.Now(),
				SourceID:  "VULNERABILITY-SCAN",
				SourceIP:  ip,
				Target:    net.JoinHostPort(ip, strconv.Itoa(vuln.Port)),
				Type:      "Service Vulnerability",
				Severity:  vuln.Severity,
				Signature: vuln.ID,
				Context:   fmt.Sprintf("%s - %s", vuln.ID, vuln.Description),
				Action:    ActionNotify,
				Details: map[string]interface{}{
					"cve":        vuln.ID,
					"cvss":       vuln.CVSS,
					"port":       vuln.Port,
					"service":    vuln.Service,
					"mitigation": vuln.Mitigation,
					"references": vuln.References,
				},
			}
			indicators = append(indicators, indicator)
		}
	}

	// C. Behavioral Anomaly Check (BehavioralAnalyzer)
	behavioralIndicators, _ := ssw.BehaviorAnalyzer.AnalyzeProfile(ip)

	if len(behavioralIndicators) > 0 {
		indicators = append(indicators, behavioralIndicators...)
	}

	return indicators
}

// UpdateIDSRules calls the RuleManager to update IDS rules
func (ssw *SecurityScannerWrapper) UpdateIDSRules() bool {
	fmt.Printf("[%s] ScannerWrapper: Starting IDS rule update via RuleManager.\n", time.Now().Format("15:04:05"))

	// Conclusive call to the rule manager dependency
	success := ssw.RuleManager.UpdateRules()
	if success {
		fmt.Println("[ScannerWrapper] IDS rules updated successfully.")
	} else {
		fmt.Println("[ScannerWrapper] IDS rule update FAILED.")
	}
	return success
}
