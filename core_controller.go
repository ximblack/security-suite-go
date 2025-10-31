package main

import (
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"
)

// Stoppable defines the interface for all long-running processes
type Stoppable interface {
	StopScan() bool
}

// CoreController orchestrates all security modules
type CoreController struct {
	ScannerWrapper     *SecurityScannerWrapper
	IDSModule          *IntrusionDetector
	Orchestrator       *ResponseOrchestrator
	NetworkMalwareScan *NetworkMalwareScanner
	BehavioralAnalyzer *BehavioralAnalyzer
	StreamDetector     *StreamDetector
	RunningProcesses   map[string]Stoppable
	mu                 sync.Mutex
}

// NewCoreController initializes all security components
func NewCoreController(verbose bool) *CoreController {
	const YARA_RULES_PATH = "yara_rules.yar"
	const QUARANTINE_DIR = "quarantine_zone"

	regexPatterns := []ThreatPattern{}

	// Initialize components
	md, err := NewMalwareDetector(YARA_RULES_PATH, regexPatterns)
	if err != nil {
		fmt.Printf("[ERROR] Failed to initialize MalwareDetector: %v. Running without YARA.\n", err)
	}

	orchestrator := NewResponseOrchestrator(QUARANTINE_DIR)
	
	// Initialize RuleManager first
	ruleManager := NewRuleManager()
	
	// Pass RuleManager to IntrusionDetector
	idsModule := NewIntrusionDetector(ruleManager)
	behavioralAnalyzer := NewBehavioralAnalyzer()
	networkScanner := NewNetworkMalwareScanner("eth0", md, behavioralAnalyzer, orchestrator)
	scannerWrapper := NewSecurityScannerWrapper(ruleManager, md, orchestrator)
	streamDetector := NewStreamDetector()

	return &CoreController{
		ScannerWrapper:     scannerWrapper,
		IDSModule:          idsModule,
		Orchestrator:       orchestrator,
		NetworkMalwareScan: networkScanner,
		BehavioralAnalyzer: behavioralAnalyzer,
		StreamDetector:     streamDetector,
		RunningProcesses:   make(map[string]Stoppable),
	}
}

// GetSystemStatus returns aggregated status of all modules
func (controller *CoreController) GetSystemStatus() SystemStatus {
	controller.mu.Lock()
	defer controller.mu.Unlock()

	overallHealth := "HEALTHY"
	if len(controller.RunningProcesses) == 0 {
		overallHealth = "IDLE"
	}

	return SystemStatus{
		OverallHealth: overallHealth,
		RuleManager:   controller.IDSModule.RuleManager.GetStatus(),
		MalwareEngine: ModuleStatus{
			Enabled:       true,
			EngineVersion: "2.0.0",
			ModelVersion:  "Go-YARA-v4",
			LastUpdate:    time.Now().Format(time.RFC3339),
		},
		BehavioralAnalyzer: ModuleStatus{
			Enabled:       true,
			EngineVersion: "2.0.0",
			ModelVersion:  "IsolationForest-Sim",
			LastUpdate:    time.Now().Format(time.RFC3339),
		},
		Timestamp: time.Now(),
	}
}

// ExecuteScan performs a scan and returns results
func (controller *CoreController) ExecuteScan(targetType, target string, depth int) (map[string]interface{}, error) {
	var indicators []ThreatIndicator
	var message string

	switch targetType {
	case "file":
		indicators, message = controller.ScannerWrapper.ScanFile(target)
	case "directory":
		indicators, message = controller.ScannerWrapper.ScanDirectory(target, strconv.Itoa(depth))
	case "network":
		indicators, message = controller.ScannerWrapper.ScanNetwork(target, "quick")
	default:
		return nil, fmt.Errorf("unknown scan type: %s", targetType)
	}

	result := map[string]interface{}{
		"status":                           "complete",
		"message":                          message,
		"total_files_scanned":              len(indicators),
		"total_files_scanned_with_findings": len(indicators),
		"threats":                          indicators,
		"timestamp":                        time.Now().Format(time.RFC3339),
	}

	return result, nil
}

// UpdateDefinitions updates threat definitions
func (controller *CoreController) UpdateDefinitions() (string, error) {
	success := controller.IDSModule.RuleManager.UpdateRules()
	if success {
		controller.IDSModule.LoadRules()
		status := controller.IDSModule.RuleManager.GetStatus()
		return fmt.Sprintf("Rules updated successfully. Last update: %s", status.LastUpdated), nil
	}
	return "Rule update failed", fmt.Errorf("failed to update IDS rules")
}

// StopAllServices stops all running services
func (controller *CoreController) StopAllServices() {
	controller.mu.Lock()
	defer controller.mu.Unlock()

	for name, process := range controller.RunningProcesses {
		if process.StopScan() {
			fmt.Printf("[INFO] Stopped process: %s\n", name)
			delete(controller.RunningProcesses, name)
		}
	}
}

// StartTrafficMonitor starts network traffic monitoring
func (controller *CoreController) StartTrafficMonitor(iface string) string {
	controller.NetworkMalwareScan.Interface = iface

	err := controller.NetworkMalwareScan.StartScan()
	if err != nil {
		return fmt.Sprintf("[ERROR] Failed to start traffic monitor on %s: %v", iface, err)
	}

	controller.mu.Lock()
	controller.RunningProcesses["traffic_monitor"] = controller.NetworkMalwareScan
	controller.mu.Unlock()

	return fmt.Sprintf("[SUCCESS] Traffic monitor started on interface: %s", iface)
}

// UpdateIDSRules updates IDS rules
func (controller *CoreController) UpdateIDSRules() string {
	if controller.IDSModule.RuleManager.UpdateRules() {
		controller.IDSModule.LoadRules()
		status := controller.IDSModule.RuleManager.GetStatus()
		return fmt.Sprintf("[SUCCESS] IDS rules updated and reloaded. Last update: %s", status.LastUpdated)
	}
	return "[FAILED] IDS rule update failed."
}

// StopAllScanners gracefully shuts down all active processes
func (controller *CoreController) StopAllScanners() string {
	controller.mu.Lock()
	defer controller.mu.Unlock()

	stoppedCount := 0
	for name, process := range controller.RunningProcesses {
		if process.StopScan() {
			fmt.Printf("[INFO] Stopped process: %s\n", name)
			delete(controller.RunningProcesses, name)
			stoppedCount++
		}
	}

	return fmt.Sprintf("[SUCCESS] Successfully stopped %d processes.", stoppedCount)
}

// ExecuteDemonstrationFlow shows the full security response capability
func (controller *CoreController) ExecuteDemonstrationFlow() {
	fmt.Println("\n=======================================================")
	fmt.Println("--- DEMONSTRATION: REAL THREAT RESPONSE EXECUTION ---")
	fmt.Println("=======================================================")

	// DEMO 1: Block Network Access
	fmt.Println("\n[DEMO 1] Generating Critical Network Threat...")
	networkThreat := ThreatIndicator{
		Timestamp: time.Now(),
		SourceID:  "BEHAVIORAL-ANOMALY-101",
		SourceIP:  "192.168.1.50",
		Target:    "172.217.168.110:443",
		Severity:  ThreatLevelCritical,
		Signature: "Unusual Outbound C2 Attempt",
		Details:   map[string]interface{}{"process": "cmd.exe"},
	}

	networkOutcome := controller.Orchestrator.HandleThreat(networkThreat)
	fmt.Printf("\n[RESPONSE] Network Block Outcome (Action: %s):\n", networkOutcome.Action)
	fmt.Printf("  Status: %s\n", networkOutcome.Status)
	fmt.Printf("  Message: %s\n", networkOutcome.Message)

	// DEMO 2: Quarantine File
	fmt.Println("\n[DEMO 2] Generating High File Threat...")
	dummyFilePath := "suspicious_file.bin"
	os.WriteFile(dummyFilePath, []byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"), 0644)
	fmt.Printf("  Created dummy file: %s\n", dummyFilePath)

	fileThreat := ThreatIndicator{
		Timestamp: time.Now(),
		SourceID:  "MALWARE-SCAN-201",
		SourceIP:  "N/A",
		Target:    dummyFilePath,
		Severity:  ThreatLevelHigh,
		Signature: "EICAR Test Signature Match",
		Details:   map[string]interface{}{"filepath": dummyFilePath},
	}

	fileOutcome := controller.Orchestrator.HandleThreat(fileThreat)
	fmt.Printf("\n[RESPONSE] File Quarantine Outcome (Action: %s):\n", fileOutcome.Action)
	fmt.Printf("  Status: %s\n", fileOutcome.Status)
	fmt.Printf("  Message: %s\n", fileOutcome.Message)

	os.Remove(dummyFilePath)
	fmt.Println("\n=======================================================")
}

// Wrapper methods for scanning
func (controller *CoreController) ScanFile(targetPath string) (string, []ThreatIndicator) {
	indicators, msg := controller.ScannerWrapper.ScanFile(targetPath)
	return msg, indicators
}

func (controller *CoreController) ScanDirectory(targetPath string, depth int) (string, []ThreatIndicator) {
	indicators, msg := controller.ScannerWrapper.ScanDirectory(targetPath, strconv.Itoa(depth))
	return msg, indicators
}

func (controller *CoreController) ScanNetwork(targetIP string, scanType string) (string, []ThreatIndicator) {
	indicators, msg := controller.ScannerWrapper.ScanNetwork(targetIP, scanType)
	return msg, indicators
}

func (controller *CoreController) GetRunningProcesses() map[string]Stoppable {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	return controller.RunningProcesses
}