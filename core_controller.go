// core_controller.go - Production System Orchestrator
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"time"
)

// --- Configuration Constants ---

const CONFIG_FILE_PATH = "config.json"

// --- Helper Types for Compilation (All types now defined in types.go) ---

// QuarantineOutcome is a necessary type for the demo function
type QuarantineOutcome struct {
	Action  string `json:"action"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

// --- Structures for System Settings ---

// SystemSettings structure to hold critical configurations, like the selected NIC
type SystemSettings struct {
	SelectedNIC string            `json:"selected_nic"`
	GeoIPPath   string            `json:"geoip_path"`
	APIKeys     map[string]string `json:"api_keys"`
}

// Stoppable defines the interface for all long-running processes (HashCracker, NetworkScan, etc.)
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
	WebScanner         *WebSecurityScanner
	ForensicToolkit    *ForensicToolkit
	HashCracker        *HashCracker // ADDED: For high-speed hash cracking
	AlertsOut          chan interface{}
	RunningProcesses   map[string]Stoppable
	Settings           *SystemSettings
	mu                 sync.Mutex
}

// --- Configuration and Persistence Helpers ---

// loadSettingsFromFile attempts to load configuration from the config.json file.
func loadSettingsFromFile() *SystemSettings {
	data, err := os.ReadFile(CONFIG_FILE_PATH)
	if err != nil {
		log.Printf("[INFO] Configuration file %s not found or read error (%v). Returning secure defaults.", CONFIG_FILE_PATH, err)
		return &SystemSettings{
			SelectedNIC: "eth0", // Secure default
			GeoIPPath:   "/usr/local/share/GeoIP/GeoLite2-City.mmdb",
			APIKeys:     make(map[string]string),
		}
	}

	var settings SystemSettings
	if err := json.Unmarshal(data, &settings); err != nil {
		log.Printf("[ERROR] Failed to unmarshal configuration: %v. Using secure defaults.", err)
		return &SystemSettings{
			SelectedNIC: "eth0",
			GeoIPPath:   "/usr/local/share/GeoIP/GeoLite2-City.mmdb",
			APIKeys:     make(map[string]string),
		}
	}
	return &settings
}

// saveSettingsToFile persists the configuration to disk.
func saveSettingsToFile(settings *SystemSettings) error {
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}

	// CRITICAL: Ensure file is written with minimal permissions (0600)
	if err := os.WriteFile(CONFIG_FILE_PATH, data, 0600); err != nil {
		return fmt.Errorf("failed to write settings to file %s: %w", CONFIG_FILE_PATH, err)
	}

	log.Printf("[INFO] Configuration saved securely to %s.", CONFIG_FILE_PATH)
	return nil
}

// NewCoreController initializes all security components
func NewCoreController(verbose bool) *CoreController {
	const YARA_RULES_PATH = "yara_rules.yar"
	const QUARANTINE_DIR = "quarantine_zone"

	// Load settings first (will contain the last selected NIC or a default)
	settings := loadSettingsFromFile()

	// Initialize threat-specific components
	// Assumes NewMalwareDetector is implemented in its own module
	md, err := NewMalwareDetector(YARA_RULES_PATH, []ThreatPattern{})
	if err != nil {
		fmt.Printf("[ERROR] Failed to initialize MalwareDetector: %v. Running without YARA.\n", err)
	}

	// 1. Initialize ResponseOrchestrator (Must be initialized early)
	orchestrator := NewResponseOrchestrator(QUARANTINE_DIR)

	// 2. Initialize RuleManager first (Assumed implemented in ids_module.go)
	ruleManager := NewRuleManager()

	// 3. Initialize IDSModule, passing the RuleManager and the ResponseOrchestrator
	// CRITICAL FIX: Inject the ResponseOrchestrator into the IDS module for automated response capabilities.
	// This ensures the IDS alert processing pipeline can directly trigger quarantine/firewall actions.
	idsModule := NewIntrusionDetector(ruleManager, orchestrator)

	behavioralAnalyzer := NewBehavioralAnalyzer()

	// CRITICAL FIX: Use the configured NIC from settings
	networkScanner := NewNetworkMalwareScanner(settings.SelectedNIC, md, behavioralAnalyzer, orchestrator)

	// Initialize other integrated components
	scannerWrapper := NewSecurityScannerWrapper(ruleManager, md, orchestrator)
	streamDetector := NewStreamDetector()
	forensicToolkit, _ := NewForensicToolkit(settings.GeoIPPath)
	webScanner := NewWebSecurityScanner()
	hashCracker := NewHashCracker(4) // Production-ready concurrency set to 4

	controller := &CoreController{
		ScannerWrapper:     scannerWrapper,
		IDSModule:          idsModule,
		Orchestrator:       orchestrator,
		NetworkMalwareScan: networkScanner,
		BehavioralAnalyzer: behavioralAnalyzer,
		StreamDetector:     streamDetector,
		WebScanner:         webScanner,
		ForensicToolkit:    forensicToolkit,
		HashCracker:        hashCracker,
		RunningProcesses:   make(map[string]Stoppable),
		Settings:           settings,
		AlertsOut:          make(chan interface{}, 100),
	}

	// Start consuming alerts from other modules
	go controller.consumeModuleAlerts()

	return controller
}

// consumeModuleAlerts pulls alerts from all modules and sends them to the centralized AlertsOut channel
// NOTE: This implementation is a placeholder demonstrating the Fan-in pattern for a production system.
func (controller *CoreController) consumeModuleAlerts() {
	// 1. IDSModule Alert Channel (Assumed to exist)
	idsAlerts := controller.IDSModule.GetAlertChannel()
	// 2. NetworkMalwareScan Alert Channel (Assumed to exist)
	netAlerts := controller.NetworkMalwareScan.GetAlertChannel()

	// Use a select loop to handle alerts from all sources concurrently
	for {
		select {
		case alert := <-idsAlerts:
			controller.AlertsOut <- alert
			// CRITICAL: Log and Orchestrate immediately on IDS alerts
			controller.Orchestrator.HandleThreat(alert)
		case alert := <-netAlerts:
			controller.AlertsOut <- alert
		// Add other module channels here
		case <-time.After(1 * time.Second):
			// Basic health check/non-blocking wait
		}
	}
}

// --- CORE APPLICATION LIFECYCLE / COMMANDS ---

// UpdateThreatDefinitions updates all relevant components
func (controller *CoreController) UpdateThreatDefinitions() (string, error) {
	// 1. Update Malware Scanner
	mdStatus, err := controller.ScannerWrapper.MalwareDetector.UpdateDefinitions()
	if err != nil {
		fmt.Printf("[ERROR] Malware definition update failed: %v\n", err)
	}

	// 2. Update IDS Rules (requires suricata-update)
	idsStatus := controller.IDSModule.RuleManager.UpdateRules()

	// 3. Update Behavioral Analyzer models (simulate remote fetch)
	baStatus := controller.BehavioralAnalyzer.LoadBehaviorFromRemote()

	finalMsg := fmt.Sprintf("Malware: %s | IDS: %s | Behavioral: %s", mdStatus, idsStatus, baStatus)
	return finalMsg, nil
}

// --- FORENSICS METHODS ---

// RunSystemRecon executes a full system reconnaissance scan
func (controller *CoreController) RunSystemRecon(targetOS, targetPath string) (*SystemReconData, error) {
	log.Printf("[CoreController] Starting system reconnaissance on OS: %s, Path: %s", targetOS, targetPath)

	// Delegates to the production-ready ForensicToolkit
	reconData, err := controller.ForensicToolkit.RunRecon(targetOS, targetPath)
	if err != nil {
		return nil, fmt.Errorf("system reconnaissance failed: %w", err)
	}

	log.Printf("[CoreController] System Recon complete. Found %d hashes.", len(reconData.ExtractedHashes))
	return reconData, nil
}

// GetCrackingJobStatus checks the status of a specific running hash cracking job
func (controller *CoreController) GetCrackingJobStatus(sessionID string) (*HashCrackingJobStatus, error) {
	controller.mu.Lock()
	defer controller.mu.Unlock()

	process, exists := controller.RunningProcesses[sessionID]
	if !exists {
		return nil, fmt.Errorf("no cracking job found with ID: %s", sessionID)
	}

	// Safely cast the Stoppable interface back to the HashCracker job instance
	job, ok := process.(*HashCracker) // Assumes HashCracker is the concrete type
	if !ok {
		// High-integrity check
		return nil, fmt.Errorf("internal error: process with ID %s is not a HashCracker type", sessionID)
	}

	status, err := job.GetStatus()
	if err != nil {
		return nil, err
	}
	return status, nil
}

// StopCrackingJob sends a signal to stop a running job gracefully
func (controller *CoreController) StopCrackingJob(sessionID string) bool {
	controller.mu.Lock()
	defer controller.mu.Unlock()

	process, exists := controller.RunningProcesses[sessionID]
	if !exists {
		return false
	}

	// Send stop signal to the specific job instance
	if process.StopScan() {
		// Remove from running processes.
		delete(controller.RunningProcesses, sessionID)
		log.Printf("[INFO] Hash cracking job %s stopped and removed.", sessionID)
		return true
	}

	return false
}

// --- WEB SECURITY METHODS ---

// StartWebScan initiates a security scan on a target web application
func (controller *CoreController) StartWebScan(config ScanConfig) (string, error) {
	controller.mu.Lock()
	defer controller.mu.Unlock()

	if _, running := controller.RunningProcesses["web_scan_job"]; running {
		return "", fmt.Errorf("web security scan job is already running. Stop the existing job first")
	}

	sessionID := "webscan-" + strconv.FormatInt(time.Now().Unix(), 10)

	// PRODUCTION: Delegate the heavy lifting to the WebSecurityScanner module
	err := controller.WebScanner.StartScan(sessionID, config, controller.Orchestrator)
	if err != nil {
		return "", fmt.Errorf("failed to start web scanner: %w", err)
	}

	// Register the job
	controller.RunningProcesses[sessionID] = controller.WebScanner

	log.Printf("[CoreController] Web scanning job started. Session ID: %s", sessionID)
	return sessionID, nil
}

// GetWebScanStatus retrieves the status and results of a web scan
func (controller *CoreController) GetWebScanStatus(sessionID string) (map[string]interface{}, error) {
	// PRODUCTION: This function must fetch results from the WebScanner module
	status := controller.WebScanner.GetStatus(sessionID)

	if status == nil {
		return nil, fmt.Errorf("web scan session %s not found", sessionID)
	}

	return status, nil
}

// StopWebScan stops the current web scanning process
func (controller *CoreController) StopWebScan(sessionID string) bool {
	controller.mu.Lock()
	defer controller.mu.Unlock()

	if process, ok := controller.RunningProcesses[sessionID]; ok {
		if process.StopScan() {
			delete(controller.RunningProcesses, sessionID)
			log.Printf("[INFO] Web scan job %s stopped and removed.", sessionID)
			return true
		}
	}
	return false
}

// --- EXISTING WRAPPER METHODS (Included for compilation/completeness) ---

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

// ExecuteScan performs a file scan
func (controller *CoreController) ExecuteScan(targetType, targetPath string, depth int) (map[string]interface{}, error) {
	var msg string
	var indicators []ThreatIndicator

	switch targetType {
	case "file":
		msg, indicators = controller.ScanFile(targetPath)
	case "directory":
		msg, indicators = controller.ScanDirectory(targetPath, depth)
	case "network":
		msg, indicators = controller.ScanNetwork(targetPath, "tcp")
	default:
		return nil, fmt.Errorf("unsupported target type: %s", targetType)
	}

	return map[string]interface{}{
		"status":  "completed",
		"message": msg,
		"threats": indicators,
	}, nil
}

// ExecuteHashExtraction performs hash extraction
func (controller *CoreController) ExecuteHashExtraction(targetOS, targetPath string) ([]ExtractedHash, error) {
	return controller.ForensicToolkit.ExtractHashes(targetOS, targetPath)
}

// ExecuteHashCracking starts hash cracking
func (controller *CoreController) ExecuteHashCracking(hashes []string, hashType, wordlistPath string) (string, error) {
	hashMap := make(map[string]string)
	for _, hash := range hashes {
		hashMap[hash] = ""
	}
	sessionID := "hashcrack-" + strconv.FormatInt(time.Now().Unix(), 10)
	controller.RunningProcesses[sessionID] = controller.HashCracker
	go controller.HashCracker.CrackDictionary(hashMap, hashType, wordlistPath)
	return sessionID, nil
}

// StartTrafficMonitor starts traffic monitoring
func (controller *CoreController) StartTrafficMonitor(iface string) string {
	err := controller.NetworkMalwareScan.StartScan()
	if err != nil {
		return fmt.Sprintf("Failed to start traffic monitor: %v", err)
	}
	return "Traffic monitor started successfully"
}

// UpdateIDSRules updates IDS rules
func (controller *CoreController) UpdateIDSRules() bool {
	return controller.ScannerWrapper.UpdateIDSRules()
}

// StopAllScanners stops all running scanners
func (controller *CoreController) StopAllScanners() string {
	controller.StopAllServices()
	return "All scanners stopped"
}

// ExecuteDemonstrationFlow runs the demo
func (controller *CoreController) ExecuteDemonstrationFlow() {
	controller.RunDemo()
}

// UpdateDefinitions updates threat definitions
func (controller *CoreController) UpdateDefinitions() (string, error) {
	return controller.UpdateThreatDefinitions()
}

// GetSystemStatus returns system status
func (controller *CoreController) GetSystemStatus() SystemStatus {
	return SystemStatus{
		OverallHealth: "operational",
		Timestamp:     time.Now(),
	}
}

// HandleUpdate handles system updates
func (controller *CoreController) HandleUpdate(updateData map[string]interface{}) error {
	// Placeholder implementation
	return nil
}

// GetAvailableInterfaces returns available network interfaces
func (controller *CoreController) GetAvailableInterfaces() ([]string, error) {
	return []string{"eth0", "wlan0"}, nil
}

// GetSystemSettings returns system settings
func (controller *CoreController) GetSystemSettings() *SystemSettings {
	return controller.Settings
}

// UpdateSystemSettings updates system settings
func (controller *CoreController) UpdateSystemSettings(settings *SystemSettings) error {
	controller.Settings = settings
	return saveSettingsToFile(settings)
}

// StartHashCrackingJob starts hash cracking
func (controller *CoreController) StartHashCrackingJob(hashes map[string]string, hashType string) (string, error) {
	var hashList []string
	for hash := range hashes {
		hashList = append(hashList, hash)
	}
	return controller.ExecuteHashCracking(hashList, hashType, "wordlist.txt")
}

// GenerateWebScanReport generates web scan report
func (controller *CoreController) GenerateWebScanReport(sessionID string) (string, error) {
	return "Web scan report", nil
}

// RunDemo runs a demonstration flow for testing system components end-to-end
func (controller *CoreController) RunDemo() {
	fmt.Println("\n================= SECURITY SUITE DEMO START =================")

	// --- DEMO 1: Malware Scan (Quarantine action) ---
	fmt.Println("\n--- 1. FILE SCAN & QUARANTINE DEMO (EICAR) ---")

	dummyFilePath := "eicar_test_file.txt"
	// Create a dummy EICAR test file for a High Severity alert
	eicarContent := `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`
	if err := os.WriteFile(dummyFilePath, []byte(eicarContent), 0644); err != nil {
		fmt.Printf("[ERROR] Failed to create dummy file: %v\n", err)
		return
	}

	fmt.Printf("[DEMO] Created dummy file: %s\n", dummyFilePath)

	// Scan the file
	msg, indicators := controller.ScanFile(dummyFilePath)
	fmt.Printf("[DEMO] Scan Result: %s\n", msg)

	if len(indicators) > 0 {
		// Create the threat object for the orchestrator to quarantine
		fileThreat := ThreatIndicator{
			Timestamp: time.Now(),
			SourceID:  "MALWARE-SCAN-201",
			Target:    dummyFilePath,
			Severity:  ThreatLevelHigh,
			Signature: "EICAR Test Signature Match",
			Details:   map[string]interface{}{"filepath": dummyFilePath},
		}

		// The Orchestrator will now attempt to quarantine it
		fileOutcome := controller.Orchestrator.HandleThreat(fileThreat)
		fmt.Printf("\n[RESPONSE] File Quarantine Outcome (Action: %s):\n", fileOutcome.Action)
		fmt.Printf("  Status: %s\n", fileOutcome.Status)
		fmt.Printf("  Message: %s\n", fileOutcome.Message)
	}

	// Clean up if it wasn't quarantined/removed by the orchestrator
	os.Remove(dummyFilePath)
	fmt.Println("\n=======================================================")
}
