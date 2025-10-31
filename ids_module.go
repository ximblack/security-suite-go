package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// --- Configuration Constants ---

const (
	// IDS rules directory
	IDS_RULES_DIR_NAME = "ids_rules"
	// Suricata paths (adjust for your distribution)
	SURICATA_CONF_PATH    = "/etc/suricata/suricata.yaml"
	SURICATA_EVE_LOG_PATH = "/var/log/suricata/eve.json"
	SURICATA_UPDATE_TOOL  = "suricata-update"
	SURICATA_BINARY       = "suricata"
	// Local rules file
	SURICATA_RULES_FILENAME = "security_suite_local.rules"
)

var (
	IDS_RULES_DIR    = filepath.Join(".", IDS_RULES_DIR_NAME)
	FINAL_RULES_PATH = filepath.Join(IDS_RULES_DIR, SURICATA_RULES_FILENAME)
)

// init ensures directories are set up
func init() {
	if err := os.MkdirAll(IDS_RULES_DIR, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "[RuleManager ERROR] Failed to create IDS rule directory: %v\n", err)
	}
}

// RuleManager handles Suricata rules
type RuleManager struct {
	LastUpdated   time.Time
	RulesLoaded   bool
	RulesChecksum string
	mu            sync.RWMutex
}

// NewRuleManager initializes a RuleManager
func NewRuleManager() *RuleManager {
	rm := &RuleManager{}
	rm.LoadRulesStatus()
	return rm
}

// LoadRulesStatus checks if rules file exists
func (rm *RuleManager) LoadRulesStatus() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	_, err := os.Stat(FINAL_RULES_PATH)
	if os.IsNotExist(err) {
		rm.RulesLoaded = false
		rm.RulesChecksum = ""
		rm.createDefaultRules()
		return
	}

	rm.RulesLoaded = true
	rm.RulesChecksum = "PROD_V1"

	info, err := os.Stat(FINAL_RULES_PATH)
	if err == nil {
		rm.LastUpdated = info.ModTime()
	} else {
		rm.LastUpdated = time.Time{}
	}
}

// createDefaultRules creates initial rules file
func (rm *RuleManager) createDefaultRules() {
	defaultRules := `# Security Suite Local Rules
# Custom detection rules for the security suite

# Detect port scanning
alert tcp any any -> $HOME_NET any (msg:"SECURITY_SUITE Port Scan Detected"; flags:S; threshold:type threshold, track by_src, count 20, seconds 10; sid:1000001; rev:1;)

# Detect suspicious DNS queries
alert dns any any -> any any (msg:"SECURITY_SUITE Suspicious DNS Query to Known C2 Domain"; dns_query; content:".tk"; sid:1000002; rev:1;)

# Detect outbound connections to suspicious ports
alert tcp $HOME_NET any -> $EXTERNAL_NET [8080,4433,9001] (msg:"SECURITY_SUITE Suspicious Outbound Connection"; flow:to_server,established; sid:1000003; rev:1;)

# Detect SMB lateral movement attempts
alert tcp $HOME_NET any -> $HOME_NET 445 (msg:"SECURITY_SUITE Potential Lateral Movement via SMB"; flow:to_server,established; threshold:type threshold, track by_src, count 10, seconds 60; sid:1000004; rev:1;)

# Detect data exfiltration (large outbound transfer)
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"SECURITY_SUITE Large Data Exfiltration Detected"; flow:to_server,established; threshold:type threshold, track by_src, count 100, seconds 10; sid:1000005; rev:1;)

# Detect ICMP tunneling
alert icmp any any -> any any (msg:"SECURITY_SUITE ICMP Tunneling Attempt"; dsize:>100; sid:1000006; rev:1;)

# Detect suspicious user agents
alert http any any -> any any (msg:"SECURITY_SUITE Suspicious HTTP User Agent"; flow:to_server,established; content:"User-Agent|3a|"; http_header; content:"curl"; http_header; sid:1000007; rev:1;)

# Detect base64 encoded data in HTTP
alert http any any -> any any (msg:"SECURITY_SUITE Base64 Data in HTTP POST"; flow:to_server,established; content:"POST"; http_method; content:"base64"; http_client_body; sid:1000008; rev:1;)

# Detect SSH brute force
alert tcp any any -> $HOME_NET 22 (msg:"SECURITY_SUITE SSH Brute Force Attempt"; flow:to_server,established; content:"SSH"; threshold:type threshold, track by_src, count 5, seconds 60; sid:1000009; rev:1;)

# Detect RDP brute force
alert tcp any any -> $HOME_NET 3389 (msg:"SECURITY_SUITE RDP Brute Force Attempt"; flow:to_server,established; threshold:type threshold, track by_src, count 5, seconds 60; sid:1000010; rev:1;)
`
	err := os.WriteFile(FINAL_RULES_PATH, []byte(defaultRules), 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[RuleManager ERROR] Failed to create default rules: %v\n", err)
	} else {
		fmt.Println("[RuleManager] Created default Suricata rules")
	}
}

// UpdateRules runs suricata-update to fetch latest rules
func (rm *RuleManager) UpdateRules() bool {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	fmt.Printf("[RuleManager] Executing Suricata rule update: %s\n", SURICATA_UPDATE_TOOL)

	// Check if suricata-update exists
	if _, err := exec.LookPath(SURICATA_UPDATE_TOOL); err != nil {
		fmt.Fprintf(os.Stderr, "[RuleManager ERROR] suricata-update not found: %v\n", err)
		return false
	}

	// Run suricata-update
	cmd := exec.Command("sudo", SURICATA_UPDATE_TOOL, "--no-test", "--no-reload")
	output, err := cmd.CombinedOutput()

	if err != nil {
		fmt.Fprintf(os.Stderr, "[RuleManager ERROR] Failed to update rules: %v\nOutput: %s\n", err, string(output))
		return false
	}

	rm.LastUpdated = time.Now()
	rm.RulesLoaded = true

	fmt.Printf("[RuleManager] Rules updated successfully at %s\n", rm.LastUpdated.Format(time.RFC3339))
	fmt.Printf("[RuleManager] Update output: %s\n", string(output))

	return true
}

// GetStatus returns rule manager status
func (rm *RuleManager) GetStatus() RuleManagerStatus {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	return RuleManagerStatus{
		RulesLoaded:  rm.RulesLoaded,
		LastUpdated:  rm.LastUpdated.Format(time.RFC3339),
		Error:        "",
		RulesVersion: rm.RulesChecksum,
	}
}

// --- Intrusion Detector Core ---

// IntrusionDetector manages Suricata IDS integration
type IntrusionDetector struct {
	Interface       string
	Monitoring      bool
	RuleManager     *RuleManager
	LastLogPosition int64
	suricataPID     int
	mu              sync.RWMutex
	stopChan        chan struct{}
}

// NewIntrusionDetector initializes the IDS module
func NewIntrusionDetector(rm *RuleManager) *IntrusionDetector {
	ids := &IntrusionDetector{
		Monitoring:  false,
		RuleManager: rm,
		stopChan:    make(chan struct{}),
	}
	ids.initializeLogPosition()
	return ids
}

// initializeLogPosition sets starting point for reading alerts
func (id *IntrusionDetector) initializeLogPosition() {
	id.mu.Lock()
	defer id.mu.Unlock()

	f, err := os.Open(SURICATA_EVE_LOG_PATH)
	if err != nil {
		id.LastLogPosition = 0
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err == nil {
		id.LastLogPosition = info.Size()
		fmt.Printf("[IntrusionDetector] Initial log position set to %d bytes\n", id.LastLogPosition)
	} else {
		id.LastLogPosition = 0
	}
}

// GetMonitoringStatus returns current IDS status
func (id *IntrusionDetector) GetMonitoringStatus() IDSStatus {
	id.mu.RLock()
	defer id.mu.RUnlock()

	return IDSStatus{
		Monitoring:        id.Monitoring,
		Interface:         id.Interface,
		RuleManagerStatus: id.RuleManager.GetStatus(),
	}
}

// StartMonitoring starts Suricata on the specified interface
func (id *IntrusionDetector) StartMonitoring(iface string) error {
	id.mu.Lock()
	defer id.mu.Unlock()

	if id.Monitoring {
		return fmt.Errorf("monitoring already active on interface %s", id.Interface)
	}

	fmt.Printf("[IntrusionDetector] Starting Suricata on interface %s...\n", iface)

	// Check if Suricata is already running
	checkCmd := exec.Command("pgrep", "-x", "Suricata")
	if err := checkCmd.Run(); err == nil {
		fmt.Println("[IntrusionDetector] Suricata already running, will use existing instance")
		id.Interface = iface
		id.Monitoring = true
		go id.monitorAlerts()
		return nil
	}

	// Start Suricata in daemon mode
	cmd := exec.Command("sudo", SURICATA_BINARY,
		"-i", iface,
		"-c", SURICATA_CONF_PATH,
		"-D", // Daemon mode
		"--pidfile", "/var/run/suricata.pid",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to start Suricata: %v\nOutput: %s", err, string(output))
	}

	// Wait a moment for Suricata to initialize
	time.Sleep(2 * time.Second)

	// Verify Suricata started
	checkCmd = exec.Command("pgrep", "-x", "Suricata")
	if err := checkCmd.Run(); err != nil {
		return fmt.Errorf("suricata failed to start")
	}

	// Read PID from pidfile
	if pidBytes, err := os.ReadFile("/var/run/suricata.pid"); err == nil {
		pidStr := strings.TrimSpace(string(pidBytes))
		if pid, err := strconv.Atoi(pidStr); err == nil {
			id.suricataPID = pid
		}
	}

	id.Interface = iface
	id.Monitoring = true

	fmt.Println("[IntrusionDetector] Suricata started successfully")

	// Start monitoring alerts
	go id.monitorAlerts()

	return nil
}

// monitorAlerts continuously monitors Suricata alerts
func (id *IntrusionDetector) monitorAlerts() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-id.stopChan:
			return
		case <-ticker.C:
			id.CheckForAlerts()
		}
	}
}

// StopMonitoring stops Suricata gracefully
func (id *IntrusionDetector) StopMonitoring() error {
	id.mu.Lock()
	defer id.mu.Unlock()

	if !id.Monitoring {
		return nil
	}

	fmt.Println("[IntrusionDetector] Stopping Suricata...")

	// Send SIGTERM to Suricata
	cmd := exec.Command("sudo", "pkill", "-15", "Suricata")
	if err := cmd.Run(); err != nil {
		fmt.Printf("[IntrusionDetector] Warning: failed to stop Suricata: %v\n", err)
	}

	close(id.stopChan)
	id.stopChan = make(chan struct{})
	id.Monitoring = false
	id.suricataPID = 0

	fmt.Println("[IntrusionDetector] Suricata stopped")
	return nil
}

// LoadRules reloads Suricata rules without restart
func (id *IntrusionDetector) LoadRules() error {
	fmt.Println("[IntrusionDetector] Reloading Suricata rules...")

	// Send USR2 signal to Suricata to reload rules
	cmd := exec.Command("sudo", "pkill", "-USR2", "Suricata")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to reload rules: %v", err)
	}

	id.RuleManager.LoadRulesStatus()
	fmt.Println("[IntrusionDetector] Rules reloaded successfully")
	return nil
}

// CheckForAlerts reads new alerts from Suricata eve.json log
func (id *IntrusionDetector) CheckForAlerts() []ThreatIndicator {
	id.mu.Lock()
	defer id.mu.Unlock()

	f, err := os.Open(SURICATA_EVE_LOG_PATH)
	if err != nil {
		// Log file doesn't exist yet
		return nil
	}
	defer f.Close()

	// Seek to last known position
	_, err = f.Seek(id.LastLogPosition, io.SeekStart)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[IntrusionDetector ERROR] Failed to seek: %v\n", err)
		return nil
	}

	alerts := make([]ThreatIndicator, 0)
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var rawAlert map[string]interface{}
		if err := json.Unmarshal(line, &rawAlert); err != nil {
			continue
		}

		eventType, ok := rawAlert["event_type"].(string)
		if !ok || eventType != "alert" {
			continue
		}

		var idsAlert IDSAlert
		if err := json.Unmarshal(line, &idsAlert); err != nil {
			fmt.Fprintf(os.Stderr, "[IntrusionDetector ERROR] Failed to unmarshal alert: %v\n", err)
			continue
		}

		// Convert IDS alert to ThreatIndicator
		var severity ThreatLevel
		var action ResponseAction

		switch idsAlert.Alert.Severity {
		case 1:
			severity = ThreatLevelCritical
			action = ActionBlock
		case 2:
			severity = ThreatLevelHigh
			action = ActionNotify
		case 3:
			severity = ThreatLevelMedium
			action = ActionLog
		default:
			severity = ThreatLevelInfo
			action = ActionLog
		}

		indicator := ThreatIndicator{
			Timestamp: idsAlert.Timestamp,
			SourceID:  "IDS-Suricata",
			SourceIP:  idsAlert.SourceIp,
			Target:    idsAlert.DestIp,
			Protocol:  idsAlert.Protocol,
			Severity:  severity,
			Signature: idsAlert.Alert.Signature,
			Context:   fmt.Sprintf("IDS Alert: %s", idsAlert.Alert.Signature),
			Action:    action,
			Details: map[string]interface{}{
				"event_type": idsAlert.EventType,
				"action":     idsAlert.Alert.Action,
			},
		}
		alerts = append(alerts, indicator)

		// Log the alert
		fmt.Printf("[IDS ALERT] %s: %s -> %s (%s)\n",
			severity, idsAlert.SourceIp, idsAlert.DestIp, idsAlert.Alert.Signature)
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		fmt.Fprintf(os.Stderr, "[IntrusionDetector ERROR] Scanner error: %v\n", err)
	}

	// Update position
	currentPos, _ := f.Seek(0, io.SeekCurrent)
	id.LastLogPosition = currentPos

	return alerts
}

// GetStatistics returns IDS statistics
func (id *IntrusionDetector) GetStatistics() map[string]interface{} {
	id.mu.RLock()
	defer id.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["monitoring"] = id.Monitoring
	stats["interface"] = id.Interface
	stats["log_position"] = id.LastLogPosition

	// Get Suricata stats if running
	if id.Monitoring {
		cmd := exec.Command("sudo", "suricatasc", "-c", "dump-counters")
		output, err := cmd.Output()
		if err == nil {
			stats["suricata_counters"] = string(output)
		}
	}

	return stats
}

// CheckSuricataHealth verifies Suricata is running properly
func (id *IntrusionDetector) CheckSuricataHealth() bool {
	cmd := exec.Command("pgrep", "-x", "Suricata")
	return cmd.Run() == nil
}

// GetSuricataVersion returns the installed Suricata version
func (id *IntrusionDetector) GetSuricataVersion() string {
	cmd := exec.Command(SURICATA_BINARY, "--build-info")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Version") {
			return strings.TrimSpace(line)
		}
	}
	return "unknown"
}
