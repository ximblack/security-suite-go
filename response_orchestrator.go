package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ResponseOrchestrator manages and executes automated response actions.
type ResponseOrchestrator struct {
	QuarantineDir string
	mu            sync.Mutex
	actionLog     []ResponseOutcome
}

// NewResponseOrchestrator initializes the orchestrator.
func NewResponseOrchestrator(quarantineDir string) *ResponseOrchestrator {
	// Ensure the quarantine directory exists
	if err := os.MkdirAll(quarantineDir, 0700); err != nil {
		fmt.Printf("[ERROR] Failed to create quarantine directory %s: %v\n", quarantineDir, err)
	}
	return &ResponseOrchestrator{
		QuarantineDir: quarantineDir,
		actionLog:     make([]ResponseOutcome, 0),
	}
}

// HandleThreat takes a ThreatIndicator and determines/executes the appropriate action.
func (ro *ResponseOrchestrator) HandleThreat(threat ThreatIndicator) ResponseOutcome {
	// Policy Logic: Map severity/signature to an action.
	var action ResponseAction

	// Example Policy:
	if threat.Severity == ThreatLevelCritical {
		// Use Target field for determining network vs file action
		if strings.Contains(threat.Target, ".") && !strings.Contains(threat.Target, "/") {
			// Simple heuristic: If it looks like an IP/hostname but not a file path
			action = ActionBlockNetworkAccess
		} else {
			action = ActionQuarantineFile
		}
	} else if threat.Severity == ThreatLevelHigh {
		action = ActionQuarantineFile
	} else {
		action = ActionLogAndMonitor
	}

	fmt.Printf("[ORCHESTRATOR] Threat %s (%s) mapped to action: %s\n", threat.Signature, threat.Severity, action)

	var outcome ResponseOutcome
	switch action {
	case ActionQuarantineFile:
		outcome = ro.handleQuarantineFile(threat.Target)

	case ActionBlockNetworkAccess:
		// Extract IP from Target
		ip := ""
		if strings.Contains(threat.Target, ":") {
			ip = strings.Split(threat.Target, ":")[0]
		} else {
			ip = threat.Target
		}
		outcome = ro.handleBlockNetworkAccess(ip)

	case ActionLogAndMonitor:
		outcome = ResponseOutcome{
			Action:  ActionLogAndMonitor,
			Status:  "COMPLETED",
			Message: fmt.Sprintf("Threat logged to DB for review: %s", threat.Signature),
		}

	default:
		outcome = ResponseOutcome{Action: action, Status: "FAILED", Message: "Unsupported action."}
	}

	ro.logAction(outcome)
	return outcome
}

// handleBlockNetworkAccess attempts to block an IP address using `iptables`.
func (ro *ResponseOrchestrator) handleBlockNetworkAccess(targetIP string) ResponseOutcome {
	response := ResponseOutcome{
		Action:        ActionBlockNetworkAccess,
		ExecutionTime: time.Now(),
	}

	if targetIP == "" {
		response.Status = "FAILED"
		response.Message = "Target IP is empty."
		return response
	}

	// Command: sudo iptables -A INPUT -s <targetIP> -j DROP
	cmdArgs := []string{"sudo", "iptables", "-A", "INPUT", "-s", targetIP, "-j", "DROP"}

	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	output, err := cmd.CombinedOutput()

	if err != nil {
		response.Status = "FAILED"
		response.Message = fmt.Sprintf("Failed to execute network block: %v. Output: %s", err, string(output))
		fmt.Printf("[ERROR] Network block failed: %s\n", response.Message)
		return response
	}

	response.Status = "COMPLETED"
	response.Message = fmt.Sprintf("Successfully executed network block for IP: %s. Command: sudo iptables -A INPUT -s %s -j DROP. Output: %s", targetIP, targetIP, strings.TrimSpace(string(output)))
	return response
}

// handleQuarantineFile attempts to move a detected file to the quarantine directory.
func (ro *ResponseOrchestrator) handleQuarantineFile(targetFile string) ResponseOutcome {
	response := ResponseOutcome{
		Action:        ActionQuarantineFile,
		ExecutionTime: time.Now(),
	}

	if targetFile == "" {
		response.Status = "FAILED"
		response.Message = "Quarantine target file path is empty."
		return response
	}

	// Determine the new quarantine path
	filename := filepath.Base(targetFile)
	quarantineName := fmt.Sprintf("%s.quarantined_%s", filename, time.Now().Format("20060102150405"))
	newPath := filepath.Join(ro.QuarantineDir, quarantineName)

	// Command: sudo mv <targetFile> <newPath>
	cmdArgs := []string{"sudo", "mv", targetFile, newPath}

	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	output, err := cmd.CombinedOutput()

	if err != nil {
		response.Status = "FAILED"
		response.Message = fmt.Sprintf("Failed to quarantine file: %v. Output: %s", err, string(output))
		fmt.Printf("[ERROR] File quarantine failed: %s\n", response.Message)
		return response
	}

	response.Status = "COMPLETED"
	response.Message = fmt.Sprintf("Successfully quarantined file: sudo mv %s %s. Output: %s", targetFile, newPath, strings.TrimSpace(string(output)))
	return response
}

// logAction adds a completed action to the history.
func (ro *ResponseOrchestrator) logAction(outcome ResponseOutcome) {
	ro.mu.Lock()
	defer ro.mu.Unlock()
	ro.actionLog = append(ro.actionLog, outcome)
}

// GetActionLog returns the history of actions taken by the orchestrator.
func (ro *ResponseOrchestrator) GetActionLog() []ResponseOutcome {
	ro.mu.Lock()
	defer ro.mu.Unlock()
	// Return a copy to prevent external modification
	logCopy := make([]ResponseOutcome, len(ro.actionLog))
	copy(logCopy, ro.actionLog)
	return logCopy
}