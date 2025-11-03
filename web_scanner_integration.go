// web_scanner_integration.go
package main

import (
	"encoding/json" // Added for API handlers
	// Added for CLI handler
	"fmt"
	"log"
	"net/http" // Added for API handlers
	"net/url"  // Added for URL validation (Hardening)
	"time"
)

// Helper function for URL validation (Hardening)
func validateTargetURL(targetURL string) error {
	u, err := url.ParseRequestURI(targetURL)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}
	// Ensure scheme is http or https for web scanning
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("unsupported URL scheme: %s. Must be http or https", u.Scheme)
	}
	return nil
}

// ===== INTEGRATION HOOK FOR CORE CONTROLLER =====

// Add to CoreController struct in core_controller.go:
/*
type CoreController struct {
	// ... existing fields ...
	WebScanner *WebSecurityScanner  // ADD THIS LINE
	// Orchestrator *ResponseOrchestrator // This is needed for the HandleThreat call
}
*/

// Add to NewCoreController() in core_controller.go:
/*
func NewCoreController(verbose bool) *CoreController {
	// ... existing initialization ...

	webScanner := NewWebSecurityScanner()  // ADD THIS

	return &CoreController{
		// ... existing fields ...
		WebScanner: webScanner,  // ADD THIS
		// ... existing fields ...
	}
}
*/

// ===== WEB SCANNER WRAPPER METHODS FOR CORE CONTROLLER =====

// Add these methods to core_controller.go:

// ScanWebApplication performs a comprehensive web security scan
func (controller *CoreController) ScanWebApplication(targetURL string, config ScanConfig) ([]WebVulnerability, string, error) {
	// HARDENING: Validate target URL before starting the scan
	if err := validateTargetURL(targetURL); err != nil {
		return nil, "", fmt.Errorf("security scan aborted: %w", err)
	}

	config.TargetURL = targetURL // Ensure config has the validated URL

	log.Printf("[CoreController] Starting web application scan: %s", targetURL)

	// Start scan by calling the functional component
	vulnerabilities, err := controller.WebScanner.ScanWebsite(config)
	if err != nil {
		return nil, "", fmt.Errorf("web scan failed: %v", err)
	}

	// Convert vulnerabilities to threat indicators for unified handling
	for _, vuln := range vulnerabilities {
		indicator := ThreatIndicator{
			Timestamp: vuln.Timestamp,
			SourceID:  "WEB-SCANNER",
			Target:    vuln.URL,
			Severity:  vuln.Severity,
			Signature: vuln.VulnType,
			Context:   vuln.Description,
			Details: map[string]interface{}{
				"method":      vuln.Method,
				"parameter":   vuln.Parameter,
				"payload":     vuln.Payload,
				"evidence":    vuln.Evidence,
				"remediation": vuln.Remediation,
				"cvss":        vuln.CVSS,
				"cwe":         vuln.CWE,
				"owasp":       vuln.OWASP,
			},
		}

		// Send to response orchestrator if critical/high
		if vuln.Severity == ThreatLevelCritical || vuln.Severity == ThreatLevelHigh {
			// This call assumes controller.Orchestrator is correctly initialized
			go controller.Orchestrator.HandleThreat(indicator)
		}
	}

	// Generate summary message
	message := fmt.Sprintf("Web scan complete. Found %d vulnerabilities (Critical: %d, High: %d, Medium: %d, Low: %d)",
		len(vulnerabilities),
		countBySeverity(vulnerabilities, ThreatLevelCritical),
		countBySeverity(vulnerabilities, ThreatLevelHigh),
		countBySeverity(vulnerabilities, ThreatLevelMedium),
		countBySeverity(vulnerabilities, ThreatLevelLow))

	log.Println("[CoreController]", message)

	return vulnerabilities, message, nil
}

// QuickWebScan performs a fast web scan with default settings
func (controller *CoreController) QuickWebScan(targetURL string) ([]WebVulnerability, string, error) {
	config := ScanConfig{
		TargetURL:           targetURL, // Will be validated and set in ScanWebApplication
		ScanDepth:           1,
		EnableCrawling:      true,
		TestAuthentication:  false,
		TestSQLInjection:    true,
		TestXSS:             true,
		TestCSRF:            false,
		TestLFI:             true,
		TestRCE:             false,
		TestSSRF:            false,
		TestXXE:             false,
		TestOpenRedirect:    true,
		TestPathTraversal:   true,
		TestSecurityHeaders: true,
		TestSSL:             true,
	}

	return controller.ScanWebApplication(targetURL, config)
}

// FullWebScan performs a comprehensive web scan with all tests enabled
func (controller *CoreController) FullWebScan(targetURL string, authCreds map[string]string) ([]WebVulnerability, string, error) {
	config := ScanConfig{
		TargetURL:           targetURL, // Will be validated and set in ScanWebApplication
		ScanDepth:           3,
		EnableCrawling:      true,
		TestAuthentication:  true,
		TestSQLInjection:    true,
		TestXSS:             true,
		TestCSRF:            true,
		TestLFI:             true,
		TestRCE:             true,
		TestSSRF:            true,
		TestXXE:             true,
		TestOpenRedirect:    true,
		TestPathTraversal:   true,
		TestSecurityHeaders: true,
		TestSSL:             true,
		AuthCredentials:     authCreds,
	}

	return controller.ScanWebApplication(targetURL, config)
}

// GetWebScanReport generates a formatted report
func (controller *CoreController) GetWebScanReport(format string) (string, error) {
	return controller.WebScanner.GenerateReport(format)
}

// Helper function to count vulnerabilities by severity
func countBySeverity(vulnerabilities []WebVulnerability, severity ThreatLevel) int {
	count := 0
	for _, vuln := range vulnerabilities {
		if vuln.Severity == severity {
			count++
		}
	}
	return count
}

// ===== WEB SERVER API ENDPOINTS =====

// Add these handlers to web_server.go:

// handleWebScan processes web security scan requests
func (ws *WebServer) handleWebScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is supported", http.StatusMethodNotAllowed)
		return
	}

	var reqBody struct {
		TargetURL           string            `json:"target_url"`
		ScanType            string            `json:"scan_type"` // "quick" or "full"
		ScanDepth           int               `json:"scan_depth"`
		EnableCrawling      bool              `json:"enable_crawling"`
		TestAuthentication  bool              `json:"test_authentication"`
		TestSQLInjection    bool              `json:"test_sql_injection"`
		TestXSS             bool              `json:"test_xss"`
		TestCSRF            bool              `json:"test_csrf"`
		TestLFI             bool              `json:"test_lfi"`
		TestRCE             bool              `json:"test_rce"`
		TestSSRF            bool              `json:"test_ssrf"`
		TestXXE             bool              `json:"test_xxe"`
		TestOpenRedirect    bool              `json:"test_open_redirect"`
		TestPathTraversal   bool              `json:"test_path_traversal"`
		TestSecurityHeaders bool              `json:"test_security_headers"`
		TestSSL             bool              `json:"test_ssl"`
		AuthCredentials     map[string]string `json:"auth_credentials"`
	}

	w.Header().Set("Content-Type", "application/json")

	// HARDENING: Securely decode JSON body and check for errors (including EOF)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields() // Prevent silent acceptance of extraneous data
	if err := decoder.Decode(&reqBody); err != nil {
		http.Error(w, "Invalid request body or unknown fields: "+err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("[WebServer] Web scan requested: %s (type: %s)", reqBody.TargetURL, reqBody.ScanType)

	var vulnerabilities []WebVulnerability
	var message string
	var err error

	// Execute appropriate scan type
	if reqBody.ScanType == "quick" {
		vulnerabilities, message, err = ws.Controller.QuickWebScan(reqBody.TargetURL)
	} else if reqBody.ScanType == "full" {
		vulnerabilities, message, err = ws.Controller.FullWebScan(reqBody.TargetURL, reqBody.AuthCredentials)
	} else {
		// Custom scan configuration
		config := ScanConfig{
			// TargetURL is validated inside ScanWebApplication
			ScanDepth:           reqBody.ScanDepth,
			EnableCrawling:      reqBody.EnableCrawling,
			TestAuthentication:  reqBody.TestAuthentication,
			TestSQLInjection:    reqBody.TestSQLInjection,
			TestXSS:             reqBody.TestXSS,
			TestCSRF:            reqBody.TestCSRF,
			TestLFI:             reqBody.TestLFI,
			TestRCE:             reqBody.TestRCE,
			TestSSRF:            reqBody.TestSSRF,
			TestXXE:             reqBody.TestXXE,
			TestOpenRedirect:    reqBody.TestOpenRedirect,
			TestPathTraversal:   reqBody.TestPathTraversal,
			TestSecurityHeaders: reqBody.TestSecurityHeaders,
			TestSSL:             reqBody.TestSSL,
			AuthCredentials:     reqBody.AuthCredentials,
		}
		vulnerabilities, message, err = ws.Controller.ScanWebApplication(reqBody.TargetURL, config)
	}

	if err != nil {
		log.Printf("[WebServer ERROR] Web scan failed: %v", err)
		// Use a dedicated error response format
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}

	// Return results
	response := map[string]interface{}{
		"status":          "complete",
		"message":         message,
		"vulnerabilities": vulnerabilities,
		"summary": map[string]int{
			"total":    len(vulnerabilities),
			"critical": countBySeverity(vulnerabilities, ThreatLevelCritical),
			"high":     countBySeverity(vulnerabilities, ThreatLevelHigh),
			"medium":   countBySeverity(vulnerabilities, ThreatLevelMedium),
			"low":      countBySeverity(vulnerabilities, ThreatLevelLow),
		},
		"timestamp": time.Now().Format(time.RFC3339),
	}

	json.NewEncoder(w).Encode(response)
}

// handleWebScanReport generates and returns a formatted report (moved to web_server.go)
// func (ws *WebServer) handleWebScanReport(w http.ResponseWriter, r *http.Request) {
// 	if r.Method != http.MethodGet {
// 		http.Error(w, "Only GET method is supported", http.StatusMethodNotAllowed)
// 		return
// 	}
//
// 	format := r.URL.Query().Get("format")
// 	if format == "" {
// 		format = "json"
// 	}
//
// 	report, err := ws.Controller.GetWebScanReport(format)
// 	if err != nil {
// 		http.Error(w, fmt.Sprintf("Failed to generate report: %v", err), http.StatusInternalServerError)
// 		return
// 	}
//
// 	// Set Content-Type based on format for proper browser/client rendering
// 	switch format {
// 	case "json":
// 		w.Header().Set("Content-Type", "application/json")
// 	case "html":
// 		w.Header().Set("Content-Type", "text/html")
// 	case "text":
// 		w.Header().Set("Content-Type", "text/plain")
// 	default:
// 		w.Header().Set("Content-Type", "text/plain")
// 	}
//
// 	w.Write([]byte(report))
// }

// ===== REGISTRATION IN WEB SERVER =====

// Add to WebServer.Start() method in web_server.go:
/*
func (ws *WebServer) Start() {
	// ... existing routes ...

	// Web security scanner endpoints
	http.HandleFunc("/api/webscan", ws.handleWebScan)
	http.HandleFunc("/api/webscan/report", ws.handleWebScanReport)

	// ... rest of server setup ...
}
*/

// ===== CLI INTEGRATION =====

// Add to main.go CLI handler:
/*
func handleWebScanCLI(args []string, controller *CoreController) {
	webScanFlags := flag.NewFlagSet("webscan", flag.ExitOnError)
	targetURL := webScanFlags.String("url", "", "Target URL to scan")
	scanType := webScanFlags.String("type", "quick", "Scan type: quick, full, custom")
	depth := webScanFlags.Int("depth", 2, "Crawl depth")
	reportFormat := webScanFlags.String("format", "text", "Report format: text, json, html")

	// Parse CLI arguments for the webscan subcommand
	webScanFlags.Parse(args)

	if *targetURL == "" {
		fmt.Println("Error: -url is required")
		webScanFlags.Usage()
		return
	}

	// HARDENING: Validate URL before proceeding with CLI scan
	if err := validateTargetURL(*targetURL); err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Starting web security scan of: %s\n", *targetURL)

	var vulnerabilities []WebVulnerability
	var message string
	var err error

	if *scanType == "quick" {
		vulnerabilities, message, err = controller.QuickWebScan(*targetURL)
	} else if *scanType == "full" {
		// Note: CLI full scan currently uses nil for AuthCredentials;
		// these would need to be passed via additional flags if required.
		vulnerabilities, message, err = controller.FullWebScan(*targetURL, nil)
	} else {
		config := ScanConfig{
			TargetURL:          *targetURL,
			ScanDepth:          *depth,
			EnableCrawling:     true,
			TestSQLInjection:   true,
			TestXSS:            true,
			TestSecurityHeaders: true,
			TestSSL:            true,
		}
		vulnerabilities, message, err = controller.ScanWebApplication(*targetURL, config)
	}

	if err != nil {
		fmt.Printf("Scan failed: %v\n", err)
		return
	}

	fmt.Println(message)

	// Generate and display report
	report, _ := controller.GetWebScanReport(*reportFormat)
	fmt.Println(report)
}
*/

// Add to main.go switch statement:
/*
switch command {
	// ... existing cases ...
	case "webscan":
		handleWebScanCLI(args[1:], controller)
	// ... rest of cases ...
}
*/
