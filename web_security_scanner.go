// web_security_scanner.go
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// WebSecurityScanner performs comprehensive web application security testing
type WebSecurityScanner struct {
	Client              *http.Client
	MaxConcurrency      int
	Timeout             time.Duration
	FollowRedirects     bool
	UserAgent           string
	CustomHeaders       map[string]string
	DiscoveredEndpoints []string
	Results             []WebVulnerability
	mu                  sync.RWMutex
	AuthTokens          map[string]string
	CookieJar           *CookieStore
	stopChan            chan struct{}
}

// --- SHARED TYPES (All types now defined in types.go) ---

// CookieStore manages session cookies (implements http.CookieJar)
type CookieStore struct {
	cookies map[string][]*http.Cookie
	mu      sync.RWMutex
}

// NewWebSecurityScanner creates a production-ready web security scanner
func NewWebSecurityScanner() *WebSecurityScanner {
	// Configure an http.Transport to allow skipping SSL verification (for testing)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // For testing self-signed certs
		},
		MaxIdleConns:       100,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: false,
	}

	wss := &WebSecurityScanner{
		Client: &http.Client{
			Transport: transport,
			Timeout:   15 * time.Second,
			// Custom redirect checker to prevent excessive redirects or follow open redirects
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				// By returning this error, the client returns the *last* response,
				// which allows us to inspect the Location header for Open Redirect testing.
				return nil
			},
		},
		MaxConcurrency:      20,
		Timeout:             15 * time.Second,
		FollowRedirects:     true,
		UserAgent:           "SecuritySuite/2.0 Web Scanner",
		CustomHeaders:       make(map[string]string),
		DiscoveredEndpoints: make([]string, 0),
		Results:             make([]WebVulnerability, 0),
		AuthTokens:          make(map[string]string),
		CookieJar: &CookieStore{
			cookies: make(map[string][]*http.Cookie),
		},
		stopChan: make(chan struct{}),
	}
	// PRODUCTION: Assign the custom CookieJar to the client
	wss.Client.Jar = wss.CookieJar
	return wss
}

// ScanWebsite performs a comprehensive web security scan
func (wss *WebSecurityScanner) ScanWebsite(config ScanConfig) ([]WebVulnerability, error) {
	fmt.Printf("[WebScanner] Starting comprehensive scan of %s\n", config.TargetURL)

	targetURL, err := url.Parse(config.TargetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %v", err)
	}

	wss.mu.Lock()
	wss.Results = make([]WebVulnerability, 0)
	wss.DiscoveredEndpoints = make([]string, 0)
	wss.mu.Unlock()

	// Phase 1: Information Gathering
	wss.performReconnaissance(targetURL)

	// Phase 2: Endpoint Discovery
	if config.EnableCrawling {
		wss.crawlWebsite(targetURL, config.ScanDepth)
	}

	// Phase 3: Authentication Testing
	if config.TestAuthentication {
		wss.testAuthentication(targetURL, config.AuthCredentials)
	}

	// Phase 4-10: Vulnerability Testing
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, wss.MaxConcurrency)
	endpoints := wss.getEndpointsToTest(targetURL)

	for _, endpoint := range endpoints {
		wg.Add(1)
		go func(ep string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if config.TestSQLInjection {
				wss.testSQLInjection(ep)
			}
			if config.TestXSS {
				wss.testXSS(ep)
			}
			if config.TestLFI {
				wss.testLFI(ep)
			}
			if config.TestPathTraversal {
				wss.testPathTraversal(ep)
			}
			if config.TestRCE {
				wss.testRCE(ep)
			}

			// These tests usually only need to run once per host,
			// but we run them inside the goroutine for concurrency management.
			if config.TestSSRF {
				wss.testSSRF(targetURL)
			}
			if config.TestXXE {
				wss.testXXE(targetURL)
			}
			if config.TestCSRF {
				wss.testCSRF(targetURL)
			}
			if config.TestSecurityHeaders {
				wss.testSecurityHeaders(targetURL)
			}
			if config.TestSSL {
				wss.testSSLConfiguration(targetURL)
			}
			if config.TestOpenRedirect {
				wss.testOpenRedirect(targetURL)
			}
		}(endpoint)
	}

	wg.Wait()

	fmt.Printf("[WebScanner] Scan completed. Found %d vulnerabilities.\n", len(wss.Results))
	return wss.GetResults(), nil
}

// GetResults safely returns a copy of the scan results
func (wss *WebSecurityScanner) GetResults() []WebVulnerability {
	wss.mu.RLock()
	defer wss.mu.RUnlock()

	resultsCopy := make([]WebVulnerability, len(wss.Results))
	copy(resultsCopy, wss.Results)
	return resultsCopy
}

// GenerateReport generates a formatted report (text, json, html)
func (wss *WebSecurityScanner) GenerateReport(format string) (string, error) {
	results := wss.GetResults()
	if len(results) == 0 {
		return "No vulnerabilities found.", nil
	}
	switch strings.ToLower(format) {
	case "json":
		return wss.generateJSONReport(results)
	case "html":
		return wss.generateHTMLReport(results)
	case "text":
		return wss.generateTextReport(results)
	default:
		return wss.generateJSONReport(results)
	}
}

// --- Report Generation Helpers (Kept for completeness) ---

func (wss *WebSecurityScanner) generateJSONReport(results []WebVulnerability) (string, error) {
	// ... (JSON report logic from previous iteration) ...
	report := struct {
		Timestamp       time.Time          `json:"timestamp"`
		TargetURL       string             `json:"target_url"`
		Vulnerabilities []WebVulnerability `json:"vulnerabilities"`
	}{
		Timestamp:       time.Now(),
		TargetURL:       results[0].URL,
		Vulnerabilities: results,
	}

	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON report: %w", err)
	}
	return string(jsonData), nil
}

func (wss *WebSecurityScanner) generateTextReport(results []WebVulnerability) (string, error) {
	// ... (Text report logic from previous iteration) ...
	var report strings.Builder
	report.WriteString("============================================\n")
	report.WriteString("WEB SECURITY SCAN REPORT\n")
	report.WriteString("============================================\n")
	report.WriteString(fmt.Sprintf("Timestamp: %s\n", time.Now().Format(time.RFC850)))
	if len(results) > 0 {
		report.WriteString(fmt.Sprintf("Target: %s\n\n", results[0].URL))
	} else {
		report.WriteString("Target: N/A (No results)\n\n")
	}

	severityCounts := make(map[ThreatLevel]int)
	for _, vuln := range results {
		severityCounts[vuln.Severity]++
	}

	report.WriteString("SUMMARY OF FINDINGS\n")
	report.WriteString("--------------------------------------------\n")
	report.WriteString(fmt.Sprintf("Total Vulnerabilities: %d\n", len(results)))
	report.WriteString(fmt.Sprintf("  CRITICAL: %d\n", severityCounts[ThreatLevelCritical]))
	report.WriteString(fmt.Sprintf("  HIGH:     %d\n", severityCounts[ThreatLevelHigh]))
	report.WriteString(fmt.Sprintf("  MEDIUM:   %d\n", severityCounts[ThreatLevelMedium]))
	report.WriteString(fmt.Sprintf("  LOW:      %d\n\n", severityCounts[ThreatLevelLow]))

	report.WriteString("============================================\n")
	report.WriteString("DETAILED FINDINGS\n")
	report.WriteString("============================================\n\n")

	for i, vuln := range results {
		report.WriteString(fmt.Sprintf("[%d] %s - %s\n", i+1, vuln.Severity, vuln.VulnType))
		report.WriteString(fmt.Sprintf("URL: %s\n", vuln.URL))
		if vuln.Parameter != "" {
			report.WriteString(fmt.Sprintf("Parameter: %s\n", vuln.Parameter))
		}
		if vuln.Payload != "" {
			report.WriteString(fmt.Sprintf("Payload: %s\n", vuln.Payload))
		}
		report.WriteString(fmt.Sprintf("Description: %s\n", vuln.Description))
		report.WriteString(fmt.Sprintf("CVSS: %.1f | CWE: %s | OWASP: %s\n", vuln.CVSS, vuln.CWE, vuln.OWASP))
		report.WriteString(fmt.Sprintf("Remediation: %s\n", vuln.Remediation))
		report.WriteString("\n---\n\n")
	}

	return report.String(), nil
}

func (wss *WebSecurityScanner) generateHTMLReport(results []WebVulnerability) (string, error) {
	// ... (HTML report logic from previous iteration) ...
	if len(results) == 0 {
		return "<html><body><h1>Security Scan Report</h1><p>No vulnerabilities found.</p></body></html>", nil
	}

	var html strings.Builder
	html.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Security Scan Report</title>
  <style>
    body { font-family: sans-serif; margin: 20px; background-color: #f4f4f4; }
    .report-container { max-width: 900px; margin: auto; background: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
    h1 { color: #333; border-bottom: 2px solid #eee; padding-bottom: 10px; }
    .finding { border: 1px solid #ddd; padding: 15px; margin-bottom: 15px; border-radius: 5px; }
    .critical { border-left: 5px solid #d9534f; background-color: #f2dede; }
    .high { border-left: 5px solid #f0ad4e; background-color: #fcf8e3; }
    .medium { border-left: 5px solid #5bc0de; background-color: #d9edf7; }
    .low { border-left: 5px solid #5cb85c; background-color: #dff0d8; }
    strong { font-weight: bold; }
  </style>
</head>
<body>
<div class="report-container">
  <h1>Web Security Scan Report</h1>
  <p><strong>Target:</strong> ` + results[0].URL + `</p>
  <p><strong>Timestamp:</strong> ` + time.Now().Format(time.RFC850) + `</p>
  <h2>Detailed Findings (` + fmt.Sprintf("%d", len(results)) + ` Total)</h2>
`)

	for _, vuln := range results {
		html.WriteString(fmt.Sprintf(`
<div class="finding %s">
    <strong>%s - %s</strong>
    <p><strong>URL:</strong> %s</p>
`, strings.ToLower(string(vuln.Severity)), vuln.Severity, vuln.VulnType, vuln.URL))

		if vuln.Parameter != "" {
			html.WriteString(fmt.Sprintf(`<p><strong>Parameter:</strong> %s</p>`, vuln.Parameter))
		}
		if vuln.Payload != "" {
			html.WriteString(fmt.Sprintf(`<p><strong>Payload:</strong> <pre>%s</pre></p>`, vuln.Payload))
		}
		html.WriteString(fmt.Sprintf(`
    <p><strong>Description:</strong> %s</p>
    <p><strong>Remediation:</strong> %s</p>
    <p><small>CVSS: %.1f | CWE: %s | OWASP: %s | Confidence: %s</small></p>
</div>
`, vuln.Description, vuln.Remediation, vuln.CVSS, vuln.CWE, vuln.OWASP, vuln.Confidence))
	}

	html.WriteString(`
</div>
</body>
</html>`)

	return html.String(), nil
}

// --- CORE SCANNER LOGIC (PRODUCTION-GRADE) ---

// addVulnerability safely adds a vulnerability result
func (wss *WebSecurityScanner) addVulnerability(v WebVulnerability) {
	wss.mu.Lock()
	defer wss.mu.Unlock()
	wss.Results = append(wss.Results, v)
}

// performReconnaissance is Phase 1 (Initial step, adds base URL)
func (wss *WebSecurityScanner) performReconnaissance(targetURL *url.URL) {
	fmt.Println("[WebScanner] Phase 1: Information Gathering")
	wss.mu.Lock()
	wss.DiscoveredEndpoints = append(wss.DiscoveredEndpoints, targetURL.String())
	wss.mu.Unlock()
}

// crawlWebsite is Phase 2 (Functional, depth-limited crawler)
func (wss *WebSecurityScanner) crawlWebsite(baseURL *url.URL, depth int) {
	fmt.Printf("[Crawler] Starting production-level crawling of %s (Depth: %d)\n", baseURL.Host, depth)

	var visited sync.Map
	queue := make(chan *url.URL, 1000)

	queue <- baseURL
	visited.Store(baseURL.String(), true)

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, wss.MaxConcurrency)

	// Use an external loop to control depth
	for currentDepth := 0; currentDepth < depth; currentDepth++ {
		// Get the current set of URLs to process for this depth
		var urlsAtThisDepth []*url.URL
		// Drain the queue to a slice for the current depth level
		for {
			select {
			case u := <-queue:
				urlsAtThisDepth = append(urlsAtThisDepth, u)
			default:
				goto PROCESS_URLS
			}
		}

	PROCESS_URLS:
		if len(urlsAtThisDepth) == 0 {
			break // Queue is empty for this depth
		}

		fmt.Printf("[Crawler] Processing %d URLs at Depth %d\n", len(urlsAtThisDepth), currentDepth)

		for _, currentURL := range urlsAtThisDepth {
			wg.Add(1)
			go func(currentURL *url.URL, currentDepth int) {
				defer wg.Done()
				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				body, _, err := wss.getBodyContentWithCode(currentURL.String()) // Use the new utility function
				if err != nil {
					return
				}

				// Regex to find all links (a href)
				linkRegex := regexp.MustCompile(`href=["'](.[^"']+)["']`)
				matches := linkRegex.FindAllStringSubmatch(body, -1)

				for _, match := range matches {
					if len(match) < 2 {
						continue
					}

					link := match[1]
					resolvedURL, err := currentURL.Parse(link)
					if err != nil {
						continue
					}

					// Only follow links on the same host
					if resolvedURL.Host != currentURL.Host {
						continue
					}

					// Normalize URL (remove query and fragment for endpoint tracking)
					normalizedURL := resolvedURL.Scheme + "://" + resolvedURL.Host + resolvedURL.Path

					if _, loaded := visited.LoadOrStore(normalizedURL, true); !loaded {
						// New, unvisited endpoint found
						wss.mu.Lock()
						wss.DiscoveredEndpoints = append(wss.DiscoveredEndpoints, normalizedURL)
						wss.mu.Unlock()

						if currentDepth < depth-1 {
							// For the next depth level, add the full URL (including query if any)
							select {
							case queue <- resolvedURL:
							default:
								// Channel full, skip link
							}
						}
					}
				}
			}(currentURL, currentDepth)
		}
		wg.Wait()
	}
	// We do not close the queue here as it might still be used by concurrent routines finishing up.
	// We rely on the garbage collector.
}

// getEndpointsToTest aggregates all unique endpoints found
func (wss *WebSecurityScanner) getEndpointsToTest(baseURL *url.URL) []string {
	uniqueEndpoints := make(map[string]bool)
	uniqueEndpoints[baseURL.String()] = true

	for _, ep := range wss.DiscoveredEndpoints {
		uniqueEndpoints[ep] = true
	}

	var endpoints []string
	for ep := range uniqueEndpoints {
		endpoints = append(endpoints, ep)
	}
	return endpoints
}

// --- VULNERABILITY TEST FUNCTIONS ---

// testAuthentication is Phase 3
func (wss *WebSecurityScanner) testAuthentication(targetURL *url.URL, creds map[string]string) {
	fmt.Println("[WebScanner] Phase 3: Authentication & Session Management Testing")

	// ... (Existing implementation for default login check) ...
	loginEndpoint := targetURL.String()
	if !strings.HasSuffix(loginEndpoint, "/") {
		loginEndpoint += "/"
	}
	loginEndpoint += "login"

	defaultCreds := []struct{ username, password string }{
		{"admin", "password"}, {"user", "user"}, {"root", "toor"},
	}

	for _, cred := range defaultCreds {
		if wss.testLogin(loginEndpoint, cred.username, cred.password) {
			wss.addVulnerability(WebVulnerability{
				VulnType:    "Weak Authentication - Default/Common Credentials",
				Severity:    ThreatLevelHigh,
				URL:         targetURL.String(),
				Description: fmt.Sprintf("Vulnerable credential pair found: %s/%s", cred.username, cred.password),
				Remediation: "Change default credentials and enforce strong password policies.",
				CVSS:        6.8, CWE: "CWE-287", OWASP: "A07:2021 - Identification and Authentication Failures",
				Confidence: "High",
			})
		}
	}
}

// testLogin performs a real network POST request
func (wss *WebSecurityScanner) testLogin(endpoint, username, password string) bool {
	data := url.Values{
		"username": {username},
		"password": {password},
	}

	req, err := http.NewRequest("POST", endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return false
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wss.applyCustomHeaders(req)

	resp, err := wss.Client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Check for a standard success code after login (e.g., 302 redirect)
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		// Check the Location header to ensure it's not a redirect to an error page
		if location, ok := resp.Header["Location"]; ok && len(location) > 0 && !strings.Contains(location[0], "error") {
			return true // Success
		}
	}

	// Check for session cookies
	if len(resp.Cookies()) > 0 {
		return true
	}

	return false
}

// testSQLInjection is Phase 4 (Existing implementation)
func (wss *WebSecurityScanner) testSQLInjection(targetURL string) {
	// ... (Existing implementation: uses injectPayload and detectSQLInjection) ...
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return
	}
	query := parsedURL.Query()

	payloads := []struct {
		payload   string
		detection string
	}{
		{"' AND 1=1 --", ""},
		{"'", "sql syntax error"},
		{`"`, "sql syntax error"},
	}

	for param := range query {
		for _, payloadData := range payloads {
			testURL := wss.injectPayload(targetURL, param, payloadData.payload)

			if wss.detectSQLInjection(testURL, payloadData.payload, payloadData.detection) {
				wss.addVulnerability(WebVulnerability{
					VulnType:    "SQL Injection (Error/Boolean-Based)",
					Severity:    ThreatLevelCritical,
					URL:         targetURL,
					Method:      "GET",
					Parameter:   param,
					Payload:     payloadData.payload,
					Evidence:    fmt.Sprintf("Detection based on: %s", payloadData.detection),
					Description: "Potential SQL injection vulnerability detected in GET parameter. Check evidence for details.",
					Remediation: "Use parameterized queries (prepared statements) for all database interaction.",
					CVSS:        9.8, CWE: "CWE-89", OWASP: "A03:2021 - Injection",
					Confidence: "Medium",
				})
			}
		}
	}
}

// testXSS is Phase 4 (Existing implementation)
func (wss *WebSecurityScanner) testXSS(targetURL string) {
	// ... (Existing implementation: uses injectPayload and detectXSS) ...
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return
	}
	query := parsedURL.Query()

	fmt.Printf("[WebScanner] Testing XSS: %s\n", targetURL)
	payloads := []struct {
		payload   string
		detection string
	}{
		{"<script>alert('XSS-TEST')</script>", "<script>alert('XSS-TEST')</script>"},
		{"\" onmouseover=alert('XSS-TEST') x=\"", "onmouseover=alert('XSS-TEST')"},
	}

	for param := range query {
		for _, payloadData := range payloads {
			testURL := wss.injectPayload(targetURL, param, payloadData.payload)
			if wss.detectXSS(testURL, payloadData.detection) {
				wss.addVulnerability(WebVulnerability{
					VulnType:    "Cross-Site Scripting (XSS) - Reflected",
					Severity:    ThreatLevelHigh,
					URL:         targetURL,
					Method:      "GET",
					Parameter:   param,
					Payload:     payloadData.payload,
					Evidence:    "Unescaped payload reflected in the HTML body.",
					Description: "Reflected XSS vulnerability detected in GET parameter. Payload was found unescaped in the response.",
					Remediation: "Implement proper input validation and output encoding on all user-controlled data.",
					CVSS:        7.5, CWE: "CWE-79", OWASP: "A03:2021 - Injection",
					Confidence: "High",
				})
			}
		}
	}
}

// testLFI is Phase 4 (Existing implementation)
func (wss *WebSecurityScanner) testLFI(targetURL string) {
	// ... (Existing implementation: uses injectPayload and detectLFI) ...
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return
	}
	query := parsedURL.Query()

	fmt.Printf("[WebScanner] Testing LFI: %s\n", targetURL)
	payloads := []struct {
		payload   string
		detection string // String expected in response for detection
	}{
		{"../../../etc/passwd", "root:x:0:0"},       // Linux
		{"..\\..\\..\\windows\\win.ini", "[fonts]"}, // Windows
	}

	for param := range query {
		for _, payloadData := range payloads {
			testURL := wss.injectPayload(targetURL, param, payloadData.payload)
			if wss.detectLFI(testURL, payloadData.detection) {
				wss.addVulnerability(WebVulnerability{
					VulnType:    "Local File Inclusion (LFI)",
					Severity:    ThreatLevelCritical,
					URL:         targetURL,
					Method:      "GET",
					Parameter:   param,
					Payload:     payloadData.payload,
					Evidence:    fmt.Sprintf("Response contains unique file signature: %s", payloadData.detection),
					Description: "LFI vulnerability detected, allowing reading of arbitrary system files.",
					Remediation: "Do not pass user-controlled input to file system calls; use whitelisting for file names.",
					CVSS:        9.0, CWE: "CWE-22", OWASP: "A01:2021 - Broken Access Control",
					Confidence: "High",
				})
			}
		}
	}
}

// testPathTraversal is Phase 4 (New production logic)
func (wss *WebSecurityScanner) testPathTraversal(targetURL string) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return
	}
	query := parsedURL.Query()

	fmt.Printf("[WebScanner] Testing Path Traversal: %s\n", targetURL)
	// Path Traversal payloads using various encoding/truncation methods
	payloads := []struct {
		payload   string
		detection string // String expected in response for detection
	}{
		{"....//....//....//etc/passwd", "root:x:0:0"},        // Double-encoding
		{"..%2f..%2f..%2fetc%2fpasswd", "root:x:0:0"},         // URL-encoded slash
		{"..%252f..%252f..%252fetc%252fpasswd", "root:x:0:0"}, // Double-URL-encoded slash
	}

	for param := range query {
		for _, payloadData := range payloads {
			testURL := wss.injectPayload(targetURL, param, payloadData.payload)

			// Re-use detectLFI as Path Traversal is an LFI variant checking for signature reflection
			if wss.detectLFI(testURL, payloadData.detection) {
				wss.addVulnerability(WebVulnerability{
					VulnType:    "Path Traversal (Double-Encoded)",
					Severity:    ThreatLevelCritical,
					URL:         targetURL,
					Method:      "GET",
					Parameter:   param,
					Payload:     payloadData.payload,
					Evidence:    fmt.Sprintf("Response contains file signature: %s", payloadData.detection),
					Description: "Path Traversal vulnerability detected via unusual encoding, bypassing basic sanitization.",
					Remediation: "Canonicalize all user input paths before validation. Use strict input validation and do not rely on blacklist filtering.",
					CVSS:        9.0, CWE: "CWE-22", OWASP: "A01:2021 - Broken Access Control",
					Confidence: "High",
				})
			}
		}
	}
}

// testRCE is Phase 4 (New production logic)
func (wss *WebSecurityScanner) testRCE(targetURL string) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return
	}
	query := parsedURL.Query()

	fmt.Printf("[WebScanner] Testing RCE: %s\n", targetURL)
	// Common RCE payloads that produce predictable output (VULNTEST999)
	payloads := []struct {
		payload   string
		detection string
	}{
		// Linux/Unix based common payloads
		{"; echo VULNTEST999", "VULNTEST999"},
		{"| echo VULNTEST999", "VULNTEST999"},
		{"`echo VULNTEST999`", "VULNTEST999"},
		// Windows based common payloads
		{"& echo VULNTEST999", "VULNTEST999"},
	}

	for param := range query {
		for _, payloadData := range payloads {
			testURL := wss.injectPayload(targetURL, param, payloadData.payload)

			if wss.detectRCE(testURL, payloadData.detection) {
				wss.addVulnerability(WebVulnerability{
					VulnType:    "Remote Code Execution (RCE) via OS Command Injection",
					Severity:    ThreatLevelCritical,
					URL:         targetURL,
					Method:      "GET",
					Parameter:   param,
					Payload:     payloadData.payload,
					Evidence:    fmt.Sprintf("Injected command output reflected: %s", payloadData.detection),
					Description: "RCE vulnerability detected, allowing execution of arbitrary OS commands.",
					Remediation: "Never pass unsanitized user input to system command functions (e.g., shell_exec, system). Use explicit, whitelisted commands.",
					CVSS:        9.8, CWE: "CWE-78", OWASP: "A03:2021 - Injection",
					Confidence: "High",
				})
				return // Found RCE, move to next endpoint
			}
		}
	}
}

// testSSRF is Phase 5 (New production logic)
func (wss *WebSecurityScanner) testSSRF(targetURL *url.URL) {
	fmt.Println("[WebScanner] Phase 5: Server-Side Request Forgery Testing")

	// Common parameters used for image fetching, redirects, or API calls
	params := []string{"url", "source", "endpoint", "img", "callback", "file", "redir"}
	// Internal targets used to detect SSRF
	payloads := []string{
		"http://127.0.0.1:80",    // Loopback test
		"http://localhost/admin", // Common internal path
		// Metadata services: If running on cloud, this is critical
		"http://metadata.google.internal/0/instance/hostname", // GCE
		"http://169.254.169.254/latest/meta-data/",            // AWS EC2
	}

	for _, param := range params {
		for _, payload := range payloads {
			testURL := wss.injectPayload(targetURL.String(), param, payload)

			body, respCode, _ := wss.getBodyContentWithCode(testURL)

			// Strong indicator: leakage of internal IP address or metadata signature
			if strings.Contains(body, "metadata.google.internal") ||
				strings.Contains(body, "instance/hostname") ||
				strings.Contains(body, "latest/meta-data") ||
				(respCode == 200 && strings.Contains(body, "admin")) { // Successful access to a local admin page

				wss.addVulnerability(WebVulnerability{
					VulnType:    "Server-Side Request Forgery (SSRF) - Internal Access",
					Severity:    ThreatLevelCritical,
					URL:         testURL,
					Method:      "GET",
					Parameter:   param,
					Payload:     payload,
					Evidence:    fmt.Sprintf("Leaked internal data/metadata found in response (HTTP %d)", respCode),
					Description: "SSRF vulnerability detected, allowing the application to fetch internal/local resources.",
					Remediation: "Implement strict whitelisting of destination IPs/hostnames and protocols. Reject private/loopback IP ranges.",
					CVSS:        9.1, CWE: "CWE-918", OWASP: "A10:2021 - Server-Side Request Forgery (SSRF)",
					Confidence: "High",
				})
			}
		}
	}
}

// testXXE is Phase 6 (New production logic)
func (wss *WebSecurityScanner) testXXE(targetURL *url.URL) {
	fmt.Println("[WebScanner] Phase 6: XML External Entity Testing")

	testEndpoint := targetURL.String()

	// XXE Payload: attempts to read /etc/passwd and reflect it in the response (Billion Laughs is too noisy)
	xxePayload := `<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>`

	// Execute POST request with XML payload
	body, respCode, err := wss.postXMLContent(testEndpoint, xxePayload)
	if err != nil {
		return
	}

	// Check for the known signature of /etc/passwd
	if respCode == 200 && strings.Contains(body, "root:x:0:0") {
		wss.addVulnerability(WebVulnerability{
			VulnType:    "XML External Entity (XXE) - File Leakage",
			Severity:    ThreatLevelCritical,
			URL:         testEndpoint,
			Method:      "POST",
			Payload:     xxePayload,
			Evidence:    fmt.Sprintf("Response contains content of /etc/passwd (HTTP %d)", respCode),
			Description: "XXE vulnerability detected, allowing the parsing of external entities which leaked file content.",
			Remediation: "Disable DTDs (Document Type Definitions) and external entity processing entirely in your XML parser.",
			CVSS:        8.5, CWE: "CWE-611", OWASP: "A05:2021 - Security Misconfiguration",
			Confidence: "High",
		})
	}
}

// testCSRF is Phase 7 (New production logic)
func (wss *WebSecurityScanner) testCSRF(targetURL *url.URL) {
	fmt.Println("[WebScanner] Phase 7: Cross-Site Request Forgery (CSRF) Testing (Heuristic)")

	// Heuristic target: look for a sensitive endpoint that is POST-only.
	testEndpoint := targetURL.String() + "/profile/update"

	// 1. Check for anti-CSRF token presence via a simple GET request
	req, err := http.NewRequest("GET", testEndpoint, nil)
	if err != nil {
		return
	}
	wss.applyCustomHeaders(req)
	resp, err := wss.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	lowerBody := strings.ToLower(string(body))

	// Simple heuristic: check for common token names in the HTML body (e.g., hidden fields in a form)
	tokenPatterns := regexp.MustCompile(`(csrf|anti-forgery|token|nonce)`)
	tokenFound := tokenPatterns.MatchString(lowerBody)

	if !tokenFound {
		// 2. If no token is found, attempt a POST request *without* any token (CSRF simulation)
		data := url.Values{"email": {"csrftest@gemini.com"}}

		postReq, _ := http.NewRequest("POST", testEndpoint, strings.NewReader(data.Encode()))
		postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		wss.applyCustomHeaders(postReq)

		postResp, postErr := wss.Client.Do(postReq)
		if postErr != nil {
			return
		}
		defer postResp.Body.Close()

		// Success indicators: 200 OK or 3xx Redirect
		if postResp.StatusCode >= 200 && postResp.StatusCode < 400 {
			wss.addVulnerability(WebVulnerability{
				VulnType:    "Cross-Site Request Forgery (CSRF) - Heuristic",
				Severity:    ThreatLevelHigh,
				URL:         testEndpoint,
				Method:      "POST",
				Parameter:   "N/A",
				Payload:     "State-changing action without CSRF token",
				Evidence:    fmt.Sprintf("Successful state-changing POST (HTTP %d) with no anti-CSRF token found on page.", postResp.StatusCode),
				Description: "CSRF vulnerability detected. The server accepted a state-changing POST request without requiring an anti-CSRF token.",
				Remediation: "Implement synchronization tokens (CSRF tokens) for all state-changing requests (POST, PUT, DELETE).",
				CVSS:        6.8, CWE: "CWE-352", OWASP: "A04:2021 - Insecure Design",
				Confidence: "Medium",
			})
		}
	}
}

// testSecurityHeaders is Phase 8 (Existing implementation)
func (wss *WebSecurityScanner) testSecurityHeaders(targetURL *url.URL) {
	fmt.Println("[WebScanner] Phase 8: Security Headers Analysis")
	// ... (Existing implementation) ...
	req, err := http.NewRequest("GET", targetURL.String(), nil)
	if err != nil {
		return
	}
	wss.applyCustomHeaders(req)

	resp, err := wss.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.Header.Get("X-Content-Type-Options") == "" {
		wss.addVulnerability(WebVulnerability{
			VulnType:    "Missing X-Content-Type-Options Header",
			Severity:    ThreatLevelLow,
			URL:         targetURL.String(),
			Description: "The X-Content-Type-Options header is missing, which can allow MIME-type sniffing.",
			Remediation: "Set the X-Content-Type-Options header to 'nosniff'.",
			CVSS:        4.3, CWE: "CWE-200", OWASP: "A05:2021 - Security Misconfiguration",
			Confidence: "High",
		})
	}

	// Check for insecure cookies
	for _, cookie := range resp.Cookies() {
		if !cookie.Secure && targetURL.Scheme == "https" {
			wss.addVulnerability(WebVulnerability{
				VulnType:    "Insecure Cookie",
				Severity:    ThreatLevelMedium,
				URL:         targetURL.String(),
				Method:      "GET",
				Parameter:   cookie.Name,
				Description: fmt.Sprintf("Cookie '%s' is missing the 'Secure' flag over HTTPS.", cookie.Name),
				Remediation: "Ensure all cookies transmitted over HTTPS have the 'Secure' attribute set.",
				CVSS:        5.7, CWE: "CWE-614", OWASP: "A05:2021 - Security Misconfiguration",
				Confidence: "High",
			})
		}
	}
}

// testSSLConfiguration is Phase 9 (New production logic)
func (wss *WebSecurityScanner) testSSLConfiguration(targetURL *url.URL) {
	fmt.Println("[WebScanner] Phase 9: SSL/TLS Configuration Testing")

	if targetURL.Scheme != "https" {
		fmt.Printf("[WebScanner] Skipping SSL/TLS check for non-HTTPS URL: %s\n", targetURL.String())
		return
	}

	// Use a standard TCP dialer and TLS client to connect to the host
	conf := &tls.Config{
		InsecureSkipVerify: true, // Allow connection even if cert is invalid for testing purposes
	}

	conn, err := tls.DialWithDialer(nil, "tcp", targetURL.Host+":443", conf)
	if err != nil {
		fmt.Printf("[WebScanner ERROR] Failed to connect via TLS: %v\n", err)
		return
	}
	defer conn.Close()

	connState := conn.ConnectionState()

	// Check for weak TLS versions (PRODUCTION CHECK)
	if connState.Version < tls.VersionTLS12 {
		versionMap := map[uint16]string{
			tls.VersionSSL30: "SSLv3.0",
			tls.VersionTLS10: "TLSv1.0",
			tls.VersionTLS11: "TLSv1.1",
		}

		// Get the name, defaulting to "Unknown"
		versionName := versionMap[connState.Version]
		if versionName == "" {
			versionName = "Unknown/Custom"
		}

		wss.addVulnerability(WebVulnerability{
			VulnType:    "Weak TLS/SSL Protocol",
			Severity:    ThreatLevelCritical,
			URL:         targetURL.String(),
			Description: fmt.Sprintf("The server supports weak protocol: %s. Only TLS 1.2+ is secure.", versionName),
			Remediation: "Disable SSLv3, TLS 1.0, and TLS 1.1 on the server. Only enable TLS 1.2 and TLS 1.3.",
			CVSS:        9.3, CWE: "CWE-327", OWASP: "A05:2021 - Security Misconfiguration",
			Confidence: "High",
		})
	}
}

// testOpenRedirect is Phase 10 (Existing implementation)
func (wss *WebSecurityScanner) testOpenRedirect(targetURL *url.URL) {
	// ... (Existing implementation) ...
	fmt.Println("[WebScanner] Phase 10: Open Redirect Testing")
	payloads := []string{
		"https://evil.com",
		"//evil.com",
	}

	// Check common redirect parameters
	redirectEndpoints := []string{
		targetURL.String() + "/redirect",
		targetURL.String() + "/login?next=",
	}

	for _, endpoint := range redirectEndpoints {
		parsedEndpoint, err := url.Parse(endpoint)
		if err != nil {
			continue
		}

		param := "next" // Default guess
		if strings.Contains(parsedEndpoint.RawQuery, "=") {
			parts := strings.Split(parsedEndpoint.RawQuery, "=")
			if len(parts) > 0 {
				param = parts[0]
			}
		}

		for _, payload := range payloads {
			testURL := wss.injectPayload(endpoint, param, payload)

			req, err := http.NewRequest("GET", testURL, nil)
			if err != nil {
				continue
			}
			wss.applyCustomHeaders(req)

			// Use the scanner's client which has CheckRedirect disabled
			resp, err := wss.Client.Do(req)
			if err != nil && err != http.ErrUseLastResponse {
				continue
			}
			if resp == nil {
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				location := resp.Header.Get("Location")
				if strings.Contains(location, payload) || strings.Contains(location, url.QueryEscape(payload)) {
					wss.addVulnerability(WebVulnerability{
						VulnType:    "Open Redirect",
						Severity:    ThreatLevelMedium,
						URL:         testURL,
						Method:      "GET",
						Parameter:   param,
						Payload:     payload,
						Evidence:    fmt.Sprintf("Redirected to: %s", location),
						Description: "Open redirect vulnerability detected, allowing redirection to external sites.",
						Remediation: "Ensure all redirect targets are whitelisted internal paths, or use relative paths.",
						CVSS:        6.1, CWE: "CWE-601", OWASP: "A01:2021 - Broken Access Control",
						Confidence: "High",
					})
				}
			}
		}
	}
}

// --- CORE UTILITY FUNCTIONS ---

// injectPayload modifies a given URL's query parameter with a payload
func (wss *WebSecurityScanner) injectPayload(baseURL string, param string, payload string) string {
	parsedURL, _ := url.Parse(baseURL)
	q := parsedURL.Query()
	q.Set(param, payload)
	parsedURL.RawQuery = q.Encode()
	return parsedURL.String()
}

// detectSQLInjection checks for database error messages or the presence of specific detection strings.
func (wss *WebSecurityScanner) detectSQLInjection(testURL, payload, detection string) bool {
	body, _, err := wss.getBodyContentWithCode(testURL)
	if err != nil {
		return false
	}

	// 1. Check for database error strings (Error-based SQLi)
	errorPatterns := []string{
		"sql syntax error", "mysql_fetch_array", "error in your sql syntax",
		"warning: mysql", "supplied argument is not a valid mysql",
		"unclosed quotation mark", "microsoft access driver", "oci-8",
	}
	lowerBody := strings.ToLower(body)
	for _, pattern := range errorPatterns {
		if strings.Contains(lowerBody, pattern) {
			return true
		}
	}

	// 2. Check for the user-supplied 'detection' string
	if detection != "" && strings.Contains(body, detection) {
		return true
	}

	return false
}

// detectXSS checks if the unescaped payload or a detectable part of it is reflected in the HTML body.
func (wss *WebSecurityScanner) detectXSS(testURL string, detection string) bool {
	body, _, err := wss.getBodyContentWithCode(testURL)
	if err != nil {
		return false
	}

	// Check for the unescaped payload's reflection
	if strings.Contains(body, detection) {
		return true
	}

	return false
}

// detectLFI checks for the unique content of the known file used in the payload (e.g., /etc/passwd content).
func (wss *WebSecurityScanner) detectLFI(testURL string, detection string) bool {
	body, _, err := wss.getBodyContentWithCode(testURL)
	if err != nil {
		return false
	}

	if detection != "" && strings.Contains(body, detection) {
		return true
	}

	return false
}

// detectRCE checks for the unique, injected output string (VULNTEST999) reflected in the body.
func (wss *WebSecurityScanner) detectRCE(testURL string, detection string) bool {
	body, _, err := wss.getBodyContentWithCode(testURL)
	if err != nil {
		return false
	}

	return strings.Contains(body, detection)
}

// applyCustomHeaders sets the User-Agent and any custom headers before a request.
func (wss *WebSecurityScanner) applyCustomHeaders(req *http.Request) {
	req.Header.Set("User-Agent", wss.UserAgent)
	for k, v := range wss.CustomHeaders {
		req.Header.Set(k, v)
	}
}

// getBodyContentWithCode fetches, returns the body content as a string, and the status code.
func (wss *WebSecurityScanner) getBodyContentWithCode(url string) (string, int, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", 0, err
	}
	wss.applyCustomHeaders(req)

	resp, err := wss.Client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", resp.StatusCode, err
	}
	return string(body), resp.StatusCode, nil
}

// postXMLContent executes a POST request with XML content and returns the body and status code.
func (wss *WebSecurityScanner) postXMLContent(url string, xmlContent string) (string, int, error) {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(xmlContent)))
	if err != nil {
		return "", 0, err
	}

	req.Header.Set("Content-Type", "application/xml")
	wss.applyCustomHeaders(req)

	resp, err := wss.Client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", resp.StatusCode, err
	}
	return string(body), resp.StatusCode, nil
}

// CookieStore implementation methods
func (cs *CookieStore) SetCookies(u *url.URL, cookies []*http.Cookie) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.cookies[u.Host] = cookies
}

func (cs *CookieStore) Cookies(u *url.URL) []*http.Cookie {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.cookies[u.Host]
}

// StartScan initiates a web security scan
func (wss *WebSecurityScanner) StartScan(sessionID string, config ScanConfig, orchestrator *ResponseOrchestrator) error {
	go func() {
		_, err := wss.ScanWebsite(config)
		if err != nil {
			fmt.Printf("[WebScanner] Scan failed: %v\n", err)
		}
	}()
	return nil
}

// GetStatus returns the current status of the web scan
func (wss *WebSecurityScanner) GetStatus(sessionID string) map[string]interface{} {
	wss.mu.RLock()
	defer wss.mu.RUnlock()

	return map[string]interface{}{
		"session_id": sessionID,
		"status":     "completed", // Simplified status
		"results":    len(wss.Results),
	}
}

// StopScan implements the Stoppable interface
func (wss *WebSecurityScanner) StopScan() bool {
	select {
	case <-wss.stopChan:
		// Already stopped
	default:
		close(wss.stopChan)
	}
	return true
}
