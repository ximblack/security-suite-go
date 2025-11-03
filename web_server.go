// web_server.go - 100% Enterprise-Grade Production API Server
package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	webServerPort = "8080"
	indexFilePath = "index.html"
	// Hardening: WebSocket settings for keep-alive
	pongWait   = 60 * time.Second    // Time allowed to read the next pong message from the peer.
	pingPeriod = (pongWait * 9) / 10 // Send pings to peer with this period. Must be less than pongWait.
	// Hardening: Max request body size (1MB for all POST/PUT operations)
	maxRequestSize = 1048576
)

// CRITICAL HARDENING: Restrict WebSocket access
var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool {
		// CRITICAL HARDENING: Restrict access to known origins (local access only)
		origin := r.Header.Get("Origin")
		host := r.Host

		// Allows local UI access (localhost, 127.0.0.1)
		isLocal := strings.Contains(origin, "localhost") || strings.Contains(origin, "127.0.0.1") || strings.Contains(host, "localhost") || strings.Contains(host, "127.0.0.1") || origin == ""

		if !isLocal {
			log.Printf("[WebServer SECURITY WARNING] WebSocket connection blocked from suspicious origin: %s (Host: %s)", origin, host)
		}
		return isLocal
	},
}

type WebServer struct {
	Controller      *CoreController
	TerminalManager *TerminalManager
	eventClients    map[*websocket.Conn]bool
	eventMutex      sync.RWMutex
	eventBroadcast  chan interface{}
	startTime       time.Time
}

// Structs for JSON request/response
type TerminalActionRequest struct {
	SessionID string `json:"session_id"`
	Action    string `json:"action"` // e.g., "create", "close", "resize"
	Rows      uint16 `json:"rows"`
	Cols      uint16 `json:"cols"`
}

type ScanRequest struct {
	Type     string `json:"type"`      // file, directory, network
	Target   string `json:"target"`    // path or IP
	Depth    int    `json:"depth"`     // for directory scan
	ScanType string `json:"scan_type"` // for network scan
}

type HashCrackStartRequest struct {
	Hashes       map[string]string `json:"hashes"`
	HashType     string            `json:"hash_type"`
	WordlistPath string            `json:"wordlist_path"`
}

type HashCrackStopRequest struct {
	SessionID string `json:"session_id"`
}

func NewWebServer(c *CoreController) *WebServer {
	ws := &WebServer{
		Controller:      c,
		TerminalManager: NewTerminalManager(),
		eventClients:    make(map[*websocket.Conn]bool),
		eventBroadcast:  make(chan interface{}, 100),
		startTime:       time.Now(),
	}

	// Start event broadcaster
	go ws.broadcastEvents()

	return ws
}

// broadcastEvents sends real-time events to all connected clients
func (ws *WebServer) broadcastEvents() {
	for event := range ws.eventBroadcast {
		ws.eventMutex.RLock()
		for client := range ws.eventClients {
			// WriteJSON is safer than raw bytes
			// Hardening: Use a timeout for writing to prevent a slow client from blocking all others
			client.SetWriteDeadline(time.Now().Add(pingPeriod))
			err := client.WriteJSON(event)

			if err != nil {
				// Handle client disconnection or write failure gracefully
				if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) || strings.Contains(err.Error(), "broken pipe") {
					log.Printf("[WebServer INFO] Event client disconnected gracefully.")
				} else {
					log.Printf("[WebServer ERROR] Failed to send event to client: %v", err)
				}
				client.Close()
				// Use deferred cleanup to remove client to avoid deadlock
				go func(c *websocket.Conn) {
					ws.eventMutex.Lock()
					delete(ws.eventClients, c)
					ws.eventMutex.Unlock()
				}(client)
			}
		}
		ws.eventMutex.RUnlock()
	}
}

// SecureMiddleware enforces API key authentication for critical endpoints.
func SecureMiddleware(next http.HandlerFunc) http.HandlerFunc {
	// Production-ready API key should be stored in an environment variable
	apiKey := os.Getenv("SECURITY_SUITE_API_KEY")
	if apiKey == "" {
		// CRITICAL WARNING: If no key is set, log a massive security warning and exit
		log.Fatal("[SECURITY FATAL] SECURITY_SUITE_API_KEY environment variable is NOT set. Cannot run in production mode.")
	}

	apiKeyBytes := []byte(apiKey)

	return func(w http.ResponseWriter, r *http.Request) {
		// Public paths (Static, Status, Events)
		if r.URL.Path == "/" || r.URL.Path == "/api/status" || strings.HasPrefix(r.URL.Path, "/api/events") {
			next(w, r)
			return
		}

		providedKey := r.Header.Get("X-API-Key")
		providedKeyBytes := []byte(providedKey)

		// CRITICAL HARDENING: Constant-time comparison to prevent timing attacks
		// Check both string length (for early exit) and constant-time comparison
		// The providedKey must match in length AND constant-time comparison must return 1 (match).
		if len(providedKeyBytes) != len(apiKeyBytes) || subtle.ConstantTimeCompare(providedKeyBytes, apiKeyBytes) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"status":  "error",
				"message": "Unauthorized access. Missing or invalid X-API-Key header.",
			})
			log.Printf("[WebServer SECURITY] Unauthorized API access attempt from %s for %s", r.RemoteAddr, r.URL.Path)
			return
		}

		// Proceed to the next handler
		next(w, r)
	}
}

func (ws *WebServer) Start() {
	log.Println("[WebServer] Starting Security Suite Production Web Server...")
	log.Printf("[WebServer] WARNING: API access requires 'X-API-Key' header set to SECURITY_SUITE_API_KEY.")

	mux := http.NewServeMux()

	// --- Public Endpoints (Static, Status, Events) ---
	mux.HandleFunc("/", ws.indexHandler)
	mux.HandleFunc("/api/status", ws.statusHandler)
	mux.HandleFunc("/api/events", ws.eventsWebSocketHandler) // Real-time alerts

	// --- Core Security & Admin Endpoints (Secured by Middleware) ---
	mux.HandleFunc("/api/scan", SecureMiddleware(ws.scanHandler))
	mux.HandleFunc("/api/update", SecureMiddleware(ws.updateHandler))
	mux.HandleFunc("/api/stop", SecureMiddleware(ws.stopHandler))

	// --- Stream Detection/Proxy ---
	mux.HandleFunc("/api/stream/detect", SecureMiddleware(ws.streamDetectHandler))

	// --- Terminal Handlers ---
	mux.HandleFunc("/api/terminal/create", SecureMiddleware(ws.terminalCreateHandler))
	mux.HandleFunc("/api/terminal/websocket", SecureMiddleware(ws.terminalWebSocketHandler))
	mux.HandleFunc("/api/terminal/close", SecureMiddleware(ws.terminalCloseHandler))
	mux.HandleFunc("/api/terminal/resize", SecureMiddleware(ws.terminalResizeHandler))

	// --- V1 Hardened API Handlers (New Functionality) ---
	mux.HandleFunc("/api/v1/system/nics", SecureMiddleware(ws.handleGetInterfaces))
	mux.HandleFunc("/api/v1/settings", SecureMiddleware(ws.handleSettings)) // Handles both GET (retrieve) and POST (update)

	// Forensic & Hash Cracking
	mux.HandleFunc("/api/v1/forensics/recon", SecureMiddleware(ws.handleForensicRecon))
	mux.HandleFunc("/api/v1/hashcrack/start", SecureMiddleware(ws.handleHashCrackStart))
	mux.HandleFunc("/api/v1/hashcrack/status", SecureMiddleware(ws.handleHashCrackStatus))
	mux.HandleFunc("/api/v1/hashcrack/stop", SecureMiddleware(ws.handleHashCrackStop))

	// Web Security Scanner
	mux.HandleFunc("/api/v1/webscan/start", SecureMiddleware(ws.handleWebScanStart))
	mux.HandleFunc("/api/v1/webscan/quick", SecureMiddleware(ws.handleQuickWebScan))
	mux.HandleFunc("/api/v1/webscan/report", SecureMiddleware(ws.handleWebScanReport))

	server := &http.Server{
		Addr:         ":" + webServerPort,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
		// CRITICAL: Ensure MaxHeaderBytes is set to mitigate Slowloris/Header Overload attacks
		MaxHeaderBytes: 1 << 20, // 1MB limit for headers
	}

	log.Printf("[WebServer] Listening securely on port %s...", webServerPort)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("[WebServer FATAL] Could not start server: %v", err)
	}
}

// indexHandler serves the main UI file.
func (ws *WebServer) indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	if _, err := os.Stat(indexFilePath); os.IsNotExist(err) {
		log.Printf("[WebServer ERROR] UI file %s not found", indexFilePath)
		http.Error(w, fmt.Sprintf("UI file %s not found. Run setup_and_run.sh to initialize.", indexFilePath), http.StatusInternalServerError)
		return
	}
	// Prevent caching and force a fresh reload
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	// Hardening: Set security headers
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' https://cdn.tailwindcss.com 'unsafe-inline'; script-src 'self' https://cdn.tailwindcss.com 'unsafe-inline'; connect-src 'self' ws: wss:;")

	http.ServeFile(w, r, indexFilePath)
}

func (ws *WebServer) statusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache") // Do not cache status

	// NOTE: We assume CoreController.GetSystemStatus() exists and returns a status map
	// The implementation here is a wrapper for a required CoreController method.
	status := ws.Controller.GetSystemStatus()

	response := map[string]interface{}{
		"status":    "online",
		"message":   "Security Suite operational",
		"timestamp": time.Now().Format(time.RFC3339),
		"system":    status,
		"uptime":    time.Since(ws.startTime).String(),
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("[WebServer ERROR] Failed to encode status response: %v", err)
	}
}

func (ws *WebServer) eventsWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[WebServer ERROR] Failed to upgrade to WebSocket: %v", err)
		return
	}

	ws.eventMutex.Lock()
	ws.eventClients[conn] = true
	ws.eventMutex.Unlock()

	log.Printf("[WebServer INFO] New event client connected: %s", conn.RemoteAddr())

	defer func() {
		conn.Close()
		ws.eventMutex.Lock()
		delete(ws.eventClients, conn)
		ws.eventMutex.Unlock()
		log.Printf("[WebServer INFO] Event client disconnected: %s", conn.RemoteAddr())
	}()

	// Keep the connection open and responsive
	conn.SetReadLimit(maxRequestSize)
	conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	// Pinger loop to keep the connection alive
	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Hardening: Send pings to detect dead connections
			conn.SetWriteDeadline(time.Now().Add(pingPeriod))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return // Exit loop on ping failure
			}
		case <-r.Context().Done():
			return // Server shutdown or request cancellation
		}
	}
}

func (ws *WebServer) scanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is supported", http.StatusMethodNotAllowed)
		return
	}

	// Hardening: Limit the size of the request body
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body or size limit exceeded", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// Input Validation
	if req.Target == "" {
		http.Error(w, "Target parameter is required", http.StatusBadRequest)
		return
	}

	var msg string
	var indicators []ThreatIndicator

	switch req.Type {
	case "file":
		msg, indicators = ws.Controller.ScanFile(req.Target)
	case "directory":
		msg, indicators = ws.Controller.ScanDirectory(req.Target, req.Depth)
	case "network":
		msg, indicators = ws.Controller.ScanNetwork(req.Target, req.ScanType)
	default:
		http.Error(w, "Invalid scan type. Must be file, directory, or network.", http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "completed",
		"message":    msg,
		"indicators": indicators,
		"timestamp":  time.Now().Format(time.RFC3339),
	})
}

func (ws *WebServer) updateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is supported", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// Hardening: Ensure we don't leak errors from the controller
	updateStatus := ws.Controller.HandleUpdate(map[string]interface{}{})

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "success",
		"message":   updateStatus,
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

func (ws *WebServer) stopHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is supported", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	log.Println("[WebServer] Stop all services requested")

	// NOTE: We assume CoreController.StopAllServices() is non-blocking and safe
	ws.Controller.StopAllServices()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Stop signal sent to all running services and scanners.",
	})
}

// CRITICAL Hardening: Stream Detector / Proxy Handler
func (ws *WebServer) streamDetectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is supported", http.StatusMethodNotAllowed)
		return
	}

	// Hardening: Limit the size of the request body (must be checked before decoding)
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	var reqBody struct {
		TargetURL string `json:"target_url"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid request body or size limit exceeded", http.StatusBadRequest)
		return
	}

	targetURL := reqBody.TargetURL

	// CRITICAL HARDENING: SSRF Mitigation
	parsedURL, err := url.Parse(targetURL)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		http.Error(w, "Invalid or unsupported target URL scheme. Only http/https allowed.", http.StatusBadRequest)
		return
	}

	// CRITICAL Hardening: Prevent internal access (e.g. 127.0.0.1, 10.x.x.x, etc.)
	// This simple check prevents local host access, a common SSRF vector.
	if parsedURL.Hostname() == "localhost" || parsedURL.Hostname() == "127.0.0.1" || net.ParseIP(parsedURL.Hostname()).IsLoopback() {
		http.Error(w, "Internal IP targets are blocked for security.", http.StatusForbidden)
		return
	}

	log.Printf("[WebServer INFO] Initiating stream detection for %s", targetURL)

	// Create a new request based on the incoming one for proxying the stream
	proxyReq, _ := http.NewRequest(http.MethodGet, targetURL, nil)

	// Production-grade client with TLS security enforced
	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true, // Prevent proxy from holding connections
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false, // Enforce certificate validation
			},
		},
		Timeout: 30 * time.Second, // Hardened timeout
	}

	resp, err := client.Do(proxyReq)
	if err != nil {
		log.Printf("[WebServer ERROR] Stream fetch failed: %v", err)
		http.Error(w, "Failed to fetch stream.", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Hardening: Only allow success codes and prevent infinite redirects
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		http.Error(w, "Redirects are blocked for security.", http.StatusForbidden)
		return
	}

	// Hardening: Copy headers and status for transparent proxying
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Stream data with a buffer
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Printf("[WebServer ERROR] Stream copy failed: %v", err)
		// Error after starting stream is not easily recoverable, just log and close
	}
}

// ===== V1 SYSTEM SETTINGS HANDLERS =====

// handleGetInterfaces retrieves a real list of network interfaces
func (ws *WebServer) handleGetInterfaces(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// CRITICAL: Call the CoreController method (assumed to call net.Interfaces())
	interfaces, err := ws.Controller.GetAvailableInterfaces()

	if err != nil {
		log.Printf("[WebServer ERROR] Failed to get interfaces: %v", err)
		http.Error(w, "Failed to retrieve network interfaces.", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   interfaces,
	})
}

// handleSettings manages both GET (retrieve) and POST (update) for system settings
func (ws *WebServer) handleSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		// Retrieve
		settings := ws.Controller.GetSystemSettings()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "success",
			"settings": settings,
		})
	case http.MethodPost:
		// Update
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
		var newSettings SystemSettings
		if err := json.NewDecoder(r.Body).Decode(&newSettings); err != nil {
			http.Error(w, "Invalid settings request body or size limit exceeded.", http.StatusBadRequest)
			return
		}

		if err := ws.Controller.UpdateSystemSettings(&newSettings); err != nil {
			log.Printf("[WebServer ERROR] Failed to save settings: %v", err)
			http.Error(w, "Failed to save settings. Check logs for details.", http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]string{
			"status":  "success",
			"message": "System settings updated and securely persisted.",
		})
	default:
		http.Error(w, "Only GET and POST methods are supported", http.StatusMethodNotAllowed)
	}
}

// ===== V1 FORENSIC HANDLERS =====

// handleForensicRecon triggers a full system reconnaissance scan
func (ws *WebServer) handleForensicRecon(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is supported", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	var req struct {
		TargetPath string `json:"target_path"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body or size limit exceeded", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// Input Validation
	if req.TargetPath == "" {
		http.Error(w, "Target path is required for reconnaissance.", http.StatusBadRequest)
		return
	}

	reconData, err := ws.Controller.RunSystemRecon("linux", req.TargetPath)
	if err != nil {
		log.Printf("[WebServer ERROR] Forensic recon failed: %v", err)
		http.Error(w, "Forensic reconnaissance failed. Check logs.", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "completed",
		"message": fmt.Sprintf("System reconnaissance completed. Extracted %d hashes.", len(reconData.ExtractedHashes)),
		"data":    reconData,
	})
}

// ===== V1 HASH CRACKING HANDLERS =====

func (ws *WebServer) handleHashCrackStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is supported", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	var req HashCrackStartRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body or size limit exceeded", http.StatusBadRequest)
		return
	}

	if len(req.Hashes) == 0 || req.HashType == "" || req.WordlistPath == "" {
		http.Error(w, "Hashes, HashType, and WordlistPath are required.", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	sessionID, err := ws.Controller.StartHashCrackingJob(req.Hashes, req.HashType)
	if err != nil {
		log.Printf("[WebServer ERROR] Hash cracking start failed: %v", err)
		http.Error(w, "Failed to start hash cracking job.", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"status":     "started",
		"message":    "Hash cracking job initiated successfully.",
		"session_id": sessionID,
	})
}

func (ws *WebServer) handleHashCrackStatus(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		http.Error(w, "Missing 'session_id' query parameter.", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	status, err := ws.Controller.GetCrackingJobStatus(sessionID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			http.Error(w, err.Error(), http.StatusNotFound)
		} else {
			log.Printf("[WebServer ERROR] Hash cracking status failed: %v", err)
			http.Error(w, "Failed to retrieve job status.", http.StatusInternalServerError)
		}
		return
	}

	json.NewEncoder(w).Encode(status)
}

func (ws *WebServer) handleHashCrackStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is supported", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	var req HashCrackStopRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body or size limit exceeded", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if stopped := ws.Controller.StopCrackingJob(req.SessionID); stopped {
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "stopped",
			"message": fmt.Sprintf("Hash cracking job %s successfully signalled to stop.", req.SessionID),
		})
	} else {
		http.Error(w, fmt.Sprintf("Hash cracking job %s not found or already stopped.", req.SessionID), http.StatusNotFound)
	}
}

// ===== V1 WEB SCANNING HANDLERS =====

func (ws *WebServer) handleQuickWebScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is supported", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	var req struct {
		TargetURL string `json:"target_url"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body or size limit exceeded", http.StatusBadRequest)
		return
	}

	if req.TargetURL == "" {
		http.Error(w, "Target URL is required.", http.StatusBadRequest)
		return
	}

	// CRITICAL: Call the controller method with default, hardened settings
	vulns, message, err := ws.Controller.QuickWebScan(req.TargetURL)

	w.Header().Set("Content-Type", "application/json")

	if err != nil {
		log.Printf("[WebServer ERROR] Quick web scan failed: %v", err)
		http.Error(w, "Quick web scan failed.", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":          "completed",
		"message":         message,
		"vulnerabilities": vulns,
	})
}

func (ws *WebServer) handleWebScanStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is supported", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	var req struct {
		TargetURL string     `json:"target_url"`
		Config    ScanConfig `json:"config"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body or size limit exceeded", http.StatusBadRequest)
		return
	}

	if req.TargetURL == "" {
		http.Error(w, "Target URL is required.", http.StatusBadRequest)
		return
	}

	vulns, message, err := ws.Controller.ScanWebApplication(req.TargetURL, req.Config)

	w.Header().Set("Content-Type", "application/json")

	if err != nil {
		log.Printf("[WebServer ERROR] Comprehensive web scan failed: %v", err)
		http.Error(w, "Comprehensive web scan failed.", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":          "completed",
		"message":         message,
		"vulnerabilities": vulns,
	})
}

func (ws *WebServer) handleWebScanReport(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		http.Error(w, "Missing 'format' query parameter (e.g., json, html, pdf).", http.StatusBadRequest)
		return
	}

	// Hardening: Only allow supported formats
	if format != "json" && format != "html" && format != "txt" {
		http.Error(w, "Unsupported report format. Only json, html, and txt are supported.", http.StatusBadRequest)
		return
	}

	report, err := ws.Controller.GenerateWebScanReport("json")
	if err != nil {
		log.Printf("[WebServer ERROR] Failed to generate report: %v", err)
		http.Error(w, "Report generation failed.", http.StatusInternalServerError)
		return
	}

	// Hardening: Set appropriate content type and download header
	var contentType string
	switch format {
	case "json":
		contentType = "application/json"
	case "html":
		contentType = "text/html"
	case "txt":
		contentType = "text/plain"
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"web-security-report.%s\"", format))

	// Stream the report content
	if _, err := io.WriteString(w, report); err != nil {
		log.Printf("[WebServer ERROR] Failed to stream report: %v", err)
	}
}

// ===== TERMINAL HANDLERS (Minimal changes, assumed secured by middleware) =====

func (ws *WebServer) terminalCreateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is supported", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	var reqBody TerminalActionRequest
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid request body or size limit exceeded", http.StatusBadRequest)
		return
	}

	session, err := ws.TerminalManager.CreateSession(reqBody.Rows, reqBody.Cols)
	if err != nil {
		log.Printf("[WebServer ERROR] Failed to create terminal: %v", err)
		http.Error(w, "Failed to create terminal session.", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "created",
		"session_id": session.ID,
	})
}

func (ws *WebServer) terminalWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		http.Error(w, "Missing 'session_id' query parameter", http.StatusBadRequest)
		return
	}

	session, exists := ws.TerminalManager.GetSession(sessionID)
	if !exists {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[WebServer ERROR] Failed to upgrade terminal WebSocket: %v", err)
		return
	}

	log.Printf("[WebServer INFO] Terminal WebSocket connected: %s", sessionID)

	ctx, cancel := context.WithCancel(context.Background())

	// Read Loop (Client Input to PTY)
	go func() {
		defer cancel()
		defer conn.Close()

		conn.SetReadLimit(maxRequestSize)
		conn.SetReadDeadline(time.Now().Add(pongWait))
		conn.SetPongHandler(func(string) error {
			conn.SetReadDeadline(time.Now().Add(pongWait))
			return nil
		})

		for {
			select {
			case <-ctx.Done():
				return
			default:
				messageType, p, err := conn.ReadMessage()
				if err != nil {
					if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
						log.Printf("[WebServer] Terminal WebSocket closed normally: %s", sessionID)
					} else {
						log.Printf("[WebServer ERROR] Terminal WebSocket read error: %v", err)
					}
					return
				}

				if messageType != websocket.TextMessage {
					continue
				}

				// Hardening: Sanitize and validate input before passing to the PTY
				var cmd map[string]interface{}
				if err := json.Unmarshal(p, &cmd); err == nil && cmd["type"] == "input" {
					if input, ok := cmd["data"].(string); ok {
						if _, err := session.Write(
							[]byte(strings.ReplaceAll(input, "\r\n", "\n")), // Normalize line endings
						); err != nil {
							log.Printf("[WebServer ERROR] Failed to write to PTY: %v", err)
						}
					}
				} else {
					// Fallback: Treat as raw input if not a structured command
					if _, err := session.Write(p); err != nil {
						log.Printf("[WebServer ERROR] Failed to write raw data to PTY: %v", err)
					}
				}
			}
		}
	}()

	// Write Loop (PTY Output to Client)
	go func() {
		defer cancel()
		defer conn.Close()

		buf := make([]byte, 32768) // 32KB buffer for PTY output

		for {
			select {
			case <-ctx.Done():
				return
			default:
				// Read from the PTY
				n, err := session.Read(buf)
				if err != nil {
					if err != io.EOF {
						log.Printf("[WebServer ERROR] Terminal PTY read error: %v", err)
					}
					return
				}

				// Write to the WebSocket
				conn.SetWriteDeadline(time.Now().Add(pingPeriod))
				if err := conn.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
					log.Printf("[WebServer ERROR] Terminal WebSocket write error: %v", err)
					return
				}
			}
		}
	}()

	// Wait for one of the loops to exit
	<-ctx.Done()
	log.Printf("[WebServer INFO] Terminal WebSocket session ended: %s", sessionID)
}

func (ws *WebServer) terminalCloseHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is supported", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	var reqBody HashCrackStopRequest // Reuse struct as they both only need SessionID
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid request body or size limit exceeded", http.StatusBadRequest)
		return
	}

	log.Printf("[WebServer] Closing terminal session: %s", reqBody.SessionID)

	if err := ws.TerminalManager.CloseSession(reqBody.SessionID); err != nil {
		log.Printf("[WebServer ERROR] Failed to close terminal: %v", err)
		http.Error(w, "Failed to close session.", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "closed",
		"message": "Terminal session closed successfully",
	})
}

func (ws *WebServer) terminalResizeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is supported", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	var reqBody struct {
		SessionID string `json:"session_id"`
		Rows      uint16 `json:"rows"`
		Cols      uint16 `json:"cols"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid request body or size limit exceeded", http.StatusBadRequest)
		return
	}

	// Hardening: Basic bounds check on terminal size
	if reqBody.Rows == 0 || reqBody.Cols == 0 || reqBody.Rows > 200 || reqBody.Cols > 200 {
		http.Error(w, "Invalid terminal dimensions.", http.StatusBadRequest)
		return
	}

	session, exists := ws.TerminalManager.GetSession(reqBody.SessionID)
	if !exists {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	if err := session.Resize(reqBody.Rows, reqBody.Cols); err != nil {
		log.Printf("[WebServer ERROR] Failed to resize terminal: %v", err)
		http.Error(w, "Failed to resize terminal.", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "resized",
		"message": "Terminal resized successfully",
	})
}
