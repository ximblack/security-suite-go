// web_server_prod.go
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	webServerPort = "8080"
	indexFilePath = "index.html"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool {
		// WARNING: This must be restricted to known origins in a real production environment (e.g., config-driven CORS).
		return true
	},
}

type WebServer struct {
	Controller      *CoreController
	TerminalManager *TerminalManager
	eventClients    map[*websocket.Conn]bool
	eventMutex      sync.RWMutex
	eventBroadcast  chan interface{}
	startTime       time.Time // Added for production-ready uptime calculation
}

func NewWebServer(c *CoreController) *WebServer {
	ws := &WebServer{
		Controller:      c,
		TerminalManager: NewTerminalManager(),
		eventClients:    make(map[*websocket.Conn]bool),
		eventBroadcast:  make(chan interface{}, 100),
		startTime:       time.Now(), // Record server start time
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
			err := client.WriteJSON(event)
			if err != nil {
				log.Printf("[WebServer] Failed to send event to client: %v", err)
				client.Close()
				delete(ws.eventClients, client)
			}
		}
		ws.eventMutex.RUnlock()
	}
}

func (ws *WebServer) Start() {
	log.Println("[WebServer] Starting Security Suite Production Web Server...")

	if ws.Controller == nil {
		log.Fatal("[WebServer FATAL] CoreController is nil. Cannot start server.")
	}

	// Static file serving
	http.HandleFunc("/", ws.indexHandler)

	// API endpoints
	http.HandleFunc("/api/status", ws.statusHandler)
	http.HandleFunc("/api/scan", ws.scanHandler)
	http.HandleFunc("/api/update", ws.updateHandler)
	http.HandleFunc("/api/stop", ws.stopHandler)
	http.HandleFunc("/api/stream/detect", ws.streamDetectHandler)
	http.HandleFunc("/api/stream/proxy", ws.streamProxyHandler)

	// Real-time events WebSocket
	http.HandleFunc("/api/events", ws.eventsWebSocketHandler)

	// Terminal endpoints - PRODUCTION READY
	http.HandleFunc("/api/terminal/create", ws.terminalCreateHandler)
	http.HandleFunc("/api/terminal/ws", ws.terminalWebSocketHandler)
	http.HandleFunc("/api/terminal/close", ws.terminalCloseHandler)
	http.HandleFunc("/api/terminal/resize", ws.terminalResizeHandler)

	log.Printf("[WebServer] Server listening on http://localhost:%s", webServerPort)
	log.Printf("[WebServer] Access the Security Suite at: http://localhost:%s", webServerPort)

	if err := http.ListenAndServe(":"+webServerPort, nil); err != nil {
		log.Fatalf("[WebServer FATAL] Server failed to start: %v", err)
	}
}

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

	http.ServeFile(w, r, indexFilePath)
}

func (ws *WebServer) statusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")

	status := ws.Controller.GetSystemStatus()

	response := map[string]interface{}{
		"status":    "online",
		"message":   "Security Suite operational",
		"timestamp": time.Now().Format(time.RFC3339),
		"system":    status,
		"uptime":    time.Since(ws.startTime).String(), // Real uptime calculation
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("[WebServer ERROR] Failed to encode status response: %v", err)
	}
}

func (ws *WebServer) scanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is supported", http.StatusMethodNotAllowed)
		return
	}

	var reqBody struct {
		TargetType string `json:"target_type"`
		Target     string `json:"target"`
		Depth      int    `json:"depth"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		log.Printf("[WebServer ERROR] Invalid scan request: %v", err)
		http.Error(w, "Invalid request body format", http.StatusBadRequest)
		return
	}

	log.Printf("[WebServer] Scan request: type=%s, target=%s, depth=%d",
		reqBody.TargetType, reqBody.Target, reqBody.Depth)

	w.Header().Set("Content-Type", "application/json")

	// Execute scan asynchronously and stream results
	go func() {
		scanResult, err := ws.Controller.ExecuteScan(reqBody.TargetType, reqBody.Target, reqBody.Depth)

		event := map[string]interface{}{
			"type":      "scan_complete",
			"timestamp": time.Now().Format(time.RFC3339),
		}

		if err != nil {
			log.Printf("[WebServer ERROR] Scan execution failed: %v", err)
			event["status"] = "error"
			event["message"] = err.Error()
		} else {
			event["status"] = "success"
			event["data"] = scanResult
			log.Printf("[WebServer] Scan completed successfully: %s", scanResult["message"])
		}

		// Broadcast to all connected clients
		ws.eventBroadcast <- event
	}()

	// Immediate response
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "started",
		"message": "Scan initiated. Results will be streamed via WebSocket.",
	})
}

func (ws *WebServer) updateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is supported", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	log.Println("[WebServer] Definition update requested")

	updateStatus, err := ws.Controller.UpdateDefinitions()

	if err != nil {
		log.Printf("[WebServer ERROR] Definition update failed: %v", err)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}

	log.Printf("[WebServer] Definition update successful: %s", updateStatus)

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

	message := ws.Controller.StopAllScanners()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": message,
	})
}

func (ws *WebServer) streamDetectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is supported", http.StatusMethodNotAllowed)
		return
	}

	var reqBody struct {
		URL  string `json:"url"`
		Port int    `json:"port"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	log.Printf("[WebServer] Stream detection requested: url=%s, port=%d", reqBody.URL, reqBody.Port)

	w.Header().Set("Content-Type", "application/json")

	streamInfo := ws.Controller.StreamDetector.DetectStream(reqBody.URL, reqBody.Port)

	if streamInfo == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "not_found",
			"message": "No stream detected at specified location",
		})
		return
	}

	log.Printf("[WebServer] Stream detected: %s", streamInfo.URL)
	json.NewEncoder(w).Encode(streamInfo)
}

func (ws *WebServer) streamProxyHandler(w http.ResponseWriter, r *http.Request) {
	streamURL := r.URL.Query().Get("url")
	if streamURL == "" {
		http.Error(w, "Missing 'url' query parameter", http.StatusBadRequest)
		return
	}

	log.Printf("[WebServer] Stream proxy requested: %s", streamURL)

	streamInfo := ws.Controller.StreamDetector.DetectStream(streamURL, 0)
	if streamInfo == nil || streamInfo.Status != "active" {
		http.Error(w, "Invalid or inactive stream URL", http.StatusBadRequest)
		return
	}

	// Proxy the stream
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(streamURL)
	if err != nil {
		log.Printf("[WebServer ERROR] Stream fetch failed: %v", err)
		http.Error(w, fmt.Sprintf("Failed to fetch stream: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Copy headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(resp.StatusCode)

	// Stream data
	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, writeErr := w.Write(buf[:n]); writeErr != nil {
				log.Printf("[WebServer ERROR] Stream write failed: %v", writeErr)
				break
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
		if err != nil {
			break
		}
	}
}

// eventsWebSocketHandler handles real-time event streaming
func (ws *WebServer) eventsWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[WebServer ERROR] WebSocket upgrade failed: %v", err)
		return
	}

	log.Println("[WebServer] New event client connected")

	ws.eventMutex.Lock()
	ws.eventClients[conn] = true
	ws.eventMutex.Unlock()

	defer func() {
		ws.eventMutex.Lock()
		delete(ws.eventClients, conn)
		ws.eventMutex.Unlock()
		conn.Close()
		log.Println("[WebServer] Event client disconnected")
	}()

	// Keep connection alive
	for {
		// Read loop is necessary to detect connection closure
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}
}

// ===== PRODUCTION-READY TERMINAL HANDLERS =====

func (ws *WebServer) terminalCreateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is supported", http.StatusMethodNotAllowed)
		return
	}

	log.Println("[WebServer] Creating new terminal session...")

	session, err := ws.TerminalManager.CreateSession()
	if err != nil {
		log.Printf("[WebServer ERROR] Failed to create terminal: %v", err)
		http.Error(w, fmt.Sprintf("Failed to create terminal: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("[WebServer] Terminal session created: %s", session.ID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"session_id": session.ID,
		"status":     "created",
		"message":    "Terminal session initialized successfully",
	})
}

func (ws *WebServer) terminalWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		http.Error(w, "Missing session_id parameter", http.StatusBadRequest)
		return
	}

	session, exists := ws.TerminalManager.GetSession(sessionID)
	if !exists {
		log.Printf("[WebServer ERROR] Terminal session not found: %s", sessionID)
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[WebServer ERROR] Terminal WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	log.Printf("[WebServer] Terminal WebSocket connected: %s", sessionID)

	// Channel to signal termination
	done := make(chan struct{})

	// Goroutine: Terminal output -> WebSocket
	go func() {
		defer close(done)
		for {
			select {
			case output, ok := <-session.OutputChan:
				if !ok {
					log.Printf("[WebServer] Terminal output channel closed: %s", sessionID)
					return
				}

				if err := conn.WriteMessage(websocket.TextMessage, []byte(output)); err != nil {
					log.Printf("[WebServer ERROR] Terminal WebSocket write error: %v", err)
					return
				}
			case <-done:
				return
			}
		}
	}()

	// Main loop: WebSocket -> Terminal input
	for {
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				log.Printf("[WebServer] Terminal WebSocket closed normally: %s", sessionID)
			} else {
				log.Printf("[WebServer ERROR] Terminal WebSocket read error: %v", err)
			}
			break
		}

		if messageType != websocket.TextMessage {
			continue
		}

		// Try to parse as JSON command
		var cmd map[string]interface{}
		if err := json.Unmarshal(message, &cmd); err == nil {
			if cmdType, ok := cmd["type"].(string); ok {
				switch cmdType {
				case "resize":
					if rows, ok := cmd["rows"].(float64); ok {
						if cols, ok := cmd["cols"].(float64); ok {
							if err := session.Resize(uint16(rows), uint16(cols)); err != nil {
								log.Printf("[WebServer ERROR] Terminal resize failed: %v", err)
							}
							continue
						}
					}
				case "input":
					if input, ok := cmd["data"].(string); ok {
						if err := session.SendInput(input); err != nil {
							log.Printf("[WebServer ERROR] Terminal input send failed: %v", err)
						}
						continue
					}
				}
			}
		}

		// If not JSON or unrecognized command, treat as raw input
		if err := session.SendInput(string(message)); err != nil {
			log.Printf("[WebServer ERROR] Terminal raw input failed: %v", err)
		}
	}

	log.Printf("[WebServer] Terminal WebSocket handler exiting: %s", sessionID)
}

func (ws *WebServer) terminalCloseHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is supported", http.StatusMethodNotAllowed)
		return
	}

	var reqBody struct {
		SessionID string `json:"session_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	log.Printf("[WebServer] Closing terminal session: %s", reqBody.SessionID)

	if err := ws.TerminalManager.CloseSession(reqBody.SessionID); err != nil {
		log.Printf("[WebServer ERROR] Failed to close terminal: %v", err)
		http.Error(w, fmt.Sprintf("Failed to close session: %v", err), http.StatusInternalServerError)
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

	var reqBody struct {
		SessionID string `json:"session_id"`
		Rows      uint16 `json:"rows"`
		Cols      uint16 `json:"cols"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	session, exists := ws.TerminalManager.GetSession(reqBody.SessionID)
	if !exists {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	if err := session.Resize(reqBody.Rows, reqBody.Cols); err != nil {
		http.Error(w, fmt.Sprintf("Resize failed: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "resized",
	})
}
