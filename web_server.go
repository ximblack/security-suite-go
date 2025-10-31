package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/websocket"
)

const (
	webServerPort = "8080"
	indexFilePath = "index.html"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins for development
	},
}

type WebServer struct {
	Controller      *CoreController
	TerminalManager *TerminalManager
}

func NewWebServer(c *CoreController) *WebServer {
	return &WebServer{
		Controller:      c,
		TerminalManager: NewTerminalManager(),
	}
}

func (ws *WebServer) Start() {
	log.Println("Starting Security Suite Go Web Server...")

	if ws.Controller == nil {
		log.Fatal("Fatal: CoreController is nil. Cannot start server.")
	}

	// Setup routes
	http.HandleFunc("/", ws.indexHandler)
	http.HandleFunc("/api/status", ws.statusHandler)
	http.HandleFunc("/api/scan", ws.scanHandler)
	http.HandleFunc("/api/update", ws.updateHandler)
	http.HandleFunc("/api/stop", ws.stopHandler)
	http.HandleFunc("/api/stream/detect", ws.streamDetectHandler)
	http.HandleFunc("/api/stream/proxy", ws.streamProxyHandler)

	// Terminal endpoints
	http.HandleFunc("/api/terminal/create", ws.terminalCreateHandler)
	http.HandleFunc("/api/terminal/ws", ws.terminalWebSocketHandler)
	http.HandleFunc("/api/terminal/close", ws.terminalCloseHandler)

	// Execute command with sudo
	http.HandleFunc("/api/execute/sudo", ws.executeSudoHandler)

	log.Printf("Server listening on http://localhost:%s", webServerPort)
	log.Fatal(http.ListenAndServe(":"+webServerPort, nil))
}

func (ws *WebServer) indexHandler(w http.ResponseWriter, r *http.Request) {
	if _, err := os.Stat(indexFilePath); os.IsNotExist(err) {
		http.Error(w, fmt.Sprintf("UI file %s not found.", indexFilePath), http.StatusInternalServerError)
		return
	}
	http.ServeFile(w, r, indexFilePath)
}

func (ws *WebServer) statusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	status := ws.Controller.GetSystemStatus()

	response := map[string]interface{}{
		"status":    "online",
		"message":   "Go Web Server is operational",
		"timestamp": time.Now().Format(time.RFC3339),
		"system":    status,
	}

	json.NewEncoder(w).Encode(response)
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
		http.Error(w, "Invalid request body format", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	scanResult, err := ws.Controller.ExecuteScan(reqBody.TargetType, reqBody.Target, reqBody.Depth)

	if err != nil {
		log.Printf("[WEB ERROR] Scan execution failed: %v", err)
		errorResponse := map[string]interface{}{
			"status":  "error",
			"message": fmt.Sprintf("Scan failed: %s", err.Error()),
		}
		json.NewEncoder(w).Encode(errorResponse)
		return
	}

	json.NewEncoder(w).Encode(scanResult)
}

func (ws *WebServer) updateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is supported", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	updateStatus, err := ws.Controller.UpdateDefinitions()

	if err != nil {
		log.Printf("[WEB ERROR] Definition update failed: %v", err)
		errorResponse := map[string]interface{}{
			"status":  "error",
			"message": fmt.Sprintf("Update failed: %s", err.Error()),
		}
		json.NewEncoder(w).Encode(errorResponse)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "complete",
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

	ws.Controller.StopAllServices()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "complete",
		"message": "All background security services have been gracefully stopped.",
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

	w.Header().Set("Content-Type", "application/json")

	streamInfo := ws.Controller.StreamDetector.DetectStream(reqBody.URL, reqBody.Port)

	if streamInfo == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "not_found",
			"message": "No stream detected at the specified location",
		})
		return
	}

	json.NewEncoder(w).Encode(streamInfo)
}

func (ws *WebServer) streamProxyHandler(w http.ResponseWriter, r *http.Request) {
	streamURL := r.URL.Query().Get("url")
	if streamURL == "" {
		http.Error(w, "Missing 'url' query parameter", http.StatusBadRequest)
		return
	}

	streamInfo := ws.Controller.StreamDetector.DetectStream(streamURL, 0)
	if streamInfo == nil || streamInfo.Status != "active" {
		http.Error(w, "Invalid or inactive stream URL", http.StatusBadRequest)
		return
	}

	resp, err := http.Get(streamURL)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch stream: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(resp.StatusCode)

	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			w.Write(buf[:n])
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
		if err != nil {
			break
		}
	}
}

// terminalCreateHandler creates a new terminal session
func (ws *WebServer) terminalCreateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is supported", http.StatusMethodNotAllowed)
		return
	}

	session, err := ws.TerminalManager.CreateSession()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create terminal: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"session_id": session.ID,
		"status":     "created",
	})
}

// terminalWebSocketHandler handles WebSocket connections for terminal I/O
func (ws *WebServer) terminalWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		http.Error(w, "Missing session_id parameter", http.StatusBadRequest)
		return
	}

	session, exists := ws.TerminalManager.GetSession(sessionID)
	if !exists {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	// Goroutine to read from terminal and send to WebSocket
	go func() {
		for output := range session.OutputChan {
			err := conn.WriteMessage(websocket.TextMessage, []byte(output))
			if err != nil {
				log.Printf("WebSocket write error: %v", err)
				return
			}
		}
	}()

	// Read from WebSocket and send to terminal
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				log.Printf("WebSocket closed normally")
			} else {
				log.Printf("WebSocket read error: %v", err)
			}
			break
		}

		// Handle special commands
		var cmd map[string]interface{}
		if err := json.Unmarshal(message, &cmd); err == nil {
			if cmdType, ok := cmd["type"].(string); ok {
				switch cmdType {
				case "resize":
					if rows, ok := cmd["rows"].(float64); ok {
						if cols, ok := cmd["cols"].(float64); ok {
							session.Resize(uint16(rows), uint16(cols))
							continue
						}
					}
				case "input":
					if input, ok := cmd["data"].(string); ok {
						session.SendInput(input)
						continue
					}
				}
			}
		}

		// If not a special command, treat as raw input
		session.SendInput(string(message))
	}
}

// terminalCloseHandler closes a terminal session
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

	err := ws.TerminalManager.CloseSession(reqBody.SessionID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to close session: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "closed",
		"message": "Terminal session closed successfully",
	})
}

// executeSudoHandler executes a command with sudo prompt handling
func (ws *WebServer) executeSudoHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is supported", http.StatusMethodNotAllowed)
		return
	}

	var reqBody struct {
		Command string `json:"command"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	session, err := ws.TerminalManager.ExecuteCommandWithSudo(reqBody.Command)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to execute command: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"session_id": session.ID,
		"status":     "executing",
		"message":    "Command sent. Check terminal for sudo prompt.",
	})
}
