package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings" // Added for robust password prompt detection
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
)

// TerminalSession represents a fully interactive PTY terminal session
type TerminalSession struct {
	ID           string
	PTY          *os.File
	Command      *exec.Cmd
	InputChan    chan string
	OutputChan   chan string
	Active       bool
	mu           sync.Mutex
	lastActivity time.Time
	rows         uint16
	cols         uint16
}

// TerminalManager manages multiple concurrent terminal sessions
type TerminalManager struct {
	sessions      map[string]*TerminalSession
	mu            sync.RWMutex
	cleanupTicker *time.Ticker
	stopCleanup   chan struct{}
}

// NewTerminalManager creates a production-ready terminal manager
func NewTerminalManager() *TerminalManager {
	tm := &TerminalManager{
		sessions:    make(map[string]*TerminalSession),
		stopCleanup: make(chan struct{}),
	}

	// Start session cleanup goroutine to prevent resource leaks
	go tm.cleanupInactiveSessions()

	log.Println("[TerminalManager] Initialized with automatic session cleanup")
	return tm
}

// CreateSession creates a new fully interactive bash terminal session
func (tm *TerminalManager) CreateSession(rows, cols uint16) (*TerminalSession, error) {
	sessionID := fmt.Sprintf("term_%d", time.Now().UnixNano())

	log.Printf("[TerminalManager] Creating session: %s", sessionID)

	// Create bash command with proper environment
	cmd := exec.Command("/bin/bash")

	// Set environment variables for proper terminal color and prompt (UX enhancement)
	cmd.Env = append(os.Environ(),
		"TERM=xterm-256color",
		"COLORTERM=truecolor",
		// Custom PS1 for clear separation from application logs
		"PS1=\\[\\033[01;32m\\]\\u@\\h\\[\\033[00m\\]:\\[\\033[01;34m\\]\\w\\[\\033[00m\\]\\$ ",
	)

	// Start the command with a PTY (pseudo-terminal)
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to start PTY: %v", err)
	}

	// Set initial terminal size (default to 24x80)
	if err := pty.Setsize(ptmx, &pty.Winsize{
		Rows: 24,
		Cols: 80,
	}); err != nil {
		log.Printf("[TerminalManager] Warning: failed to set initial terminal size: %v", err)
	}

	session := &TerminalSession{
		ID:           sessionID,
		PTY:          ptmx,
		Command:      cmd,
		InputChan:    make(chan string, 100),
		OutputChan:   make(chan string, 1000),
		Active:       true,
		lastActivity: time.Now(),
		rows:         24,
		cols:         80,
	}

	// Start concurrent I/O and process monitoring goroutines
	go session.readOutput()
	go session.writeInput()
	go session.monitorProcess()

	tm.mu.Lock()
	tm.sessions[sessionID] = session
	tm.mu.Unlock()

	log.Printf("[TerminalManager] Session created successfully: %s (PID: %d)", sessionID, cmd.Process.Pid)

	return session, nil
}

// GetSession retrieves an active session by ID
func (tm *TerminalManager) GetSession(id string) (*TerminalSession, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	session, exists := tm.sessions[id]
	if !exists {
		return nil, false
	}

	session.mu.Lock()
	active := session.Active
	session.mu.Unlock()

	return session, active
}

// CloseSession gracefully closes and removes a terminal session
func (tm *TerminalManager) CloseSession(id string) error {
	tm.mu.Lock()
	session, exists := tm.sessions[id]
	if !exists {
		tm.mu.Unlock()
		return fmt.Errorf("session not found: %s", id)
	}
	delete(tm.sessions, id)
	tm.mu.Unlock()

	log.Printf("[TerminalManager] Closing session: %s", id)

	return session.Close()
}

// cleanupInactiveSessions removes inactive sessions periodically
func (tm *TerminalManager) cleanupInactiveSessions() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			tm.performCleanup()
		case <-tm.stopCleanup:
			return
		}
	}
}

func (tm *TerminalManager) performCleanup() {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	inactiveThreshold := 30 * time.Minute // Production-ready threshold
	now := time.Now()

	for id, session := range tm.sessions {
		session.mu.Lock()
		if !session.Active || now.Sub(session.lastActivity) > inactiveThreshold {
			session.mu.Unlock()
			log.Printf("[TerminalManager] Cleaning up inactive session: %s", id)
			session.Close()
			delete(tm.sessions, id)
		} else {
			session.mu.Unlock()
		}
	}
}

// StopCleanup stops the cleanup goroutine (called on shutdown)
func (tm *TerminalManager) StopCleanup() {
	close(tm.stopCleanup)
}

// ===== TerminalSession Methods =====

// readOutput continuously reads from PTY and sends to output channel
func (ts *TerminalSession) readOutput() {
	defer func() {
		ts.mu.Lock()
		ts.Active = false
		ts.mu.Unlock()
		close(ts.OutputChan)
		log.Printf("[Terminal %s] Output reader exiting", ts.ID)
	}()

	reader := bufio.NewReader(ts.PTY)
	buf := make([]byte, 4096)

	for {
		ts.mu.Lock()
		active := ts.Active
		ts.mu.Unlock()

		if !active {
			break
		}

		// Set read deadline to allow periodic checks (prevents goroutine lock)
		ts.PTY.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

		n, err := reader.Read(buf)
		if err != nil {
			if err == io.EOF {
				log.Printf("[Terminal %s] PTY closed (EOF)", ts.ID)
				break
			}
			// Handle timeout from SetReadDeadline, which is expected
			if netErr, ok := err.(interface{ Timeout() bool }); ok && netErr.Timeout() {
				continue
			}
			if err != io.ErrClosedPipe {
				log.Printf("[Terminal %s] Read error: %v", ts.ID, err)
			}
			break
		}

		if n > 0 {
			output := string(buf[:n])

			// Send output to channel (with timeout to prevent blocking the reader)
			select {
			case ts.OutputChan <- output:
				ts.mu.Lock()
				ts.lastActivity = time.Now()
				ts.mu.Unlock()
			case <-time.After(1 * time.Second):
				log.Printf("[Terminal %s] Output channel blocked, dropping data", ts.ID)
			}
		}
	}
}

// writeInput continuously writes from input channel to PTY
func (ts *TerminalSession) writeInput() {
	defer log.Printf("[Terminal %s] Input writer exiting", ts.ID)

	for input := range ts.InputChan {
		ts.mu.Lock()
		active := ts.Active
		ts.mu.Unlock()

		if !active {
			break
		}

		// Write input to PTY
		_, err := ts.PTY.Write([]byte(input))
		if err != nil {
			if err != io.ErrClosedPipe {
				log.Printf("[Terminal %s] Write error: %v", ts.ID, err)
			}
			// Mark inactive on write error
			ts.mu.Lock()
			ts.Active = false
			ts.mu.Unlock()
			break
		}

		ts.mu.Lock()
		ts.lastActivity = time.Now()
		ts.mu.Unlock()
	}
}

// monitorProcess monitors the bash process and marks session inactive if it exits
func (ts *TerminalSession) monitorProcess() {
	err := ts.Command.Wait()

	ts.mu.Lock()
	ts.Active = false
	ts.mu.Unlock()

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			log.Printf("[Terminal %s] Process exited with status: %d", ts.ID, exitErr.ExitCode())
		} else {
			log.Printf("[Terminal %s] Process exited: %v", ts.ID, err)
		}
	} else {
		log.Printf("[Terminal %s] Process exited normally", ts.ID)
	}

	// Send exit notification to the client
	select {
	case ts.OutputChan <- fmt.Sprintf("\r\n[Process exited]\r\n"):
	case <-time.After(1 * time.Second):
	}
}

// SendInput sends input to the terminal (thread-safe)
func (ts *TerminalSession) SendInput(input string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if !ts.Active {
		return fmt.Errorf("terminal session is not active")
	}

	select {
	case ts.InputChan <- input:
		return nil
	case <-time.After(5 * time.Second):
		return fmt.Errorf("timeout sending input to terminal")
	}
}

// Resize resizes the terminal window
func (ts *TerminalSession) Resize(rows, cols uint16) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if !ts.Active {
		return fmt.Errorf("terminal session is not active")
	}

	if rows == 0 || cols == 0 {
		return fmt.Errorf("invalid terminal size: %dx%d", rows, cols)
	}

	// Update stored dimensions
	ts.rows = rows
	ts.cols = cols

	// Set PTY window size using the cross-platform library function
	winsize := &pty.Winsize{
		Rows: rows,
		Cols: cols,
	}

	if err := pty.Setsize(ts.PTY, winsize); err != nil {
		return fmt.Errorf("failed to resize PTY: %v", err)
	}

	log.Printf("[Terminal %s] Resized to %dx%d", ts.ID, cols, rows)

	return nil
}

// GetSize returns current terminal dimensions
func (ts *TerminalSession) GetSize() (rows, cols uint16) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.rows, ts.cols
}

// IsActive returns whether the session is currently active
func (ts *TerminalSession) IsActive() bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.Active
}

// Write sends data to the terminal
func (ts *TerminalSession) Write(data []byte) (int, error) {
	return ts.PTY.Write(data)
}

// Read reads data from the terminal
func (ts *TerminalSession) Read(p []byte) (int, error) {
	return ts.PTY.Read(p)
}

// Close gracefully closes the terminal session
func (ts *TerminalSession) Close() error {
	ts.mu.Lock()

	if !ts.Active {
		ts.mu.Unlock()
		return nil
	}

	ts.Active = false
	ts.mu.Unlock()

	log.Printf("[Terminal %s] Closing session...", ts.ID)

	// Close input channel to stop the writeInput goroutine
	close(ts.InputChan)

	// Send SIGTERM to bash process for graceful shutdown
	if ts.Command.Process != nil {
		if err := ts.Command.Process.Signal(syscall.SIGTERM); err != nil {
			log.Printf("[Terminal %s] Failed to send SIGTERM: %v", ts.ID, err)
			// Force kill after short delay if SIGTERM fails
			time.AfterFunc(2*time.Second, func() {
				if ts.Command.Process != nil {
					ts.Command.Process.Kill()
				}
			})
		}
	}

	// Close PTY
	if ts.PTY != nil {
		if err := ts.PTY.Close(); err != nil {
			log.Printf("[Terminal %s] PTY close error: %v", ts.ID, err)
		}
	}

	log.Printf("[Terminal %s] Session closed", ts.ID)

	return nil
}

// ===== Advanced Terminal Features =====

// ExecuteCommand executes a single command and returns output
// Note: This helper uses a generous timeout to ensure completion, but
// is less reliable than a fully interactive session listening for the prompt.
func (tm *TerminalManager) ExecuteCommand(command string) (string, error) {
	session, err := tm.CreateSession(24, 80)
	if err != nil {
		return "", err
	}
	defer tm.CloseSession(session.ID)

	// Send command
	if err := session.SendInput(command + "\n"); err != nil {
		return "", err
	}

	// Collect output for up to 30 seconds
	output := ""
	timeout := time.After(30 * time.Second)

	for {
		select {
		case data, ok := <-session.OutputChan:
			if !ok {
				return output, nil
			}
			output += data
		case <-timeout:
			return output, fmt.Errorf("command execution timeout")
		}
	}
}

// ExecuteCommandWithSudo executes a command with sudo, robustly handling the interactive password prompt
func (tm *TerminalManager) ExecuteCommandWithSudo(command, password string) (*TerminalSession, error) {
	session, err := tm.CreateSession(24, 80)
	if err != nil {
		return nil, err
	}

	// Send sudo command
	if err := session.SendInput(fmt.Sprintf("sudo %s\n", command)); err != nil {
		session.Close()
		return nil, err
	}

	// Robustly wait for the password prompt
	promptTimer := time.NewTimer(500 * time.Millisecond)
	defer promptTimer.Stop()
	promptFound := false

	for !promptFound {
		select {
		case data, ok := <-session.OutputChan:
			if !ok {
				session.Close()
				return nil, fmt.Errorf("session closed while waiting for sudo prompt")
			}
			// Look for common sudo password prompt string
			if strings.Contains(data, "[sudo] password for") {
				promptFound = true
				break
			}
		case <-promptTimer.C:
			// If timeout, break and proceed to send password anyway (may not be required or prompt missed)
			break
		}
	}

	// Send password if provided
	if password != "" {
		if err := session.SendInput(password + "\n"); err != nil {
			session.Close()
			return nil, err
		}
	}

	return session, nil
}

// GetSessionCount returns the number of active sessions
func (tm *TerminalManager) GetSessionCount() int {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return len(tm.sessions)
}

// CloseAllSessions closes all active terminal sessions
func (tm *TerminalManager) CloseAllSessions() {
	tm.mu.Lock()
	sessions := make([]*TerminalSession, 0, len(tm.sessions))
	for _, session := range tm.sessions {
		sessions = append(sessions, session)
	}
	// Clear the map before unlocking, relying on the local slice to close them
	tm.sessions = make(map[string]*TerminalSession)
	tm.mu.Unlock()

	log.Printf("[TerminalManager] Closing all %d sessions", len(sessions))

	for _, session := range sessions {
		session.Close()
	}
}
