package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/creack/pty"
)

// TerminalSession represents an interactive terminal session
type TerminalSession struct {
	ID            string
	PTY           *os.File
	Command       *exec.Cmd
	InputChan     chan string
	OutputChan    chan string
	Active        bool
	mu            sync.Mutex
	lastActivity  time.Time
}

// TerminalManager manages multiple terminal sessions
type TerminalManager struct {
	sessions map[string]*TerminalSession
	mu       sync.RWMutex
}

// NewTerminalManager creates a new terminal manager
func NewTerminalManager() *TerminalManager {
	tm := &TerminalManager{
		sessions: make(map[string]*TerminalSession),
	}
	
	// Start cleanup goroutine for inactive sessions
	go tm.cleanupInactiveSessions()
	
	return tm
}

// CreateSession creates a new terminal session
func (tm *TerminalManager) CreateSession() (*TerminalSession, error) {
	sessionID := fmt.Sprintf("term_%d", time.Now().UnixNano())
	
	// Create a new bash session
	cmd := exec.Command("/bin/bash")
	
	// Start the command with a PTY
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to start PTY: %v", err)
	}
	
	session := &TerminalSession{
		ID:           sessionID,
		PTY:          ptmx,
		Command:      cmd,
		InputChan:    make(chan string, 100),
		OutputChan:   make(chan string, 1000),
		Active:       true,
		lastActivity: time.Now(),
	}
	
	// Start output reader
	go session.readOutput()
	
	// Start input writer
	go session.writeInput()
	
	tm.mu.Lock()
	tm.sessions[sessionID] = session
	tm.mu.Unlock()
	
	return session, nil
}

// GetSession retrieves a session by ID
func (tm *TerminalManager) GetSession(id string) (*TerminalSession, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	
	session, exists := tm.sessions[id]
	return session, exists
}

// CloseSession closes and removes a session
func (tm *TerminalManager) CloseSession(id string) error {
	tm.mu.Lock()
	session, exists := tm.sessions[id]
	if !exists {
		tm.mu.Unlock()
		return fmt.Errorf("session not found")
	}
	delete(tm.sessions, id)
	tm.mu.Unlock()
	
	return session.Close()
}

// cleanupInactiveSessions removes sessions inactive for more than 30 minutes
func (tm *TerminalManager) cleanupInactiveSessions() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		tm.mu.Lock()
		for id, session := range tm.sessions {
			session.mu.Lock()
			if time.Since(session.lastActivity) > 30*time.Minute {
				session.mu.Unlock()
				session.Close()
				delete(tm.sessions, id)
				fmt.Printf("[TerminalManager] Cleaned up inactive session: %s\n", id)
			} else {
				session.mu.Unlock()
			}
		}
		tm.mu.Unlock()
	}
}

// readOutput reads from PTY and sends to output channel
func (ts *TerminalSession) readOutput() {
	defer close(ts.OutputChan)
	
	reader := bufio.NewReader(ts.PTY)
	buf := make([]byte, 1024)
	
	for ts.Active {
		n, err := reader.Read(buf)
		if err != nil {
			if err != io.EOF {
				fmt.Printf("[Terminal %s] Read error: %v\n", ts.ID, err)
			}
			ts.mu.Lock()
			ts.Active = false
			ts.mu.Unlock()
			break
		}
		
		if n > 0 {
			output := string(buf[:n])
			ts.OutputChan <- output
			ts.mu.Lock()
			ts.lastActivity = time.Now()
			ts.mu.Unlock()
		}
	}
}

// writeInput writes from input channel to PTY
func (ts *TerminalSession) writeInput() {
	for input := range ts.InputChan {
		if !ts.Active {
			break
		}
		
		_, err := ts.PTY.Write([]byte(input))
		if err != nil {
			fmt.Printf("[Terminal %s] Write error: %v\n", ts.ID, err)
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

// SendInput sends input to the terminal
func (ts *TerminalSession) SendInput(input string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	
	if !ts.Active {
		return fmt.Errorf("session is not active")
	}
	
	select {
	case ts.InputChan <- input:
		return nil
	case <-time.After(5 * time.Second):
		return fmt.Errorf("timeout sending input")
	}
}

// Resize resizes the terminal window
func (ts *TerminalSession) Resize(rows, cols uint16) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	
	if !ts.Active {
		return fmt.Errorf("session is not active")
	}
	
	return pty.Setsize(ts.PTY, &pty.Winsize{
		Rows: rows,
		Cols: cols,
	})
}

// Close closes the terminal session
func (ts *TerminalSession) Close() error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	
	if !ts.Active {
		return nil
	}
	
	ts.Active = false
	close(ts.InputChan)
	
	if ts.Command.Process != nil {
		ts.Command.Process.Kill()
	}
	
	if ts.PTY != nil {
		ts.PTY.Close()
	}
	
	return nil
}

// ExecuteCommandWithSudo executes a command with sudo in a terminal session
func (tm *TerminalManager) ExecuteCommandWithSudo(command string) (*TerminalSession, error) {
	session, err := tm.CreateSession()
	if err != nil {
		return nil, err
	}
	
	// Send the sudo command
	err = session.SendInput(fmt.Sprintf("sudo %s\n", command))
	if err != nil {
		session.Close()
		return nil, err
	}
	
	return session, nil
}