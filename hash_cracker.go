// hash_cracker.go
package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec" // REQUIRED for external Hashcat integration
	"strings"
	"sync"
	"time"
)

// CrackedHashResult holds a successfully cracked hash and its plaintext
type CrackedHashResult struct {
	Hash      string `json:"hash"`
	PlainText string `json:"plaintext"`
	HashType  string `json:"hash_type"`
}

// HashCracker provides high-speed concurrent hash cracking capabilities
type HashCracker struct {
	mu            sync.Mutex
	Concurrency   int
	WordlistPath  string
	SessionID     string // Unique ID for a cracking session
	StopSignal    chan struct{}
	ResultsChan   chan CrackedHashResult
	ProgressTotal int64
	ProgressCount int64
}

// NewHashCracker creates a new, concurrently-aware hash cracker
func NewHashCracker(concurrency int) *HashCracker {
	if concurrency <= 0 {
		concurrency = 4 // Default to 4 cores
	}
	return &HashCracker{
		Concurrency: concurrency,
		StopSignal:  make(chan struct{}),
		// Buffer the results channel to prevent blocking while streaming to the WebSockets
		ResultsChan: make(chan CrackedHashResult, 100),
	}
}

// CrackDictionary runs a concurrent dictionary attack against a list of hashes
func (hc *HashCracker) CrackDictionary(hashes map[string]string, hashType string, wordlistPath string) {
	// Reset counters
	hc.mu.Lock()
	hc.ProgressTotal = int64(len(hashes))
	hc.ProgressCount = 0
	hc.SessionID = fmt.Sprintf("CRACK-%d", time.Now().UnixNano())
	hc.mu.Unlock()

	hashTypeLower := strings.ToLower(hashType)

	fmt.Printf("[HashCracker] Session %s: Starting crack job on %d hashes (Type: %s) with wordlist: %s\n",
		hc.SessionID, len(hashes), hashType, wordlistPath)

	// --- Check if external tool (Hashcat) is required ---
	if hashTypeLower == "ntlm" || hashTypeLower == "bcrypt" || hashTypeLower == "sha512-crypt" {
		hc.crackExternalWithHashcat(hashes, hashType, wordlistPath)
		return // External tool handles the whole process
	}
	// ---------------------------------------------------

	wordlistChan := make(chan string, 1000)
	var wg sync.WaitGroup

	// --- 1. Worker Goroutines (Native Go) ---
	for i := 0; i < hc.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hc.worker(hashes, hashType, wordlistChan)
		}()
	}

	// --- 2. Wordlist Loader ---
	go func() {
		defer close(wordlistChan) // Ensure the channel is closed when done

		file, err := os.Open(wordlistPath)
		if err != nil {
			fmt.Printf("[HashCracker ERROR] Failed to open wordlist: %v\n", err)
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			select {
			case wordlistChan <- scanner.Text():
				// Sent word
			case <-hc.StopSignal:
				return // Stop reading file if signal received
			}
		}

		if err := scanner.Err(); err != nil && err != io.EOF {
			fmt.Printf("[HashCracker ERROR] Failed to read wordlist: %v\n", err)
		}
	}()

	// --- 3. Progress Reporter ---
	go hc.nativeProgressReporter()

	// Wait for all workers to finish
	wg.Wait()

	hc.mu.Lock()
	close(hc.StopSignal) // Ensure reporter also stops
	hc.mu.Unlock()

	close(hc.ResultsChan) // Signal that all results have been sent
	fmt.Printf("[HashCracker] Session %s: Cracking job finished.\n", hc.SessionID)
}

// worker processes words from the wordlist against the target hashes (Native Go)
func (hc *HashCracker) worker(hashes map[string]string, hashType string, wordlistChan <-chan string) {
	hashesToCrack := make(map[string]string)
	for hash, username := range hashes {
		hashesToCrack[hash] = username
	}

	for word := range wordlistChan {
		// Stop if all hashes are cracked
		if len(hashesToCrack) == 0 {
			return
		}

		var crackedHash string

		// --- PRODUCTION Hashing logic: Only common, simple types supported in-memory ---
		switch strings.ToLower(hashType) {
		case "md5":
			h := md5.New()
			io.WriteString(h, word)
			crackedHash = hex.EncodeToString(h.Sum(nil))
		case "sha256":
			h := sha256.New()
			io.WriteString(h, word)
			crackedHash = hex.EncodeToString(h.Sum(nil))
		default:
			// Should be caught by CrackDictionary, but defensive programming
			continue
		}

		// Check if the cracked hash matches any target hash
		if _, ok := hashesToCrack[crackedHash]; ok {
			hc.mu.Lock()
			hc.ResultsChan <- CrackedHashResult{
				Hash:      crackedHash,
				PlainText: word,
				HashType:  hashType,
			}

			delete(hashesToCrack, crackedHash)
			hc.ProgressCount++
			hc.mu.Unlock()
		}

		// Check for stop signal after a word is processed
		select {
		case <-hc.StopSignal:
			return
		default:
			// Continue
		}
	}
}

// crackExternalWithHashcat handles complex, slow hashes by calling Hashcat (Production Scaffolding)
func (hc *HashCracker) crackExternalWithHashcat(hashes map[string]string, hashType string, wordlistPath string) {
	fmt.Printf("[HashCracker: Hashcat] Using external tool for %s. Hashcat must be installed.\n", hashType)

	// CRITICAL ENTERPRISE CHECK: Verify Hashcat executable exists in PATH
	_, err := exec.LookPath("hashcat")
	if err != nil {
		fmt.Printf("[HashCracker: Hashcat CRITICAL ERROR] Hashcat executable not found in PATH: %v. Cannot proceed.\n", err)
		// Send a final, unrecoverable signal
		hc.mu.Lock()
		close(hc.ResultsChan)
		hc.mu.Unlock()
		return
	}

	// 1. Determine Hashcat mode
	var hashcatMode string
	switch strings.ToLower(hashType) {
	case "ntlm":
		hashcatMode = "1000"
	case "bcrypt":
		hashcatMode = "3200"
	case "sha512-crypt":
		hashcatMode = "1800"
	default:
		fmt.Printf("[HashCracker: Hashcat ERROR] Unsupported hash type for Hashcat: %s\n", hashType)
		return
	}

	// 2. Write hashes to a temporary file
	tempHashFile, err := os.CreateTemp("", "hashes-*.txt")
	if err != nil {
		fmt.Printf("[HashCracker: Hashcat ERROR] Failed to create temp hash file: %v\n", err)
		return
	}
	defer os.Remove(tempHashFile.Name())
	defer tempHashFile.Close()

	// Write all hashes to the file (one per line)
	for hash := range hashes {
		tempHashFile.WriteString(hash + "\n")
	}
	tempHashFile.Sync()

	fmt.Printf("[HashCracker: Hashcat] Calling hashcat with mode %s on %s...\n", hashcatMode, tempHashFile.Name())

	// 3. Construct and Execute Hashcat Command
	// Arguments:
	// -a 0 (Attack mode: Straight/Dictionary)
	// -m [Mode] (Hash type mode)
	// --outfile-format 2 (Output cracked hash:password)
	// --outfile [file] (Output file for results)
	// --force (Override Hashcat warnings/checks if needed in a controlled environment)
	// [Hash File] [Wordlist File]

	tempResultFile, err := os.CreateTemp("", "results-*.txt")
	if err != nil {
		fmt.Printf("[HashCracker: Hashcat ERROR] Failed to create temp result file: %v\n", err)
		return
	}
	defer os.Remove(tempResultFile.Name())
	defer tempResultFile.Close()

	cmd := exec.Command("hashcat",
		"-a", "0",
		"-m", hashcatMode,
		"--potfile-disable",     // Don't use potfile for immediate results
		"--outfile-format", "2", // Hash:Plaintext
		"--outfile", tempResultFile.Name(),
		"--force", // Use force in automation to avoid prompt interruption
		tempHashFile.Name(),
		wordlistPath,
	)

	// Run command and wait for completion
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Note: Hashcat returns an error code even if it finds some cracks but doesn't finish the session normally
		fmt.Printf("[HashCracker: Hashcat] Hashcat exited, error: %v, Output:\n%s\n", err, string(output))
	} else {
		fmt.Printf("[HashCracker: Hashcat] Hashcat completed successfully. Output:\n%s\n", string(output))
	}

	// 4. Parse Results
	crackedCount := hc.parseHashcatResults(tempResultFile.Name(), hashType)

	// This is a post-process tally for external tools
	hc.mu.Lock()
	hc.ProgressCount = int64(crackedCount)
	hc.mu.Unlock()

	// Signal that all results from the Hashcat run have been streamed
	close(hc.ResultsChan)
}

// parseHashcatResults reads the Hashcat output file and streams results
func (hc *HashCracker) parseHashcatResults(filePath string, hashType string) int {
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("[HashCracker: Hashcat ERROR] Failed to open results file: %v\n", err)
		return 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	cracked := 0

	// Hashcat --outfile-format 2 outputs: hash:plaintext
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)

		if len(parts) == 2 {
			crackedHash := parts[0]
			plaintext := parts[1]

			hc.mu.Lock()
			hc.ResultsChan <- CrackedHashResult{
				Hash:      crackedHash,
				PlainText: plaintext,
				HashType:  hashType,
			}
			hc.mu.Unlock()
			cracked++
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("[HashCracker: Hashcat ERROR] Error reading Hashcat results: %v\n", err)
	}
	return cracked
}

// nativeProgressReporter is the progress loop for native Go cracking
func (hc *HashCracker) nativeProgressReporter() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			hc.mu.Lock()
			// Prevent division by zero
			if hc.ProgressTotal > 0 {
				progress := float64(hc.ProgressCount) / float64(hc.ProgressTotal)
				fmt.Printf("[HashCracker] Session %s Progress: %d/%d cracked (%.2f%%)\n",
					hc.SessionID, hc.ProgressCount, hc.ProgressTotal, progress*100)
			}
			hc.mu.Unlock()

		case <-hc.StopSignal:
			// Ensure final progress update
			hc.mu.Lock()
			if hc.ProgressTotal > 0 {
				finalProgress := float64(hc.ProgressCount) / float64(hc.ProgressTotal)
				fmt.Printf("[HashCracker] Session %s FINAL Progress: %d/%d cracked (%.2f%%). Done.\n",
					hc.SessionID, hc.ProgressCount, hc.ProgressTotal, finalProgress*100)
			}
			hc.mu.Unlock()
			return
		}
	}
}

// Stop sends a signal to stop all running cracking processes gracefully
func (hc *HashCracker) Stop() {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	select {
	case <-hc.StopSignal:
		// Already closed
	default:
		// Closing the channel signals all Go routines to stop
		close(hc.StopSignal)
	}

	// NOTE: For the external Hashcat process, we rely on it completing its job.
	// Implementing a kill function here would require tracking the *cmd* object,
	// which is typically undesirable in automated forensic processing unless a timeout is hit.
	fmt.Printf("[HashCracker] Session %s: Stop signal sent to native workers.\n", hc.SessionID)
}

// GetResultsChannel returns the channel where CrackedHashResult objects are streamed
func (hc *HashCracker) GetResultsChannel() <-chan CrackedHashResult {
	return hc.ResultsChan
}

// StopScan implements the Stoppable interface
func (hc *HashCracker) StopScan() bool {
	hc.Stop()
	return true
}

// GetStatus returns the current status of the hash cracking job
func (hc *HashCracker) GetStatus() (*HashCrackingJobStatus, error) {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	status := &HashCrackingJobStatus{
		SessionID:   hc.SessionID,
		Status:      "running", // Simplified status
		Progress:    float64(hc.ProgressCount) / float64(hc.ProgressTotal) * 100,
		TotalHashes: int(hc.ProgressTotal),
		LastUpdated: time.Now(),
	}

	if hc.ProgressCount >= hc.ProgressTotal {
		status.Status = "finished"
	}

	return status, nil
}
