package main

import (
	"bufio"
	"bytes" // ADDED: Required for bytes.NewReader in AnalyzeRunningProcesses
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang" // PRODUCTION: MaxMind GeoIP2 Reader

	// --- NEW NETWORK FORENSICS IMPORTS ---
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	// ------------------------------------
)

// ExtractedHash represents a hash extracted from a forensic source (defined in core_controller.go)

// GeoLocationData holds detailed geo-location information
type GeoLocationData struct {
	CountryName string  `json:"country_name"`
	CityName    string  `json:"city_name"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	TimeZone    string  `json:"time_zone"`
}

// NetworkSession represents a reconstructed connection from packet data
type NetworkSession struct {
	Timestamp        time.Time       `json:"timestamp"`
	Protocol         string          `json:"protocol"`
	SrcIP            string          `json:"src_ip"`
	DstIP            string          `json:"dst_ip"`
	SrcPort          uint16          `json:"src_port"`
	DstPort          uint16          `json:"dst_port"`
	TotalPackets     int             `json:"total_packets"`
	AppLayerProtocol string          `json:"app_layer_protocol"`
	PayloadSnippet   string          `json:"payload_snippet"` // e.g., HTTP request line, part of a shell command
	GeoLocation      GeoLocationData `json:"geo_location"`
}

// ProcessInfo holds details about a running system process
type ProcessInfo struct {
	PID  int    `json:"pid"`
	User string `json:"user"`
	CPU  string `json:"cpu_usage"`
	Mem  string `json:"mem_usage"`
	Cmd  string `json:"command"`
}

// SystemReconData holds comprehensive reconnaissance information (defined in core_controller.go)

// ForensicToolkit provides methods for data parsing and analysis
type ForensicToolkit struct {
	GeoIPDB   *geoip2.Reader
	GeoIPPath string
}

// NewForensicToolkit initializes the toolkit, including GeoIP database access.
func NewForensicToolkit(geoIPPath string) (*ForensicToolkit, error) {
	ft := &ForensicToolkit{GeoIPPath: geoIPPath}

	// Load GeoIP database for production use
	if geoIPPath != "" {
		db, err := geoip2.Open(geoIPPath)
		if err != nil {
			// NOTE: Logging error but allowing the toolkit to function without GeoIP
			fmt.Printf("[ForensicToolkit ERROR] Failed to open GeoIP database at %s: %v. Geo-location lookups disabled.\n", geoIPPath, err)
		} else {
			ft.GeoIPDB = db
			fmt.Printf("[ForensicToolkit] GeoIP database loaded successfully.\n")
		}
	} else {
		fmt.Printf("[ForensicToolkit] GeoIP path not provided. Geo-location lookups disabled.\n")
	}

	return ft, nil
}

// ResolveGeoLocation resolves an IP address to geographical data
func (ft *ForensicToolkit) ResolveGeoLocation(ipStr string) GeoLocationData {
	if ft.GeoIPDB == nil {
		return GeoLocationData{CountryName: "N/A (DB not loaded)"}
	}

	ip := net.ParseIP(ipStr)
	if ip == nil || ip.IsPrivate() || ip.IsLoopback() {
		return GeoLocationData{CountryName: "Private/Local"}
	}

	record, err := ft.GeoIPDB.City(ip)
	if err != nil {
		return GeoLocationData{CountryName: "Unknown"}
	}

	return GeoLocationData{
		CountryName: record.Country.Names["en"],
		CityName:    record.City.Names["en"],
		Latitude:    record.Location.Latitude,
		Longitude:   record.Location.Longitude,
		TimeZone:    record.Location.TimeZone,
	}
}

// --- HOST FORENSICS ORCHESTRATOR (NEW) ---

// ExtractHashes is the public-facing entry point for hash extraction.
// It orchestrates the file search and subsequent parsing.
func (ft *ForensicToolkit) ExtractHashes(targetOS, targetPath string) ([]ExtractedHash, error) {
	log.Printf("[ForensicToolkit] Starting unified hash extraction for OS: %s, Path: %s", targetOS, targetPath)

	// 1. Find potential credential files within the target path
	credentialFiles, err := ft.FindSensitiveFiles(targetPath)
	if err != nil {
		return nil, fmt.Errorf("failed to search for sensitive files: %w", err)
	}

	if len(credentialFiles) == 0 {
		return nil, nil // No files found, not an error
	}

	// 2. Extract hashes from the identified files
	hashes, err := ft.ExtractHashesFromFiles(credentialFiles, targetOS)
	if err != nil {
		return nil, fmt.Errorf("failed to parse hashes from files: %w", err)
	}

	log.Printf("[ForensicToolkit] Completed extraction, %d hashes found.", len(hashes))
	return hashes, nil
}

// --- HOST FORENSICS CORE LOGIC ---

// ExtractHashesFromFiles processes files to find credential hashes
func (ft *ForensicToolkit) ExtractHashesFromFiles(filePaths []string, targetOS string) ([]ExtractedHash, error) {
	fmt.Printf("[ForensicToolkit] Starting hash extraction from %d files (OS: %s)...\n", len(filePaths), targetOS)

	var allHashes []ExtractedHash
	var mu sync.Mutex

	// PRODUCTION: This function must contain the *real* logic for parsing known credential formats.
	for _, path := range filePaths {
		// Example: Process Linux /etc/shadow or similar NTLM/Hashcat compatible file formats
		if strings.Contains(strings.ToLower(path), "shadow") || strings.Contains(strings.ToLower(path), "htpasswd") {
			hashes, err := ft.parseShadowFormat(path)
			if err != nil {
				// Non-fatal error for one file, log it and continue
				fmt.Printf("[ForensicToolkit WARNING] Failed to parse %s: %v\n", path, err)
				continue
			}
			mu.Lock()
			allHashes = append(allHashes, hashes...)
			mu.Unlock()
		} else {
			// Other OS/file parsing logic (e.g., Windows registry hive parsing) goes here
			// For professional production code, we only include the core, non-simulated flow.
		}
	}

	return allHashes, nil
}

// parseShadowFormat simulates the real-world parsing of the /etc/shadow file or similar colon-separated hash files.
func (ft *ForensicToolkit) parseShadowFormat(path string) ([]ExtractedHash, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var hashes []ExtractedHash
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip comments and empty lines
		}

		parts := strings.Split(line, ":")
		if len(parts) >= 2 {
			username := parts[0]
			hashField := parts[1]

			if strings.HasPrefix(hashField, "$") && len(hashField) > 5 {
				// This is a typical Unix crypt hash (MD5, SHA256, SHA512)
				hashType := "UNIX-CRYPT"
				if strings.HasPrefix(hashField, "$6$") {
					hashType = "SHA512-Crypt"
				} else if strings.HasPrefix(hashField, "$5$") {
					hashType = "SHA256-Crypt"
				}

				hashes = append(hashes, ExtractedHash{
					Hash:       hashField,
					Username:   username,
					SourceFile: path,
					HashType:   hashType,
					Context:    "Shadow/Credential File",
				})
			}
		}
	}

	return hashes, scanner.Err()
}

// AnalyzeRunningProcesses uses 'ps aux' for reconnaissance
func (ft *ForensicToolkit) AnalyzeRunningProcesses(limit int) ([]ProcessInfo, error) {
	fmt.Printf("[ForensicToolkit] Analyzing running processes (Limit: %d)...\n", limit)

	// PRODUCTION: Execute 'ps aux' command
	cmd := exec.Command("ps", "aux")
	output, err := cmd.Output()
	if err != nil {
		// Check for common non-fatal error on minimal systems
		if strings.Contains(err.Error(), "no such file or directory") || strings.Contains(err.Error(), "not found") {
			return nil, fmt.Errorf("system command 'ps' not found or failed to execute: %w", err)
		}
		return nil, fmt.Errorf("failed to execute 'ps aux': %w", err)
	}

	// FIX: Used imported 'bytes' package
	scanner := bufio.NewScanner(bytes.NewReader(output))
	processes := []ProcessInfo{}

	// Skip header line
	if scanner.Scan() {
		// Discard header
	}

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)

		// Expected fields for ps aux output (minimal length is usually 11)
		if len(parts) >= 11 {
			pid, _ := strconv.Atoi(parts[1])

			processes = append(processes, ProcessInfo{
				PID:  pid,
				User: parts[0],
				CPU:  parts[2],
				Mem:  parts[3],
				Cmd:  strings.Join(parts[10:], " "),
			})
		}

		if limit > 0 && len(processes) >= limit {
			break
		}
	}

	return processes, nil
}

// FindSensitiveFiles searches for common paths and file extensions containing sensitive data.
func (ft *ForensicToolkit) FindSensitiveFiles(rootPath string) ([]string, error) {
	fmt.Printf("[ForensicToolkit] Starting sensitive file search at: %s\n", rootPath)

	sensitiveFiles := []string{}
	// UPDATED: Added more production-relevant extensions like .sql and .db
	targetPatterns := map[string]bool{
		".key": true, ".pem": true, ".cer": true, ".crt": true, ".pfx": true, // Crypto keys/certs
		"id_rsa": true, "id_dsa": true, "config.json": true, "credentials": true,
		"passwords.txt": true, ".bash_history": true, "web.config": true, // Common sensitive names
		"htpasswd": true, ".env": true, ".git/config": true, ".vault": true,
		".sql": true, ".db": true, // Database files
	}

	err := filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // Continue walking if there's an error on a specific path
		}

		// Skip hidden directories (starting with '.') except for the root itself
		if d.IsDir() && strings.HasPrefix(d.Name(), ".") && path != rootPath {
			return filepath.SkipDir
		}

		fileName := strings.ToLower(d.Name())

		// Check for file extensions
		ext := filepath.Ext(fileName)
		if targetPatterns[ext] {
			sensitiveFiles = append(sensitiveFiles, path)
			return nil
		}

		// Check for file names (like id_rsa or passwords.txt)
		if targetPatterns[fileName] {
			sensitiveFiles = append(sensitiveFiles, path)
			return nil
		}

		// Check for files within known paths (e.g., .ssh/config)
		if strings.Contains(strings.ToLower(path), ".ssh/id_") || strings.Contains(strings.ToLower(path), "/etc/shadow") {
			sensitiveFiles = append(sensitiveFiles, path)
			return nil
		}

		return nil
	})

	return sensitiveFiles, err
}

// --- NETWORK FORENSICS (NEW PRODUCTION LOGIC) ---

// AnalyzePCAPFile reads a PCAP file, reconstructs sessions, and extracts network intelligence.
func (ft *ForensicToolkit) AnalyzePCAPFile(pcapFilePath string) ([]NetworkSession, error) {
	fmt.Printf("[ForensicToolkit] Starting PCAP analysis on: %s\n", pcapFilePath)

	// Open the PCAP file
	handle, err := pcap.OpenOffline(pcapFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open PCAP file: %w", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	sessions := make(map[string]*NetworkSession)
	var mu sync.Mutex // Mutex for map access

	// Iterate over packets
	for packet := range packetSource.Packets() {
		// PRODUCTION CHECK: Only process packets with IP layer
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ip, _ := ipLayer.(*layers.IPv4)

		// PRODUCTION CHECK: Only process packets with TCP or UDP layer
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		udpLayer := packet.Layer(layers.LayerTypeUDP)

		var srcPort, dstPort uint16
		var protocol string

		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			srcPort = uint16(tcp.SrcPort)
			dstPort = uint16(tcp.DstPort)
			protocol = "TCP"
		} else if udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			srcPort = uint16(udp.SrcPort)
			dstPort = uint16(udp.DstPort)
			protocol = "UDP"
		} else {
			continue
		}

		// --- Session Key Creation (Unique Bidirectional Identifier) ---
		// Sort the IPs and ports to create a consistent key for a single conversation
		var sessionKey string
		// Note: Using bytes.Compare on IP slices is a production-level method to normalize the flow key.
		if bytes.Compare(ip.SrcIP, ip.DstIP) < 0 {
			sessionKey = fmt.Sprintf("%s:%d-%s:%d-%s", ip.SrcIP, srcPort, ip.DstIP, dstPort, protocol)
		} else {
			sessionKey = fmt.Sprintf("%s:%d-%s:%d-%s", ip.DstIP, dstPort, ip.SrcIP, srcPort, protocol)
		}

		mu.Lock()
		session, ok := sessions[sessionKey]
		if !ok {
			// Initialize new session
			session = &NetworkSession{
				Timestamp:        packet.Metadata().Timestamp,
				Protocol:         protocol,
				SrcIP:            ip.SrcIP.String(),
				DstIP:            ip.DstIP.String(),
				SrcPort:          srcPort,
				DstPort:          dstPort,
				AppLayerProtocol: "UNKNOWN",
			}
			// Geo-tag the destination IP right away (common for external traffic)
			session.GeoLocation = ft.ResolveGeoLocation(ip.DstIP.String())
			sessions[sessionKey] = session
		}
		session.TotalPackets++

		// --- Application Layer Payload Analysis (Deep Packet Inspection) ---
		app := packet.ApplicationLayer()
		if app != nil && session.PayloadSnippet == "" {
			payload := app.Payload()

			if len(payload) > 0 {
				session.PayloadSnippet = ft.extractAppPayloadSnippet(payload, packet.Metadata().Timestamp, ip.DstIP.String())

				// Attempt to identify protocol based on port/signature (e.g., HTTP, TLS, SSH)
				session.AppLayerProtocol = ft.identifyAppProtocol(srcPort, dstPort, payload)
			}
		}
		mu.Unlock()
	}

	// Convert map to slice
	finalSessions := make([]NetworkSession, 0, len(sessions))
	for _, session := range sessions {
		finalSessions = append(finalSessions, *session)
	}

	fmt.Printf("[ForensicToolkit] PCAP analysis complete. Extracted %d unique network sessions.\n", len(finalSessions))
	return finalSessions, nil
}

// extractAppPayloadSnippet focuses on the most relevant part of a payload
func (ft *ForensicToolkit) extractAppPayloadSnippet(payload []byte, timestamp time.Time, dstIP string) string {
	// Simple approach: look for non-printable characters or make a safe snippet
	safeSnippet := strings.ReplaceAll(string(payload), "\n", "\\n")
	safeSnippet = strings.ReplaceAll(safeSnippet, "\r", "\\r")

	maxLen := 120
	if len(safeSnippet) > maxLen {
		return safeSnippet[:maxLen] + "..."
	}

	// PRODUCTION: For full robustness, this is where Yara rules or keyword matching would happen
	// Example: Check for common keywords in the payload
	lowerPayload := strings.ToLower(string(payload))
	if strings.Contains(lowerPayload, "password") || strings.Contains(lowerPayload, "user-agent: hack") {
		return "POSSIBLE EXFILTRATION/ATTACK DATA: " + safeSnippet
	}

	return safeSnippet
}

// identifyAppProtocol identifies the application protocol based on ports and payload
func (ft *ForensicToolkit) identifyAppProtocol(srcPort, dstPort uint16, payload []byte) string {
	lowerPayload := strings.ToLower(string(payload))

	// 1. Port-based check
	if srcPort == 80 || dstPort == 80 {
		return "HTTP"
	} else if srcPort == 443 || dstPort == 443 {
		return "HTTPS/TLS"
	} else if srcPort == 21 || dstPort == 21 {
		return "FTP"
	} else if srcPort == 22 || dstPort == 22 {
		return "SSH"
	} else if srcPort == 53 || dstPort == 53 {
		return "DNS"
	}

	// 2. Signature-based check (if not a standard port)
	if strings.HasPrefix(lowerPayload, "get ") || strings.HasPrefix(lowerPayload, "post ") || strings.HasPrefix(lowerPayload, "head ") {
		return "HTTP"
	}
	// Add check for TLS/SSL handshake start bytes (not fully implemented here for brevity)
	if len(payload) > 0 && (payload[0] == 0x16 || payload[0] == 0x17) {
		return "TLS/SSL (Signature)"
	}

	return "UNKNOWN"
}

// RunRecon executes a full system reconnaissance scan
func (ft *ForensicToolkit) RunRecon(targetOS, targetPath string) (*SystemReconData, error) {
	log.Printf("[ForensicToolkit] Starting system reconnaissance on OS: %s, Path: %s", targetOS, targetPath)

	reconData := &SystemReconData{
		Timestamp: time.Now(),
		HostName:  "localhost", // Default, could be enhanced
		TargetIP:  "127.0.0.1", // Default, could be enhanced
	}

	// Extract hashes
	hashes, err := ft.ExtractHashes(targetOS, targetPath)
	if err != nil {
		return nil, fmt.Errorf("hash extraction failed: %w", err)
	}
	reconData.ExtractedHashes = hashes

	// Analyze running processes
	processes, err := ft.AnalyzeRunningProcesses(50) // Limit to 50 processes
	if err != nil {
		log.Printf("[ForensicToolkit WARNING] Process analysis failed: %v", err)
	} else {
		// Convert ProcessInfo to interface{} for compatibility
		reconData.RunningProcesses = make([]interface{}, len(processes))
		for i, p := range processes {
			reconData.RunningProcesses[i] = p
		}
	}

	// Find sensitive files
	sensitiveFiles, err := ft.FindSensitiveFiles(targetPath)
	if err != nil {
		log.Printf("[ForensicToolkit WARNING] Sensitive file search failed: %v", err)
	} else {
		reconData.SensitiveFiles = sensitiveFiles
	}

	log.Printf("[ForensicToolkit] System Recon complete. Found %d hashes, %d processes, %d sensitive files.",
		len(reconData.ExtractedHashes), len(reconData.RunningProcesses), len(reconData.SensitiveFiles))

	return reconData, nil
}
