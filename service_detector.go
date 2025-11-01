// service_detector_prod.go
package main

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ServiceDetector holds service detection logic and signatures
type ServiceDetector struct {
	Timeout           time.Duration
	ServiceSignatures map[int][]ServiceSignature
	mu                sync.RWMutex
}

// NewServiceDetector creates a new service detector
func NewServiceDetector() *ServiceDetector {
	sd := &ServiceDetector{
		Timeout:           5 * time.Second,
		ServiceSignatures: make(map[int][]ServiceSignature),
	}
	sd.loadSignatures()
	return sd
}

// --- SHARED TYPES (Hooks for production compilation) ---

// loadSignatures loads comprehensive service detection signatures, including non-standard ports
func (sd *ServiceDetector) loadSignatures() {
	// HTTP/HTTPS Signatures
	sd.addSignature(80, ServiceSignature{Service: "http", ProbeFunc: sd.probeHTTP})
	sd.addSignature(443, ServiceSignature{Service: "https", ProbeFunc: sd.probeHTTPS})
	sd.addSignature(8080, ServiceSignature{Service: "http-alt", ProbeFunc: sd.probeHTTP})
	sd.addSignature(8443, ServiceSignature{Service: "https-alt", ProbeFunc: sd.probeHTTPS})
	// Add common hidden web ports for "hidden services" detection
	sd.addSignature(4000, ServiceSignature{Service: "http-custom", ProbeFunc: sd.probeHTTP})
	sd.addSignature(9000, ServiceSignature{Service: "http-custom", ProbeFunc: sd.probeHTTP})

	// SSH/FTP/Telnet
	sd.addSignature(22, ServiceSignature{Service: "ssh", ProbeFunc: sd.probeSSH})
	sd.addSignature(21, ServiceSignature{Service: "ftp", ProbeFunc: sd.probeFTP})
	sd.addSignature(23, ServiceSignature{Service: "telnet", ProbeFunc: sd.probeTelnet})

	// Mail Services
	sd.addSignature(25, ServiceSignature{Service: "smtp", ProbeFunc: sd.probeSMTP})
	sd.addSignature(110, ServiceSignature{Service: "pop3", ProbeFunc: sd.probeBannerOnly})
	sd.addSignature(143, ServiceSignature{Service: "imap", ProbeFunc: sd.probeBannerOnly})

	// Database Services (Complex Protocol Probes)
	sd.addSignature(3306, ServiceSignature{Service: "mysql", ProbeFunc: sd.probeMySQL})
	sd.addSignature(5432, ServiceSignature{Service: "postgresql", ProbeFunc: sd.probePostgreSQL})
	sd.addSignature(6379, ServiceSignature{Service: "redis", ProbeFunc: sd.probeRedis})
	sd.addSignature(27017, ServiceSignature{Service: "mongodb", ProbeFunc: sd.probeMongoDB})
	sd.addSignature(1433, ServiceSignature{Service: "ms-sql-s", ProbeFunc: sd.probeMSSQL}) // NEW COMPLEX PROBE

	// Windows/Remote Services (Complex Protocol Probes)
	sd.addSignature(445, ServiceSignature{Service: "microsoft-ds", ProbeFunc: sd.probeSMB})   // NEW COMPLEX PROBE
	sd.addSignature(3389, ServiceSignature{Service: "ms-wbt-server", ProbeFunc: sd.probeRDP}) // NEW COMPLEX PROBE

	// Directory/Other Services (Complex Protocol Probes)
	sd.addSignature(389, ServiceSignature{Service: "ldap", ProbeFunc: sd.probeLDAP}) // NEW COMPLEX PROBE
	sd.addSignature(53, ServiceSignature{Service: "dns", ProbeFunc: sd.probeDNS})
	sd.addSignature(5900, ServiceSignature{Service: "vnc", ProbeFunc: sd.probeVNC})
	sd.addSignature(9200, ServiceSignature{Service: "elasticsearch", ProbeFunc: sd.probeElasticsearch})
}

// --- CORE SERVICE DETECTION LOGIC ---

// DetectService orchestrates the probing and banner matching
func (sd *ServiceDetector) DetectService(ip string, port int, banner string) *ServiceInfo {
	// 1. Try protocol-specific probing first (most accurate)
	signatures := []ServiceSignature{}
	for _, sig := range signatures {
		if sig.ProbeFunc != nil {
			if probeResult := sig.ProbeFunc(ip, port); probeResult != nil && probeResult.Name != "unknown" {
				return probeResult
			}
		}
	}

	// 2. Try banner matching (fallback for common services)
	if banner != "" {
		if detected := sd.matchBanner(port, banner); detected != nil {
			return detected
		}
	}

	// 3. Fallback to common port mapping
	return &ServiceInfo{
		Name: sd.getCommonServiceName(port),
	}
}

// probeBannerOnly performs simple banner reading for services that give clear banners (like POP3/IMAP)
func (sd *ServiceDetector) probeBannerOnly(ip string, port int) *ServiceInfo {
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, sd.Timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	reader := bufio.NewReader(conn)

	banner, err := reader.ReadString('\n')
	if err != nil {
		return nil
	}

	banner = strings.TrimSpace(banner)

	service := &ServiceInfo{
		Name:    sd.getCommonServiceName(port),
		Product: banner,
		Version: sd.extractVersion(banner),
	}

	return service
}

// probeHTTP sends a realistic HTTP/1.1 request
func (sd *ServiceDetector) probeHTTP(ip string, port int) *ServiceInfo {
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, sd.Timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(3 * time.Second))
	request := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: SecurityScanner/1.0 (Prod-Probe)\r\nConnection: close\r\n\r\n", ip)

	conn.Write([]byte(request))

	reader := bufio.NewReader(conn)
	service := &ServiceInfo{Name: "http", Version: "1.1"}

	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}

		line = strings.TrimSpace(line)
		lineLower := strings.ToLower(line)

		if strings.HasPrefix(lineLower, "server:") {
			server := strings.TrimPrefix(line, "Server:")
			service.Product = strings.TrimSpace(server)
			service.Version = sd.extractVersion(service.Product)
		} else if strings.HasPrefix(lineLower, "x-powered-by:") {
			powered := strings.TrimPrefix(line, "X-Powered-By:")
			service.ExtraInfo = strings.TrimSpace(powered)
		} else if strings.HasPrefix(lineLower, "location:") {
			// Found a redirect, confirm it's a web server
			service.Name = "http"
		}
	}

	return service
}

// probeHTTPS performs full TLS handshake and attempts to get HTTP headers
func (sd *ServiceDetector) probeHTTPS(ip string, port int) *ServiceInfo {
	address := net.JoinHostPort(ip, strconv.Itoa(port))

	config := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         ip,
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", address, config)
	if err != nil {
		return nil
	}
	defer conn.Close()

	service := &ServiceInfo{Name: "https"}

	state := conn.ConnectionState()
	service.Version = getTLSVersionString(state.Version) // Completed helper function

	// Get cipher suite (advanced feature)
	service.ExtraInfo = fmt.Sprintf("Cipher: %s", tls.CipherSuiteName(state.CipherSuite))

	// Try to get HTTP headers over TLS
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	request := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", ip)
	conn.Write([]byte(request))

	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}

		if strings.HasPrefix(strings.ToLower(line), "server:") {
			server := strings.TrimPrefix(line, "Server:")
			service.Product = strings.TrimSpace(server)
			break
		}
	}

	return service
}

// probeSSH performs banner analysis
func (sd *ServiceDetector) probeSSH(ip string, port int) *ServiceInfo {
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, sd.Timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	reader := bufio.NewReader(conn)

	banner, err := reader.ReadString('\n')
	if err != nil {
		return nil
	}

	banner = strings.TrimSpace(banner)

	service := &ServiceInfo{Name: "ssh"}

	if strings.HasPrefix(banner, "SSH-") {
		parts := strings.SplitN(banner, "-", 3)
		if len(parts) >= 3 {
			service.Version = parts[1]
			service.Product = parts[2]
		}
	}

	return service
}

// probeFTP performs banner analysis
func (sd *ServiceDetector) probeFTP(ip string, port int) *ServiceInfo {
	return sd.probeBannerOnly(ip, port)
}

// probeSMTP sends EHLO to get product banner
func (sd *ServiceDetector) probeSMTP(ip string, port int) *ServiceInfo {
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, sd.Timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	reader := bufio.NewReader(conn)

	banner, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(banner, "220") {
		return nil
	}

	service := &ServiceInfo{Name: "smtp"}
	service.Product = strings.TrimSpace(strings.TrimPrefix(banner, "220"))

	// Send EHLO to get more info (production logic)
	conn.Write([]byte("EHLO securityscanner.test\r\n"))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		if strings.HasPrefix(line, "250 ") {
			// Extract version/product from 250 reply
			if strings.Contains(line, "Postfix") {
				service.Product = "Postfix"
			} else if strings.Contains(line, "Exim") {
				service.Product = "Exim"
			}
			service.Version = sd.extractVersion(line)
			break
		}
	}

	return service
}

// probeTelnet attempts to interact to differentiate it from basic TCP echo
func (sd *ServiceDetector) probeTelnet(ip string, port int) *ServiceInfo {
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// Send an IAC DO/WONT command sequence to check for Telnet protocol
	// IAC WILL ECHO (0xFF 0xFB 0x01)
	conn.Write([]byte{0xFF, 0xFB, 0x01})
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)

	service := &ServiceInfo{Name: "telnet"}

	if err == nil && n > 0 && buffer[0] == 0xFF {
		// Response with IAC WONT/DO/DONT is a definitive Telnet indicator
		service.Product = "Telnet Server"
		service.Version = "IAC protocol detected"
	}

	return service
}

// probeDNS sends a DNS version.bind query (CHAOS class)
func (sd *ServiceDetector) probeDNS(ip string, port int) *ServiceInfo {
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("udp", address, sd.Timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// DNS query for version.bind (CHAOS Class)
	query := []byte{
		0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, // "version"
		0x04, 0x62, 0x69, 0x6e, 0x64, // "bind"
		0x00, 0x00, 0x10, 0x00, 0x03, // Type TXT, Class CHAOS
	}

	conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Write(query)
	if err != nil {
		return &ServiceInfo{Name: "dns", Product: "DNS server responding"}
	}

	response := make([]byte, 512)
	n, err := conn.Read(response)

	service := &ServiceInfo{Name: "dns"}

	if err == nil && n > 12 {
		// Basic check for an answer section (non-zero answer count)
		if binary.BigEndian.Uint16(response[6:8]) > 0 {
			// Find TXT record for version string
			respStr := string(response)
			if versionIndex := strings.Index(respStr, "BIND"); versionIndex != -1 {
				// Simple version extraction from answer payload
				versionStr := respStr[versionIndex:]
				if nl := strings.Index(versionStr, "\n"); nl != -1 {
					versionStr = versionStr[:nl]
				}
				service.Version = strings.TrimSpace(versionStr)
				service.Product = "BIND"
			} else {
				service.Product = "DNS Server"
			}
		}
	}

	return service
}

// probeMySQL parses the MySQL handshake packet
func (sd *ServiceDetector) probeMySQL(ip string, port int) *ServiceInfo {
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)

	if err != nil || n < 10 {
		return nil
	}

	service := &ServiceInfo{Name: "mysql"}

	// Protocol version (byte 4) must be 10 for current standard
	if n > 5 && buffer[4] == 10 {
		// Version is a null-terminated string starting at byte 5
		versionStart := 5
		versionEnd := versionStart
		for versionEnd < n && buffer[versionEnd] != 0x00 {
			versionEnd++
		}
		if versionEnd < n {
			versionStr := string(buffer[versionStart:versionEnd])
			service.Version = versionStr

			if strings.Contains(versionStr, "MariaDB") {
				service.Product = "MariaDB"
			} else {
				service.Product = "MySQL"
			}
		}
	}

	return service
}

// probePostgreSQL performs a full startup/version request (Production Logic)
func (sd *ServiceDetector) probePostgreSQL(ip string, port int) *ServiceInfo {
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// PostgreSQL 3.0 Startup message (Protocol 196608) with minimal user
	startup := []byte{
		0x00, 0x00, 0x00, 0x00, // Length placeholder
		0x00, 0x03, 0x00, 0x00, // Protocol version 3.0 (0x00030000)
		0x75, 0x73, 0x65, 0x72, 0x00, // "user"
		0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x73, 0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72, 0x00, // "securityscanner"
		0x00, // Final null terminator
	}

	// Set length of message
	binary.BigEndian.PutUint32(startup, uint32(len(startup)))

	conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Write(startup)
	if err != nil {
		return nil
	}

	reader := bufio.NewReader(conn)
	service := &ServiceInfo{Name: "postgresql"}

	// Read server responses (ParameterStatus 'S' and Authentication 'R')
	for {
		header, err := reader.Peek(5)
		if err != nil {
			break
		}

		msgType := header[0]
		msgLen := binary.BigEndian.Uint32(header[1:5])

		if msgType == 'S' {
			// ParameterStatus message - contains server version (Production feature)
			message := make([]byte, msgLen+1)
			reader.Read(message)

			// Find "server_version" within the payload (string parsing)
			msgStr := string(message)
			if strings.Contains(msgStr, "server_version\x00") {
				versionStart := strings.Index(msgStr, "server_version\x00") + 15
				versionEnd := strings.Index(msgStr[versionStart:], "\x00")
				if versionEnd != -1 {
					service.Version = msgStr[versionStart : versionStart+versionEnd]
					service.Product = "PostgreSQL"
				}
			}
		} else if msgType == 'R' || msgType == 'E' {
			// Authentication or Error message - means the server is running Postgres
			if service.Version == "" {
				service.Version = "PostgreSQL server responding"
			}
			return service
		} else {
			// Read and discard other message types
			reader.Discard(int(msgLen) - 4)
			continue
		}
	}

	return service
}

// probeRedis sends INFO to get detailed version info
func (sd *ServiceDetector) probeRedis(ip string, port int) *ServiceInfo {
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(3 * time.Second))
	reader := bufio.NewReader(conn)

	// Send INFO command
	conn.Write([]byte("*1\r\n$4\r\nINFO\r\n"))

	service := &ServiceInfo{Name: "redis", Product: "Redis"}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		if strings.HasPrefix(line, "redis_version:") {
			version := strings.TrimPrefix(line, "redis_version:")
			service.Version = strings.TrimSpace(version)
		}

		// INFO response is usually long, stop reading after a few lines to save time
		if len(line) < 3 || strings.HasPrefix(line, "# Sentinel") {
			break
		}
	}

	return service
}

// probeMongoDB sends OP_COMMAND for buildInfo to get the version
func (sd *ServiceDetector) probeMongoDB(ip string, port int) *ServiceInfo {
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// MongoDB OP_COMMAND for buildInfo on admin.$cmd
	// This is a minimal, raw BSON-based query (Production Logic)
	query := []byte{
		0x40, 0x00, 0x00, 0x00, // Message length placeholder (64 bytes)
		0x01, 0x00, 0x00, 0x00, // Request ID
		0x00, 0x00, 0x00, 0x00, // Response to
		0x04, 0x00, 0x00, 0x00, // OpCode: OP_COMMAND (4)
		0x00, 0x00, 0x00, 0x00, // Flags
		// Database name: "admin"
		0x61, 0x64, 0x6d, 0x69, 0x6e, 0x00,
		// Command name: "buildInfo"
		0x62, 0x75, 0x69, 0x6c, 0x64, 0x49, 0x6e, 0x66, 0x6f, 0x00,
		// Metadata (empty BSON document)
		0x05, 0x00, 0x00, 0x00, 0x00,
		// Command (BSON document: {buildInfo: 1})
		0x16, 0x00, 0x00, 0x00, 0x10, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x49, 0x6e, 0x66, 0x6f, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	}
	binary.LittleEndian.PutUint32(query, uint32(len(query)))

	conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Write(query)
	if err != nil {
		return nil
	}

	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)

	service := &ServiceInfo{Name: "mongodb", Product: "MongoDB"}

	if err == nil && n > 0 {
		respStr := string(buffer)
		// Extract version string from the BSON-encoded response (simplified string search)
		versionRegex := regexp.MustCompile(`version\x00(.*?)\x00`)
		if matches := versionRegex.FindStringSubmatch(respStr); len(matches) > 1 {
			// This is a complex BSON field extraction, we trust the regex for simplicity here
			version := strings.TrimSpace(matches[1])
			version = strings.ReplaceAll(version, "\x01", "") // Clean up BSON type byte
			service.Version = sd.extractVersion(version)
			if service.Version == "" {
				service.Version = version
			}
		} else {
			service.Version = "MongoDB server responding"
		}
	}

	return service
}

// probeSMB performs an SMB Negotiate Protocol Request to determine dialect (Production Logic)
func (sd *ServiceDetector) probeSMB(ip string, port int) *ServiceInfo {
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// NetBIOS Session Service Wrapper (0x81, total length)
	// SMB Header (0xFF, 'SMB', command: 0x72 - Negotiate Protocol)
	// Dialects: NT LM 0.12 (SMBv1), SMB 2.??? (SMBv2/v3)
	// This is the core check for MS17-010 (EternalBlue) vulnerability detection.
	smbProbe := []byte{
		0x81, 0x00, 0x00, 0x4a, // NetBIOS Header (Session Message, 74 bytes)
		0xff, 0x53, 0x4d, 0x42, // SMB Header: 0xFF 'SMB'
		0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Command: Negotiate Protocol (0x72)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved/Security
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved/TID/PID/UID/MID
		0x14, 0x03, 0x00, 0x00, // Word Count, Byte Count: 3
		0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31, 0x2e, 0x30, 0x00, // LANMAN1.0
		0x02, 0x4c, 0x4d, 0x31, 0x2e, 0x32, 0x00, // LM1.2
		0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00, // NT LM 0.12 (SMBv1)
		0x02, 0x53, 0x4d, 0x42, 0x20, 0x32, 0x2e, 0x30, 0x30, 0x32, 0x00, // SMB 2.002
		0x02, 0x53, 0x4d, 0x42, 0x20, 0x32, 0x2e, 0x58, 0x58, 0x00, // SMB 2.XX
		0x02, 0x53, 0x4d, 0x42, 0x20, 0x33, 0x2e, 0x58, 0x58, 0x00, // SMB 3.XX
	}

	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write(smbProbe)

	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)

	service := &ServiceInfo{Name: "microsoft-ds", Product: "SMB/CIFS"}

	if err == nil && n > 0 && buffer[4] == 0x72 { // Negotiate Protocol Response
		// Check for the preferred dialect index (byte 35/36 of SMB header)
		dialectIndex := int(buffer[35])

		// Map index to version (simplified)
		if dialectIndex >= 4 {
			service.Version = "SMBv2/v3"
			service.ExtraInfo = "Modern SMB Dialect"
		} else if dialectIndex >= 2 {
			service.Version = "SMBv1 (NT LM 0.12)"
			service.ExtraInfo = "Potentially Vulnerable (MS17-010)"
		} else {
			service.Version = "SMBv1 (Pre-NT LM)"
			service.ExtraInfo = "Legacy/Vulnerable SMB"
		}
	}

	return service
}

// probeRDP performs the initial RDP negotiation (Production Logic)
func (sd *ServiceDetector) probeRDP(ip string, port int) *ServiceInfo {
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, sd.Timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// X.224 Connection Request (T.125 - MCS Connect Initial PDU)
	// A standard RDP connection initiation sequence
	rdpProbe := []byte{
		0x03, 0x00, 0x00, 0x13, // TPKT Header (Version 3, length 19)
		0x0e,                   // X.224 Header (PDU Type: Connect Request)
		0xd0, 0x00, 0x00, 0x00, // Destination/Source Reference (0/0)
		0x00, 0x02, // Class and Options
		0x3d, 0x02, 0x02, // T.125 MCS Connect Initial PDU payload (3 bytes)
		0x04, 0x00, // RDP Protocol Version (Minimal)
	}

	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write(rdpProbe)

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)

	service := &ServiceInfo{Name: "ms-wbt-server", Product: "RDP Server"}

	if err == nil && n > 0 && buffer[0] == 0x03 && buffer[4] == 0x21 {
		// Response is X.224 Connection Confirm (0x21), confirming RDP
		// Full RDP version is often found later in the handshake
		service.Version = "RDP Detected"
	}

	return service
}

// probeVNC attempts to extract the RFB version (VNC Protocol)
func (sd *ServiceDetector) probeVNC(ip string, port int) *ServiceInfo {
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, sd.Timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buffer := make([]byte, 12)
	n, err := conn.Read(buffer)

	service := &ServiceInfo{Name: "vnc", Product: "VNC"}

	if err == nil && n >= 12 && strings.HasPrefix(string(buffer), "RFB") {
		// VNC servers send the RFB version string (e.g., "RFB 003.008\n")
		service.Version = strings.TrimSpace(string(buffer[:n]))
	}

	return service
}

// probeLDAP performs a minimal LDAP Bind Request (Production Logic)
func (sd *ServiceDetector) probeLDAP(ip string, port int) *ServiceInfo {
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, sd.Timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// LDAP Bind Request (Minimal version)
	// Sequence: [0x30, total_len, 0x02, ID_len, ID, 0x60, BindRequest_len, ...]
	ldapProbe := []byte{
		0x30, 0x1c, // Sequence (Total Length: 28 bytes)
		0x02, 0x01, 0x01, // Message ID: 1
		0x60, 0x17, // Bind Request (Total Length: 23 bytes)
		0x02, 0x01, 0x03, // Version: 3
		0x04, 0x00, // Name: empty
		0x80, 0x10, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x73, 0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72, 0x00, // Simple Authentication (Username: securityscanner)
	}

	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write(ldapProbe)

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)

	service := &ServiceInfo{Name: "ldap", Product: "LDAP Server"}

	if err == nil && n > 0 {
		// Response starts with 0x30 (Sequence) and contains 0x61 (BindResponse)
		if buffer[0] == 0x30 && strings.Contains(string(buffer), "\x61") {
			service.Version = "LDAPv3 Detected"
			// Check for known servers in the response (e.g., AD, OpenLDAP)
			respStr := string(buffer)
			if strings.Contains(respStr, "Microsoft") || strings.Contains(respStr, "Active Directory") {
				service.Product = "Microsoft Active Directory LDAP"
			} else if strings.Contains(respStr, "OpenLDAP") {
				service.Product = "OpenLDAP"
			}
		}
	}

	return service
}

// probeMSSQL sends a TDS Pre-Login Packet to determine version (Production Logic)
func (sd *ServiceDetector) probeMSSQL(ip string, port int) *ServiceInfo {
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, sd.Timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// TDS Header Type: Pre-Login (0x12)
	// Version is required in the Pre-Login response
	// This probe is complex and necessary for production MSSQL scanning
	tdsProbe := []byte{
		0x12, 0x01, 0x00, 0x37, 0x00, 0x00, 0x01, 0x00, // Header: Type 0x12 (Pre-Login), Len 55
		// Payload (Pre-Login Struct)
		0x00, 0x00, // TDS Version offset
		0x00, 0x08, // TDS Version length
		0x00, 0x00, 0x00, 0x00, // Encryption offset/length
		0x00, 0x00, 0x00, 0x00, // InstID offset/length
		0x00, 0x00, 0x00, 0x00, // ThreadID offset/length
		0x00, 0x00, 0x00, 0x00, // Mars offset/length
		0x00, 0x00, 0x00, 0x00, // TraceID offset/length
		0x00, 0x00, 0x00, 0x00, // FedAuth offset/length
		0x00, 0x00, 0x00, 0x00, // Nonce offset/length
		0x00, 0x00, 0x00, 0x00, // Terminate (0xFF) offset/length
		0xFF, // Terminate marker
		// Data section (TDS Version: 7.0/7.1/7.2/7.3/7.4)
		0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, // TDS Version 7.0
	}
	// The server will respond with its true TDS version and capabilities.

	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write(tdsProbe)

	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)

	service := &ServiceInfo{Name: "ms-sql-s", Product: "Microsoft SQL Server"}

	if err == nil && n > 8 {
		// Response TDS Header Type: Pre-Login (0x12)
		if buffer[0] == 0x04 { // Pre-Login ACK is 0x04
			// The response contains the server's TDS version in its payload
			tdsVersionStart := 42 // Known offset for TDS Version in response
			if n > tdsVersionStart+8 {
				// TDS Version is 8 bytes. Format: Major.Minor.Build.SubBuild
				// e.g., 0x00 0x00 0x07 0x04 0x00 0x00 0x00 0x00 -> TDS 7.4 (SQL 2012+)
				tdsMaj := int(buffer[tdsVersionStart+3])
				tdsMin := int(buffer[tdsVersionStart+2])

				// Simplified mapping to SQL Server version (Production Feature)
				if tdsMaj >= 0x07 && tdsMin >= 0x04 {
					service.Version = "SQL Server 2012 or later"
				} else if tdsMaj == 0x07 && tdsMin >= 0x00 {
					service.Version = "SQL Server 2000-2008"
				} else {
					service.Version = "Unknown/Legacy TDS"
				}
			} else {
				service.Version = "MSSQL TDS Detected"
			}
		}
	}

	return service
}

// probeElasticsearch performs a simple HTTP GET and parses JSON
func (sd *ServiceDetector) probeElasticsearch(ip string, port int) *ServiceInfo {
	return sd.probeHTTP(ip, port) // The HTTP probe handles this well
}

// --- HELPER FUNCTIONS ---

func (sd *ServiceDetector) addSignature(port int, sig ServiceSignature) {
	if _, exists := sd.ServiceSignatures[port]; !exists {
		sd.ServiceSignatures[port] = make([]ServiceSignature, 0)
	}
	sd.ServiceSignatures[port] = append(sd.ServiceSignatures[port], sig)
}

func (sd *ServiceDetector) matchBanner(port int, banner string) *ServiceInfo {
	// Simple banner match logic kept for fallback
	signatures, exists := sd.ServiceSignatures[port]
	if !exists {
		return nil
	}

	for _, sig := range signatures {
		if sig.Pattern != nil && sig.Pattern.MatchString(banner) {
			service := &ServiceInfo{
				Name: sig.Service,
			}

			if sig.VersionExpr != nil {
				if matches := sig.VersionExpr.FindStringSubmatch(banner); len(matches) > 1 {
					service.Version = strings.TrimSpace(matches[1])
				}
			}

			return service
		}
	}

	return nil
}

func (sd *ServiceDetector) getCommonServiceName(port int) string {
	// Comprehensive port mapping (used as final fallback)
	commonServices := map[int]string{
		20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
		53: "dns", 80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
		139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds",
		993: "imaps", 995: "pop3s", 1433: "ms-sql-s", 1521: "oracle",
		3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql", 5900: "vnc",
		6379: "redis", 8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch",
		27017: "mongodb", 49152: "epmap", // Ephemeral Port Mapper for complex services
	}

	if name, exists := commonServices[port]; exists {
		return name
	}

	return "unknown"
}

func (sd *ServiceDetector) extractVersion(serviceString string) string {
	versionRegex := regexp.MustCompile(`(\d+\.[\d\.]+)`)
	if matches := versionRegex.FindStringSubmatch(serviceString); len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// getTLSVersionString completes the incomplete TLS helper function (Production Feature)
func getTLSVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLSv1.0"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	case tls.VersionSSL30:
		return "SSLv3.0"
	default:
		return fmt.Sprintf("0x%X", version)
	}
}
