package main

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ServiceDetector identifies services running on open ports
type ServiceDetector struct {
	ServiceSignatures map[int][]ServiceSignature
	Timeout           time.Duration
}

// ServiceSignature defines patterns for service identification
type ServiceSignature struct {
	Service     string
	Pattern     *regexp.Regexp
	VersionExpr *regexp.Regexp
	Probe       []byte
}

// NewServiceDetector creates a new service detector
func NewServiceDetector() *ServiceDetector {
	sd := &ServiceDetector{
		ServiceSignatures: make(map[int][]ServiceSignature),
		Timeout:           5 * time.Second,
	}

	sd.loadSignatures()
	return sd
}

// loadSignatures loads service detection signatures
func (sd *ServiceDetector) loadSignatures() {
	// HTTP signatures
	sd.addSignature(80, ServiceSignature{
		Service:     "http",
		Pattern:     regexp.MustCompile(`HTTP/\d\.\d`),
		VersionExpr: regexp.MustCompile(`Server:\s*([^\r\n]+)`),
		Probe:       []byte("GET / HTTP/1.0\r\n\r\n"),
	})

	sd.addSignature(443, ServiceSignature{
		Service:     "https",
		Pattern:     regexp.MustCompile(`HTTP/\d\.\d`),
		VersionExpr: regexp.MustCompile(`Server:\s*([^\r\n]+)`),
	})

	sd.addSignature(8080, ServiceSignature{
		Service:     "http-proxy",
		Pattern:     regexp.MustCompile(`HTTP/\d\.\d`),
		VersionExpr: regexp.MustCompile(`Server:\s*([^\r\n]+)`),
		Probe:       []byte("GET / HTTP/1.0\r\n\r\n"),
	})

	// SSH signatures
	sd.addSignature(22, ServiceSignature{
		Service:     "ssh",
		Pattern:     regexp.MustCompile(`SSH-\d\.\d`),
		VersionExpr: regexp.MustCompile(`SSH-\d\.\d-([^\r\n]+)`),
	})

	// FTP signatures
	sd.addSignature(21, ServiceSignature{
		Service:     "ftp",
		Pattern:     regexp.MustCompile(`^220`),
		VersionExpr: regexp.MustCompile(`220[\s-]+([^\r\n]+)`),
	})

	// SMTP signatures
	sd.addSignature(25, ServiceSignature{
		Service:     "smtp",
		Pattern:     regexp.MustCompile(`^220`),
		VersionExpr: regexp.MustCompile(`220\s+([^\r\n]+)`),
		Probe:       []byte("EHLO test\r\n"),
	})

	// Telnet signatures
	sd.addSignature(23, ServiceSignature{
		Service: "telnet",
		Pattern: regexp.MustCompile(`[\xFF\xFD\xFE]`), // IAC commands
	})

	// MySQL signatures
	sd.addSignature(3306, ServiceSignature{
		Service:     "mysql",
		Pattern:     regexp.MustCompile(`mysql`),
		VersionExpr: regexp.MustCompile(`\x00(\d+\.\d+\.\d+)`),
	})

	// PostgreSQL signatures
	sd.addSignature(5432, ServiceSignature{
		Service: "postgresql",
		Pattern: regexp.MustCompile(`PostgreSQL|postgres`),
	})

	// Redis signatures
	sd.addSignature(6379, ServiceSignature{
		Service: "redis",
		Pattern: regexp.MustCompile(`\$\d+\r\n`),
		Probe:   []byte("*1\r\n$4\r\nPING\r\n"),
	})

	// MongoDB signatures
	sd.addSignature(27017, ServiceSignature{
		Service: "mongodb",
		Pattern: regexp.MustCompile(`MongoDB`),
	})

	// SMB signatures
	sd.addSignature(445, ServiceSignature{
		Service: "microsoft-ds",
		Pattern: regexp.MustCompile(`\xFFSMB`),
	})

	// RDP signatures
	sd.addSignature(3389, ServiceSignature{
		Service: "ms-wbt-server",
		Pattern: regexp.MustCompile(`\x03\x00\x00`),
	})

	// VNC signatures
	sd.addSignature(5900, ServiceSignature{
		Service:     "vnc",
		Pattern:     regexp.MustCompile(`RFB \d{3}\.\d{3}`),
		VersionExpr: regexp.MustCompile(`RFB (\d{3}\.\d{3})`),
	})
}

// addSignature adds a service signature to the detector
func (sd *ServiceDetector) addSignature(port int, sig ServiceSignature) {
	if _, exists := sd.ServiceSignatures[port]; !exists {
		sd.ServiceSignatures[port] = make([]ServiceSignature, 0)
	}
	sd.ServiceSignatures[port] = append(sd.ServiceSignatures[port], sig)
}

// DetectService identifies the service running on a port
func (sd *ServiceDetector) DetectService(ip string, port int, banner string) *ServiceInfo {
	service := &ServiceInfo{
		Name: "unknown",
	}

	// Try banner matching first
	if banner != "" {
		if detected := sd.matchBanner(port, banner); detected != nil {
			return detected
		}
	}

	// Try probing
	if signatures, exists := sd.ServiceSignatures[port]; exists {
		for _, sig := range signatures {
			if sig.Probe != nil {
				if probeResult := sd.probeService(ip, port, sig); probeResult != nil {
					return probeResult
				}
			}
		}
	}

	// Fallback to common port mapping
	service.Name = sd.getCommonServiceName(port)

	return service
}

// matchBanner matches a banner against known signatures
func (sd *ServiceDetector) matchBanner(port int, banner string) *ServiceInfo {
	signatures, exists := sd.ServiceSignatures[port]
	if !exists {
		return nil
	}

	for _, sig := range signatures {
		if sig.Pattern.MatchString(banner) {
			service := &ServiceInfo{
				Name: sig.Service,
			}

			// Extract version if possible
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

// probeService actively probes a service
func (sd *ServiceDetector) probeService(ip string, port int, sig ServiceSignature) *ServiceInfo {
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, sd.Timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// Send probe
	if sig.Probe != nil {
		conn.SetWriteDeadline(time.Now().Add(sd.Timeout))
		_, err = conn.Write(sig.Probe)
		if err != nil {
			return nil
		}
	}

	// Read response
	conn.SetReadDeadline(time.Now().Add(sd.Timeout))
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil || n == 0 {
		return nil
	}

	response := string(buffer[:n])

	// Match pattern
	if sig.Pattern.MatchString(response) {
		service := &ServiceInfo{
			Name: sig.Service,
		}

		// Extract version
		if sig.VersionExpr != nil {
			if matches := sig.VersionExpr.FindStringSubmatch(response); len(matches) > 1 {
				service.Version = strings.TrimSpace(matches[1])
			}
		}

		return service
	}

	return nil
}

// getCommonServiceName returns the common service name for a port
func (sd *ServiceDetector) getCommonServiceName(port int) string {
	commonServices := map[int]string{
		20:    "ftp-data",
		21:    "ftp",
		22:    "ssh",
		23:    "telnet",
		25:    "smtp",
		53:    "dns",
		80:    "http",
		110:   "pop3",
		111:   "rpcbind",
		135:   "msrpc",
		139:   "netbios-ssn",
		143:   "imap",
		443:   "https",
		445:   "microsoft-ds",
		993:   "imaps",
		995:   "pop3s",
		1433:  "ms-sql-s",
		1521:  "oracle",
		3306:  "mysql",
		3389:  "ms-wbt-server",
		5432:  "postgresql",
		5900:  "vnc",
		6379:  "redis",
		8080:  "http-proxy",
		27017: "mongodb",
	}

	if name, exists := commonServices[port]; exists {
		return name
	}

	return "unknown"
}

// DetectHTTPService performs detailed HTTP service detection
func (sd *ServiceDetector) DetectHTTPService(ip string, port int) *ServiceInfo {
	service := &ServiceInfo{
		Name: "http",
	}

	address := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, sd.Timeout)
	if err != nil {
		return service
	}
	defer conn.Close()

	// Send HTTP request
	request := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: SecurityScanner/2.0\r\nConnection: close\r\n\r\n", ip)
	conn.Write([]byte(request))

	// Read response
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buffer := make([]byte, 8192)
	n, _ := conn.Read(buffer)

	if n > 0 {
		response := string(buffer[:n])

		// Extract Server header
		serverRegex := regexp.MustCompile(`Server:\s*([^\r\n]+)`)
		if matches := serverRegex.FindStringSubmatch(response); len(matches) > 1 {
			service.Product = matches[1]
			service.Version = sd.extractVersion(matches[1])
		}

		// Detect specific technologies
		if strings.Contains(response, "X-Powered-By: PHP") {
			service.ExtraInfo = "PHP"
		} else if strings.Contains(response, "X-AspNet-Version") {
			service.ExtraInfo = "ASP.NET"
		}
	}

	return service
}

// extractVersion extracts version from service string
func (sd *ServiceDetector) extractVersion(serviceString string) string {
	versionRegex := regexp.MustCompile(`(\d+\.[\d\.]+)`)
	if matches := versionRegex.FindStringSubmatch(serviceString); len(matches) > 1 {
		return matches[1]
	}
	return ""
}
