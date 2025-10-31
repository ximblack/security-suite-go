package main

import (
	"net"
	"strconv"
	"strings"
	"time"
)

// OSDetector performs operating system detection
type OSDetector struct {
	Timeout time.Duration
}

// NewOSDetector creates a new OS detector
func NewOSDetector() *OSDetector {
	return &OSDetector{
		Timeout: 5 * time.Second,
	}
}

// DetectOS attempts to identify the operating system
func (od *OSDetector) DetectOS(ip string, port int) *OSFingerprint {
	fingerprint := &OSFingerprint{
		OS:       "Unknown",
		Accuracy: 0,
	}

	// Collect TCP fingerprints
	tcpFingerprint := od.getTCPFingerprint(ip, port)
	if tcpFingerprint != nil {
		fingerprint.TTL = tcpFingerprint.TTL
		fingerprint.WindowSize = tcpFingerprint.WindowSize
		fingerprint.TCPFingerprint = tcpFingerprint.Signature
	}

	// Analyze fingerprint
	od.analyzeFingerprint(fingerprint)

	return fingerprint
}

// TCPFingerprint contains TCP/IP stack characteristics
type TCPFingerprint struct {
	TTL        int
	WindowSize int
	Signature  string
}

// getTCPFingerprint collects TCP/IP stack characteristics
func (od *OSDetector) getTCPFingerprint(ip string, port int) *TCPFingerprint {
	// This is a simplified implementation
	// Real OS detection would analyze:
	// - TCP window size
	// - TCP options
	// - IP TTL
	// - IP flags
	// - TCP timestamp
	// - TCP sequence numbers

	address := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, od.Timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	fingerprint := &TCPFingerprint{
		TTL:        64, // Would be extracted from raw socket
		WindowSize: 8192,
		Signature:  "Generic",
	}

	return fingerprint
}

// analyzeFingerprint analyzes collected data to identify OS
func (od *OSDetector) analyzeFingerprint(fp *OSFingerprint) {
	// TTL-based detection (simplified)
	switch fp.TTL {
	case 64:
		fp.OS = "Linux/Unix"
		fp.OSFamily = "Unix"
		fp.Accuracy = 70
	case 128:
		fp.OS = "Windows"
		fp.OSFamily = "Windows"
		fp.Accuracy = 70
	case 255:
		fp.OS = "Solaris/AIX"
		fp.OSFamily = "Unix"
		fp.Accuracy = 60
	}

	// Window size analysis
	if fp.WindowSize == 8192 {
		if fp.OS == "Linux/Unix" {
			fp.OS = "Linux 2.6.x/3.x/4.x"
			fp.Accuracy = 85
		}
	} else if fp.WindowSize == 65535 {
		if fp.OS == "Windows" {
			fp.OS = "Windows 10/11"
			fp.Accuracy = 80
		}
	}
}

// OSSignature defines OS detection signatures
type OSSignature struct {
	Name       string
	TTL        []int
	WindowSize []int
	TCPOptions string
	Accuracy   int
}

// Common OS signatures
var osSignatures = []OSSignature{
	{
		Name:       "Linux 4.x/5.x",
		TTL:        []int{64},
		WindowSize: []int{29200, 5840},
		TCPOptions: "M*,S,T,N,W*",
		Accuracy:   90,
	},
	{
		Name:       "Windows 10",
		TTL:        []int{128},
		WindowSize: []int{8192, 65535},
		TCPOptions: "M*,N,W*,S,T",
		Accuracy:   85,
	},
	{
		Name:       "Windows 11",
		TTL:        []int{128},
		WindowSize: []int{65535},
		TCPOptions: "M*,N,W*,S,T",
		Accuracy:   85,
	},
	{
		Name:       "macOS",
		TTL:        []int{64},
		WindowSize: []int{65535},
		TCPOptions: "M*,N,W*,N,N,T",
		Accuracy:   90,
	},
	{
		Name:       "FreeBSD",
		TTL:        []int{64},
		WindowSize: []int{65535},
		TCPOptions: "M*,N,W*,N,N,T",
		Accuracy:   85,
	},
}

// MatchSignature matches collected data against known signatures
func (od *OSDetector) MatchSignature(fp *OSFingerprint) *OSSignature {
	for _, sig := range osSignatures {
		// Check TTL
		ttlMatch := false
		for _, ttl := range sig.TTL {
			if fp.TTL == ttl {
				ttlMatch = true
				break
			}
		}

		if !ttlMatch {
			continue
		}

		// Check window size
		wsMatch := false
		for _, ws := range sig.WindowSize {
			if fp.WindowSize == ws {
				wsMatch = true
				break
			}
		}

		if wsMatch {
			return &sig
		}
	}

	return nil
}

// ServiceBasedOSDetection attempts OS detection based on service banners
func (od *OSDetector) ServiceBasedOSDetection(services map[int]*ServiceInfo) string {
	for _, service := range services {
		// SSH banner analysis
		if service.Name == "ssh" && service.Version != "" {
			if strings.Contains(service.Version, "Ubuntu") {
				return "Ubuntu Linux"
			} else if strings.Contains(service.Version, "Debian") {
				return "Debian Linux"
			} else if strings.Contains(service.Version, "Red Hat") {
				return "Red Hat Enterprise Linux"
			}
		}

		// HTTP server analysis
		if service.Name == "http" && service.Product != "" {
			if strings.Contains(service.Product, "Microsoft-IIS") {
				return "Windows Server"
			} else if strings.Contains(service.Product, "Apache") && strings.Contains(service.Product, "Ubuntu") {
				return "Ubuntu Linux"
			}
		}

		// SMB analysis
		if service.Name == "microsoft-ds" {
			return "Windows"
		}
	}

	return "Unknown"
}

// stringContains is a helper to check if a string contains a substring
func stringContains(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
