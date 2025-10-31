package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// StreamInfo holds data about a detected stream
type StreamInfo struct {
	URL    string `json:"url"`
	Status string `json:"status"`
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// StreamDetector detects network video streams using production protocols
type StreamDetector struct {
	streamPatterns    []*regexp.Regexp
	commonCameraPorts []int
	detectionTimeout  time.Duration
	httpClient        *http.Client
	cache             map[string]*CachedStreamResult
	cacheMu           sync.RWMutex
}

// CachedStreamResult caches stream detection results
type CachedStreamResult struct {
	Info      *StreamInfo
	Timestamp time.Time
}

// NewStreamDetector initializes a production stream detector
func NewStreamDetector() *StreamDetector {
	// Create HTTP client with custom transport
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // For self-signed certificates
		},
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 5 * time.Second,
		}).DialContext,
		MaxIdleConns:       10,
		IdleConnTimeout:    10 * time.Second,
		DisableCompression: true,
		DisableKeepAlives:  false,
	}

	return &StreamDetector{
		streamPatterns: []*regexp.Regexp{
			regexp.MustCompile(`^rtsp://`),
			regexp.MustCompile(`^rtsps://`),
			regexp.MustCompile(`^http://`),
			regexp.MustCompile(`^https://`),
		},
		commonCameraPorts: []int{
			554,  // RTSP default
			8554, // RTSP alternate
			80,   // HTTP
			8080, // HTTP alternate
			443,  // HTTPS
			8443, // HTTPS alternate
			8000, // Common camera port
			8001, // Common camera port
			5000, // MJPEG common
			81,   // Camera alternate
		},
		detectionTimeout: 5 * time.Second,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return fmt.Errorf("stopped after 3 redirects")
				}
				return nil
			},
		},
		cache: make(map[string]*CachedStreamResult),
	}
}

// isIPAddress checks if string is valid IP
func (d *StreamDetector) isIPAddress(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil
}

// extractName extracts descriptive name from URL
func (d *StreamDetector) extractName(u string) string {
	parsedURL, err := url.Parse(u)
	if err != nil || parsedURL.Host == "" {
		return "Unknown Stream"
	}
	return parsedURL.Host
}

// tryOpenFeed attempts to connect to a stream URL
func (d *StreamDetector) tryOpenFeed(u string) *StreamInfo {
	parsedURL, err := url.Parse(u)
	if err != nil || parsedURL.Host == "" {
		log.Printf("[StreamDetector] Invalid URL: %s", u)
		return nil
	}

	host := parsedURL.Hostname()
	port := parsedURL.Port()
	scheme := parsedURL.Scheme

	// Infer port from scheme if not specified
	if port == "" {
		switch scheme {
		case "rtsp", "rtsps":
			port = "554"
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			return nil
		}
	}

	address := net.JoinHostPort(host, port)

	log.Printf("[StreamDetector] Probing %s at %s...", scheme, address)

	// Try TCP connection first
	ctx, cancel := context.WithTimeout(context.Background(), d.detectionTimeout)
	defer cancel()

	var d_dialer net.Dialer
	conn, err := d_dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		log.Printf("[StreamDetector] Connection failed: %v", err)
		return nil
	}
	defer conn.Close()

	// Set deadline for read operations
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	if scheme == "http" || scheme == "https" {
		return d.detectHTTPStream(u)
	} else if scheme == "rtsp" || scheme == "rtsps" {
		return d.detectRTSPStream(u, conn)
	}

	return nil
}

// detectHTTPStream detects HTTP/HTTPS video streams
func (d *StreamDetector) detectHTTPStream(streamURL string) *StreamInfo {
	req, err := http.NewRequest("GET", streamURL, nil)
	if err != nil {
		return nil
	}

	// Set headers that cameras typically respond to
	req.Header.Set("User-Agent", "SecuritySuite/2.0")
	req.Header.Set("Accept", "*/*")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		log.Printf("[StreamDetector] HTTP request failed: %v", err)
		return nil
	}
	defer resp.Body.Close()

	// Check content type for video streams
	contentType := resp.Header.Get("Content-Type")
	log.Printf("[StreamDetector] Content-Type: %s", contentType)

	if strings.Contains(contentType, "multipart/x-mixed-replace") ||
		strings.Contains(contentType, "video/") ||
		strings.Contains(contentType, "image/jpeg") ||
		strings.Contains(contentType, "application/octet-stream") {

		info := &StreamInfo{
			URL:    streamURL,
			Status: "active",
			Name:   d.extractName(streamURL),
			Reason: fmt.Sprintf("HTTP stream detected (Content-Type: %s)", contentType),
		}
		log.Printf("[StreamDetector] Stream DETECTED: %s", streamURL)
		return info
	}

	// Check for common camera web interfaces
	if resp.StatusCode == 200 || resp.StatusCode == 401 {
		info := &StreamInfo{
			URL:    streamURL,
			Status: "detected (partial)",
			Name:   d.extractName(streamURL),
			Reason: fmt.Sprintf("HTTP server responding (Status: %d), may be camera web interface", resp.StatusCode),
		}
		return info
	}

	return nil
}

// detectRTSPStream detects RTSP video streams
func (d *StreamDetector) detectRTSPStream(streamURL string, conn net.Conn) *StreamInfo {
	// Send RTSP OPTIONS request
	rtspRequest := fmt.Sprintf("OPTIONS %s RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: SecuritySuite/2.0\r\n\r\n", streamURL)

	_, err := conn.Write([]byte(rtspRequest))
	if err != nil {
		log.Printf("[StreamDetector] Failed to send RTSP request: %v", err)
		return nil
	}

	// Read response
	buffer := make([]byte, 2048)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Printf("[StreamDetector] Failed to read RTSP response: %v", err)
		return nil
	}

	response := string(buffer[:n])
	log.Printf("[StreamDetector] RTSP Response: %s", response)

	// Check for RTSP response
	if strings.Contains(response, "RTSP/1.0") {
		info := &StreamInfo{
			URL:    streamURL,
			Status: "active",
			Name:   d.extractName(streamURL),
			Reason: "RTSP stream confirmed via OPTIONS response",
		}
		log.Printf("[StreamDetector] RTSP Stream DETECTED: %s", streamURL)
		return info
	}

	return nil
}

// probeIPForStream probes an IP for common camera stream protocols
func (d *StreamDetector) probeIPForStream(ip string, explicitPort int) *StreamInfo {
	portsToTry := d.commonCameraPorts
	if explicitPort != 0 {
		portsToTry = []int{explicitPort}
	}

	log.Printf("[StreamDetector] Scanning %s for camera streams...", ip)

	// Common camera stream paths
	rtspPaths := []string{
		"/",
		"/live",
		"/stream",
		"/h264",
		"/video",
		"/cam1",
		"/ch01",
		"/Streaming/Channels/101",
		"/cam/realmonitor",
		"/videostream.cgi",
	}

	httpPaths := []string{
		"/",
		"/video",
		"/mjpg/video.mjpg",
		"/mjpeg",
		"/axis-cgi/mjpg/video.cgi",
		"/cgi-bin/viewer/video.jpg",
		"/videostream.cgi",
		"/snap.jpg",
		"/image.jpg",
	}

	// Try RTSP first (most common for cameras)
	for _, port := range portsToTry {
		if port == 554 || port == 8554 {
			for _, path := range rtspPaths {
				candidateURL := fmt.Sprintf("rtsp://%s%s", net.JoinHostPort(ip, strconv.Itoa(port)), path)
				if result := d.tryOpenFeed(candidateURL); result != nil {
					return result
				}
			}
		}
	}

	// Try HTTP/HTTPS
	for _, port := range portsToTry {
		if port == 80 || port == 8080 || port == 8000 || port == 81 {
			for _, path := range httpPaths {
				candidateURL := fmt.Sprintf("http://%s%s", net.JoinHostPort(ip, strconv.Itoa(port)), path)
				if result := d.tryOpenFeed(candidateURL); result != nil {
					return result
				}
			}
		}
		if port == 443 || port == 8443 {
			for _, path := range httpPaths {
				candidateURL := fmt.Sprintf("https://%s%s", net.JoinHostPort(ip, strconv.Itoa(port)), path)
				if result := d.tryOpenFeed(candidateURL); result != nil {
					return result
				}
			}
		}
	}

	log.Printf("[StreamDetector] No camera stream detected at %s", ip)
	return nil
}

// DetectStream is the main entry point for stream detection
func (d *StreamDetector) DetectStream(urlOrIP string, port int) *StreamInfo {
	urlOrIP = strings.TrimSpace(urlOrIP)

	// Check cache first
	cacheKey := fmt.Sprintf("%s:%s", urlOrIP, strconv.Itoa(port))
	d.cacheMu.RLock()
	cached, exists := d.cache[cacheKey]
	d.cacheMu.RUnlock()

	if exists && time.Since(cached.Timestamp) < 5*time.Minute {
		log.Printf("[StreamDetector] Returning cached result for %s", urlOrIP)
		return cached.Info
	}

	var result *StreamInfo

	// Check if it's a URL
	isURL := false
	for _, pattern := range d.streamPatterns {
		if pattern.MatchString(strings.ToLower(urlOrIP)) {
			isURL = true
			break
		}
	}

	if isURL {
		result = d.tryOpenFeed(urlOrIP)
	} else if d.isIPAddress(urlOrIP) {
		result = d.probeIPForStream(urlOrIP, port)
	} else {
		// Could be hostname
		result = d.probeIPForStream(urlOrIP, port)
	}

	// Cache result
	if result != nil {
		d.cacheMu.Lock()
		d.cache[cacheKey] = &CachedStreamResult{
			Info:      result,
			Timestamp: time.Now(),
		}
		d.cacheMu.Unlock()
	}

	return result
}

// ScanSubnet scans an entire subnet for camera streams
func (d *StreamDetector) ScanSubnet(subnet string) []*StreamInfo {
	results := make([]*StreamInfo, 0)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Parse CIDR
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		log.Printf("[StreamDetector] Invalid subnet: %v", err)
		return results
	}

	// Generate IP list
	ips := make([]string, 0)
	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); d.incIP(ip) {
		ips = append(ips, ip.String())
	}

	// Remove network and broadcast
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}

	log.Printf("[StreamDetector] Scanning subnet %s (%d hosts)...", subnet, len(ips))

	// Concurrent scan with semaphore
	semaphore := make(chan struct{}, 20) // Max 20 concurrent scans

	for _, ip := range ips {
		wg.Add(1)
		go func(targetIP string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if info := d.probeIPForStream(targetIP, 0); info != nil {
				mu.Lock()
				results = append(results, info)
				mu.Unlock()
				log.Printf("[StreamDetector] Found stream: %s", info.URL)
			}
		}(ip)
	}

	wg.Wait()
	log.Printf("[StreamDetector] Subnet scan complete. Found %d streams", len(results))

	return results
}

// incIP increments an IP address
func (d *StreamDetector) incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ClearCache clears the detection cache
func (d *StreamDetector) ClearCache() {
	d.cacheMu.Lock()
	defer d.cacheMu.Unlock()
	d.cache = make(map[string]*CachedStreamResult)
	log.Println("[StreamDetector] Cache cleared")
}

// GetCacheSize returns the number of cached results
func (d *StreamDetector) GetCacheSize() int {
	d.cacheMu.RLock()
	defer d.cacheMu.RUnlock()
	return len(d.cache)
}
