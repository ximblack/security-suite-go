package main

import (
	"math/rand"
	"net"
	"regexp"
	"sync"
	"time"
)

// --- Core Security Data Models (Single Source of Truth) ---

// ThreatLevel defines the severity of a detected threat.
type ThreatLevel string

const (
	ThreatLevelInfo     ThreatLevel = "INFO"
	ThreatLevelLow      ThreatLevel = "LOW"
	ThreatLevelMedium   ThreatLevel = "MEDIUM"
	ThreatLevelHigh     ThreatLevel = "HIGH"
	ThreatLevelCritical ThreatLevel = "CRITICAL"
)

// ResponseAction defines potential automated responses.
type ResponseAction string

const (
	ActionLogOnly            ResponseAction = "LOG_ONLY"
	ActionNotify             ResponseAction = "NOTIFY_USER"
	ActionBlockPort          ResponseAction = "BLOCK_PORT"
	ActionQuarantine         ResponseAction = "QUARANTINE_DEVICE"
	ActionBlockNetworkAccess ResponseAction = "BLOCK_NETWORK_ACCESS"
	ActionQuarantineFile     ResponseAction = "QUARANTINE_FILE"
	ActionIsolateHost        ResponseAction = "ISOLATE_HOST"
	ActionSendAlert          ResponseAction = "SEND_ALERT"
	ActionLogToDB            ResponseAction = "LOG_TO_DB"
	ActionIncreaseMonitoring ResponseAction = "INCREASE_MONITORING"
	ActionAttemptRemediation ResponseAction = "ATTEMPT_REMEDIATION"
	ActionBlock              ResponseAction = "BLOCK"
	ActionLog                ResponseAction = "LOG"
	ActionLogAndMonitor      ResponseAction = "LOG_AND_MONITOR"
)

// ThreatIndicator represents a single security event or finding.
type ThreatIndicator struct {
	Timestamp time.Time              `json:"timestamp"`
	SourceID  string                 `json:"source_id"` // e.g., "IDS-ALERT-1002"
	SourceIP  string                 `json:"source_ip"`
	Target    string                 `json:"target"` // file path, network connection, or process
	Protocol  string                 `json:"protocol"`
	Severity  ThreatLevel            `json:"severity"`
	Signature string                 `json:"signature"` // Name of matched pattern/rule
	Context   string                 `json:"context"`   // Detailed explanation
	Score     float64                `json:"score"`     // Numerical score (e.g., anomaly score)
	Action    ResponseAction         `json:"action"`    // Suggested action
	Details   map[string]interface{} `json:"details"`   // Additional dynamic information
	Type      string                 `json:"type"`      // Type of threat
}

// ThreatEvent is used by response_orchestrator.go and security_suite.go
type ThreatEvent struct {
	Timestamp      time.Time
	SourceModule   string
	Severity       ThreatLevel
	Description    string
	AssociatedData string // IP address or file path
}

// BehaviorProfile holds aggregated data for a single IP address.
type BehaviorProfile struct {
	DeviceIP             string             `json:"device_ip"`
	ConnectionFrequency  map[string]float64 `json:"connection_frequency"`
	DataTransferPattern  []float64          `json:"data_transfer_pattern"` // 24 hourly slots
	ActiveHours          []int              `json:"active_hours"`          // Hours 0-23
	ProtocolDistribution map[string]float64 `json:"protocol_distribution"`
	TypicalServices      []int              `json:"typical_services"`
	FirstSeen            time.Time          `json:"first_seen"`
	LastUpdate           time.Time          `json:"last_update"`
	FeatureVector        []float64          `json:"feature_vector"`
	AlertHistory         []ThreatIndicator  `json:"alert_history"`
	AnomalyScore         float64            `json:"anomaly_score"`
	AnomalyScoreHistory  []float64          `json:"anomaly_score_history"`
	IsQuarantined        bool               `json:"is_quarantined"`
}

// ThreatPattern defines a signature used for detection.
type ThreatPattern struct {
	Name        string      `json:"name"`
	Pattern     string      `json:"pattern"` // hash, regex, or YARA rule
	PatternType string      `json:"pattern_type"`
	Severity    ThreatLevel `json:"severity"`
	Description string      `json:"description"`
	Tags        []string    `json:"tags"`
}

// ResponseOutcome records the result of an executed response action.
type ResponseOutcome struct {
	Action        ResponseAction `json:"action"`
	Status        string         `json:"status"` // COMPLETED, PENDING, FAILED
	Message       string         `json:"message"`
	ExecutionTime time.Time      `json:"execution_time"`
	ThreatID      string         `json:"threat_id"`
	Target        string         `json:"target"`
}

// RuleManagerStatus reports IDS rule status.
type RuleManagerStatus struct {
	RulesLoaded      bool     `json:"rules_loaded"`
	LastUpdated      string   `json:"last_updated"`
	Error            string   `json:"error"`
	RulesVersion     string   `json:"rules_version"`
	ActiveInterfaces []string `json:"active_interfaces"`
}

// IDSStatus is the public-facing IDS status.
type IDSStatus struct {
	Monitoring        bool              `json:"monitoring"`
	Interface         string            `json:"interface"`
	RuleManagerStatus RuleManagerStatus `json:"rule_manager_status"`
}

// SystemStatus aggregates all module statuses.
type SystemStatus struct {
	OverallHealth      string            `json:"overall_health"`
	RuleManager        RuleManagerStatus `json:"rule_manager"`
	MalwareEngine      ModuleStatus      `json:"malware_engine"`
	BehavioralAnalyzer ModuleStatus      `json:"behavioral_analyzer"`
	Timestamp          time.Time         `json:"timestamp"`
}

// ModuleStatus represents the status of a security module.
type ModuleStatus struct {
	Enabled       bool   `json:"enabled"`
	EngineVersion string `json:"engine_version"`
	ModelVersion  string `json:"model_version"`
	LastUpdate    string `json:"last_update"`
}

// --- Suricata/IDS Log Structures ---

// AlertDetails captures the nested 'alert' object in EVE JSON.
type AlertDetails struct {
	Action      string `json:"action"`
	GID         int    `json:"gid"`
	SignatureID int    `json:"signature_id"`
	Rev         int    `json:"rev"`
	Signature   string `json:"signature"`
	Category    string `json:"category"`
	Severity    int    `json:"severity"`
}

// SuricataLogEntry represents a line in eve.json log.
type SuricataLogEntry struct {
	Timestamp time.Time    `json:"timestamp"`
	EventType string       `json:"event_type"`
	SrcIP     string       `json:"src_ip"`
	DestIP    string       `json:"dest_ip"`
	Proto     string       `json:"proto"`
	SrcPort   int          `json:"src_port"`
	DestPort  int          `json:"dest_port"`
	Alert     AlertDetails `json:"alert"`
}

// IDSAlert represents an alert from Suricata EVE JSON log.
type IDSAlert struct {
	Timestamp time.Time `json:"timestamp"`
	EventType string    `json:"event_type"`
	SourceIp  string    `json:"src_ip"`
	DestIp    string    `json:"dest_ip"`
	Protocol  string    `json:"proto"`
	Alert     struct {
		Signature string `json:"signature"`
		Severity  int    `json:"severity"`
		Action    string `json:"action"`
	} `json:"alert"`
}

// LogMessage represents a log message for inter-module communication
type LogMessage struct {
	Level string
	Text  string
}

// ServiceInfo holds banner and version data for a discovered service
type ServiceInfo struct {
	Port       int
	Name       string
	Version    string
	Product    string
	Banner     string
	ExtraInfo  string
	Hostname   string
	OS         string
	DeviceType string
	CPE        []string
}

// Vulnerability holds a detected vulnerability finding
type Vulnerability struct {
	ID          string
	Description string
	Severity    ThreatLevel
	CVSS        float64
	Port        int
	Service     string
	Mitigation  string
	References  []string
}

// MalwareBehavior defines patterns associated with known malware
type MalwareBehavior struct {
	Ports     []int
	Protocols []string
	Patterns  []string
	Severity  ThreatLevel
	IOCs      map[string]string
}

// OSFingerprint contains OS detection results
type OSFingerprint struct {
	IP             string
	OS             string
	Accuracy       int
	Vendor         string
	OSFamily       string
	OSGeneration   string
	DeviceType     string
	TTL            int
	WindowSize     int
	TCPFingerprint string
	Services       map[int]*ServiceInfo
}

// BaselineStatistics holds statistical baselines for anomaly detection
type BaselineStatistics struct {
	BytesInMean    float64
	BytesInStdDev  float64
	BytesOutMean   float64
	BytesOutStdDev float64
	ConnRateMean   float64
	ConnRateStdDev float64
	DNSCountMean   float64
	DNSCountStdDev float64
	LastUpdated    time.Time
}

// IsolationForest implements isolation forest algorithm for anomaly detection
type IsolationForest struct {
	Trees         []*IsolationTree
	NumTrees      int
	SubsampleSize int
	MaxDepth      int
	TrainingData  [][]float64
	mu            sync.RWMutex
	rng           *rand.Rand
}

// IsolationTree represents a single tree in the isolation forest
type IsolationTree struct {
	Root     *IsolationNode
	MaxDepth int
}

// IsolationNode represents a node in the isolation tree
type IsolationNode struct {
	SplitFeature int
	SplitValue   float64
	Left         *IsolationNode
	Right        *IsolationNode
	Size         int
	IsLeaf       bool
}

// OSSignature defines a production-grade signature for a specific OS
type OSSignature struct {
	ID           string
	OS           string
	Confidence   int
	TTL          []int
	WindowSize   []int
	TCPFlags     []string
	TCPOptions   []string
	MatchContext string
}

// ServiceSignature defines patterns for service identification
type ServiceSignature struct {
	Service     string
	Pattern     *regexp.Regexp
	VersionExpr *regexp.Regexp
	ProbeFunc   func(ip string, port int) *ServiceInfo
}

// TLSInfo contains SSL/TLS certificate information
type TLSInfo struct {
	Version      string
	Cipher       string
	Issuer       string
	Subject      string
	NotBefore    time.Time
	NotAfter     time.Time
	IsExpired    bool
	IsSelfSigned bool
	SANs         []string
}

// Helper functions
func containsInt(s []int, e int) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func containsString(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	if ip.To4() != nil {
		privateRanges := []struct {
			start string
			end   string
		}{
			{"10.0.0.0", "10.255.255.255"},
			{"172.16.0.0", "172.31.255.255"},
			{"192.168.0.0", "192.168.255.255"},
			{"127.0.0.0", "127.255.255.255"},
			{"169.254.0.0", "169.254.255.255"},
		}

		for _, r := range privateRanges {
			start := net.ParseIP(r.start).To4()
			end := net.ParseIP(r.end).To4()
			if ipInRange(ip.To4(), start, end) {
				return true
			}
		}
		return false
	}

	if ip.To16() != nil && ip.To4() == nil {
		if ip.IsPrivate() {
			return true
		}
	}

	return false
}

func ipInRange(ip, start, end net.IP) bool {
	if len(ip) != len(start) || len(ip) != len(end) {
		return false
	}
	for i := range ip {
		if ip[i] < start[i] {
			return false
		}
		if ip[i] > end[i] {
			return false
		}
		if ip[i] > start[i] && ip[i] < end[i] {
			return true
		}
	}
	return true
}
