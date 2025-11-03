package main

import (
	"fmt"
	"log"
	"time"
)

// SecuritySuite is the main orchestrator for all security modules.
type SecuritySuite struct {
	Config               SuiteConfig
	Analyzer             *BehavioralAnalyzer
	IDS                  *IntrusionDetector
	MalwareDetector      *MalwareDetector
	TrafficDetector      *NetworkMalwareScanner
	ResponseOrchestrator *ResponseOrchestrator
	WebServer            *WebServer
	ScannerWrapper       *SecurityScannerWrapper
	ThreatHistory        []*ThreatEvent
}

// SuiteConfig holds configuration for the entire suite.
type SuiteConfig struct {
	LogLevel         string
	DBPath           string
	AnalysisInterval time.Duration
}

// NewSecuritySuite initializes all components and returns the main suite instance.
func NewSecuritySuite(config SuiteConfig) *SecuritySuite {
	log.Println("Initializing security components...")

	// Initialize RuleManager first
	ruleManager := NewRuleManager()

	// Initialize MalwareDetector with empty patterns
	md, err := NewMalwareDetector("yara_rules.yar", []ThreatPattern{})
	if err != nil {
		log.Printf("[WARN] MalwareDetector initialization failed: %v", err)
	}

	// Initialize BehavioralAnalyzer
	analyzer := NewBehavioralAnalyzer()

	// Initialize ResponseOrchestrator
	orchestrator := NewResponseOrchestrator("quarantine_zone")

	// Initialize IDS
	ids := NewIntrusionDetector(ruleManager, orchestrator)

	// Initialize NetworkMalwareScanner (TrafficDetector)
	trafficDetector := NewNetworkMalwareScanner("eth0", md, analyzer, orchestrator)

	// Initialize ScannerWrapper
	scannerWrapper := NewSecurityScannerWrapper(ruleManager, md, orchestrator)

	suite := &SecuritySuite{
		Config:               config,
		ResponseOrchestrator: orchestrator,
		Analyzer:             analyzer,
		TrafficDetector:      trafficDetector,
		IDS:                  ids,
		ScannerWrapper:       scannerWrapper,
		MalwareDetector:      md,
		ThreatHistory:        make([]*ThreatEvent, 0),
	}

	return suite
}

// Start initiates all security components and monitoring loops.
func (ss *SecuritySuite) Start() {
	log.Println("Security suite starting...")
	ss.IDS.StartMonitoring("eth0")

	// Start integrated, periodic analysis in a separate goroutine
	go ss.startPeriodicAnalysis()
}

// Stop attempts a graceful shutdown of all services.
func (ss *SecuritySuite) Stop() {
	ss.IDS.LoadRules() // Simulate stop by calling LoadRules
	log.Println("Security suite stopped.")
}

func (ss *SecuritySuite) startPeriodicAnalysis() {
	ticker := time.NewTicker(ss.Config.AnalysisInterval)
	defer ticker.Stop()

	for range ticker.C {
		log.Println("Running periodic security analysis...")
		ss.runIntegratedChecks()
	}
}

func (ss *SecuritySuite) runIntegratedChecks() {
	// Example: Run behavioral analysis on all profiles
	for ip := range ss.Analyzer.Profiles {
		indicators, _ := ss.Analyzer.AnalyzeProfile(ip)
		for _, indicator := range indicators {
			event := &ThreatEvent{
				Timestamp:      indicator.Timestamp,
				SourceModule:   "BehavioralAnalyzer",
				Severity:       indicator.Severity,
				Description:    indicator.Signature,
				AssociatedData: indicator.SourceIP,
			}
			ss.ProcessDetection(event)
		}
	}
}

// ProcessDetection handles a detection event from any module and logs it.
func (ss *SecuritySuite) ProcessDetection(event *ThreatEvent) {
	ss.ThreatHistory = append(ss.ThreatHistory, event)
	log.Printf("NEW THREAT: [%s] %s Source: %s", event.Severity, event.Description, event.SourceModule)

	// Convert ThreatEvent to ThreatIndicator for ResponseOrchestrator
	indicator := ThreatIndicator{
		Timestamp: event.Timestamp,
		SourceID:  event.SourceModule,
		SourceIP:  event.AssociatedData,
		Target:    event.AssociatedData,
		Severity:  event.Severity,
		Signature: event.Description,
		Context:   fmt.Sprintf("Threat from %s: %s", event.SourceModule, event.Description),
	}

	ss.ResponseOrchestrator.HandleThreat(indicator)
}
