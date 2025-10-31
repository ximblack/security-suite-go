package main

import (
	"fmt"
	"math"
	"net"
	"sort"
	"sync"
	"time"

	"gonum.org/v1/gonum/stat"
)

// BehavioralAnalyzer uses statistical analysis and anomaly detection
type BehavioralAnalyzer struct {
	Profiles            map[string]*BehaviorProfile
	mu                  sync.RWMutex
	MalwareBehaviors    map[string]MalwareBehavior
	TrainingData        [][]float64
	BaselineStats       *BaselineStatistics
	LastTrainTime       time.Time
	TrainingDataCounter int
	AnomalyThreshold    float64
}

// BaselineStatistics holds statistical baselines for anomaly detection
type BaselineStatistics struct {
	BytesInMean      float64
	BytesInStdDev    float64
	BytesOutMean     float64
	BytesOutStdDev   float64
	ConnRateMean     float64
	ConnRateStdDev   float64
	DNSCountMean     float64
	DNSCountStdDev   float64
	LastUpdated      time.Time
}

// MalwareBehavior defines patterns associated with known malware
type MalwareBehavior struct {
	Ports     []int
	Protocols []string
	Patterns  []string
	Severity  ThreatLevel
}

// NewBehavioralAnalyzer initializes the analyzer
func NewBehavioralAnalyzer() *BehavioralAnalyzer {
	analyzer := &BehavioralAnalyzer{
		Profiles:            make(map[string]*BehaviorProfile),
		MalwareBehaviors:    loadMalwareBehaviors(),
		TrainingData:        make([][]float64, 0),
		BaselineStats:       &BaselineStatistics{},
		LastTrainTime:       time.Time{},
		TrainingDataCounter: 0,
		AnomalyThreshold:    3.0, // 3 standard deviations
	}
	
	fmt.Println("[BehavioralAnalyzer] Initializing production ML model...")
	return analyzer
}

// loadMalwareBehaviors loads known malware behavioral patterns
func loadMalwareBehaviors() map[string]MalwareBehavior {
	return map[string]MalwareBehavior{
		"C2_Beaconing": {
			Ports:     []int{8080, 4433, 9001, 443, 80},
			Protocols: []string{"TCP"},
			Patterns:  []string{"high_freq_connections", "small_periodic_data"},
			Severity:  ThreatLevelCritical,
		},
		"Lateral_Movement": {
			Ports:     []int{445, 139, 3389, 22, 23},
			Protocols: []string{"SMB", "RPC", "RDP", "SSH"},
			Patterns:  []string{"multiple_failed_logins", "unusual_internal_scans"},
			Severity:  ThreatLevelHigh,
		},
		"Data_Exfiltration": {
			Ports:     []int{21, 22, 80, 443},
			Protocols: []string{"FTP", "SFTP", "HTTP", "HTTPS"},
			Patterns:  []string{"large_outbound_transfer", "off_hours_activity"},
			Severity:  ThreatLevelCritical,
		},
		"Port_Scanning": {
			Ports:     []int{},
			Protocols: []string{"TCP", "UDP"},
			Patterns:  []string{"multiple_port_connections", "syn_scan_pattern"},
			Severity:  ThreatLevelHigh,
		},
	}
}

// TrainModel computes statistical baselines from training data using production algorithms
func (ba *BehavioralAnalyzer) TrainModel() bool {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	if len(ba.TrainingData) < 100 {
		fmt.Printf("[BehavioralAnalyzer] Training requires minimum 100 samples (have %d)\n", len(ba.TrainingData))
		return false
	}

	fmt.Printf("[BehavioralAnalyzer] Training model on %d samples...\n", len(ba.TrainingData))

	// Extract feature columns
	bytesIn := make([]float64, len(ba.TrainingData))
	bytesOut := make([]float64, len(ba.TrainingData))
	connRate := make([]float64, len(ba.TrainingData))
	dnsCount := make([]float64, len(ba.TrainingData))

	for i, sample := range ba.TrainingData {
		if len(sample) >= 4 {
			bytesIn[i] = sample[0]
			bytesOut[i] = sample[1]
			connRate[i] = sample[2]
			dnsCount[i] = sample[3]
		}
	}

	// Compute statistical baselines
	ba.BaselineStats = &BaselineStatistics{
		BytesInMean:    stat.Mean(bytesIn, nil),
		BytesInStdDev:  stat.StdDev(bytesIn, nil),
		BytesOutMean:   stat.Mean(bytesOut, nil),
		BytesOutStdDev: stat.StdDev(bytesOut, nil),
		ConnRateMean:   stat.Mean(connRate, nil),
		ConnRateStdDev: stat.StdDev(connRate, nil),
		DNSCountMean:   stat.Mean(dnsCount, nil),
		DNSCountStdDev: stat.StdDev(dnsCount, nil),
		LastUpdated:    time.Now(),
	}

	ba.LastTrainTime = time.Now()
	ba.TrainingData = make([][]float64, 0) // Clear after training
	ba.TrainingDataCounter = 0

	fmt.Printf("[BehavioralAnalyzer] Model trained successfully at %s\n", ba.LastTrainTime.Format(time.RFC3339))
	fmt.Printf("  Baseline - BytesIn: %.2f±%.2f, BytesOut: %.2f±%.2f, ConnRate: %.2f±%.2f, DNS: %.2f±%.2f\n",
		ba.BaselineStats.BytesInMean, ba.BaselineStats.BytesInStdDev,
		ba.BaselineStats.BytesOutMean, ba.BaselineStats.BytesOutStdDev,
		ba.BaselineStats.ConnRateMean, ba.BaselineStats.ConnRateStdDev,
		ba.BaselineStats.DNSCountMean, ba.BaselineStats.DNSCountStdDev)

	return true
}

// UpdateProfile updates behavior profile with new observation
func (ba *BehavioralAnalyzer) UpdateProfile(ip string, featureVector []float64, isTrainingData bool) *BehaviorProfile {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	profile, exists := ba.Profiles[ip]
	if !exists {
		profile = &BehaviorProfile{
			DeviceIP:             ip,
			ConnectionFrequency:  make(map[string]float64),
			DataTransferPattern:  make([]float64, 24),
			ActiveHours:          make([]int, 0),
			ProtocolDistribution: make(map[string]float64),
			TypicalServices:      make([]int, 0),
			FirstSeen:            time.Now(),
		}
		ba.Profiles[ip] = profile
	}

	// Update profile with new observation
	if len(featureVector) >= 4 {
		now := time.Now()
		hour := now.Hour()

		// Update data transfer pattern
		totalBytesMB := (featureVector[0] + featureVector[1]) / 1024 / 1024
		profile.DataTransferPattern[hour] += totalBytesMB

		// Track active hours
		if !containsInt(profile.ActiveHours, hour) {
			profile.ActiveHours = append(profile.ActiveHours, hour)
			sort.Ints(profile.ActiveHours)
		}

		// Store feature vector for analysis
		profile.FeatureVector = featureVector
	}

	profile.LastUpdate = time.Now()

	// Add to training data if applicable
	if isTrainingData && !isPrivateIP(ip) {
		ba.TrainingData = append(ba.TrainingData, featureVector)
		ba.TrainingDataCounter++

		// Auto-retrain when threshold reached
		if ba.TrainingDataCounter >= 250 {
			go ba.TrainModel() // Train in background
		}
	}

	return profile
}

// AnalyzeProfile performs production anomaly detection using statistical analysis
func (ba *BehavioralAnalyzer) AnalyzeProfile(ip string) ([]ThreatIndicator, *BehaviorProfile) {
	ba.mu.RLock()
	defer ba.mu.RUnlock()

	profile, exists := ba.Profiles[ip]
	if !exists {
		return nil, nil
	}

	indicators := make([]ThreatIndicator, 0)

	// Statistical Anomaly Detection using Z-scores
	if ba.BaselineStats.LastUpdated.IsZero() {
		// No baseline yet, skip anomaly detection
		profile.AnomalyScore = 0.0
		return indicators, profile
	}

	if len(profile.FeatureVector) >= 4 {
		// Calculate Z-scores for each feature
		zScores := make([]float64, 4)
		
		// Bytes In
		if ba.BaselineStats.BytesInStdDev > 0 {
			zScores[0] = (profile.FeatureVector[0] - ba.BaselineStats.BytesInMean) / ba.BaselineStats.BytesInStdDev
		}
		
		// Bytes Out
		if ba.BaselineStats.BytesOutStdDev > 0 {
			zScores[1] = (profile.FeatureVector[1] - ba.BaselineStats.BytesOutMean) / ba.BaselineStats.BytesOutStdDev
		}
		
		// Connection Rate
		if ba.BaselineStats.ConnRateStdDev > 0 {
			zScores[2] = (profile.FeatureVector[2] - ba.BaselineStats.ConnRateMean) / ba.BaselineStats.ConnRateStdDev
		}
		
		// DNS Count
		if ba.BaselineStats.DNSCountStdDev > 0 {
			zScores[3] = (profile.FeatureVector[3] - ba.BaselineStats.DNSCountMean) / ba.BaselineStats.DNSCountStdDev
		}

		// Compute composite anomaly score (using Euclidean distance in Z-score space)
		anomalyScore := 0.0
		for _, z := range zScores {
			anomalyScore += z * z
		}
		anomalyScore = math.Sqrt(anomalyScore)
		
		profile.AnomalyScore = anomalyScore

		// Check if anomaly exceeds threshold
		if anomalyScore > ba.AnomalyThreshold {
			severity := ThreatLevelMedium
			if anomalyScore > ba.AnomalyThreshold*2 {
				severity = ThreatLevelHigh
			}
			if anomalyScore > ba.AnomalyThreshold*3 {
				severity = ThreatLevelCritical
			}

			indicator := ThreatIndicator{
				Timestamp: time.Now(),
				SourceIP:  ip,
				SourceID:  "BEHAVIOR-ML-ANOMALY",
				Type:      "Statistical Anomaly",
				Severity:  severity,
				Context:   fmt.Sprintf("Statistical anomaly detected (Z-score: %.2f). BytesIn: %.2fσ, BytesOut: %.2fσ, ConnRate: %.2fσ, DNS: %.2fσ", 
					anomalyScore, zScores[0], zScores[1], zScores[2], zScores[3]),
				Score:     anomalyScore,
				Action:    ActionIncreaseMonitoring,
			}
			indicators = append(indicators, indicator)
		}
	}

	// Heuristic malware pattern matching
	for name, pattern := range ba.MalwareBehaviors {
		if ba.checkHeuristicMatch(profile, pattern) {
			indicator := ThreatIndicator{
				Timestamp: time.Now(),
				SourceIP:  ip,
				SourceID:  "BEHAVIOR-HEURISTIC-MATCH",
				Type:      "Malware Behavior Pattern",
				Severity:  pattern.Severity,
				Context:   fmt.Sprintf("Behavior matched known %s pattern (Ports: %v)", name, pattern.Ports),
				Score:     1.0,
				Action:    ActionIsolateHost,
			}
			indicators = append(indicators, indicator)
		}
	}

	return indicators, profile
}

// checkHeuristicMatch checks if profile matches known malware patterns
func (ba *BehavioralAnalyzer) checkHeuristicMatch(profile *BehaviorProfile, pattern MalwareBehavior) bool {
	// Check for matching ports
	hasMatchingPort := false
	if len(pattern.Ports) > 0 {
		for _, p := range pattern.Ports {
			for _, servicePort := range profile.TypicalServices {
				if p == servicePort {
					hasMatchingPort = true
					break
				}
			}
			if hasMatchingPort {
				break
			}
		}
	} else {
		// Pattern doesn't require specific ports
		hasMatchingPort = true
	}

	if !hasMatchingPort {
		return false
	}

	// Check for suspicious timing (off-hours activity)
	nowHour := time.Now().Hour()
	isOffHours := nowHour < 6 || nowHour > 22 // Outside 6am-10pm

	// Check for high data transfer during off hours (exfiltration indicator)
	if isOffHours && len(profile.FeatureVector) >= 2 {
		totalBytes := profile.FeatureVector[0] + profile.FeatureVector[1]
		if totalBytes > 100*1024*1024 { // > 100MB
			return true
		}
	}

	// Check for scanning behavior (many connections to different ports)
	if len(profile.TypicalServices) > 20 {
		return true
	}

	// Check for beaconing (periodic small data transfers)
	if len(profile.FeatureVector) >= 2 {
		bytesOut := profile.FeatureVector[1]
		if bytesOut < 1024 && bytesOut > 0 { // Small periodic data
			// Check if connections are frequent
			if len(profile.FeatureVector) >= 3 && profile.FeatureVector[2] > 1.0 {
				return true
			}
		}
	}

	return false
}

// containsInt checks if slice contains an integer
func containsInt(s []int, e int) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

// isPrivateIP checks if IP is in private range
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

// ipInRange checks if IP is within range
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

// GetProfile retrieves or creates a profile
func (ba *BehavioralAnalyzer) GetProfile(ip string) *BehaviorProfile {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	profile, exists := ba.Profiles[ip]
	if !exists {
		profile = &BehaviorProfile{
			DeviceIP:             ip,
			ConnectionFrequency:  make(map[string]float64),
			DataTransferPattern:  make([]float64, 24),
			ActiveHours:          make([]int, 0),
			ProtocolDistribution: make(map[string]float64),
			TypicalServices:      make([]int, 0),
			FirstSeen:            time.Now(),
			LastUpdate:           time.Now(),
		}
		ba.Profiles[ip] = profile
	}
	return profile
}
