// behavioral_analyzer_prod.go
package main

import (
	"fmt"
	"math"
	"math/rand"
	"sort"
	"sync"
	"time"

	"gonum.org/v1/gonum/stat"
)

// --- behavioral_analyzer_prod.go implementation ---

// BehavioralAnalyzer uses statistical analysis and real anomaly detection algorithms
type BehavioralAnalyzer struct {
	Profiles            map[string]*BehaviorProfile
	mu                  sync.RWMutex
	MalwareBehaviors    map[string]MalwareBehavior
	TrainingData        [][]float64
	BaselineStats       *BaselineStatistics
	LastTrainTime       time.Time
	TrainingDataCounter int
	AnomalyThreshold    float64
	IsolationForest     *IsolationForest
}

// NewBehavioralAnalyzer initializes the analyzer with real isolation forest
func NewBehavioralAnalyzer() *BehavioralAnalyzer {
	analyzer := &BehavioralAnalyzer{
		Profiles:            make(map[string]*BehaviorProfile),
		MalwareBehaviors:    loadMalwareBehaviors(),
		TrainingData:        make([][]float64, 0),
		BaselineStats:       &BaselineStatistics{},
		LastTrainTime:       time.Time{},
		TrainingDataCounter: 0,
		AnomalyThreshold:    0.6,                             // Isolation forest threshold
		IsolationForest:     NewIsolationForest(100, 256, 8), // 100 trees, 256 sample size, max depth 8
	}

	// PRODUCTION CHANGE: Simulate background loading of dynamic data in a goroutine
	go analyzer.LoadBehaviorFromRemote()

	fmt.Println("[BehavioralAnalyzer] Initialized with production Isolation Forest and TIF-simulated data.")
	return analyzer
}

// NewIsolationForest creates a new isolation forest
func NewIsolationForest(numTrees, subsampleSize, maxDepth int) *IsolationForest {
	// PRODUCTION CHANGE: Initialize with a dedicated random source
	source := rand.NewSource(time.Now().UnixNano())

	return &IsolationForest{
		Trees:         make([]*IsolationTree, 0, numTrees),
		NumTrees:      numTrees,
		SubsampleSize: subsampleSize,
		MaxDepth:      maxDepth,
		TrainingData:  make([][]float64, 0),
		rng:           rand.New(source),
	}
}

// LoadBehaviorFromRemote simulates loading dynamic threat data from a remote feed
func (ba *BehavioralAnalyzer) LoadBehaviorFromRemote() {
	// In a complete application, this would parse a JSON/YAML feed over TLS.
	ba.mu.Lock()
	defer ba.mu.Unlock()

	// Complex, dynamically-like-structured TIF data
	ba.MalwareBehaviors["APT_Hydra"] = MalwareBehavior{
		Ports:     []int{1433, 3306, 5432, 21}, // Database and control ports
		Protocols: []string{"TCP", "FTP"},
		Patterns:  []string{"multiple_db_auth_failures", "high_volume_port_21_transfers"},
		Severity:  ThreatLevelCritical,
		IOCs: map[string]string{
			"hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			"dns_c2":      "api.hydraserver.com",
		},
	}
	// Update an existing signature with new IOCs
	ba.MalwareBehaviors["C2_Beaconing"] = MalwareBehavior{
		Ports:     []int{8080, 4433, 9001, 443, 80},
		Protocols: []string{"TCP"},
		Patterns:  []string{"high_freq_connections", "small_periodic_data"},
		Severity:  ThreatLevelCritical,
		IOCs:      map[string]string{"dns_c2": "c2.evil-host.net", "ip_c2": "1.2.3.4"},
	}

	fmt.Printf("[BehavioralAnalyzer] Updated TIF with %d signatures.\n", len(ba.MalwareBehaviors))
}

// loadMalwareBehaviors loads known malware behavioral patterns (base signatures)
func loadMalwareBehaviors() map[string]MalwareBehavior {
	return map[string]MalwareBehavior{
		"C2_Beaconing": { // Will be updated by remote
			Ports:     []int{8080, 4433, 9001, 443, 80},
			Protocols: []string{"TCP"},
			Patterns:  []string{"high_freq_connections", "small_periodic_data"},
			Severity:  ThreatLevelCritical,
			IOCs:      map[string]string{},
		},
		"Lateral_Movement": {
			Ports:     []int{445, 139, 3389, 22, 23},
			Protocols: []string{"SMB", "RPC", "RDP", "SSH"},
			Patterns:  []string{"multiple_failed_logins", "unusual_internal_scans"},
			Severity:  ThreatLevelHigh,
			IOCs:      map[string]string{},
		},
		"Data_Exfiltration": {
			Ports:     []int{21, 22, 80, 443},
			Protocols: []string{"FTP", "SFTP", "HTTP", "HTTPS"},
			Patterns:  []string{"large_outbound_transfer", "off_hours_activity"},
			Severity:  ThreatLevelCritical,
			IOCs:      map[string]string{},
		},
	}
}

// TrainModel trains the isolation forest on collected data
func (ba *BehavioralAnalyzer) TrainModel() bool {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	if len(ba.TrainingData) < ba.IsolationForest.SubsampleSize*5 {
		fmt.Printf("[BehavioralAnalyzer] Training requires minimum %d samples (have %d)\n", ba.IsolationForest.SubsampleSize*5, len(ba.TrainingData))
		return false
	}

	fmt.Printf("[BehavioralAnalyzer] Training Isolation Forest on %d samples...\n", len(ba.TrainingData))

	// Train isolation forest
	ba.IsolationForest.Train(ba.TrainingData)

	// Also compute statistical baselines for hybrid approach
	ba.computeBaselineStats()

	ba.LastTrainTime = time.Now()
	ba.TrainingData = make([][]float64, 0) // Clear after training
	ba.TrainingDataCounter = 0

	fmt.Printf("[BehavioralAnalyzer] Model trained successfully at %s\n", ba.LastTrainTime.Format(time.RFC3339))
	return true
}

// computeBaselineStats computes statistical baselines
func (ba *BehavioralAnalyzer) computeBaselineStats() {
	if len(ba.TrainingData) == 0 {
		return
	}

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

	// Calculate and store real statistical baselines
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
}

// Train trains the isolation forest
func (iforest *IsolationForest) Train(data [][]float64) {
	iforest.mu.Lock()
	defer iforest.mu.Unlock()

	iforest.TrainingData = data
	iforest.Trees = make([]*IsolationTree, 0, iforest.NumTrees)

	// Build trees
	for i := 0; i < iforest.NumTrees; i++ {
		// Sample data
		sample := iforest.subsample(data)

		// Build tree
		tree := &IsolationTree{
			MaxDepth: iforest.MaxDepth,
		}
		tree.Root = iforest.buildTree(sample, 0)

		iforest.Trees = append(iforest.Trees, tree)
	}
}

// subsample randomly samples data - enhanced to use dedicated random source
func (iforest *IsolationForest) subsample(data [][]float64) [][]float64 {
	if len(data) <= iforest.SubsampleSize {
		return data
	}

	sample := make([][]float64, iforest.SubsampleSize)
	indices := make(map[int]bool)

	// Use dedicated rng source
	for len(indices) < iforest.SubsampleSize {
		idx := iforest.rng.Intn(len(data)) // Use Intn for proper random index selection
		if !indices[idx] {
			indices[idx] = true
			sample[len(indices)-1] = data[idx]
		}
	}

	return sample
}

// buildTree recursively builds an isolation tree - enhanced to use dedicated random source
func (iforest *IsolationForest) buildTree(data [][]float64, depth int) *IsolationNode {
	node := &IsolationNode{
		Size: len(data),
	}

	// Leaf conditions
	if depth >= iforest.MaxDepth || len(data) <= 1 {
		node.IsLeaf = true
		return node
	}

	// Check if all samples are identical
	allSame := true
	if len(data) > 1 {
		for i := 1; i < len(data); i++ {
			for j := 0; j < len(data[0]); j++ {
				if data[i][j] != data[0][j] {
					allSame = false
					break
				}
			}
			if !allSame {
				break
			}
		}
	}

	if allSame {
		node.IsLeaf = true
		return node
	}

	// Select random feature and split value
	numFeatures := len(data[0])
	feature := iforest.rng.Intn(numFeatures) // Use Intn for feature selection

	// Find min and max for this feature
	min := data[0][feature]
	max := data[0][feature]
	for _, sample := range data {
		if sample[feature] < min {
			min = sample[feature]
		}
		if sample[feature] > max {
			max = sample[feature]
		}
	}

	// Random split value between min and max
	if min == max {
		node.IsLeaf = true
		return node
	}

	// Production-grade split value selection using rng.Float64() (0.0 to 1.0) for uniform split in range
	randSplitValue := iforest.rng.Float64()
	splitValue := min + (max-min)*randSplitValue

	node.SplitFeature = feature
	node.SplitValue = splitValue

	// Split data
	leftData := make([][]float64, 0)
	rightData := make([][]float64, 0)

	for _, sample := range data {
		if sample[feature] < splitValue {
			leftData = append(leftData, sample)
		} else {
			rightData = append(rightData, sample)
		}
	}

	// Recursively build children
	if len(leftData) > 0 {
		node.Left = iforest.buildTree(leftData, depth+1)
	}
	if len(rightData) > 0 {
		node.Right = iforest.buildTree(rightData, depth+1)
	}

	return node
}

// AnomalyScore computes anomaly score for a sample
func (iforest *IsolationForest) AnomalyScore(sample []float64) float64 {
	iforest.mu.RLock()
	defer iforest.mu.RUnlock()

	if len(iforest.Trees) == 0 {
		return 0.0
	}

	// Average path length across all trees
	avgPathLength := 0.0
	for _, tree := range iforest.Trees {
		avgPathLength += tree.pathLength(sample, tree.Root, 0)
	}
	avgPathLength /= float64(len(iforest.Trees))

	// Normalize by expected path length
	c := iforest.expectedPathLength(float64(iforest.SubsampleSize))
	score := math.Pow(2, -avgPathLength/c)

	return score
}

// pathLength computes path length for a sample in a tree
func (tree *IsolationTree) pathLength(sample []float64, node *IsolationNode, depth int) float64 {
	if node.IsLeaf {
		// Add expected path length for remaining samples
		return float64(depth) + tree.expectedPathLength(float64(node.Size))
	}

	if sample[node.SplitFeature] < node.SplitValue {
		if node.Left != nil {
			return tree.pathLength(sample, node.Left, depth+1)
		}
	} else {
		if node.Right != nil {
			return tree.pathLength(sample, node.Right, depth+1)
		}
	}

	return float64(depth)
}

// expectedPathLength computes expected path length for n samples
func (tree *IsolationTree) expectedPathLength(n float64) float64 {
	if n <= 1 {
		return 0
	}
	if n == 2 {
		return 1
	}

	// Use Euler's constant approximation (c(n))
	h := math.Log(n-1) + 0.5772156649
	return 2.0*h - (2.0 * (n - 1) / n)
}

// expectedPathLength for isolation forest
func (iforest *IsolationForest) expectedPathLength(n float64) float64 {
	if n <= 1 {
		return 0
	}
	// Use Euler's constant approximation (c(n))
	h := math.Log(n-1) + 0.5772156649
	return 2.0*h - (2.0 * (n - 1) / n)
}

// getAnomalyRate simulates getting a real-time anomaly rate from a complex data stream
func (ba *BehavioralAnalyzer) getAnomalyRate() float64 {
	// Simulate adaptive rate based on time since last train and data volume
	timeFactor := time.Since(ba.LastTrainTime).Hours() / (24.0 * 7.0) // Decay over one week
	dataVolumeFactor := float64(ba.TrainingDataCounter) / 1000.0      // Normalize new data count

	// Adaptive, metric-driven rate
	rate := math.Min(1.0, dataVolumeFactor*0.1+timeFactor*0.5)
	return rate
}

// checkRetrainCondition implements adaptive, production-grade logic
func (ba *BehavioralAnalyzer) checkRetrainCondition() bool {
	// Condition 1: Time-based (e.g., retrain at least once a week)
	if time.Since(ba.LastTrainTime) > 7*24*time.Hour {
		return true
	}

	// Condition 2: Data-volume based (significant new data)
	// Trigger if new data is 50% of the training data size AND we have > 500 total samples
	if float64(ba.TrainingDataCounter) >= float64(len(ba.TrainingData))/2.0 && ba.TrainingDataCounter > 500 {
		return true
	}

	// Condition 3: Metric-based (high baseline anomaly rate detected)
	anomalyRate := ba.getAnomalyRate()
	if anomalyRate > 0.4 && len(ba.TrainingData) > 1000 {
		return true
	}

	return false
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

		// Production-grade adaptive retrain check
		if ba.checkRetrainCondition() {
			// Run training in a goroutine to avoid blocking the main data ingest loop
			go ba.TrainModel()
		}
	}

	return profile
}

// AnalyzeProfile performs real anomaly detection using Isolation Forest and Statistical Baselines
func (ba *BehavioralAnalyzer) AnalyzeProfile(ip string) ([]ThreatIndicator, *BehaviorProfile) {
	ba.mu.RLock()
	defer ba.mu.RUnlock()

	profile, exists := ba.Profiles[ip]
	if !exists {
		return nil, nil
	}

	indicators := make([]ThreatIndicator, 0)

	// 1. Isolation Forest Anomaly Detection
	if len(ba.IsolationForest.Trees) > 0 && len(profile.FeatureVector) >= 4 {
		anomalyScore := ba.IsolationForest.AnomalyScore(profile.FeatureVector)

		// Update history and current score
		profile.AnomalyScore = anomalyScore
		profile.AnomalyScoreHistory = append(profile.AnomalyScoreHistory, anomalyScore)
		if len(profile.AnomalyScoreHistory) > 100 { // Keep last 100 scores
			profile.AnomalyScoreHistory = profile.AnomalyScoreHistory[1:]
		}

		// Higher scores indicate anomalies (score > 0.6 is anomalous)
		if anomalyScore > ba.AnomalyThreshold {
			severity := ThreatLevelMedium
			action := ActionIncreaseMonitoring
			if anomalyScore > 0.7 {
				severity = ThreatLevelHigh
			}
			if anomalyScore > 0.8 {
				severity = ThreatLevelCritical
				action = ActionIsolateHost
			}

			indicator := ThreatIndicator{
				Timestamp: time.Now(),
				SourceIP:  ip,
				SourceID:  "ISOLATION-FOREST-ANOMALY",
				Type:      "Behavioral Anomaly",
				Severity:  severity,
				Context:   fmt.Sprintf("Isolation Forest detected anomaly (score: %.3f, threshold: %.3f)", anomalyScore, ba.AnomalyThreshold),
				Score:     anomalyScore,
				Action:    action,
			}
			indicators = append(indicators, indicator)
		}
	}

	// 2. Heuristic and Statistical Malware Pattern Matching
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

// checkHeuristicMatch checks if profile matches known malware patterns (Enhanced)
func (ba *BehavioralAnalyzer) checkHeuristicMatch(profile *BehaviorProfile, pattern MalwareBehavior) bool {
	// Require feature vector and baselines for statistical analysis
	if len(profile.FeatureVector) < 4 || ba.BaselineStats.LastUpdated.IsZero() {
		return false
	}

	bytesIn := profile.FeatureVector[0]
	bytesOut := profile.FeatureVector[1]
	connRate := profile.FeatureVector[2]
	dnsCount := profile.FeatureVector[3]

	// PRODUCTION LOGIC: Z-Score Check (Flag if 3 standard deviations away from the mean)
	isOutlier := false
	if ba.BaselineStats.BytesInStdDev > 0 && math.Abs(bytesIn-ba.BaselineStats.BytesInMean)/ba.BaselineStats.BytesInStdDev > 3.0 {
		isOutlier = true
	}
	if ba.BaselineStats.BytesOutStdDev > 0 && math.Abs(bytesOut-ba.BaselineStats.BytesOutMean)/ba.BaselineStats.BytesOutStdDev > 3.0 {
		isOutlier = true
	}
	if ba.BaselineStats.ConnRateStdDev > 0 && math.Abs(connRate-ba.BaselineStats.ConnRateMean)/ba.BaselineStats.ConnRateStdDev > 3.0 {
		isOutlier = true
	}
	// Note: DNS count outlier detection often benefits from specialized models, but Z-score serves as a good general indicator.
	if ba.BaselineStats.DNSCountStdDev > 0 && math.Abs(dnsCount-ba.BaselineStats.DNSCountMean)/ba.BaselineStats.DNSCountStdDev > 3.0 {
		isOutlier = true
	}

	// If it's a statistical outlier, check against known malware behavioral patterns
	if isOutlier {
		// Pattern: Data_Exfiltration (large_outbound_transfer, off_hours_activity)
		if containsString(pattern.Patterns, "large_outbound_transfer") {
			// Check for outbound data > 5x baseline AND off-hours
			if bytesOut > ba.BaselineStats.BytesOutMean*5.0 {
				nowHour := time.Now().Hour()
				isOffHours := nowHour < 6 || nowHour > 22
				if isOffHours {
					return true
				}
			}
		}

		// Pattern: C2_Beaconing (high_freq_connections, small_periodic_data)
		if containsString(pattern.Patterns, "high_freq_connections") {
			// Check for connection rate > 5x baseline AND small data packets
			if connRate > ba.BaselineStats.ConnRateMean*5.0 {
				if bytesIn < 1024 && bytesOut < 1024 { // Small periodic data (e.g., < 1KB)
					return true
				}
			}
		}
	}

	// IOC and Port-Based Check (Secondary check, even if not an outlier)
	// Check if port used is one of the malware's known C2 ports
	if len(pattern.Ports) > 0 {
		for _, p := range pattern.Ports {
			if containsInt(profile.TypicalServices, p) {
				return true
			}
		}
	}

	return false
}

// GetProfile retrieves or creates a BehaviorProfile for an IP
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
