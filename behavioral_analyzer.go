// behavioral_analyzer_prod.go - Enterprise-Grade Behavioral Anomaly Detection Module
package main

import (
	"fmt"
	"math"
	"math/rand"
	"strings"
	"sync"
	"time"

	"gonum.org/v1/gonum/stat"
)

// --- Anomaly Detection Core Structures (Isolation Forest) ---

// IsolationNode is a single node in an Isolation Tree (defined in types.go)

// IsolationTree represents a single tree in the forest (defined in types.go)

// IsolationForest is the collection of Isolation Trees (defined in types.go)

// NewIsolationForest creates a new Isolation Forest structure
func NewIsolationForest(numTrees, sampleSize, maxDepth int) *IsolationForest {
	if numTrees <= 0 {
		numTrees = 100
	}
	if sampleSize <= 0 {
		sampleSize = 256
	}
	if maxDepth <= 0 {
		maxDepth = 8
	}

	return &IsolationForest{
		NumTrees:   numTrees,
		SampleSize: sampleSize,
		MaxDepth:   maxDepth,
		// Trees are built during the Train phase
	}
}

// BuildTree recursively builds an Isolation Tree
func (iforest *IsolationForest) BuildTree(data [][]float64, currentHeight int) *IsolationNode {
	size := len(data)
	if size <= iforest.SampleSize || currentHeight >= iforest.MaxDepth || size <= 1 {
		// External Node (Leaf)
		return &IsolationNode{IsExternal: true, Size: size}
	}

	// Calculate current number of features (should be consistent, but safe check)
	if len(data[0]) == 0 {
		return &IsolationNode{IsExternal: true, Size: size} // Should not happen with valid data
	}
	numFeatures := len(data[0])

	// --- FEATURE SELECTION & SPLIT ---
	// 1. Select a random feature (column) index
	splitFeatureIndex := rand.Intn(numFeatures)

	// 2. Find the min and max for the selected feature
	minVal, maxVal := data[0][splitFeatureIndex], data[0][splitFeatureIndex]
	for _, row := range data {
		val := row[splitFeatureIndex]
		if val < minVal {
			minVal = val
		}
		if val > maxVal {
			maxVal = val
		}
	}

	if minVal == maxVal {
		// All values are the same, cannot split further
		return &IsolationNode{IsExternal: true, Size: size}
	}

	// 3. Select a random split value between min and max
	splitValue := minVal + rand.Float64()*(maxVal-minVal)

	// --- SPLITTING ---
	leftData := make([][]float64, 0)
	rightData := make([][]float64, 0)

	for _, row := range data {
		if row[splitFeatureIndex] < splitValue {
			leftData = append(leftData, row)
		} else {
			rightData = append(rightData, row)
		}
	}

	// Handle empty splits (if the random split was at an extreme)
	if len(leftData) == 0 || len(rightData) == 0 {
		return &IsolationNode{IsExternal: true, Size: size}
	}

	// Recursively build children
	return &IsolationNode{
		IsExternal:        false,
		Size:              size,
		SplitValue:        splitValue,
		SplitFeatureIndex: splitFeatureIndex,
		Left:              iforest.BuildTree(leftData, currentHeight+1),
		Right:             iforest.BuildTree(rightData, currentHeight+1),
	}
}

// PathLength calculates the path length (height) a sample takes in a tree
func (tree *IsolationTree) PathLength(sample []float64, currentPathLength int) float64 {
	node := tree.Root
	for !node.IsExternal {
		// Guard against data with too few features
		if node.SplitFeatureIndex >= len(sample) {
			break
		}

		currentPathLength++
		if sample[node.SplitFeatureIndex] < node.SplitValue {
			node = node.Left
		} else {
			node = node.Right
		}

		// Safety break for corrupted trees (should not happen)
		if node == nil {
			return float64(currentPathLength) + c(float64(tree.Root.Size))
		}
	}
	// Add correction factor c(size) for the expected path length in a leaf node
	return float64(currentPathLength) + c(float64(node.Size))
}

// c(n) is the correction factor for path length in external nodes
func c(n float64) float64 {
	if n <= 1 {
		return 0.0
	}
	// E[h] is the average path length in an Unsuccessful Search in a Binary Search Tree (BST)
	// 2 * (ln(n-1) + 0.5772156649) - 2 * (n-1) / n
	return 2.0*(math.Log(n-1)+0.5772156649) - 2.0*(n-1)/n
}

// CalculateAnomalyScore calculates the anomaly score for a given sample
// Score is between 0 (normal) and 1 (anomaly)
func (iforest *IsolationForest) CalculateAnomalyScore(sample []float64) float64 {
	if len(iforest.Trees) == 0 {
		return 0.0 // Cannot score without a trained model
	}

	var totalPathLength float64
	// Calculate average path length across all trees
	for _, tree := range iforest.Trees {
		totalPathLength += tree.PathLength(sample, 0)
	}

	avgPathLength := totalPathLength / float64(iforest.NumTrees)

	// Anomaly Score formula: 2^(-avgPathLength / c(n))
	// where n is the number of samples used to train the forest (represented by the root size of the first tree)
	n := float64(iforest.Trees[0].Root.Size)
	E_h := c(n)

	// Avoid division by zero, although c(n) should be > 0 for n > 1
	if E_h == 0 {
		return 0.0
	}

	score := math.Pow(2, -avgPathLength/E_h)
	return score
}

// --- Behavioral Analyzer Logic ---

// BehavioralAnalyzer uses statistical analysis and real anomaly detection algorithms
type BehavioralAnalyzer struct {
	Profiles            map[string]*BehaviorProfile
	mu                  sync.RWMutex
	MalwareBehaviors    map[string]MalwareBehavior
	TrainingData        [][]float64 // Feature vector: [ConnRate, BytesInRate, BytesOutRate, AvgDuration]
	BaselineStats       *BaselineStatistics
	LastTrainTime       time.Time
	TrainingDataCounter int
	AnomalyThreshold    float64 // Isolation forest score threshold (e.g., 0.6)
	IsolationForest     *IsolationForest
}

// BaselineStatistics holds the statistical mean and standard deviation for normal activity (defined in types.go)

// BehaviorProfile tracks real-time statistics for a single IP (defined in types.go)

// MalwareBehavior defines known Indicators of Behavior (IOB) (defined in types.go)

// NewBehavioralAnalyzer initializes the analyzer with real isolation forest
func NewBehavioralAnalyzer() *BehavioralAnalyzer {
	analyzer := &BehavioralAnalyzer{
		Profiles:            make(map[string]*BehaviorProfile),
		MalwareBehaviors:    loadMalwareBehaviors(), // Load actual, hardened IOBs
		TrainingData:        make([][]float64, 0),
		BaselineStats:       &BaselineStatistics{},
		LastTrainTime:       time.Time{},
		TrainingDataCounter: 0,
		AnomalyThreshold:    0.6,                              // High confidence threshold for anomaly
		IsolationForest:     NewIsolationForest(100, 256, 10), // Increased max depth for complexity
	}

	// PRODUCTION: Start a background goroutine for periodic training and maintenance
	go analyzer.runMaintenance()

	fmt.Println("[BehavioralAnalyzer] Initialized. Isolation Forest ready for training.")
	return analyzer
}

// runMaintenance handles periodic tasks like training the model
func (ba *BehavioralAnalyzer) runMaintenance() {
	ticker := time.NewTicker(15 * time.Minute) // Retrain every 15 minutes
	defer ticker.Stop()

	// Initial training placeholder (in a real system, initial data would be loaded)
	ba.mu.Lock()
	if len(ba.TrainingData) > ba.IsolationForest.SampleSize {
		ba.Train()
	}
	ba.mu.Unlock()

	for {
		select {
		case <-ticker.C:
			ba.mu.Lock()
			// Only retrain if enough new data has been collected
			if ba.TrainingDataCounter >= ba.IsolationForest.SampleSize/2 {
				fmt.Println("[BehavioralAnalyzer] Starting scheduled model retraining...")
				ba.Train()
				ba.TrainingDataCounter = 0 // Reset counter
			}
			ba.mu.Unlock()
		}
	}
}

// loadMalwareBehaviors provides a production-ready list of Indicators of Behavior (IOBs)
func loadMalwareBehaviors() map[string]MalwareBehavior {
	return map[string]MalwareBehavior{
		"Exfiltration-LargeTransfer": {
			Name:     "Exfiltration: Large Data Transfer",
			Patterns: []string{"large_data_transfer", "high_bytes_out"},
			Ports:    []int{80, 443, 21},
		},
		"C2-Beaconing": {
			Name:     "Command & Control Beaconing",
			Patterns: []string{"high_freq_connections", "small_periodic_data"},
			Ports:    []int{8080, 443, 53}, // Common C2 ports (DNS tunneling, HTTP/S)
		},
		"Lateral-Movement-Scan": {
			Name:     "Lateral Movement Scanning",
			Patterns: []string{"high_freq_connections", "short_duration"},
			Ports:    []int{22, 23, 445, 3389},
		},
	}
}

// GetProfile retrieves or creates a BehaviorProfile for an IP
func (ba *BehavioralAnalyzer) GetProfile(ip string) *BehaviorProfile {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	profile, exists := ba.Profiles[ip]
	if !exists {
		// New device/IP seen, create a new profile
		profile = &BehaviorProfile{
			DeviceIP:            ip,
			RecentDurations:     make([]float64, 0, 100), // Pre-allocate capacity
			AnomalyScoreHistory: make([]float64, 0, 10),
			LastUpdateTime:      time.Now(),
		}
		ba.Profiles[ip] = profile
	}
	return profile
}

// AddNetworkEvent updates a profile with a new network event
func (ba *BehavioralAnalyzer) AddNetworkEvent(ip string, bytesIn, bytesOut int64, duration time.Duration, dstPort uint16) {
	profile := ba.GetProfile(ip)

	profile.ConnectionFrequency++
	profile.TotalBytesIn += bytesIn
	profile.TotalBytesOut += bytesOut
	profile.RecentDurations = append(profile.RecentDurations, duration.Seconds())

	// Keep service list small
	if !containsInt(profile.TypicalServices, int(dstPort)) {
		profile.TypicalServices = append(profile.TypicalServices, int(dstPort))
	}

	// Remove old durations if the slice gets too long
	if len(profile.RecentDurations) > 100 {
		profile.RecentDurations = profile.RecentDurations[len(profile.RecentDurations)-100:]
	}

	// Update LastUpdateTime
	profile.LastUpdateTime = time.Now()

	// --- Anomaly Detection Feature Vector Generation ---
	// Calculate current rate metrics for a feature vector
	// We use a fixed 60-second window for current rate calculation
	timeSinceLastTrain := time.Since(ba.LastTrainTime)
	if timeSinceLastTrain > 60*time.Second {
		timeSinceLastTrain = 60 * time.Second
	}

	connRate := float64(profile.ConnectionFrequency) / timeSinceLastTrain.Seconds()
	bytesInRate := float64(profile.TotalBytesIn) / timeSinceLastTrain.Seconds()
	bytesOutRate := float64(profile.TotalBytesOut) / timeSinceLastTrain.Seconds()

	avgDuration := stat.Mean(profile.RecentDurations, nil)

	// Feature Vector: [Connection Rate, Bytes In Rate, Bytes Out Rate, Average Duration]
	// This vector is used for Anomaly Scoring and Training
	featureVector := []float64{connRate, bytesInRate, bytesOutRate, avgDuration}

	// Add to training data for model updates
	ba.mu.Lock()
	ba.TrainingData = append(ba.TrainingData, featureVector)
	ba.TrainingDataCounter++
	ba.mu.Unlock()
}

// Train builds the Isolation Forest model using the collected TrainingData
func (ba *BehavioralAnalyzer) Train() {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	data := ba.TrainingData
	if len(data) < 2 {
		fmt.Println("[BehavioralAnalyzer WARNING] Not enough data to train Isolation Forest.")
		return
	}

	// 1. Update Baseline Statistics
	ba.UpdateBaseline(data)

	// 2. Determine number of features (must be consistent)
	numFeatures := len(data[0])
	ba.IsolationForest.NumFeatures = numFeatures

	// 3. Build the Forest concurrently
	trees := make([]*IsolationTree, ba.IsolationForest.NumTrees)
	var wg sync.WaitGroup

	fmt.Printf("[BehavioralAnalyzer] Training %d Isolation Trees with %d samples...\\n", ba.IsolationForest.NumTrees, len(data))

	// PRODUCTION: Use concurrency for fast training
	for i := 0; i < ba.IsolationForest.NumTrees; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			// Sub-sample the data for this tree
			sampleSize := ba.IsolationForest.SampleSize
			if sampleSize > len(data) {
				sampleSize = len(data)
			}

			sample := make([][]float64, sampleSize)

			for j := 0; j < sampleSize; j++ {
				// Select a random data point from the full set
				randIndex := rand.Intn(len(data))
				sample[j] = data[randIndex]
			}

			tree := &IsolationTree{}
			tree.Root = ba.IsolationForest.BuildTree(sample, 0)
			trees[index] = tree
		}(i)
	}

	wg.Wait()
	ba.IsolationForest.Trees = trees
	ba.LastTrainTime = time.Now()

	// CRITICAL: Clear training data after training to avoid model drift from old data
	// ba.TrainingData = make([][]float64, 0)
	// For production robustness, we keep some for a rolling window, but for simplicity here, we clear:
	ba.TrainingData = data[:0] // Fast clear

	fmt.Printf("[BehavioralAnalyzer] Training complete. Baseline updated. (Time: %s)\\n", ba.LastTrainTime.Format(time.RFC3339))
}

// UpdateBaseline calculates mean and standard deviation for all features
func (ba *BehavioralAnalyzer) UpdateBaseline(data [][]float64) {
	if len(data) == 0 {
		return
	}

	// Transpose data for gonum's functions (rows become columns)
	numFeatures := len(data[0])
	columns := make([][]float64, numFeatures)
	for i := 0; i < numFeatures; i++ {
		columns[i] = make([]float64, len(data))
	}

	for i, row := range data {
		for j, val := range row {
			columns[j][i] = val
		}
	}

	// Calculate statistics for each feature (ConnRate, BytesIn, BytesOut, AvgDuration)
	if numFeatures >= 1 {
		ba.BaselineStats.ConnRateMean = stat.Mean(columns[0], nil)
		ba.BaselineStats.ConnRateStdDev = stat.StdDev(columns[0], nil)
	}
	if numFeatures >= 2 {
		ba.BaselineStats.BytesInMean = stat.Mean(columns[1], nil)
		ba.BaselineStats.BytesInStdDev = stat.StdDev(columns[1], nil)
	}
	if numFeatures >= 3 {
		ba.BaselineStats.BytesOutMean = stat.Mean(columns[2], nil)
		ba.BaselineStats.BytesOutStdDev = stat.StdDev(columns[2], nil)
	}
	if numFeatures >= 4 {
		ba.BaselineStats.AvgDurationMean = stat.Mean(columns[3], nil)
		// StdDev for AvgDuration is less critical for the current model but can be added
	}
}

// AnalyzeNetworkActivity is the core function called by NetworkMalwareScanner
func (ba *BehavioralAnalyzer) AnalyzeNetworkActivity(ip string) ([]ThreatIndicator, error) {
	profile := ba.GetProfile(ip)

	// 1. Calculate the real-time feature vector (similar to AddNetworkEvent)
	_ = 60 * time.Second
	timeSinceUpdate := time.Since(profile.LastUpdateTime)
	if timeSinceUpdate == 0 {
		timeSinceUpdate = 1 * time.Second // Avoid division by zero on fresh profiles
	}

	connRate := float64(profile.ConnectionFrequency) / timeSinceUpdate.Seconds()
	bytesInRate := float64(profile.TotalBytesIn) / timeSinceUpdate.Seconds()
	bytesOutRate := float64(profile.TotalBytesOut) / timeSinceUpdate.Seconds()

	avgDuration := stat.Mean(profile.RecentDurations, nil)

	featureVector := []float64{connRate, bytesInRate, bytesOutRate, avgDuration}

	// 2. Anomaly Scoring using Isolation Forest
	anomalyScore := 0.0
	if len(ba.IsolationForest.Trees) > 0 {
		anomalyScore = ba.IsolationForest.CalculateAnomalyScore(featureVector)
	}

	// Record the score history (for long-term behavioral changes)
	profile.AnomalyScoreHistory = append(profile.AnomalyScoreHistory, anomalyScore)
	if len(profile.AnomalyScoreHistory) > 10 { // Keep last 10 scores
		profile.AnomalyScoreHistory = profile.AnomalyScoreHistory[len(profile.AnomalyScoreHistory)-10:]
	}

	// 3. Generate Threat Indicators
	indicators := make([]ThreatIndicator, 0)

	// --- A. Isolation Forest Verdict ---
	if anomalyScore >= ba.AnomalyThreshold {
		// Calculate the deviation from the baseline (Z-score concept for context)
		zScoreConn := math.Abs(connRate-ba.BaselineStats.ConnRateMean) / ba.BaselineStats.ConnRateStdDev
		zScoreOut := math.Abs(bytesOutRate-ba.BaselineStats.BytesOutMean) / ba.BaselineStats.BytesOutStdDev

		severity := ThreatLevelMedium
		if anomalyScore >= 0.8 && (zScoreConn > 5.0 || zScoreOut > 5.0) {
			severity = ThreatLevelCritical // High score AND extreme deviation
		} else if anomalyScore >= 0.7 {
			severity = ThreatLevelHigh
		}

		indicators = append(indicators, ThreatIndicator{
			Timestamp: time.Now(),
			SourceID:  "BEHAVIORAL-ANOMALY",
			SourceIP:  ip,
			Target:    ip,
			Severity:  severity,
			Signature: fmt.Sprintf("Isolation Forest Anomaly (Score: %.4f)", anomalyScore),
			Details: map[string]interface{}{
				"connection_rate": fmt.Sprintf("%.2f/s", connRate),
				"bytes_out_rate":  fmt.Sprintf("%.2f/s", bytesOutRate),
				"description":     "Network activity significantly deviates from the established baseline and Isolation Forest model.",
			},
		})
	}

	// --- B. Known Malware Behavior Check (IOB) ---
	for _, behavior := range ba.MalwareBehaviors {
		if ba.checkBehaviorPattern(profile, featureVector, behavior) {
			indicators = append(indicators, ThreatIndicator{
				Timestamp: time.Now(),
				SourceID:  "BEHAVIORAL-IOB",
				SourceIP:  ip,
				Target:    ip,
				Severity:  ThreatLevelHigh, // IOB match is always High or Critical
				Signature: behavior.Name,
				Details: map[string]interface{}{
					"matched_patterns": strings.Join(behavior.Patterns, ", "),
					"description":      fmt.Sprintf("Behavioral pattern matches a known Indicator of Behavior for %s.", behavior.Name),
				},
			})
		}
	}

	// Reset profile counters after analysis for the next window
	profile.ConnectionFrequency = 0
	profile.TotalBytesIn = 0
	profile.TotalBytesOut = 0
	// Keep durations for stable average

	return indicators, nil
}

// checkBehaviorPattern is a high-level IOB matcher
func (ba *BehavioralAnalyzer) checkBehaviorPattern(profile *BehaviorProfile, featureVector []float64, pattern MalwareBehavior) bool {
	// Feature Vector: [0: ConnRate, 1: BytesInRate, 2: BytesOutRate, 3: AvgDuration]
	connRate := featureVector[0]
	_ = featureVector[1]
	bytesOut := featureVector[2]

	for _, p := range pattern.Patterns {
		// Pattern: large_data_transfer
		if p == "large_data_transfer" && ba.BaselineStats.BytesOutStdDev > 0 {
			// Check if BytesOutRate is > 4 standard deviations from the mean
			zScoreOut := (bytesOut - ba.BaselineStats.BytesOutMean) / ba.BaselineStats.BytesOutStdDev
			if zScoreOut > 4.0 {
				return true
			}
		}

		// Pattern: off_hours (Check for large transfer during off-hours)
		if p == "off_hours" && ba.BaselineStats.BytesOutMean > 0 {
			// Check for BytesOutRate > 5x baseline average
			if bytesOut > ba.BaselineStats.BytesOutMean*5.0 {
				nowHour := time.Now().Hour()
				// Define off-hours as 10 PM to 6 AM (22:00 to 06:00)
				isOffHours := nowHour < 6 || nowHour >= 22
				if isOffHours {
					return true
				}
			}
		}

		// Pattern: high_freq_connections (C2_Beaconing or Scanning)
		if p == "high_freq_connections" && ba.BaselineStats.ConnRateStdDev > 0 {
			// Check if Connection Rate is > 4 standard deviations from the mean
			zScoreConn := (connRate - ba.BaselineStats.ConnRateMean) / ba.BaselineStats.ConnRateStdDev
			if zScoreConn > 4.0 {
				// Pattern: small_periodic_data (If paired with high_freq, indicates C2 beaconing)
				if p2, ok := ba.MalwareBehaviors[pattern.Name]; ok {
					if containsString(p2.Patterns, "small_periodic_data") {
						// Check if data packets are small (< 1KB total)
						if profile.TotalBytesIn < 1024 && profile.TotalBytesOut < 1024 && connRate > 0 {
							// High frequency of small packets = beaconing
							return true
						}
					}
				} else {
					// High frequency alone = scanning/worm activity
					return true
				}
			}
		}
	}

	// Port-Based Check (Secondary check)
	// Check if any typical service ports match a known C2 port
	if len(pattern.Ports) > 0 {
		for _, p := range pattern.Ports {
			if containsInt(profile.TypicalServices, p) {
				return true
			}
		}
	}

	return false
}

// LoadBehaviorFromRemote simulates loading behavior profiles from a remote source
func (ba *BehavioralAnalyzer) LoadBehaviorFromRemote() string {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	fmt.Println("[BehavioralAnalyzer] Loading behavior profiles from remote source...")

	// Simulate loading remote profiles
	// In a real implementation, this would fetch from a database or API
	fmt.Println("[BehavioralAnalyzer] Remote behavior profiles loaded (simulated)")

	return "Behavior profiles loaded successfully"
}

// AnalyzeProfile analyzes a behavior profile for anomalies
func (ba *BehavioralAnalyzer) AnalyzeProfile(ip string) ([]ThreatIndicator, error) {
	return ba.AnalyzeNetworkActivity(ip)
}

// UpdateProfile updates a behavior profile with new data
func (ba *BehavioralAnalyzer) UpdateProfile(ip string, data map[string]interface{}) error {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	profile := ba.GetProfile(ip)

	// Update profile with provided data
	if connFreq, ok := data["connection_frequency"].(float64); ok {
		profile.ConnectionFrequency = int(connFreq)
	}
	if bytesIn, ok := data["total_bytes_in"].(float64); ok {
		profile.TotalBytesIn = int64(bytesIn)
	}
	if bytesOut, ok := data["total_bytes_out"].(float64); ok {
		profile.TotalBytesOut = int64(bytesOut)
	}

	profile.LastUpdateTime = time.Now()
	return nil
}

// Helper functions (required by the logic above)

// Helper functions moved to types.go
