package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

const appVersion = "2.0.0"

func main() {
	// Global flags
	mode := flag.String("mode", "web", "Run mode: cli or web (default: web)")
	version := flag.Bool("version", false, "Print version and exit")
	verbose := flag.Bool("verbose", false, "Enable verbose output")

	flag.Parse()

	if *version {
		fmt.Printf("Security Suite v%s\n", appVersion)
		os.Exit(0)
	}

	// Initialize the core controller
	controller := NewCoreController(*verbose)

	switch *mode {
	case "cli":
		runCLI(flag.Args(), controller)
	case "web":
		runWebServer(controller)
	default:
		log.Fatalf("Unknown mode: %s. Use: cli or web", *mode)
	}
}

// runCLI handles the command-line interface mode
func runCLI(args []string, controller *CoreController) {
	if len(args) == 0 {
		printCLIHelp()
		return
	}

	command := args[0]

	switch command {
	case "scan":
		handleScanCLI(args[1:], controller)
	case "monitor":
		handleMonitorCLI(args[1:], controller)
	case "update":
		handleUpdateCLI(controller)
	case "stop":
		handleStopCLI(controller)
	case "demo":
		handleDemoCLI(controller)
	case "forensic": // ADDED: New command for forensic analysis/hash extraction
		handleForensicCLI(args[1:], controller)
	case "crack": // ADDED: New command for high-speed hash cracking
		handleCrackCLI(args[1:], controller)
	case "help":
		printCLIHelp()
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printCLIHelp()
		os.Exit(1)
	}
}

func handleScanCLI(args []string, controller *CoreController) {
	scanFlags := flag.NewFlagSet("scan", flag.ExitOnError)
	targetType := scanFlags.String("type", "file", "Scan type: file, directory, network")
	target := scanFlags.String("target", "", "Target path or IP")
	depth := scanFlags.Int("depth", -1, "Directory scan depth (-1 for unlimited)")

	scanFlags.Parse(args)

	if *target == "" {
		fmt.Println("Error: -target is required")
		scanFlags.Usage()
		return
	}

	result, err := controller.ExecuteScan(*targetType, *target, *depth)
	if err != nil {
		fmt.Printf("Scan failed: %v\n", err)
		return
	}

	fmt.Printf("\nScan Results:\n")
	fmt.Printf("Status: %v\n", result["status"])
	fmt.Printf("Message: %v\n", result["message"])

	if threats, ok := result["threats"].([]ThreatIndicator); ok && len(threats) > 0 {
		fmt.Printf("\nFound %d threats:\n", len(threats))
		for i, threat := range threats {
			fmt.Printf("\n[%d] Severity: %s\n", i+1, threat.Severity)
			fmt.Printf("    Target: %s\n", threat.Target)
			fmt.Printf("    Signature: %s\n", threat.Signature)
			fmt.Printf("    Context: %s\n", threat.Context)
		}
	} else {
		fmt.Println("\nNo threats detected.")
	}
}

// handleForensicCLI executes a hash extraction from a forensic image/source.
func handleForensicCLI(args []string, controller *CoreController) {
	forensicFlags := flag.NewFlagSet("forensic", flag.ExitOnError)
	targetOS := forensicFlags.String("os", "", "Target operating system (e.g., windows, linux) - REQUIRED")
	targetPath := forensicFlags.String("target", "", "Path to the forensic image or source file - REQUIRED")

	forensicFlags.Parse(args)

	if *targetOS == "" || *targetPath == "" {
		fmt.Println("Error: -os and -target are required for forensic hash extraction.")
		forensicFlags.Usage()
		return
	}

	// The CoreController will delegate this to the ForensicToolkit
	fmt.Printf("\n[FORENSIC] Starting hash extraction from target: %s (OS: %s)...\n", *targetPath, *targetOS)
	hashes, err := controller.ExecuteHashExtraction(*targetOS, *targetPath)

	if err != nil {
		fmt.Printf("\n[FAILURE] Forensic hash extraction failed: %v\n", err)
		return
	}

	if len(hashes) == 0 {
		fmt.Println("\n[SUCCESS] Hash extraction completed. No hashes were found.")
		return
	}

	fmt.Printf("\n[SUCCESS] Extracted %d hashes:\n", len(hashes))
	for i, hash := range hashes {
		fmt.Printf("\n[%d] Type: %s | User: %s\n", i+1, hash.HashType, hash.Username)
		fmt.Printf("    Hash: %s\n", hash.Hash)
		fmt.Printf("    Source: %s\n", hash.SourceFile)
	}
}

// handleCrackCLI executes a hash cracking dictionary attack.
func handleCrackCLI(args []string, controller *CoreController) {
	crackFlags := flag.NewFlagSet("crack", flag.ExitOnError)
	hashesRaw := crackFlags.String("hashes", "", "Comma-separated list of hashes to crack (or read from stdin if empty)")
	hashType := crackFlags.String("type", "", "Hash type (e.g., MD5, SHA256, NTLM) - REQUIRED")
	wordlistPath := crackFlags.String("wordlist", "", "Path to the wordlist file - REQUIRED")

	crackFlags.Parse(args)

	if *hashType == "" || *wordlistPath == "" {
		fmt.Println("Error: -type and -wordlist are required for hash cracking.")
		crackFlags.Usage()
		return
	}

	var hashes []string
	if *hashesRaw != "" {
		// Parse comma-separated list of hashes from flag
		hashes = strings.Split(*hashesRaw, ",")
		for i, h := range hashes {
			hashes[i] = strings.TrimSpace(h)
		}
	} else {
		// In a production environment, reading from a file or stdin is common for long hash lists.
		fmt.Println("Error: -hashes is required for CLI mode. Use web mode for file upload support.")
		crackFlags.Usage()
		return
	}

	if len(hashes) == 0 {
		fmt.Println("Error: No valid hashes provided.")
		return
	}

	fmt.Printf("\n[CRACKER] Starting dictionary attack on %d hashes (Type: %s)...\n", len(hashes), *hashType)

	// ExecuteHashCracking starts the job in a background goroutine and returns a session ID.
	sessionID, err := controller.ExecuteHashCracking(hashes, *hashType, *wordlistPath)

	if err != nil {
		fmt.Printf("\n[FAILURE] Failed to start cracking job: %v\n", err)
		return
	}

	fmt.Printf("\n[JOB STARTED] Session ID: %s\n", sessionID)
	fmt.Println("Monitor the logs for real-time cracked hash results. Press Ctrl+C to stop the application (which will terminate the job).")

	// The CoreController's cracking process will stream results to stdout/logs.
	// Keep the main routine alive to allow the background cracking job to run.
	select {}
}

func handleMonitorCLI(args []string, controller *CoreController) {
	monitorFlags := flag.NewFlagSet("monitor", flag.ExitOnError)
	iface := monitorFlags.String("iface", "eth0", "Network interface to monitor")

	monitorFlags.Parse(args)

	msg := controller.StartTrafficMonitor(*iface)
	fmt.Println(msg)

	// Keep running until interrupted
	fmt.Println("Press Ctrl+C to stop monitoring...")
	select {}
}

func handleUpdateCLI(controller *CoreController) {
	msg := controller.UpdateIDSRules()
	fmt.Println(msg)
}

func handleStopCLI(controller *CoreController) {
	msg := controller.StopAllScanners()
	fmt.Println(msg)
}

func handleDemoCLI(controller *CoreController) {
	// 2. Use strings.Repeat("string", count)
	separator := strings.Repeat("=", 60)

	fmt.Println("\n" + separator)
	fmt.Println("SECURITY SUITE DEMONSTRATION")
	fmt.Println(separator + "\n") // Use the repeated string variable

	controller.ExecuteDemonstrationFlow()
}

func printCLIHelp() {
	fmt.Println("Security Suite - Advanced Security Analysis Tool")
	fmt.Printf("Version: %s\n\n", appVersion)
	fmt.Println("Usage: security_suite [options] <command> [command-options]")
	fmt.Println("\nGlobal Options:")
	fmt.Println("  -mode string    Run mode: cli or web (default: web)")
	fmt.Println("  -version        Print version and exit")
	fmt.Println("  -verbose        Enable verbose output")
	fmt.Println("\nCommands:")
	fmt.Println("  scan            Perform security scan")
	fmt.Println("  monitor         Start real-time network monitoring")
	fmt.Println("  update          Update threat definitions")
	fmt.Println("  stop            Stop all active processes")
	fmt.Println("  demo            Run demonstration flow")
	fmt.Println("  forensic        Extract hashes or metadata from forensic images") // ADDED
	fmt.Println("  crack           Run a dictionary attack to crack hashes")        // ADDED
	fmt.Println("  help            Show this help message")
	fmt.Println("\nScan Options:")
	fmt.Println("  -type string    Scan type: file, directory, network")
	fmt.Println("  -target string  Target path or IP address")
	fmt.Println("  -depth int      Directory scan depth (-1 for unlimited)")
	fmt.Println("\nMonitor Options:")
	fmt.Println("  -iface string   Network interface to monitor (default: eth0)")
	fmt.Println("\nForensic Hash Extraction Options:") // ADDED
	fmt.Println("  -os string      Target operating system (e.g., windows, linux)")
	fmt.Println("  -target string  Path to the forensic image or source file")
	fmt.Println("\nHash Cracking Options:") // ADDED
	fmt.Println("  -hashes string  Comma-separated list of hashes (e.g., 'hash1,hash2')")
	fmt.Println("  -type string    Hash type (e.g., MD5, SHA256, NTLM)")
	fmt.Println("  -wordlist string Path to the wordlist file")
	fmt.Println("\nExamples:")
	fmt.Println("  security_suite scan -type file -target /tmp/suspicious.exe")
	fmt.Println("  security_suite forensic -os windows -target /mnt/forensic/memory.img")
	fmt.Println("  security_suite crack -type NTLM -wordlist /usr/share/wordlist/rockyou.txt -hashes '5e1f0611e13a48e71c998782a51d954a'")
	fmt.Println("  security_suite monitor -iface eth0")
	fmt.Println("  security_suite demo")
	fmt.Println("  security_suite -mode web")
	fmt.Println("\nWeb Mode:")
	fmt.Println("  Start with: security_suite -mode web")
	fmt.Println("  Then open: http://localhost:8080")
}

// runWebServer starts the web API server
func runWebServer(controller *CoreController) {
	server := NewWebServer(controller)
	server.Start()
}