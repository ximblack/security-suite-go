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
	fmt.Println("  help            Show this help message")
	fmt.Println("\nScan Options:")
	fmt.Println("  -type string    Scan type: file, directory, network")
	fmt.Println("  -target string  Target path or IP address")
	fmt.Println("  -depth int      Directory scan depth (-1 for unlimited)")
	fmt.Println("\nMonitor Options:")
	fmt.Println("  -iface string   Network interface to monitor (default: eth0)")
	fmt.Println("\nExamples:")
	fmt.Println("  security_suite scan -type file -target /tmp/suspicious.exe")
	fmt.Println("  security_suite scan -type directory -target /var/www -depth 3")
	fmt.Println("  security_suite scan -type network -target 192.168.1.0/24")
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
