package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type Config struct {
	ScanIntervalSeconds int    `json:"scan_interval_seconds"`
	DNSServer           string `json:"dns_server"`
}

func loadConfig(filename string) (*Config, error) {
	// Default configuration
	config := &Config{
		ScanIntervalSeconds: 10,
		DNSServer:           "192.168.1.1",
	}

	// Try to read config file
	data, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			// Create default config file if it doesn't exist
			defaultConfig, _ := json.MarshalIndent(config, "", "    ")
			if err := os.WriteFile(filename, defaultConfig, 0644); err != nil {
				return nil, fmt.Errorf("failed to create default config file: %v", err)
			}
			fmt.Printf("Created default config file: %s\n", filename)
			return config, nil
		}
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	// Parse config file
	if err := json.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}

	// Validate configuration
	if config.ScanIntervalSeconds < 1 {
		return nil, fmt.Errorf("scan_interval_seconds must be greater than 0")
	}
	if config.DNSServer == "" {
		return nil, fmt.Errorf("dns_server cannot be empty")
	}

	return config, nil
}

type PingResult struct {
	Timestamp time.Time
	Domain    string
	IP        string
	IsIPv6    bool
	Success   bool
	RTT       time.Duration
	Error     string
}

// ResolveDNS resolves both IPv4 and IPv6 addresses for a given domain name
func ResolveDNS(domain string, dnsServer string) ([]net.IP, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Second * 5,
			}
			return d.DialContext(ctx, network, dnsServer+":53")
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var results []net.IP

	// Resolve IPv4 addresses
	ipv4, err := resolver.LookupIP(ctx, "ip4", domain)
	if err == nil {
		results = append(results, ipv4...)
	}

	// Resolve IPv6 addresses
	ipv6, err := resolver.LookupIP(ctx, "ip6", domain)
	if err == nil {
		results = append(results, ipv6...)
	}

	if len(results) == 0 {
		return nil, &net.DNSError{
			Err:        "no records found",
			Name:       domain,
			IsNotFound: true,
		}
	}

	return results, nil
}

// PingIP sends an ICMP ping to the specified IP address with a 2-second timeout
func PingIP(ip net.IP) (time.Duration, error) {
	var network, listenAddr string
	var proto int
	var icmpType icmp.Type
	var expectedReply icmp.Type

	if ip.To4() != nil {
		network = "ip4:icmp"
		listenAddr = "0.0.0.0"
		proto = 1 // ICMP for IPv4
		icmpType = ipv4.ICMPTypeEcho
		expectedReply = ipv4.ICMPTypeEchoReply
	} else {
		network = "ip6:ipv6-icmp"
		listenAddr = "::"
		proto = 58 // ICMP for IPv6
		icmpType = ipv6.ICMPTypeEchoRequest
		expectedReply = ipv6.ICMPTypeEchoReply
	}

	c, err := icmp.ListenPacket(network, listenAddr)
	if err != nil {
		return 0, fmt.Errorf("failed to listen: %v", err)
	}
	defer c.Close()

	// Create ICMP message
	msg := icmp.Message{
		Type: icmpType,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("PING"),
		},
	}

	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal message: %v", err)
	}

	// Set deadline for the entire operation
	if err := c.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return 0, fmt.Errorf("failed to set deadline: %v", err)
	}

	// Record start time
	start := time.Now()

	// Send the message
	dst := &net.IPAddr{IP: ip}
	if _, err := c.WriteTo(msgBytes, dst); err != nil {
		return 0, fmt.Errorf("failed to send ping: %v", err)
	}

	// Wait for reply
	reply := make([]byte, 1500)
	n, peer, err := c.ReadFrom(reply)
	if err != nil {
		return 0, fmt.Errorf("failed to receive ping reply: %v", err)
	}

	// Calculate round-trip time
	rtt := time.Since(start)

	rm, err := icmp.ParseMessage(proto, reply[:n])
	if err != nil {
		return 0, fmt.Errorf("failed to parse ICMP message: %v", err)
	}

	if rm.Type != expectedReply {
		return 0, fmt.Errorf("got %+v from %v; want %v", rm, peer, expectedReply)
	}

	return rtt, nil
}

func readDomainFile() ([]string, error) {
	// Read the domain.txt file
	content, err := os.ReadFile("domain.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to read domain file: %v", err)
	}

	// Split content by newlines and filter empty lines
	var domains []string
	for _, line := range strings.Split(string(content), "\n") {
		// Trim whitespace and skip empty lines
		domain := strings.TrimSpace(line)
		if domain != "" {
			domains = append(domains, domain)
		}
	}

	return domains, nil
}

func writeResultsToCSV(results []PingResult, filename string) error {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open CSV file: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header if file is empty
	stat, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat file: %v", err)
	}
	if stat.Size() == 0 {
		header := []string{"Timestamp", "Domain", "IP", "Protocol", "Success", "RTT_ms", "Error"}
		if err := writer.Write(header); err != nil {
			return fmt.Errorf("failed to write header: %v", err)
		}
	}

	// Write results
	for _, result := range results {
		protocol := "IPv4"
		if result.IsIPv6 {
			protocol = "IPv6"
		}
		rttMs := ""
		if result.Success {
			rttMs = fmt.Sprintf("%.2f", float64(result.RTT.Microseconds())/1000.0)
		}
		record := []string{
			result.Timestamp.Format(time.RFC3339),
			result.Domain,
			result.IP,
			protocol,
			fmt.Sprintf("%v", result.Success),
			rttMs,
			result.Error,
		}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("failed to write record: %v", err)
		}
	}

	return nil
}

func scanDomains(config *Config) ([]PingResult, error) {
	domains, err := readDomainFile()
	if err != nil {
		return nil, fmt.Errorf("error reading domain file: %v", err)
	}

	var results []PingResult
	timestamp := time.Now()

	fmt.Printf("\n[%s] Starting scan...\n", timestamp.Format(time.RFC3339))
	fmt.Println("Loaded domains:", domains)

	for _, domain := range domains {
		ips, err := ResolveDNS(domain, config.DNSServer)
		if err != nil {
			result := PingResult{
				Timestamp: timestamp,
				Domain:    domain,
				Success:   false,
				Error:     fmt.Sprintf("DNS resolution failed: %v", err),
			}
			results = append(results, result)
			fmt.Printf("Error resolving DNS for %s: %v\n", domain, err)
			continue
		}

		fmt.Printf("Resolved %s to %v\n", domain, ips)
		for _, ip := range ips {
			isIPv6 := ip.To4() == nil
			fmt.Printf("Pinging %s (%v) [IPv%d]...\n", domain, ip, map[bool]int{true: 6, false: 4}[isIPv6])

			result := PingResult{
				Timestamp: timestamp,
				Domain:    domain,
				IP:        ip.String(),
				IsIPv6:    isIPv6,
			}

			rtt, err := PingIP(ip)
			if err != nil {
				result.Success = false
				result.Error = err.Error()
				fmt.Printf("Error pinging %s: %v\n", ip, err)
			} else {
				result.Success = true
				result.RTT = rtt
				fmt.Printf("Ping %s (%s): time=%v\n", domain, ip, rtt.Round(time.Millisecond))
			}

			results = append(results, result)
		}
	}

	return results, nil
}

func main() {
	const (
		configFile = "config.json"
		csvFile    = "ping_results.csv"
	)

	// Load configuration
	config, err := loadConfig(configFile)
	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		return
	}

	interval := time.Duration(config.ScanIntervalSeconds) * time.Second
	fmt.Printf("Starting periodic domain scanner:\n")
	fmt.Printf("- Interval: %v\n", interval)
	fmt.Printf("- DNS Server: %s\n", config.DNSServer)
	fmt.Printf("- Results file: %s\n", csvFile)

	// Perform first scan immediately
	results, err := scanDomains(config)
	if err != nil {
		fmt.Printf("Scan error: %v\n", err)
	} else if err := writeResultsToCSV(results, csvFile); err != nil {
		fmt.Printf("Failed to write results: %v\n", err)
	}

	// Set up ticker for periodic scans
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		results, err := scanDomains(config)
		if err != nil {
			fmt.Printf("Scan error: %v\n", err)
			continue
		}

		if err := writeResultsToCSV(results, csvFile); err != nil {
			fmt.Printf("Failed to write results: %v\n", err)
		}
	}
}
