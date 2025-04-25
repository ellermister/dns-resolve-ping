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

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// 日志级别
const (
	LogDebug   = "DEBUG"
	LogInfo    = "INFO"
	LogWarning = "WARN"
	LogError   = "ERROR"
)

// 日志级别权重
var logLevelWeight = map[string]int{
	LogDebug:   0,
	LogInfo:    1,
	LogWarning: 2,
	LogError:   3,
}

type Config struct {
	ScanIntervalSeconds int    `json:"scan_interval_seconds"`
	DNSServer           string `json:"dns_server"`
	LogLevel            string `json:"log_level"`
}

// 输出格式化日志
func logf(level, format string, args ...interface{}) {
	// 检查日志级别是否应该被输出
	configLevel := currentConfig.LogLevel
	if logLevelWeight[level] < logLevelWeight[configLevel] {
		return
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05.000")
	fmt.Printf("[%s] [%s] %s\n", timestamp, level, fmt.Sprintf(format, args...))
}

// 全局配置变量
var currentConfig *Config

func loadConfig(filename string) (*Config, error) {
	// Default configuration
	config := &Config{
		ScanIntervalSeconds: 10,
		DNSServer:           "192.168.1.1",
		LogLevel:            LogInfo, // 默认日志级别为 INFO
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
			logf(LogInfo, "Created default config file: %s", filename)
			return config, nil
		}
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	// Parse config file
	if err := json.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}

	// 验证并规范化日志级别
	if config.LogLevel == "" {
		config.LogLevel = LogInfo
	} else {
		config.LogLevel = strings.ToUpper(config.LogLevel)
		if _, exists := logLevelWeight[config.LogLevel]; !exists {
			logf(LogWarning, "Invalid log level '%s' in config, using default level 'INFO'", config.LogLevel)
			config.LogLevel = LogInfo
		}
	}

	// 更新全局配置
	currentConfig = config
	return config, nil
}

type PingResult struct {
	// ID        uint       `gorm:"primary_key"`
	gorm.Model
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

	logf(LogInfo, "Starting scan...")
	logf(LogInfo, "Loaded domains: %v", domains)

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
			logf(LogError, "Error resolving DNS for %s: %v", domain, err)
			continue
		}

		logf(LogInfo, "Resolved %s to %v", domain, ips)
		for _, ip := range ips {
			isIPv6 := ip.To4() == nil
			logf(LogInfo, "Pinging %s (%v) [IPv%d]...", domain, ip, map[bool]int{true: 6, false: 4}[isIPv6])

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
				logf(LogError, "Error pinging %s: %v", ip, err)
			} else {
				result.Success = true
				result.RTT = rtt
				logf(LogInfo, "Ping %s (%s): time=%v", domain, ip, rtt.Round(time.Millisecond))
			}

			results = append(results, result)
		}
	}

	return results, nil
}

func main() {
	const configFile = "config.json"

	// Load configuration
	config, err := loadConfig(configFile)
	if err != nil {
		logf(LogError, "Error loading config: %v", err)
		return
	}

	db, err := gorm.Open(sqlite.Open("log.db"), &gorm.Config{})
	if err != nil {
		logf(LogError, "Failed to connect database: %v", err)
		return
	}

	db.AutoMigrate(&PingResult{})

	interval := time.Duration(config.ScanIntervalSeconds) * time.Second
	logf(LogInfo, "Starting periodic domain scanner:")
	logf(LogInfo, "- Interval: %v", interval)
	logf(LogInfo, "- DNS Server: %s", config.DNSServer)

	// Start API server in a goroutine
	go func() {
		r := setupRouter(db)
		logf(LogInfo, "Starting API server on :8080")
		if err := r.Run(":8080"); err != nil {
			logf(LogError, "Failed to start API server: %v", err)
		}
	}()

	// Perform first scan immediately
	results, err := scanDomains(config)
	if err != nil {
		logf(LogError, "Scan error: %v", err)
	}

	if result := db.Create(&results); result.Error != nil {
		logf(LogError, "Failed to write to database: %v", result.Error)
	} else {
		logf(LogInfo, "Successfully wrote %d records to database", result.RowsAffected)
	}

	// Set up ticker for periodic scans
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		results, err := scanDomains(config)
		if err != nil {
			logf(LogError, "Scan error: %v", err)
			continue
		}

		if result := db.Create(&results); result.Error != nil {
			logf(LogError, "Failed to write to database: %v", result.Error)
		} else {
			logf(LogInfo, "Successfully wrote %d records to database", result.RowsAffected)
		}
	}
}
