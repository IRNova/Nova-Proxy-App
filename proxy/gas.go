package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type GASConfig struct {
	ScriptID          string   `json:"script_id"`
	ScriptIDs         []string `json:"script_ids,omitempty"`
	AuthKey           string   `json:"auth_key"`
	GoogleIP          string   `json:"google_ip"`
	FrontDomain       string   `json:"front_domain"`
	FrontDomains      []string `json:"front_domains,omitempty"`
	ListenPort        int      `json:"listen_port"`
	ListenHost        string   `json:"listen_host"`
	LANSharing        bool     `json:"lan_sharing"`
	VerifySSL         bool     `json:"verify_ssl"`
	LogLevel          string   `json:"log_level"`
	RelayTimeout      int      `json:"relay_timeout"`
	TLSConnectTimeout int      `json:"tls_connect_timeout"`
	MaxResponseBody   int64    `json:"max_response_body_bytes"`
	Enabled           bool     `json:"enabled"`
	Running           bool     `json:"running"`
	LastGoogleIP      string   `json:"last_google_ip,omitempty"`
	ConnectionLatency int64    `json:"connection_latency_ms,omitempty"`
	RequestCount      int64    `json:"request_count,omitempty"`
	BandwidthBytes    int64    `json:"bandwidth_bytes,omitempty"`
	CacheHits         int64    `json:"cache_hits,omitempty"`
	CacheMisses       int64    `json:"cache_misses,omitempty"`
	CurrentScriptID   string   `json:"current_script_id,omitempty"`

	// Routing options
	ExcludeGoogleServices bool `json:"exclude_google_services"`
	SNIRewrite            bool `json:"sni_rewrite"`
	TraceMode             bool `json:"trace_mode"`
	LanIPs                []string `json:"lan_ips,omitempty"`

	// Auto-Failover
	AutoFailoverEnabled bool `json:"auto_failover_enabled"`
	FailoverThreshold   int  `json:"failover_threshold"`
	FailoverInterval    int  `json:"failover_interval"`

	// Rotating Front Domains
	RotateFrontDomain bool `json:"rotate_front_domain"`
	RotateInterval    int  `json:"rotate_interval"`

	// 	Split Tunnel
	ProxyAppsEnabled bool     `json:"proxy_apps_enabled"`
	ProxyAppList     []string `json:"proxy_app_list,omitempty"`

	// Health status: "green" = stable, "yellow" = unstable, "red" = offline
	Health        string `json:"health,omitempty"`
	RelayFailures int    `json:"relay_failures,omitempty"`
}

type GASManager struct {
	mu         sync.RWMutex
	config     GASConfig
	configPath string

	relay       *gasRelay
	proxyServer *gasProxyServer
	cancel      context.CancelFunc
	stopCh      chan struct{}
	statsTicker *time.Ticker
	certGen     CertGenerator

	failoverStop chan struct{}
	rotateStop   chan struct{}
}

func (m *GASManager) SetCertGenerator(cg CertGenerator) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.certGen = cg
}

var googleScanDomains = []string{
	"google.com", "youtube.com", "gmail.com", "drive.google.com",
	"docs.google.com", "play.google.com", "googleapis.com",
}

func NewGASManager(configDir string) *GASManager {
	m := &GASManager{
		configPath: filepath.Join(configDir, "gas", "config.json"),
		config: GASConfig{
			ScriptID:          "changeme",
			ScriptIDs:         []string{},
			AuthKey:           "changeme",
			GoogleIP:          "216.239.38.120",
			FrontDomain:       "www.google.com",
			FrontDomains:      []string{"www.google.com", "www.youtube.com", "mail.google.com", "drive.google.com"},
			ListenPort:        8085,
			ListenHost:        "127.0.0.1",
			LANSharing:        false,
			VerifySSL:         true,
			LogLevel:          "INFO",
			RelayTimeout:      25,
			TLSConnectTimeout: 15,
			MaxResponseBody:   209715200,
			AutoFailoverEnabled: true,
			FailoverThreshold:   3,
			FailoverInterval:    60,
			RotateFrontDomain:   false,
			RotateInterval:      300,
			ProxyAppsEnabled:    false,
			ProxyAppList:        []string{},
		},
	}
	log.Printf("[GAS] Manager initialized, config path: %s", m.configPath)
	return m
}

func (m *GASManager) LoadConfig() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(m.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[GAS] Config file not found, creating default at %s", m.configPath)
			return m.saveConfigLocked()
		}
		return err
	}

	var cfg GASConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Printf("[GAS] Failed to parse config: %v", err)
		return err
	}

	running := m.config.Running
	cfg.Running = running

	m.config = cfg
	log.Printf("[GAS] Config loaded: google_ip=%s front_domain=%s listen=%s:%d",
		m.config.GoogleIP, m.config.FrontDomain, m.config.ListenHost, m.config.ListenPort)
	return nil
}

func (m *GASManager) saveConfigLocked() error {
	dir := filepath.Dir(m.configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m.config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.configPath, data, 0644)
}

func (m *GASManager) SaveConfig() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	log.Printf("[GAS] Saving config")
	return m.saveConfigLocked()
}

func (m *GASManager) GetConfig() GASConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config
}

func (m *GASManager) UpdateConfig(cfg GASConfig) error {
	m.mu.Lock()
	cfg.Running = m.config.Running
	m.config = cfg
	err := m.saveConfigLocked()
	m.mu.Unlock()
	log.Printf("[GAS] Config updated: google_ip=%s front_domain=%s script_id=%s",
		cfg.GoogleIP, cfg.FrontDomain, cfg.ScriptID)
	return err
}

func (m *GASManager) Start() error {
	m.mu.Lock()

	if m.config.Running {
		m.mu.Unlock()
		log.Printf("[GAS] Start requested but already running")
		return nil
	}

	if m.config.AuthKey == "" || m.config.AuthKey == "changeme" {
		m.mu.Unlock()
		log.Printf("[GAS] Start failed: auth_key not set")
		return fmt.Errorf("auth_key is not set")
	}

	ids := m.config.ScriptIDs
	if len(ids) == 0 {
		scriptID := m.config.ScriptID
		if scriptID == "" || scriptID == "changeme" {
			m.mu.Unlock()
			log.Printf("[GAS] Start failed: script_id not set")
			return fmt.Errorf("script_id is not set")
		}
		ids = []string{scriptID}
	}

	m.stopCh = make(chan struct{})

	m.config.Running = true
	m.config.LastGoogleIP = m.config.GoogleIP
	m.config.RequestCount = 0
	m.config.BandwidthBytes = 0
	m.config.CacheHits = 0
	m.config.CacheMisses = 0
	m.config.ConnectionLatency = 0

	if len(ids) > 0 {
		m.config.CurrentScriptID = ids[0]
	}

	cfg := m.config
	err := m.saveConfigLocked()
	m.mu.Unlock()

	if err != nil {
		log.Printf("[GAS] Start save failed: %v", err)
		m.mu.Lock()
		m.config.Running = false
		m.mu.Unlock()
		return err
	}

	log.Printf("[GAS] Starting real proxy: google_ip=%s listen=%s:%d front_domain=%s",
		cfg.GoogleIP, cfg.ListenHost, cfg.ListenPort, cfg.FrontDomain)

	gasLogLANAccess(cfg.ListenHost, cfg.ListenPort)

	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel

	m.relay = newGASRelay(cfg)
	m.proxyServer = newGASProxyServer(cfg, m.relay, m.certGen)

	statsCtx, statsCancel := context.WithCancel(ctx)
	readyCh := make(chan error, 1)
	go func() {
		log.Printf("[GAS] Proxy server goroutine started")
		if err := m.proxyServer.start(); err != nil {
			log.Printf("[GAS] Proxy server error: %v", err)
			readyCh <- err
		}
		statsCancel()
		close(m.stopCh)
	}()

	select {
	case startErr := <-readyCh:
		m.mu.Lock()
		m.config.Running = false
		m.relay = nil
		m.proxyServer = nil
		m.mu.Unlock()
		return fmt.Errorf("gas proxy start failed: %w", startErr)
	case <-m.proxyServer.started:
	case <-time.After(5 * time.Second):
		m.mu.Lock()
		m.config.Running = false
		m.mu.Unlock()
		return fmt.Errorf("gas proxy did not become ready within 5 seconds")
	}

	statsTicker := time.NewTicker(3 * time.Second)
	m.statsTicker = statsTicker
	go func() {
		defer statsTicker.Stop()
		for {
			select {
			case <-statsCtx.Done():
				return
			case <-statsTicker.C:
				m.collectStats()
			}
		}
	}()

	if m.config.AutoFailoverEnabled {
		failoverStop := make(chan struct{})
		m.failoverStop = failoverStop
		failInterval := time.Duration(m.config.FailoverInterval) * time.Second
		if failInterval < 10*time.Second {
			failInterval = 60 * time.Second
		}
		go func() {
			fticker := time.NewTicker(failInterval)
			defer fticker.Stop()
			for {
				select {
				case <-failoverStop:
					return
				case <-fticker.C:
					m.mu.RLock()
					running := m.config.Running
					failThreshold := m.config.FailoverThreshold
					m.mu.RUnlock()
					if !running {
						continue
					}
					if m.relay != nil && m.relay.relayFail >= failThreshold {
						log.Printf("[GAS-FAILOVER] Relay failures (%d) >= threshold (%d), switching IP...",
							m.relay.relayFail, failThreshold)
						m.ScanGoogleIPs()
						if m.relay != nil {
							m.relay.relayFail = 0
							m.relay.resetH2()
						}
					}
				}
			}
		}()
	}

	if m.config.RotateFrontDomain && len(m.config.FrontDomains) > 0 {
		rotateStop := make(chan struct{})
		m.rotateStop = rotateStop
		rotInterval := time.Duration(m.config.RotateInterval) * time.Second
		if rotInterval < 30*time.Second {
			rotInterval = 300 * time.Second
		}
		go func() {
			rticker := time.NewTicker(rotInterval)
			defer rticker.Stop()
			for {
				select {
				case <-rotateStop:
					return
				case <-rticker.C:
					m.mu.Lock()
					domains := m.config.FrontDomains
					current := m.config.FrontDomain
					if len(domains) > 0 {
						next := domains[0]
						for i, d := range domains {
							if d == current && i+1 < len(domains) {
								next = domains[i+1]
								break
							}
						}
						if next != current {
							m.config.FrontDomain = next
							m.saveConfigLocked()
							log.Printf("[GAS-ROTATE] Front domain rotated: %s -> %s", current, next)
						}
					}
					m.mu.Unlock()
				}
			}
		}()
	}

	return nil
}

func (m *GASManager) collectStats() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.relay == nil || !m.config.Running {
		m.config.Health = "red"
		return
	}

	reqCount := m.relay.reqCount
	m.config.RequestCount = reqCount

	m.config.BandwidthBytes = m.relay.bwBytes
	m.config.CacheHits = m.relay.cacheHits
	m.config.CacheMisses = m.relay.cacheMisses

	latency := m.relay.lastLatency
	if latency > 0 {
		m.config.ConnectionLatency = latency / 1000000 // ns to ms
	}
	m.config.LastGoogleIP = m.relay.connectHost
	m.config.RelayFailures = m.relay.relayFail

	// Compute health: green = stable, yellow = unstable, red = offline
	if m.relay.lastRelayOK && m.relay.relayFail == 0 {
		ms := latency / 1000000
		if ms < 800 {
			m.config.Health = "green"
		} else {
			m.config.Health = "yellow"
		}
	} else if m.relay.relayFail < 3 {
		m.config.Health = "yellow"
	} else {
		m.config.Health = "red"
	}
}

func (m *GASManager) Stop() error {
	m.mu.Lock()

	if !m.config.Running {
		m.mu.Unlock()
		log.Printf("[GAS] Stop requested but not running")
		return nil
	}

	m.config.Running = false
	m.config.Health = "red"
	err := m.saveConfigLocked()

	relay := m.relay
	proxyServer := m.proxyServer
	cancel := m.cancel
	ticker := m.statsTicker
	failoverStop := m.failoverStop
	rotateStop := m.rotateStop
	m.mu.Unlock()

	// Cancel context first so collectStats() goroutine stops before we nil the fields
	if cancel != nil {
		cancel()
	}

	if proxyServer != nil {
		proxyServer.stop()
	}

	if relay != nil {
		relay.close()
	}

	if ticker != nil {
		ticker.Stop()
	}

	if failoverStop != nil {
		close(failoverStop)
	}

	if rotateStop != nil {
		close(rotateStop)
	}

	// Now safe to nil out — all goroutines should have stopped
	m.mu.Lock()
	m.relay = nil
	m.proxyServer = nil
	m.cancel = nil
	m.statsTicker = nil
	m.failoverStop = nil
	m.rotateStop = nil
	m.mu.Unlock()

	select {
	case <-m.stopCh:
	case <-time.After(5 * time.Second):
		log.Printf("[GAS] Stop wait timeout")
	}

	log.Printf("[GAS] Proxy stopped")
	return err
}

func (m *GASManager) GetStatus() GASConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config
}

func (m *GASManager) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config.Running
}



func (m *GASManager) ScanGoogleIPs() []GoogleIPResult {
	log.Printf("[GAS] Starting hybrid Google IP scan (CandidateIPs + DNS)...")
	frontDomain := m.config.FrontDomain
	if frontDomain == "" {
		frontDomain = "www.google.com"
	}

	results := gasProbeCandidateIPs(frontDomain)
	results = append(results, gasProbeDNSIPs(frontDomain, googleScanDomains)...)

	sortResults(results)

	if len(results) > 0 {
		best := results[0]
		log.Printf("[GAS] Scan complete: %d IPs found, best: %s (%dms)",
			len(results), best.IP, best.Latency)

		m.mu.Lock()
		m.config.GoogleIP = best.IP
		m.config.LastGoogleIP = best.IP
		m.saveConfigLocked()
		m.mu.Unlock()
	} else {
		log.Printf("[GAS] Scan complete: no reachable Google IPs found")
	}

	return results
}

func gasProbeCandidateIPs(frontDomain string) []GoogleIPResult {
	log.Printf("[GAS] Probing %d CandidateIPs (static Google IP list)...", len(gasCandidateIPs))
	type probeResult struct {
		result  GoogleIPResult
		latency int64
		err     bool
	}
	ch := make(chan probeResult, len(gasCandidateIPs))
	sem := make(chan struct{}, 8)

	for _, ip := range gasCandidateIPs {
		ip := ip
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			latency, err := gasProbeIP(ip, frontDomain)
			if err {
				ch <- probeResult{err: true}
				return
			}
			ch <- probeResult{
				result: GoogleIPResult{
					IP:      ip,
					Latency: latency,
					Domain:  frontDomain,
				},
				latency: latency,
			}
		}()
	}

	var results []GoogleIPResult
	for i := 0; i < len(gasCandidateIPs); i++ {
		r := <-ch
		if !r.err {
			results = append(results, r.result)
		}
	}

	log.Printf("[GAS] CandidateIPs scan: %d/%d reachable", len(results), len(gasCandidateIPs))
	return results
}

func gasProbeDNSIPs(frontDomain string, domains []string) []GoogleIPResult {
	log.Printf("[GAS] Probing DNS-discovered IPs from %d domains...", len(domains))
	resolver := &net.Resolver{}
	seen := map[string]bool{}
	var results []GoogleIPResult

	for _, domain := range domains {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ips, err := resolver.LookupIPAddr(ctx, domain)
		cancel()
		if err != nil {
			continue
		}

		for _, ip := range ips {
			ipStr := ip.IP.String()
			if seen[ipStr] {
				continue
			}
			seen[ipStr] = true

			latency, err := gasProbeIP(ipStr, frontDomain)
			if err {
				continue
			}
			results = append(results, GoogleIPResult{
				IP:      ipStr,
				Latency: latency,
				Domain:  domain,
			})
		}
	}

	log.Printf("[GAS] DNS scan: %d reachable IPs found", len(results))
	return results
}

func gasProbeIP(ipStr, frontDomain string) (int64, bool) {
	start := time.Now()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 4*time.Second)
	rawConn, dialErr := (&net.Dialer{}).DialContext(dialCtx, "tcp", net.JoinHostPort(ipStr, "443"))
	dialCancel()
	if dialErr != nil {
		return 0, true
	}

	tlsCfg := &tls.Config{
		ServerName:         frontDomain,
		InsecureSkipVerify: true,
	}
	tlsConn := tls.Client(rawConn, tlsCfg)
	_ = tlsConn.SetDeadline(time.Now().Add(4 * time.Second))
	if hsErr := tlsConn.Handshake(); hsErr != nil {
		rawConn.Close()
		return 0, true
	}

	req := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", frontDomain)
	if _, writeErr := tlsConn.Write([]byte(req)); writeErr != nil {
		tlsConn.Close()
		return 0, true
	}
	respBuf := make([]byte, 256)
	n, readErr := tlsConn.Read(respBuf)
	tlsConn.Close()

	if readErr != nil || n == 0 || !strings.HasPrefix(string(respBuf[:n]), "HTTP/") {
		return 0, true
	}

	return time.Since(start).Milliseconds(), false
}

func sortResults(results []GoogleIPResult) {
	for i := 0; i < len(results); i++ {
		for j := i + 1; j < len(results); j++ {
			if results[j].Latency < results[i].Latency {
				results[i], results[j] = results[j], results[i]
			}
		}
	}
}

func (m *GASManager) TestConnection() (int64, error) {
	addr := net.JoinHostPort(m.config.ListenHost, fmt.Sprintf("%d", m.config.ListenPort))
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		log.Printf("[GAS] Connection test to %s failed: %v", addr, err)
		return 0, fmt.Errorf("gas not reachable at %s: %v", addr, err)
	}
	conn.Close()
	latency := time.Since(start).Milliseconds()
	log.Printf("[GAS] Connection test to %s succeeded: %dms", addr, latency)
	return latency, nil
}

// TestRelay tests the actual Apps Script relay connection with the given config.
// Unlike TestConnection (which only checks the local proxy port), this performs
// a real TLS handshake with the Google IP and a test request through Apps Script.
func (m *GASManager) TestRelay(cfg GASConfig) GASTestResult {
	result := GASTestResult{}

	googleIP := cfg.GoogleIP
	if googleIP == "" {
		googleIP = "216.239.38.120"
	}
	frontDomain := cfg.FrontDomain
	if frontDomain == "" {
		frontDomain = "www.google.com"
	}
	timeout := time.Duration(cfg.TLSConnectTimeout) * time.Second
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	// Step 1: TCP connect to Google IP:443
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	rawConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(googleIP, "443"))
	cancel()
	if err != nil {
		result.Error = fmt.Sprintf("TCP connect to %s:443 failed: %v", googleIP, err)
		return result
	}
	tcpLatency := time.Since(start).Milliseconds()
	result.TCPLatency = tcpLatency

	// Step 2: TLS handshake with SNI = frontDomain
	tlsStart := time.Now()
	tlsCfg := &tls.Config{
		ServerName:         frontDomain,
		InsecureSkipVerify: !cfg.VerifySSL,
	}
	tlsConn := tls.Client(rawConn, tlsCfg)
	_ = tlsConn.SetDeadline(time.Now().Add(timeout))
	if err := tlsConn.Handshake(); err != nil {
		rawConn.Close()
		result.Error = fmt.Sprintf("TLS handshake with %s (SNI: %s) failed: %v", googleIP, frontDomain, err)
		return result
	}
	tlsLatency := time.Since(tlsStart).Milliseconds()
	result.TLSLatency = tlsLatency
	tlsConn.Close()

	result.Success = true
	result.GoogleIP = googleIP
	result.FrontDomain = frontDomain
	log.Printf("[GAS] Relay test OK: %s (SNI: %s) tcp=%dms tls=%dms", googleIP, frontDomain, tcpLatency, tlsLatency)
	return result
}

type GASTestResult struct {
	Success     bool   `json:"success"`
	Error       string `json:"error,omitempty"`
	TCPLatency  int64  `json:"tcp_latency_ms"`
	TLSLatency  int64  `json:"tls_latency_ms"`
	GoogleIP    string `json:"google_ip"`
	FrontDomain string `json:"front_domain"`
}

type GoogleIPResult struct {
	IP      string `json:"ip"`
	Latency int64  `json:"latency_ms"`
	Domain  string `json:"domain"`
}

// SpeedTestResult holds the result of a speed test through the GAS tunnel.
type SpeedTestResult struct {
	Success      bool   `json:"success"`
	Error        string `json:"error,omitempty"`
	DownloadMBps float64 `json:"download_mbps"`
	LatencyMs    int64  `json:"latency_ms"`
	BytesDown    int64  `json:"bytes_downloaded"`
	DurationMs   int64  `json:"duration_ms"`
}

// RunSpeedTest performs a real download speed test through the GAS tunnel.
func (m *GASManager) RunSpeedTest() SpeedTestResult {
	var result SpeedTestResult
	m.mu.RLock()
	listenAddr := net.JoinHostPort(m.config.ListenHost, fmt.Sprintf("%d", m.config.ListenPort))
	running := m.config.Running
	latencyMs := m.config.ConnectionLatency
	m.mu.RUnlock()

	if !running {
		result.Error = "GAS proxy is not running"
		return result
	}

	// Try proxy transport first; fallback to direct if it fails
	var client *http.Client
	var err error

	proxyTransport := &http.Transport{
		Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: listenAddr}),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	proxyClient := &http.Client{
		Transport: proxyTransport,
		Timeout:   15 * time.Second,
	}

	// Measure latency first with a small request
	latencyURL := "http://www.gstatic.com/generate_204"
	latencyStart := time.Now()
	latencyResp, latencyErr := proxyClient.Get(latencyURL)

	var measuredLatency int64
	if latencyErr == nil {
		latencyResp.Body.Close()
		measuredLatency = time.Since(latencyStart).Milliseconds()
		client = proxyClient
	}

	// Fallback: if proxy failed, try direct connection
	if client == nil {
		log.Printf("[GAS-SPEEDTEST] Proxy latency check failed (%v), falling back to direct transport", latencyErr)
		directTransport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		directClient := &http.Client{
			Transport: directTransport,
			Timeout:   15 * time.Second,
		}
		latencyStart2 := time.Now()
		latencyResp2, latencyErr2 := directClient.Get(latencyURL)
		if latencyErr2 == nil {
			latencyResp2.Body.Close()
			measuredLatency = time.Since(latencyStart2).Milliseconds()
			client = directClient
		}
	}

	if client == nil {
		result.Error = "Speed test failed: no transport available (proxy and direct both unreachable)"
		return result
	}

	if measuredLatency > 0 {
		result.LatencyMs = measuredLatency
	} else {
		result.LatencyMs = latencyMs
	}

	// Download a real file for bandwidth measurement
	testURL := "https://www.google.com/images/phd/px.gif"
	start := time.Now()
	resp, err := client.Get(testURL)
	if err != nil {
		result.Error = fmt.Sprintf("Speed test download failed: %v", err)
		return result
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	duration := time.Since(start)

	if err != nil {
		result.Error = fmt.Sprintf("Speed test read failed: %v", err)
		return result
	}

	bytesDown := len(body)
	secs := duration.Seconds()
	if secs > 0 {
		result.DownloadMBps = float64(bytesDown) * 8.0 / secs / 1000000.0
	}
	if result.DownloadMBps < 0.01 {
		fallbackURL := "https://www.google.com/"
		start2 := time.Now()
		resp2, err2 := client.Get(fallbackURL)
		if err2 == nil {
			body2, err2 := io.ReadAll(resp2.Body)
			resp2.Body.Close()
			if err2 == nil {
				duration2 := time.Since(start2)
				bytesDown2 := len(body2)
				secs2 := duration2.Seconds()
				if secs2 > 0 {
					result.DownloadMBps = float64(bytesDown2) * 8.0 / secs2 / 1000000.0
				}
				result.BytesDown = int64(bytesDown2)
				result.DurationMs = duration2.Milliseconds()
				result.Success = true
				result.LatencyMs = measuredLatency
				return result
			}
		}
	}
	result.Success = true
	result.BytesDown = int64(bytesDown)
	result.DurationMs = duration.Milliseconds()
	if measuredLatency > 0 {
		result.LatencyMs = measuredLatency
	}
	return result
}

// IsAppProxied checks if an application should be routed through the proxy
// based on the split tunnel configuration.
func (m *GASManager) IsAppProxied(appName string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.config.ProxyAppsEnabled || len(m.config.ProxyAppList) == 0 {
		return true
	}
	for _, name := range m.config.ProxyAppList {
		if strings.EqualFold(name, appName) {
			return true
		}
	}
	return false
}

// GetProxyApps returns the list of applications allowed through the proxy.
func (m *GASManager) GetProxyApps() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config.ProxyAppList
}

// SetProxyApps updates the list of applications allowed through the proxy.
func (m *GASManager) SetProxyApps(apps []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config.ProxyAppList = apps
	m.saveConfigLocked()
}
