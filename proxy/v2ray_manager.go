package proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	core "github.com/v2fly/v2ray-core/v5"
	_ "github.com/v2fly/v2ray-core/v5/main/distro/all"
	"github.com/v2fly/v2ray-core/v5/infra/conf/serial"
	"golang.org/x/net/proxy"
)

type V2RaySettings struct {
	CorePort     int    `json:"core_port"`
	CoreHTTPPort int    `json:"core_http_port"`
	SocksPort    int    `json:"socks_port"`
	HTTPPort     int    `json:"http_port"`
	SelectedID   string `json:"selected_id"`
	AutoConnect  bool   `json:"auto_connect"`
	RoutingMode  string `json:"routing_mode"` // "rule", "gas", "v2ray"
	DNSLeak      bool   `json:"dns_leak"`
	Fragment     bool   `json:"fragment"`
	IPv6         bool   `json:"ipv6"`
	ProxyAll     bool   `json:"proxy_all"`
	DOH          bool   `json:"doh"`
	DOHURL       string `json:"doh_url"`
	SNIOverride  string `json:"sni_override"`
}

type V2RayManager struct {
	mu           sync.RWMutex
	store        V2RayConfigStore
	storePath    string
	settings     V2RaySettings
	settingsPath string
	corePort     int
	logFn        func(string)
	coreInstance core.Server
}

func NewV2RayManager(dataDir string, logFn func(string)) *V2RayManager {
	if dataDir == "" {
		execPath, _ := os.Executable()
		dataDir = filepath.Join(filepath.Dir(execPath), "data", "Xray")
	}
	os.MkdirAll(dataDir, 0755)

	storePath := filepath.Join(dataDir, "configs.json")
	settingsPath := filepath.Join(dataDir, "settings.json")
	store := DefaultConfigStore

	data, err := os.ReadFile(storePath)
	if err == nil {
		json.Unmarshal(data, &store)
	}

	m := &V2RayManager{
		storePath:    storePath,
		settingsPath: settingsPath,
		store:        store,
		corePort:     store.CorePort,
		logFn:        logFn,
		settings: V2RaySettings{
			CorePort:     11808,
			CoreHTTPPort: 11809,
			SocksPort:    11808,
			HTTPPort:     11809,
			RoutingMode:  "rule",
		},
	}

	if m.corePort == 0 {
		m.corePort = 11808
	}

	// Load settings from file
	m.loadSettings()

	return m
}

func (m *V2RayManager) loadSettings() {
	data, err := os.ReadFile(m.settingsPath)
	if err != nil {
		return
	}
	var s V2RaySettings
	if err := json.Unmarshal(data, &s); err != nil {
		m.log("failed to load settings: %v", err)
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.settings = s
	if s.CorePort != 0 {
		m.corePort = s.CorePort
	}
}

func (m *V2RayManager) SaveSettings(s V2RaySettings) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	oldPort := m.settings.CorePort
	oldMode := m.settings.RoutingMode
	oldID := m.settings.SelectedID
	m.settings = s
	if s.CorePort != 0 {
		m.corePort = s.CorePort
	}
	if s.CorePort != oldPort {
		m.log("settings: core port changed from %d to %d", oldPort, s.CorePort)
	}
	if s.RoutingMode != oldMode {
		m.log("settings: routing mode changed from %s to %s", oldMode, s.RoutingMode)
	}
	if s.SelectedID != oldID {
		m.log("settings: selected config id changed from %s to %s", oldID, s.SelectedID)
	}
	if err := m.saveSettingsToFile(); err != nil {
		return err
	}
	m.log("settings: saved (port=%d, mode=%s)", s.CorePort, s.RoutingMode)
	return nil
}

func (m *V2RayManager) saveSettingsToFile() error {
	data, err := json.MarshalIndent(m.settings, "", "  ")
	if err != nil {
		m.log("settings: failed to marshal: %v", err)
		return err
	}
	if err := os.WriteFile(m.settingsPath, data, 0644); err != nil {
		m.log("settings: failed to write: %v", err)
		return err
	}
	return nil
}

func (m *V2RayManager) GetSettings() V2RaySettings {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.settings
}

func (m *V2RayManager) log(format string, args ...interface{}) {
	if m.logFn != nil {
		m.logFn(fmt.Sprintf("[v2ray] "+format, args...))
	}
}



// getSelectedConfigLocked returns the selected config (caller must hold at least RLock on m.mu)
func (m *V2RayManager) getSelectedConfigLocked() *V2RayConfig {
	if m.store.SelectedID == "" {
		return nil
	}
	for _, c := range m.store.Configs {
		if c.ID == m.store.SelectedID {
			return &c
		}
	}
	return nil
}

// StartCore starts the V2Ray core as an in-process library instance
func (m *V2RayManager) StartCore() error {
	m.mu.RLock()
	cfg := m.getSelectedConfigLocked()
	port := m.corePort
	m.mu.RUnlock()

	if cfg == nil {
		m.log("StartCore: no config selected")
		return fmt.Errorf("no config selected")
	}

	m.log("StartCore: starting with config %q (protocol=%s, server=%s, port=%s, transport=%s, tls=%s)",
		cfg.Name, cfg.Protocol, cfg.Server, cfg.Port, cfg.Type, cfg.TLS)

	// Stop any existing core instance
	m.mu.Lock()
	if m.coreInstance != nil {
		m.log("StartCore: stopping previous core instance")
		m.coreInstance.Close()
		m.coreInstance = nil
	}
	m.mu.Unlock()

	// Generate V2Ray JSON config string
	configJSON, err := m.GenerateCoreJSON(*cfg)
	if err != nil {
		m.log("StartCore: generate config failed: %v", err)
		return fmt.Errorf("generate config: %w", err)
	}
	m.log("StartCore: generated JSON config (%d bytes)", len(configJSON))

	// Use v2ray-core's JSON config decoder to parse the config
	m.log("StartCore: parsing JSON config for %q", cfg.Name)
	pbConfig, err := serial.LoadJSONConfig(strings.NewReader(configJSON))
	if err != nil {
		m.log("StartCore: parse config failed: %v", err)
		return fmt.Errorf("parse v2ray config: %w", err)
	}
	m.log("StartCore: JSON config parsed to protobuf successfully")

	// Create the V2Ray instance
	m.log("StartCore: creating v2ray instance")
	instance, err := core.New(pbConfig)
	if err != nil {
		m.log("StartCore: create instance failed: %v", err)
		return fmt.Errorf("create v2ray instance: %w", err)
	}
	m.log("StartCore: instance created successfully")

	// Start the instance
	m.log("StartCore: starting v2ray instance (socks=127.0.0.1:%d, http=127.0.0.1:%d)", port, port+1)
	if err := instance.Start(); err != nil {
		m.log("StartCore: instance start failed: %v", err)
		return fmt.Errorf("start v2ray instance: %w", err)
	}
	m.log("StartCore: instance started successfully")

	m.mu.Lock()
	m.coreInstance = instance
	m.corePort = port
	m.mu.Unlock()

	m.SetCoreRunning(true)
	m.log("StartCore: V2Ray core is now running (port %d, config=%q)", port, cfg.Name)
	return nil
}

func (m *V2RayManager) StopCore() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.coreInstance == nil {
		m.log("StopCore: no running instance to stop")
		m.SetCoreRunning(false)
		return nil
	}

	m.log("StopCore: closing v2ray instance")
	if err := m.coreInstance.Close(); err != nil {
		m.log("StopCore: close error: %v", err)
		return fmt.Errorf("stop v2ray instance: %w", err)
	}
	m.coreInstance = nil

	m.SetCoreRunning(false)
	m.log("StopCore: V2Ray core stopped successfully")
	return nil
}

func (m *V2RayManager) IsCoreProcessRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.coreInstance != nil
}

func (m *V2RayManager) save() error {
	data, err := json.MarshalIndent(m.store, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.storePath, data, 0644)
}

func (m *V2RayManager) parseAndAdd(link string) (*V2RayConfig, error) {
	link = strings.TrimSpace(link)
	if link == "" {
		return nil, fmt.Errorf("empty link")
	}

	if strings.HasPrefix(link, "vmess://") ||
		strings.HasPrefix(link, "vless://") ||
		strings.HasPrefix(link, "trojan://") ||
		strings.HasPrefix(link, "ss://") ||
		strings.HasPrefix(link, "ss2022://") ||
		strings.HasPrefix(link, "hy2://") ||
		strings.HasPrefix(link, "hysteria2://") ||
		strings.HasPrefix(link, "socks://") ||
		strings.HasPrefix(link, "socks5://") {
		return ParseV2RayLink(link)
	}

	if strings.HasPrefix(link, "http://") || strings.HasPrefix(link, "https://") {
		return ParseV2RayLink(link)
	}

	if strings.HasPrefix(link, "{") || strings.HasPrefix(link, "[") {
		return ParseJSONConfig(link)
	}

	return nil, fmt.Errorf("unknown config format")
}

func (m *V2RayManager) AddConfig(link string) (*V2RayConfig, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	links := strings.Split(link, "\n")
	var lastCfg *V2RayConfig
	var results []string

	for _, l := range links {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}

		cfg, err := m.parseAndAdd(l)
		if err != nil {
			msg := fmt.Sprintf("failed: %s - %v", l[:min(len(l), 50)], err)
			m.log("AddConfig: %s", msg)
			results = append(results, msg)
			continue
		}

		if cfg != nil {
			cfg.ID = fmt.Sprintf("%x", time.Now().UnixNano())
			m.store.Configs = append(m.store.Configs, *cfg)
			lastCfg = cfg
			msg := fmt.Sprintf("added: %s (%s, server=%s:%s, transport=%s, tls=%s)", cfg.Name, cfg.Protocol, cfg.Server, cfg.Port, cfg.Type, cfg.TLS)
			m.log("AddConfig: %s", msg)
			results = append(results, msg)
		}
	}

	if err := m.save(); err != nil {
		m.log("AddConfig: save failed: %v", err)
	}

	if lastCfg != nil {
		m.log("AddConfig: total configs now %d", len(m.store.Configs))
		return lastCfg, nil
	}
	if len(results) > 0 {
		return nil, fmt.Errorf("%s", strings.Join(results, "; "))
	}
	m.log("AddConfig: no valid configs found in input")
	return nil, fmt.Errorf("no valid configs found")
}

func (m *V2RayManager) AddConfigsFromSub(subURL string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.log("AddConfigsFromSub: fetching subscription: %s", subURL)

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", subURL, nil)
	if err != nil {
		m.log("AddConfigsFromSub: invalid url: %v", err)
		return 0, fmt.Errorf("invalid sub url: %w", err)
	}
	req.Header.Set("User-Agent", "NovaProxy/1.0")

	resp, err := client.Do(req)
	if err != nil {
		m.log("AddConfigsFromSub: fetch failed: %v", err)
		return 0, fmt.Errorf("fetch failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		m.log("AddConfigsFromSub: HTTP %d from %s", resp.StatusCode, subURL)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		m.log("AddConfigsFromSub: read failed: %v", err)
		return 0, fmt.Errorf("read failed: %w", err)
	}
	m.log("AddConfigsFromSub: received %d bytes from %s", len(body), subURL)

	raw := strings.TrimSpace(string(body))

	var decoded []byte
	decoded, err = base64.StdEncoding.DecodeString(raw)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(raw)
		if err != nil {
			decoded, err = base64.RawURLEncoding.DecodeString(raw)
			if err != nil {
				m.log("AddConfigsFromSub: base64 decode failed: %v", err)
				return 0, fmt.Errorf("failed to decode subscription data: %w", err)
			}
		}
	}
	m.log("AddConfigsFromSub: decoded %d bytes", len(decoded))

	links := strings.Split(string(decoded), "\n")
	linkCount := len(links)
	m.log("AddConfigsFromSub: found %d links in subscription", linkCount)
	count := 0

	for _, l := range links {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		cfg, err := m.parseAndAdd(l)
		if err != nil {
			m.log("AddConfigsFromSub: parse error: %v — link: %s", err, l[:min(len(l), 60)])
			continue
		}
		if cfg != nil {
			cfg.ID = fmt.Sprintf("%x", time.Now().UnixNano())
			cfg.IsSub = true
			cfg.SubURL = subURL
			m.store.Configs = append(m.store.Configs, *cfg)
			m.log("AddConfigsFromSub: added %q (%s, server=%s:%s)", cfg.Name, cfg.Protocol, cfg.Server, cfg.Port)
			count++
		}
	}

	if err := m.save(); err != nil {
		m.log("AddConfigsFromSub: save failed: %v", err)
	}

	m.log("AddConfigsFromSub: done — added %d/%d configs", count, linkCount)
	return count, nil
}

func (m *V2RayManager) GetConfigs() []V2RayConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()

	configs := make([]V2RayConfig, len(m.store.Configs))
	copy(configs, m.store.Configs)
	return configs
}

func (m *V2RayManager) DeleteConfig(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	idx := -1
	var deletedName string
	for i, c := range m.store.Configs {
		if c.ID == id {
			idx = i
			deletedName = c.Name
			break
		}
	}
	if idx == -1 {
		m.log("DeleteConfig: config %s not found", id)
		return fmt.Errorf("config not found")
	}

	m.store.Configs = append(m.store.Configs[:idx], m.store.Configs[idx+1:]...)
	m.log("DeleteConfig: deleted %q (id=%s, remaining=%d)", deletedName, id, len(m.store.Configs))

	if m.store.SelectedID == id {
		m.store.SelectedID = ""
		m.log("DeleteConfig: was selected, cleared selection")
	}

	return m.save()
}

func (m *V2RayManager) SelectConfig(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, c := range m.store.Configs {
		if c.ID == id {
			m.log("SelectConfig: selected %q (id=%s, protocol=%s, server=%s:%s)", c.Name, id, c.Protocol, c.Server, c.Port)
			m.store.SelectedID = id
			return m.save()
		}
	}
	m.log("SelectConfig: config %s not found", id)
	return fmt.Errorf("config not found")
}

func (m *V2RayManager) UpdateConfig(id string, cfg V2RayConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, c := range m.store.Configs {
		if c.ID == id {
			m.log("UpdateConfig: updating %q (id=%s, protocol=%s, server=%s:%s)", c.Name, id, cfg.Protocol, cfg.Server, cfg.Port)
			cfg.ID = id // preserve original ID
			m.store.Configs[i] = cfg
			return m.save()
		}
	}
	m.log("UpdateConfig: config %s not found", id)
	return fmt.Errorf("config not found: %s", id)
}

func (m *V2RayManager) GetSelectedConfig() *V2RayConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.store.SelectedID == "" {
		return nil
	}

	for _, c := range m.store.Configs {
		if c.ID == m.store.SelectedID {
			return &c
		}
	}
	return nil
}

func (m *V2RayManager) ClearConfigs() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	count := len(m.store.Configs)
	m.store.Configs = nil
	m.store.SelectedID = ""
	m.log("ClearConfigs: cleared %d configs", count)
	return m.save()
}

func (m *V2RayManager) GetCorePort() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.store.CorePort
}

func (m *V2RayManager) SetCorePort(port int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	oldPort := m.store.CorePort
	m.store.CorePort = port
	m.corePort = port
	m.log("core port changed from %d to %d", oldPort, port)
	return m.save()
}

func (m *V2RayManager) SetCoreRunning(running bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.store.CoreRunning = running
	m.save()
}

func (m *V2RayManager) SetCoreActive(active bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.store.CoreActive = active
	m.save()
}

func (m *V2RayManager) IsCoreRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.store.CoreRunning
}

func (m *V2RayManager) IsCoreActive() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.store.CoreActive
}

func (m *V2RayManager) GetStore() V2RayConfigStore {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.store
}

func (m *V2RayManager) GetStorePath() string {
	return m.storePath
}

func (m *V2RayManager) PingConfig(cfg V2RayConfig) (time.Duration, error) {
	if cfg.Server == "" {
		m.log("PingConfig: %q skipped — no server address", cfg.Name)
		return 0, fmt.Errorf("no server address")
	}

	addr := cfg.Server
	if cfg.Port != "" {
		addr = net.JoinHostPort(cfg.Server, cfg.Port)
	}

	// Support timeout range 0-10000000ms (0 to 10000 seconds)
	timeout := 10 * time.Second
	if m.settings.RoutingMode == "test" {
		timeout = 30 * time.Second
	}

	m.log("PingConfig: pinging %q at %s (timeout=%v)", cfg.Name, addr, timeout)
	start := time.Now()
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		m.log("PingConfig: %q FAILED: %v", cfg.Name, err)
		return 0, fmt.Errorf("connection failed: %w", err)
	}
	conn.Close()

	latency := time.Since(start)
	m.log("PingConfig: %q OK — %v", cfg.Name, latency)
	return latency, nil
}

// PingConfigWithTimeout pings a config with a custom timeout in milliseconds (0-10000)
func (m *V2RayManager) PingConfigWithTimeout(cfg V2RayConfig, timeoutMs int) (time.Duration, error) {
	if cfg.Server == "" {
		m.log("PingWithTimeout: %q skipped — no server address", cfg.Name)
		return 0, fmt.Errorf("no server address")
	}

	if timeoutMs < 0 {
		timeoutMs = 0
	}
	if timeoutMs > 10000 {
		timeoutMs = 10000
	}

	addr := cfg.Server
	if cfg.Port != "" {
		addr = net.JoinHostPort(cfg.Server, cfg.Port)
	}

	timeout := time.Duration(timeoutMs) * time.Millisecond
	if timeoutMs == 0 {
		timeout = 10 * time.Second
	}

	m.log("PingWithTimeout: pinging %q at %s (timeout=%v)", cfg.Name, addr, timeout)
	start := time.Now()
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		m.log("PingWithTimeout: %q FAILED: %v", cfg.Name, err)
		return 0, fmt.Errorf("connection failed: %w", err)
	}
	conn.Close()

	latency := time.Since(start)
	m.log("PingWithTimeout: %q OK — %v", cfg.Name, latency)
	return latency, nil
}

func (m *V2RayManager) PingAllConfigs() []V2RayPingResult {
	configs := m.GetConfigs()
	m.log("PingAllConfigs: pinging %d configs", len(configs))
	results := make([]V2RayPingResult, 0, len(configs))

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, cfg := range configs {
		wg.Add(1)
		c := cfg
		go func() {
			defer wg.Done()
			latency, err := m.PingConfig(c)
			mu.Lock()
			results = append(results, V2RayPingResult{
				ID:      c.ID,
				Name:    c.Name,
				Latency: latency,
				OK:      err == nil,
				Error:   "",
			})
			if err != nil {
				results[len(results)-1].Error = err.Error()
			}
			mu.Unlock()
		}()
	}

	wg.Wait()

	okCount := 0
	for _, r := range results {
		if r.OK {
			okCount++
		}
	}
	m.log("PingAllConfigs: done — %d/%d OK", okCount, len(results))
	return results
}

type V2RayPingResult struct {
	ID      string        `json:"id"`
	Name    string        `json:"name"`
	Latency time.Duration `json:"latency"`
	OK      bool          `json:"ok"`
	Error   string        `json:"error,omitempty"`
}

// SubInfo holds subscription user information (traffic/expiry)
type SubInfo struct {
	URL       string `json:"url"`
	Upload    int64  `json:"upload"`
	Download  int64  `json:"download"`
	Total     int64  `json:"total"`
	Expire    int64  `json:"expire"`
	ExpireStr string `json:"expire_str"`
	SubURL    string `json:"sub_url"`
}

// ParseSubInfo parses the Subscription-Userinfo header or response body for sub info
func ParseSubInfoFromHeaders(header http.Header) *SubInfo {
	info := &SubInfo{}
	userinfo := header.Get("Subscription-Userinfo")
	if userinfo == "" {
		return nil
	}
	parts := strings.Split(userinfo, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])
		switch key {
		case "upload":
			info.Upload, _ = strconv.ParseInt(value, 10, 64)
		case "download":
			info.Download, _ = strconv.ParseInt(value, 10, 64)
		case "total":
			info.Total, _ = strconv.ParseInt(value, 10, 64)
		case "expire":
			info.Expire, _ = strconv.ParseInt(value, 10, 64)
			info.ExpireStr = time.Unix(info.Expire, 0).Format("2006-01-02 15:04:05")
		}
	}
	return info
}

func formatBytes(b int64) string {
	if b < 1024 {
		return fmt.Sprintf("%d B", b)
	}
	if b < 1024*1024 {
		return fmt.Sprintf("%.0f KB", float64(b)/1024)
	}
	if b < 1024*1024*1024 {
		return fmt.Sprintf("%.0f MB", float64(b)/(1024*1024))
	}
	return fmt.Sprintf("%.1f GB", float64(b)/(1024*1024*1024))
}

// TestConfigReal starts the V2Ray core with the given config and tests real connectivity
// through the SOCKS5 proxy, measuring real latency
func (m *V2RayManager) TestConfigReal(cfg V2RayConfig) (map[string]interface{}, error) {
	m.log("TestConfigReal: testing %q (protocol=%s, server=%s:%s)", cfg.Name, cfg.Protocol, cfg.Server, cfg.Port)

	port := 21000 + int(time.Now().UnixNano()%1000)
	originalPort := m.corePort

	m.mu.Lock()
	m.corePort = port
	m.mu.Unlock()

	configJSON, err := m.GenerateCoreJSON(cfg)
	if err != nil {
		m.mu.Lock()
		m.corePort = originalPort
		m.mu.Unlock()
		return nil, fmt.Errorf("generate config: %w", err)
	}

	pbConfig, err := serial.LoadJSONConfig(strings.NewReader(configJSON))
	if err != nil {
		m.mu.Lock()
		m.corePort = originalPort
		m.mu.Unlock()
		return nil, fmt.Errorf("parse config: %w", err)
	}

	instance, err := core.New(pbConfig)
	if err != nil {
		m.mu.Lock()
		m.corePort = originalPort
		m.mu.Unlock()
		return nil, fmt.Errorf("create instance: %w", err)
	}

	if err := instance.Start(); err != nil {
		m.mu.Lock()
		m.corePort = originalPort
		m.mu.Unlock()
		return nil, fmt.Errorf("start instance: %w", err)
	}

	defer func() {
		instance.Close()
		m.mu.Lock()
		m.corePort = originalPort
		m.mu.Unlock()
	}()

	time.Sleep(500 * time.Millisecond)

	socksAddr := fmt.Sprintf("127.0.0.1:%d", port)
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("socks5 dialer: %w", err)
	}

	httpTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
		DisableKeepAlives: true,
	}
	httpClient := &http.Client{
		Transport: httpTransport,
		Timeout:   15 * time.Second,
	}

	testURLs := []string{
		"https://www.google.com/generate_204",
		"https://www.gstatic.com/generate_204",
		"https://cloudflare.com/cdn-cgi/trace",
	}

	var lastErr error
	var totalLatency time.Duration
	successCount := 0
	startTime := time.Now()

	for _, testURL := range testURLs {
		reqStart := time.Now()
		resp, err := httpClient.Get(testURL)
		if err != nil {
			lastErr = err
			m.log("TestConfigReal: %q failed for %s: %v", cfg.Name, testURL, err)
			continue
		}
		resp.Body.Close()
		latency := time.Since(reqStart)
		totalLatency += latency
		successCount++
		m.log("TestConfigReal: %q OK for %s — %v", cfg.Name, testURL, latency)
	}

	if successCount == 0 {
		return nil, fmt.Errorf("all test requests failed: %w", lastErr)
	}

	avgLatency := totalLatency / time.Duration(successCount)
	elapsed := time.Since(startTime)

	result := map[string]interface{}{
		"ok":           true,
		"latency_ms":   avgLatency.Milliseconds(),
		"latency_str":  fmt.Sprintf("%dms", avgLatency.Milliseconds()),
		"success":      successCount,
		"total_tests":  len(testURLs),
		"elapsed_ms":   elapsed.Milliseconds(),
		"config_name":  cfg.Name,
		"config_proto": cfg.Protocol,
	}

	m.log("TestConfigReal: %q completed — avg latency=%dms, success=%d/%d",
		cfg.Name, avgLatency.Milliseconds(), successCount, len(testURLs))
	return result, nil
}

// SpeedTestConfig tests real download speed through the config
func (m *V2RayManager) SpeedTestConfig(cfg V2RayConfig) (map[string]interface{}, error) {
	m.log("SpeedTestConfig: testing %q (protocol=%s)", cfg.Name, cfg.Protocol)

	port := 21000 + int(time.Now().UnixNano()%1000)
	originalPort := m.corePort

	m.mu.Lock()
	m.corePort = port
	m.mu.Unlock()

	configJSON, err := m.GenerateCoreJSON(cfg)
	if err != nil {
		m.mu.Lock()
		m.corePort = originalPort
		m.mu.Unlock()
		return nil, fmt.Errorf("generate config: %w", err)
	}

	pbConfig, err := serial.LoadJSONConfig(strings.NewReader(configJSON))
	if err != nil {
		m.mu.Lock()
		m.corePort = originalPort
		m.mu.Unlock()
		return nil, fmt.Errorf("parse config: %w", err)
	}

	instance, err := core.New(pbConfig)
	if err != nil {
		m.mu.Lock()
		m.corePort = originalPort
		m.mu.Unlock()
		return nil, fmt.Errorf("create instance: %w", err)
	}

	if err := instance.Start(); err != nil {
		m.mu.Lock()
		m.corePort = originalPort
		m.mu.Unlock()
		return nil, fmt.Errorf("start instance: %w", err)
	}

	defer func() {
		instance.Close()
		m.mu.Lock()
		m.corePort = originalPort
		m.mu.Unlock()
	}()

	time.Sleep(500 * time.Millisecond)

	socksAddr := fmt.Sprintf("127.0.0.1:%d", port)
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("socks5 dialer: %w", err)
	}

	httpTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
		DisableKeepAlives: true,
	}
	httpClient := &http.Client{
		Transport: httpTransport,
		Timeout:   30 * time.Second,
	}

	testURL := "https://speed.cloudflare.com/__down?bytes=5000000"

	reqStart := time.Now()
	resp, err := httpClient.Get(testURL)
	if err != nil {
		return nil, fmt.Errorf("speed test request failed: %w", err)
	}
	defer resp.Body.Close()

	var totalBytes int64
	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)
		totalBytes += int64(n)
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
	}
	elapsed := time.Since(reqStart)

	speedMbps := int64(float64(totalBytes*8) / elapsed.Seconds() / 1000000)

	result := map[string]interface{}{
		"ok":           true,
		"speed_mbps":   speedMbps,
		"latency_ms":   0,
		"bytes":        totalBytes,
		"elapsed_ms":   elapsed.Milliseconds(),
		"config_name":  cfg.Name,
		"config_proto": cfg.Protocol,
	}

	m.log("SpeedTestConfig: %q completed — %.1f Mbps, %d bytes in %v",
		cfg.Name, speedMbps, totalBytes, elapsed)
	return result, nil
}

// AddSubWithInfo fetches a subscription and returns info about it including traffic data
func (m *V2RayManager) AddSubWithInfo(subURL string) (map[string]interface{}, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.log("AddSubWithInfo: fetching subscription: %s", subURL)

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", subURL, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid sub url: %w", err)
	}
	req.Header.Set("User-Agent", "NovaProxy/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch failed: %w", err)
	}
	defer resp.Body.Close()

	subInfo := ParseSubInfoFromHeaders(resp.Header)
	if subInfo != nil {
		subInfo.URL = subURL
		subInfo.SubURL = subURL
		m.log("AddSubWithInfo: sub info — upload=%d, download=%d, total=%d, expire=%d",
			subInfo.Upload, subInfo.Download, subInfo.Total, subInfo.Expire)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read failed: %w", err)
	}

	raw := strings.TrimSpace(string(body))
	var decoded []byte
	decoded, err = base64.StdEncoding.DecodeString(raw)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(raw)
		if err != nil {
			decoded, err = base64.RawURLEncoding.DecodeString(raw)
			if err != nil {
				return nil, fmt.Errorf("failed to decode subscription data: %w", err)
			}
		}
	}

	links := strings.Split(string(decoded), "\n")
	var configs []V2RayConfig
	count := 0

	for _, l := range links {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		cfg, err := m.parseAndAdd(l)
		if err != nil {
			continue
		}
		if cfg != nil {
			cfg.ID = fmt.Sprintf("%x", time.Now().UnixNano())
			cfg.IsSub = true
			cfg.SubURL = subURL
			m.store.Configs = append(m.store.Configs, *cfg)
			configs = append(configs, *cfg)
			count++
		}
	}

	if err := m.save(); err != nil {
		m.log("AddSubWithInfo: save failed: %v", err)
	}

	result := map[string]interface{}{
		"count":     count,
		"configs":   configs,
		"sub_info":  subInfo,
	}

	return result, nil
}

// GetSubInfo returns subscription info for configs that came from a subscription
func (m *V2RayManager) GetSubInfo() []map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	subMap := make(map[string]*SubInfo)
	for _, c := range m.store.Configs {
		if c.IsSub && c.SubURL != "" {
			if _, exists := subMap[c.SubURL]; !exists {
				subMap[c.SubURL] = &SubInfo{
					URL:    c.SubURL,
					SubURL: c.SubURL,
				}
			}
		}
	}

	var result []map[string]interface{}
	for _, info := range subMap {
		result = append(result, map[string]interface{}{
			"url":    info.URL,
			"sub_url": info.SubURL,
		})
	}
	return result
}

// ParseSubscriptionLinks parses a subscription response into structured info
func ParseSubscriptionLinks(subURL, rawData string) *SubscriptionResult {
	result := &SubscriptionResult{
		URL:     subURL,
		SubURL:  subURL,
		Configs: []V2RayConfig{},
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rawData))
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(rawData))
		if err != nil {
			decoded, err = base64.RawURLEncoding.DecodeString(strings.TrimSpace(rawData))
			if err != nil {
				result.Error = err.Error()
				return result
			}
		}
	}

	links := strings.Split(string(decoded), "\n")
	for _, l := range links {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		cfg, err := ParseV2RayLink(l)
		if err == nil && cfg != nil {
			cfg.IsSub = true
			cfg.SubURL = subURL
			result.Configs = append(result.Configs, *cfg)
		}
	}

	result.Count = len(result.Configs)
	return result
}

type SubscriptionResult struct {
	URL     string        `json:"url"`
	SubURL  string        `json:"sub_url"`
	Count   int           `json:"count"`
	Configs []V2RayConfig `json:"configs"`
	Error   string        `json:"error,omitempty"`
}

// UpdateConfigField updates a single field of a config
func (m *V2RayManager) UpdateConfigField(id, field, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, c := range m.store.Configs {
		if c.ID == id {
			updated := m.store.Configs[i]
			switch field {
			case "name":
				updated.Name = value
			case "server":
				updated.Server = value
			case "port":
				updated.Port = value
			case "uuid":
				updated.UUID = value
			case "password":
				updated.Password = value
			case "method":
				updated.Method = value
			case "encryption":
				updated.Encryption = value
			case "security":
				updated.Security = value
			case "transport":
				updated.Type = value
			case "host":
				updated.Host = value
			case "path":
				updated.Path = value
			case "tls":
				updated.TLS = value
			case "flow":
				updated.Flow = value
			case "sni":
				updated.Sni = value
			case "alpn":
				updated.Alpn = value
			case "fingerprint":
				updated.Fingerprint = value
			case "public_key":
				updated.PublicKey = value
			case "short_id":
				updated.ShortID = value
			case "group":
				updated.Group = value
			case "up_mbps":
				updated.UpMbps = value
			case "down_mbps":
				updated.DownMbps = value
			case "insecure":
				updated.Insecure = value
			case "obfs_type":
				updated.ObfsType = value
			}
			m.store.Configs[i] = updated
			m.log("UpdateConfigField: updated %s=%q for config %q (id=%s)", field, value, c.Name, id)
			return m.save()
		}
	}
	return fmt.Errorf("config not found: %s", id)
}

var _ = regexp.Compile // keep import
var _ = url.Parse       // keep import

func (m *V2RayManager) GenerateCoreJSON(cfg V2RayConfig) (string, error) {
	config := make(map[string]interface{})
	config["log"] = map[string]interface{}{
		"loglevel": "warning",
	}

	socksPort := m.corePort
	httpPort := m.corePort + 1

	m.log("GenerateCoreJSON: building config for %q (protocol=%s, server=%s:%s, socks=%d, http=%d)",
		cfg.Name, cfg.Protocol, cfg.Server, cfg.Port, socksPort, httpPort)

	inbounds := []map[string]interface{}{
		{
			"port":      socksPort,
			"listen":    "127.0.0.1",
			"protocol":  "socks",
			"settings":  map[string]interface{}{
				"udp": true,
			},
			"tag": "socks-in",
		},
		{
			"port":      httpPort,
			"listen":    "127.0.0.1",
			"protocol":  "http",
			"settings":  map[string]interface{}{},
			"tag": "http-in",
		},
	}
	config["inbounds"] = inbounds

	outbound := map[string]interface{}{
		"protocol": cfg.Protocol,
		"settings": map[string]interface{}{},
		"tag":      "proxy",
	}

	streamSettings := map[string]interface{}{}
	isHysteria2 := false

	switch cfg.Protocol {
	case "vmess":
		m.log("GenerateCoreJSON: vmess outbound — uuid=%s, security=%s", maskID(cfg.UUID), cfg.Security)
		vnext := []map[string]interface{}{
			{
				"address": cfg.Server,
				"port":    parsePort(cfg.Port),
				"users": []map[string]interface{}{
					{
						"id":       cfg.UUID,
						"security": cfg.Security,
					},
				},
			},
		}
		outbound["settings"] = map[string]interface{}{"vnext": vnext}

	case "vless":
		m.log("GenerateCoreJSON: vless outbound — encryption=%s, flow=%s", cfg.Encryption, cfg.Flow)
		vnext := []map[string]interface{}{
			{
				"address": cfg.Server,
				"port":    parsePort(cfg.Port),
				"users": []map[string]interface{}{
					{
						"id":         cfg.UUID,
						"encryption": cfg.Encryption,
						"flow":       cfg.Flow,
					},
				},
			},
		}
		outbound["settings"] = map[string]interface{}{"vnext": vnext}

	case "trojan":
		m.log("GenerateCoreJSON: trojan outbound — password=%s", maskID(cfg.Password))
		servers := []map[string]interface{}{
			{
				"address":  cfg.Server,
				"port":     parsePort(cfg.Port),
				"password": cfg.Password,
			},
		}
		outbound["settings"] = map[string]interface{}{"servers": servers}

	case "shadowsocks":
		m.log("GenerateCoreJSON: shadowsocks outbound — method=%s", cfg.Method)
		servers := []map[string]interface{}{
			{
				"address":  cfg.Server,
				"port":     parsePort(cfg.Port),
				"method":   cfg.Method,
				"password": cfg.Password,
			},
		}
		outbound["settings"] = map[string]interface{}{"servers": servers}

	case "socks":
		m.log("GenerateCoreJSON: socks outbound")
		servers := []map[string]interface{}{
			{
				"address": cfg.Server,
				"port":    parsePort(cfg.Port),
			},
		}
		outbound["settings"] = map[string]interface{}{"servers": servers}

	case "http":
		m.log("GenerateCoreJSON: http outbound")
		servers := []map[string]interface{}{
			{
				"address": cfg.Server,
				"port":    parsePort(cfg.Port),
			},
		}
		outbound["settings"] = map[string]interface{}{"servers": servers}

	case "hysteria2":
		isHysteria2 = true
		m.log("GenerateCoreJSON: hysteria2 outbound — server=%s:%s, sni=%s", cfg.Server, cfg.Port, cfg.Sni)
		vnext := []map[string]interface{}{
			{
				"address": cfg.Server,
				"port":    parsePort(cfg.Port),
				"users": []map[string]interface{}{
					{
						"account": map[string]interface{}{},
					},
				},
			},
		}
		outbound["settings"] = map[string]interface{}{"vnext": vnext}

		streamSettings["security"] = "tls"
		tlsSettings := map[string]interface{}{
			"serverName": cfg.Sni,
			"allowInsecure": cfg.Insecure == "1" || cfg.Insecure == "true",
		}
		if cfg.Alpn != "" {
			tlsSettings["alpn"] = strings.Split(cfg.Alpn, ",")
		}
		if cfg.Fingerprint != "" {
			tlsSettings["fingerprint"] = cfg.Fingerprint
		}
		streamSettings["tlsSettings"] = tlsSettings

		hy2Settings := map[string]interface{}{
			"password": cfg.Password,
		}
		if cfg.UpMbps != "" {
			hy2Settings["congestion"] = map[string]interface{}{
				"type":       "brutal",
				"up_mbps":    parseUint64(cfg.UpMbps),
				"down_mbps": parseUint64(cfg.DownMbps),
			}
		}
		if cfg.ObfsType != "" {
			hy2Settings["obfs"] = cfg.ObfsType
		}
		streamSettings["hy2Settings"] = hy2Settings

	default:
		m.log("GenerateCoreJSON: unsupported protocol %q", cfg.Protocol)
		return "", fmt.Errorf("unsupported protocol: %s", cfg.Protocol)
	}

	if !isHysteria2 {
		if cfg.Type != "" && cfg.Type != "tcp" {
			streamSettings["network"] = cfg.Type
			m.log("GenerateCoreJSON: transport=%s, host=%s, path=%s", cfg.Type, cfg.Host, cfg.Path)

			switch cfg.Type {
			case "ws":
				wsSettings := map[string]interface{}{}
				if cfg.Path != "" {
					wsSettings["path"] = cfg.Path
				}
				if cfg.Host != "" {
					wsSettings["headers"] = map[string]string{"Host": cfg.Host}
				}
				streamSettings["wsSettings"] = wsSettings
			case "grpc":
				grpcSettings := map[string]interface{}{}
				if cfg.Host != "" {
					grpcSettings["serviceName"] = cfg.Host
				}
				streamSettings["grpcSettings"] = grpcSettings
			case "quic":
				quicSettings := map[string]interface{}{}
				streamSettings["quicSettings"] = quicSettings
			}
		}

		if cfg.TLS == "tls" || cfg.Security == "tls" {
			m.log("GenerateCoreJSON: TLS enabled — sni=%s, alpn=%s, fingerprint=%s", cfg.Sni, cfg.Alpn, cfg.Fingerprint)
			tlsSettings := map[string]interface{}{
				"serverName": cfg.Sni,
			}
			if cfg.Sni == "" {
				tlsSettings["serverName"] = cfg.Server
			}
			if cfg.Alpn != "" {
				tlsSettings["alpn"] = strings.Split(cfg.Alpn, ",")
			}
			if cfg.Fingerprint != "" {
				tlsSettings["fingerprint"] = cfg.Fingerprint
			}
			streamSettings["security"] = "tls"
			streamSettings["tlsSettings"] = tlsSettings
		} else {
			streamSettings["security"] = "none"
		}
	}

	if len(streamSettings) > 1 {
		outbound["streamSettings"] = streamSettings
	}

	config["outbounds"] = []map[string]interface{}{outbound}
	config["routing"] = map[string]interface{}{
		"domainStrategy": "AsIs",
		"rules": []map[string]interface{}{
			{
				"type":        "field",
				"inboundTag":  []string{"socks-in", "http-in"},
				"outboundTag": "proxy",
			},
		},
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		m.log("GenerateCoreJSON: marshal failed: %v", err)
		return "", err
	}

	m.log("GenerateCoreJSON: config generated (%d bytes) — listening on 127.0.0.1:%d (socks) and 127.0.0.1:%d (http)",
		len(data), socksPort, httpPort)
	return string(data), nil
}

func maskID(s string) string {
	if len(s) <= 6 {
		return "***"
	}
	return s[:3] + "..." + s[len(s)-3:]
}

func parseUint64(s string) uint64 {
	var v uint64
	fmt.Sscanf(s, "%d", &v)
	return v
}

func parsePort(port string) int {
	var p int
	fmt.Sscanf(port, "%d", &p)
	if p <= 0 {
		p = 443
	}
	return p
}
