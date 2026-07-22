package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Config struct {
	Version string `json:"version"`

	Relay   RelayConfig   `json:"relay"`
	Proxy   ProxyConfig   `json:"proxy"`
	Admin   AdminConfig   `json:"admin"`
	Tunnel  TunnelConfig  `json:"tunnel"`
	ExitNode ExitNodeConfig `json:"exit_node"`

	AuthKey     string   `json:"auth_key"`
	ScriptIDs   []string `json:"script_ids"`
	FrontDomain string   `json:"front_domain"`
	FrontDomains []string `json:"front_domains,omitempty"`
	GoogleIP    string   `json:"google_ip"`

	LogLevel string `json:"log_level"`
	DataDir  string `json:"data_dir"`
}

type RelayConfig struct {
	Timeout           int  `json:"timeout"`
	TLSConnectTimeout int  `json:"tls_connect_timeout"`
	MaxResponseBody   int  `json:"max_response_body"`
	VerifySSL         bool `json:"verify_ssl"`

	PoolMax    int `json:"pool_max"`
	PoolMinIdle int `json:"pool_min_idle"`
	ConnTTL    float64 `json:"conn_ttl"`

	BatchEnabled  bool `json:"batch_enabled"`
	BatchMax      int  `json:"batch_max"`
	BatchWindowMs int  `json:"batch_window_ms"`
	SubBatch      bool `json:"sub_batch"`

	H2Connections   int `json:"h2_connections"`
	H2PingIntervalMs int `json:"h2_ping_interval_ms"`

	ParallelRelay   int  `json:"parallel_relay"`
	SNIProbeEnabled bool `json:"sni_probe_enabled"`
}

type ProxyConfig struct {
	Host       string       `json:"host"`
	Port       int          `json:"port"`
	MITM       *MITMConfig  `json:"mitm,omitempty"`
	SOCKS5     *SOCKS5Config `json:"socks5,omitempty"`
	BlockHosts []string     `json:"block_hosts,omitempty"`
}

type SOCKS5Config struct {
	Enabled bool   `json:"enabled"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
}

type MITMConfig struct {
	Enabled bool   `json:"enabled"`
	CACert  string `json:"ca_cert"`
	CAKey   string `json:"ca_key"`
}

type AdminConfig struct {
	Enabled  bool   `json:"enabled"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	TLS      bool   `json:"tls,omitempty"`
}

type TunnelConfig struct {
	Enabled bool   `json:"enabled"`
	Mode    string `json:"mode"`
	Port    int    `json:"port"`
}

type ExitNodeConfig struct {
	Enabled  bool     `json:"enabled"`
	Provider string   `json:"provider"`
	URL      string   `json:"url"`
	PSK      string   `json:"psk"`
	Mode     string   `json:"mode"`
	Hosts    []string `json:"hosts"`
}

func DefaultConfig() *Config {
	return &Config{
		Version: "1.0.0",
		Relay: RelayConfig{
			Timeout:           25,
			TLSConnectTimeout: 15,
			MaxResponseBody:   209715200,
			VerifySSL:         true,
			PoolMax:           50,
			PoolMinIdle:       15,
			ConnTTL:           45.0,
			BatchEnabled:      true,
			BatchMax:          50,
			BatchWindowMs:     15,
			SubBatch:          true,
			H2Connections:     3,
			H2PingIntervalMs:  200,
			ParallelRelay:     3,
			SNIProbeEnabled:   true,
		},
		Proxy: ProxyConfig{
			Host: "127.0.0.1",
			Port: 8080,
			SOCKS5: &SOCKS5Config{
				Enabled: true,
				Host:    "127.0.0.1",
				Port:    1080,
			},
		},
		Admin: AdminConfig{
			Enabled: true,
			Host:    "127.0.0.1",
			Port:    9090,
		},
		Tunnel: TunnelConfig{
			Enabled: false,
			Mode:    "sni-rewrite",
			Port:    18001,
		},
		ScriptIDs:   []string{},
		FrontDomain: "www.google.com",
		GoogleIP:    "216.239.38.120",
		AuthKey:     "CHANGE_ME",
		LogLevel:    "info",
		DataDir:     "data",
	}
}

func LoadConfig(path string) *Config {
	cfg := DefaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("Config not found at %s, using defaults\n", path)
		return cfg
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		fmt.Printf("Failed to parse config: %v, using defaults\n", err)
		return cfg
	}
	absPath, _ := filepath.Abs(path)
	cfg.DataDir = filepath.Join(filepath.Dir(absPath), "data")
	return cfg
}

func (c *Config) Save(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
