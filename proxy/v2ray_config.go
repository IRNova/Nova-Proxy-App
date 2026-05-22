package proxy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

type V2RayConfig struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Protocol  string `json:"protocol"`
	Server    string `json:"server"`
	Port      string `json:"port"`
	Link      string `json:"link"`
	RawJSON   string `json:"raw_json,omitempty"`
	IsJSON    bool   `json:"is_json"`
	IsSub     bool   `json:"is_sub"`
	SubURL    string `json:"sub_url,omitempty"`

	// VMess/VLESS fields
	UUID    string `json:"uuid,omitempty"`
	Encryption string `json:"encryption,omitempty"`
	Security string `json:"security,omitempty"`

	// Trojan/Shadowsocks fields
	Password string `json:"password,omitempty"`
	Method   string `json:"method,omitempty"`

	// Transport
	Type      string `json:"transport,omitempty"`
	Host      string `json:"host,omitempty"`
	Path      string `json:"path,omitempty"`
	TLS       string `json:"tls,omitempty"`
	Flow      string `json:"flow,omitempty"`
	Sni       string `json:"sni,omitempty"`
	Alpn      string `json:"alpn,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
	ShortID   string `json:"short_id,omitempty"`

	// Hysteria2 specific
	UpMbps    string `json:"up_mbps,omitempty"`
	DownMbps  string `json:"down_mbps,omitempty"`
	Insecure  string `json:"insecure,omitempty"`
	ObfsType  string `json:"obfs_type,omitempty"`

	// Grouping
	Group     string `json:"group,omitempty"`
}

type V2RayConfigStore struct {
	Configs       []V2RayConfig `json:"configs"`
	SelectedID    string        `json:"selected_id"`
	CoreRunning   bool          `json:"core_running"`
	CorePort      int           `json:"core_port"`
	CoreActive    bool          `json:"core_active"`
}

var DefaultConfigStore = V2RayConfigStore{
	CorePort: 11808,
}

func ParseV2RayLink(link string) (*V2RayConfig, error) {
	link = strings.TrimSpace(link)

	if strings.HasPrefix(link, "vmess://") {
		return parseVMess(link)
	}
	if strings.HasPrefix(link, "vless://") {
		return parseVLESS(link)
	}
	if strings.HasPrefix(link, "trojan://") {
		return parseTrojan(link)
	}
	if strings.HasPrefix(link, "ss://") {
		return parseShadowsocks(link)
	}
	if strings.HasPrefix(link, "socks://") || strings.HasPrefix(link, "socks5://") {
		return parseSocks(link)
	}
	if strings.HasPrefix(link, "http://") || strings.HasPrefix(link, "https://") {
		if strings.Contains(link, "@") {
			return parseHTTP(link)
		}
	}
	if strings.HasPrefix(link, "hy2://") || strings.HasPrefix(link, "hysteria2://") {
		return parseHysteria2(link)
	}
	if strings.HasPrefix(link, "ss2022://") {
		return parseSS2022(link)
	}

	return nil, fmt.Errorf("unsupported link format: %s", link[:min(20, len(link))])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func parseVMess(link string) (*V2RayConfig, error) {
	b64 := strings.TrimPrefix(link, "vmess://")
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(b64)
		if err != nil {
			decoded, err = base64.RawURLEncoding.DecodeString(b64)
			if err != nil {
				return nil, fmt.Errorf("failed to decode vmess config: %w", err)
			}
		}
	}

	var vmessData map[string]interface{}
	if err := json.Unmarshal(decoded, &vmessData); err != nil {
		return nil, fmt.Errorf("failed to parse vmess JSON: %w", err)
	}

	cfg := &V2RayConfig{
		Protocol: "vmess",
		Link:     link,
		IsJSON:   true,
		RawJSON:   string(decoded),
	}

	if v, ok := vmessData["ps"].(string); ok {
		cfg.Name = v
	}
	if v, ok := vmessData["add"].(string); ok {
		cfg.Server = v
	}
	if v, ok := vmessData["port"]; ok {
		cfg.Port = fmt.Sprintf("%v", v)
	}
	if v, ok := vmessData["id"].(string); ok {
		cfg.UUID = v
	}
	if v, ok := vmessData["aid"].(string); ok {
		cfg.Encryption = v
	}
	if v, ok := vmessData["scy"].(string); ok {
		cfg.Security = v
	} else if v, ok := vmessData["security"].(string); ok {
		cfg.Security = v
	}
	if v, ok := vmessData["net"].(string); ok {
		cfg.Type = v
	}
	if v, ok := vmessData["host"].(string); ok {
		cfg.Host = v
	}
	if v, ok := vmessData["path"].(string); ok {
		cfg.Path = v
	}
	if v, ok := vmessData["tls"].(string); ok {
		cfg.TLS = v
	}
	if v, ok := vmessData["sni"].(string); ok {
		cfg.Sni = v
	}
	if v, ok := vmessData["alpn"].(string); ok {
		cfg.Alpn = v
	}
	if v, ok := vmessData["fp"].(string); ok {
		cfg.Fingerprint = v
	}
	if v, ok := vmessData["group"].(string); ok {
		cfg.Group = v
	}

	if cfg.Name == "" {
		cfg.Name = fmt.Sprintf("%s:%s", cfg.Server, cfg.Port)
	}

	return cfg, nil
}

func parseVLESS(link string) (*V2RayConfig, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("failed to parse vless link: %w", err)
	}

	cfg := &V2RayConfig{
		Protocol: "vless",
		Link:     link,
		UUID:     u.User.String(),
		Server:   u.Hostname(),
		Port:     u.Port(),
		Name:     u.Fragment,
	}

	q := u.Query()
	cfg.Encryption = q.Get("encryption")
	cfg.Security = q.Get("security")
	cfg.Type = q.Get("type")
	cfg.Host = q.Get("host")
	cfg.Path = q.Get("path")
	cfg.TLS = q.Get("tls")
	cfg.Flow = q.Get("flow")
	cfg.Sni = q.Get("sni")
	cfg.Alpn = q.Get("alpn")
	cfg.Fingerprint = q.Get("fp")
	cfg.PublicKey = q.Get("pbk")
	cfg.ShortID = q.Get("sid")
	cfg.Group = q.Get("group")

	if cfg.Name == "" {
		cfg.Name = fmt.Sprintf("%s:%s", cfg.Server, cfg.Port)
	}

	return cfg, nil
}

func parseTrojan(link string) (*V2RayConfig, error) {
	u, err := url.Parse(link)
	if err != nil {
		// try with trojan://password@server:port
		rest := strings.TrimPrefix(link, "trojan://")
		atIdx := strings.Index(rest, "@")
		if atIdx == -1 {
			return nil, fmt.Errorf("failed to parse trojan link: %w", err)
		}
		password := rest[:atIdx]
		hostPort := rest[atIdx+1:]
		hashIdx := strings.Index(hostPort, "#")
		name := ""
		if hashIdx != -1 {
			name = hostPort[hashIdx+1:]
			hostPort = hostPort[:hashIdx]
		}
		host, port, splitErr := netSplitHostPort(hostPort)
		if splitErr != nil {
			return nil, fmt.Errorf("failed to parse trojan host:port: %w", err)
		}
		cfg := &V2RayConfig{
			Protocol: "trojan",
			Link:     link,
			Password: password,
			Server:   host,
			Port:     port,
			Name:     name,
		}
		if cfg.Name == "" {
			cfg.Name = fmt.Sprintf("%s:%s", cfg.Server, cfg.Port)
		}
		return cfg, nil
	}

	cfg := &V2RayConfig{
		Protocol: "trojan",
		Link:     link,
		Password: u.User.String(),
		Server:   u.Hostname(),
		Port:     u.Port(),
		Name:     u.Fragment,
	}

	q := u.Query()
	cfg.Security = q.Get("security")
	cfg.Type = q.Get("type")
	cfg.Host = q.Get("host")
	cfg.Path = q.Get("path")
	cfg.TLS = q.Get("tls")
	cfg.Sni = q.Get("sni")
	cfg.Alpn = q.Get("alpn")
	cfg.Fingerprint = q.Get("fp")
	cfg.Group = q.Get("group")

	if cfg.Name == "" {
		cfg.Name = fmt.Sprintf("%s:%s", cfg.Server, cfg.Port)
	}

	return cfg, nil
}

func parseShadowsocks(link string) (*V2RayConfig, error) {
	rest := strings.TrimPrefix(link, "ss://")

	hashIdx := strings.Index(rest, "#")
	name := ""
	if hashIdx != -1 {
		name, _ = url.QueryUnescape(rest[hashIdx+1:])
		rest = rest[:hashIdx]
	}

	atIdx := strings.Index(rest, "@")
	if atIdx != -1 {
		b64part := rest[:atIdx]
		decoded, err := base64.URLEncoding.DecodeString(b64part)
		if err != nil {
			decoded, err = base64.RawURLEncoding.DecodeString(b64part)
			if err != nil {
				decoded, err = base64.StdEncoding.DecodeString(b64part)
				if err != nil {
					// try raw std
					decoded, err = base64.RawStdEncoding.DecodeString(b64part)
				}
			}
		}
		if err == nil {
			methodPass := string(decoded)
			colonIdx := strings.Index(methodPass, ":")
			if colonIdx != -1 {
				cfg := &V2RayConfig{
					Protocol: "shadowsocks",
					Link:     link,
					Method:   methodPass[:colonIdx],
					Password: methodPass[colonIdx+1:],
					Name:     name,
				}
				hostPort := rest[atIdx+1:]
				host, port, splitErr := netSplitHostPort(hostPort)
				if splitErr == nil {
					cfg.Server = host
					cfg.Port = port
				}
				if cfg.Name == "" {
					cfg.Name = fmt.Sprintf("%s:%s", cfg.Server, cfg.Port)
				}
				return cfg, nil
			}
		}
	}

	u, err := url.Parse(link)
	if err == nil {
		cfg := &V2RayConfig{
			Protocol: "shadowsocks",
			Link:     link,
			Server:   u.Hostname(),
			Port:     u.Port(),
			Name:     u.Fragment,
		}
		if u.User != nil {
			cfg.Method = u.User.Username()
			cfg.Password, _ = u.User.Password()
		}
		if cfg.Name == "" {
			cfg.Name = fmt.Sprintf("%s:%s", cfg.Server, cfg.Port)
		}
		return cfg, nil
	}

	return nil, fmt.Errorf("failed to parse shadowsocks link")
}

func parseSocks(link string) (*V2RayConfig, error) {
	rest := link
	if strings.HasPrefix(rest, "socks5://") {
		rest = strings.TrimPrefix(rest, "socks5://")
	} else {
		rest = strings.TrimPrefix(rest, "socks://")
	}

	hashIdx := strings.Index(rest, "#")
	name := ""
	if hashIdx != -1 {
		name, _ = url.QueryUnescape(rest[hashIdx+1:])
		rest = rest[:hashIdx]
	}

	cfg := &V2RayConfig{
		Protocol: "socks",
		Link:     link,
		Name:     name,
	}

	atIdx := strings.Index(rest, "@")
	if atIdx != -1 {
		userPass := rest[:atIdx]
		colonIdx := strings.Index(userPass, ":")
		if colonIdx != -1 {
			// user:pass format with Og as username
		}
		rest = rest[atIdx+1:]
	}

	host, port, err := netSplitHostPort(rest)
	if err == nil {
		cfg.Server = host
		cfg.Port = port
	}

	if cfg.Name == "" {
		cfg.Name = fmt.Sprintf("%s:%s", cfg.Server, cfg.Port)
	}

	return cfg, nil
}

func parseHTTP(link string) (*V2RayConfig, error) {
	rest := strings.TrimPrefix(link, "https://")
	rest = strings.TrimPrefix(rest, "http://")

	hashIdx := strings.Index(rest, "#")
	name := ""
	if hashIdx != -1 {
		name, _ = url.QueryUnescape(rest[hashIdx+1:])
		rest = rest[:hashIdx]
	}

	cfg := &V2RayConfig{
		Protocol: "http",
		Link:     link,
		Name:     name,
	}

	atIdx := strings.Index(rest, "@")
	if atIdx != -1 {
		rest = rest[atIdx+1:]
	}

	host, port, err := netSplitHostPort(rest)
	if err == nil {
		cfg.Server = host
		cfg.Port = port
	}

	if cfg.Name == "" {
		cfg.Name = fmt.Sprintf("%s:%s", cfg.Server, cfg.Port)
	}

	return cfg, nil
}

func netSplitHostPort(hostport string) (string, string, error) {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return "", "", fmt.Errorf("empty hostport")
	}

	if strings.Contains(hostport, "[") {
		// IPv6
		end := strings.Index(hostport, "]")
		if end == -1 {
			return "", "", fmt.Errorf("invalid IPv6 address")
		}
		host := hostport[:end+1]
		port := ""
		if end+1 < len(hostport) && hostport[end+1] == ':' {
			port = hostport[end+2:]
		}
		return host, port, nil
	}

	colonIdx := strings.LastIndex(hostport, ":")
	if colonIdx == -1 {
		return hostport, "", nil
	}

	return hostport[:colonIdx], hostport[colonIdx+1:], nil
}

func ParseSubscription(subURL string) ([]V2RayConfig, string) {
	var configs []V2RayConfig
	var rawData string
	return configs, rawData
}

func parseHysteria2(link string) (*V2RayConfig, error) {
	rest := link
	if strings.HasPrefix(rest, "hysteria2://") {
		rest = strings.TrimPrefix(rest, "hysteria2://")
	} else {
		rest = strings.TrimPrefix(rest, "hy2://")
	}

	cfg := &V2RayConfig{
		Protocol: "hysteria2",
		Link:     link,
		Type:     "udp",
		TLS:      "tls",
	}

	hashIdx := strings.Index(rest, "#")
	if hashIdx != -1 {
		cfg.Name, _ = url.QueryUnescape(rest[hashIdx+1:])
		rest = rest[:hashIdx]
	}

	atIdx := strings.Index(rest, "@")
	if atIdx != -1 {
		cfg.Password = rest[:atIdx]
		rest = rest[atIdx+1:]
	} else {
		// parse as URL with userinfo
	}

	qIdx := strings.Index(rest, "?")
	hostPort := rest
	queryStr := ""
	if qIdx != -1 {
		hostPort = rest[:qIdx]
		queryStr = rest[qIdx+1:]
	}

	host, port, err := netSplitHostPort(hostPort)
	if err == nil {
		cfg.Server = host
		cfg.Port = port
	}

	if queryStr != "" {
		q, _ := url.ParseQuery(queryStr)
		cfg.Sni = q.Get("sni")
		if cfg.Sni == "" {
			cfg.Sni = q.Get("peer")
		}
		cfg.Host = q.Get("host")
		cfg.Insecure = q.Get("insecure")
		cfg.UpMbps = q.Get("up")
		cfg.DownMbps = q.Get("down")
		cfg.Alpn = q.Get("alpn")
		if v := q.Get("obfs"); v != "" {
			cfg.ObfsType = v
		}
	}

	if cfg.Name == "" {
		cfg.Name = fmt.Sprintf("%s:%s", cfg.Server, cfg.Port)
	}
	if cfg.Sni == "" {
		cfg.Sni = cfg.Server
	}

	return cfg, nil
}

func parseSS2022(link string) (*V2RayConfig, error) {
	rest := strings.TrimPrefix(link, "ss2022://")

	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ss2022 link: %w", err)
	}

	cfg := &V2RayConfig{
		Protocol: "shadowsocks2022",
		Link:     link,
	}

	// Try to parse userinfo from the URL
	if u.User != nil {
		cfg.Method = u.User.Username()
		cfg.Password, _ = u.User.Password()
	}

	cfg.Server = u.Hostname()
	cfg.Port = u.Port()

	q := u.Query()
	if cfg.Method == "" {
		cfg.Method = q.Get("method")
	}
	if cfg.Password == "" {
		cfg.Password = q.Get("password")
	}

	// Get name from fragment
	if u.Fragment != "" {
		cfg.Name, _ = url.QueryUnescape(u.Fragment)
	}

	if cfg.Name == "" {
		cfg.Name = fmt.Sprintf("%s:%s", cfg.Server, cfg.Port)
	}

	// Try direct parsing if URL parsing failed
	if cfg.Server == "" {
		hashIdx := strings.Index(rest, "#")
		name := ""
		if hashIdx != -1 {
			name, _ = url.QueryUnescape(rest[hashIdx+1:])
			rest = rest[:hashIdx]
		}
		parts := strings.SplitN(rest, "@", 2)
		if len(parts) == 2 {
			mp := strings.SplitN(parts[0], ":", 2)
			if len(mp) == 2 {
				cfg.Method = mp[0]
				cfg.Password = mp[1]
			}
			host, port, _ := netSplitHostPort(parts[1])
			cfg.Server = host
			cfg.Port = port
		}
		cfg.Name = name
	}

	if cfg.Name == "" {
		cfg.Name = fmt.Sprintf("%s:%s", cfg.Server, cfg.Port)
	}

	return cfg, nil
}

func ParseJSONConfig(jsonStr string) (*V2RayConfig, error) {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return nil, fmt.Errorf("invalid JSON config: %w", err)
	}

	cfg := &V2RayConfig{
		Link:   jsonStr,
		IsJSON: true,
		RawJSON: jsonStr,
	}

	if v, ok := data["protocol"].(string); ok {
		cfg.Protocol = v
	}
	if v, ok := data["name"].(string); ok {
		cfg.Name = v
	}
	if v, ok := data["server"].(string); ok {
		cfg.Server = v
	}
	if v, ok := data["port"]; ok {
		cfg.Port = fmt.Sprintf("%v", v)
	}

	return cfg, nil
}
