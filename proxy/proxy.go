package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/textproto"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// tunnelBufPool provides reusable 128KB buffers for tunnel data copying
// to reduce memory allocation and GC pressure in high-concurrency scenarios.
var tunnelBufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 128*1024)
		return &buf
	},
}

type CertGenerator interface {
	GetCACert() *x509.Certificate
	GetCAKey() interface{}
	IsCAInstalled() bool
}

type ProxyServer struct {
	Server        *http.Server
	listenAddr    string
	rules         *RuleManager
	running       bool
	mode          string // global runtime mode: "mitm" | "transparent" | "tls-rf" | "quic"
	mu            sync.RWMutex
	certCacheMu   sync.RWMutex
	certCache     map[string]*tls.Certificate
	Fingerprint   string
	certGenerator CertGenerator
	recentIngress []string
	dohResolver   *FailoverResolver
	cfPool        *CloudflarePool
	transport     *http.Transport
	logCallback   func(string)
	bytesDown     int64
	bytesUp       int64
	certBypassMap sync.Map

	// gsaDialAddr is the address of the local GSA proxy server (e.g. "127.0.0.1:8085").
	// When set, rules with Mode "gsa" will forward traffic through this proxy.
	// Set via SetGSADialAddr(); cleared when GSA proxy stops.
	gsaDialAddr string

	// SOCKS5 proxy settings
	socksAddr     string
	socksListener net.Listener
	socksRunning  bool
	socksWg       sync.WaitGroup

	// Process monitor for tracking connected apps
	procMonitor *ProcessMonitor
}

type RuleManager struct {
	rules                      []Rule
	siteGroups                 []SiteGroup
	upstreams                  []Upstream
	dnsNodes                   []DNSNode
	settingsPath               string
	rulesPath                  string
	cloudflareConfig           CloudflareConfig
	tunConfig                  TUNConfig
	closeToTray                bool
	autoStart                  bool
	showMainOnAutoStart        bool
	autoEnableProxyOnAutoStart bool
	serverHost                 string
	serverAuth                 string
	listenPort                 string
	listenHost                 string
	socksAddr                  string
	socksHost                  string
	socksPort                  string
	echProfiles                []ECHProfile
	autoRouter                 *AutoRouter
	autoRoutingConfig          AutoRoutingConfig
	mu                         sync.RWMutex
	routeEventCallback         func(domain, mode string)
	onConfigSaved              func()
	language                   string
	theme                      string
	country                    string
}

func (r *RuleManager) SetRouteEventCallback(cb func(domain, mode string)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.routeEventCallback = cb
}

func (r *RuleManager) emitRouteEvent(domain, mode string) {
	r.mu.RLock()
	cb := r.routeEventCallback
	r.mu.RUnlock()
	if cb != nil {
		cb(domain, mode)
	}
}

func (r *RuleManager) SetOnConfigSaved(cb func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onConfigSaved = cb
}

// triggerConfigSaved fires the config-saved callback asynchronously.
// It is always called from methods that already hold rm.mu, so no extra locking is needed.
func (r *RuleManager) triggerConfigSaved() {
	cb := r.onConfigSaved
	if cb != nil {
		go cb()
	}
}

type SiteGroup struct {
	ID            string           `json:"id"`
	Name          string           `json:"name"`
	Website       string           `json:"website,omitempty"`
	Domains       []string         `json:"domains"`
	Mode          string           `json:"mode"`
	Upstream      string           `json:"upstream"`
	Upstreams     []string         `json:"upstreams,omitempty"`
	DNSMode       string           `json:"dns_mode,omitempty"`
	SniFake       string           `json:"sni_fake"`
	ConnectPolicy string           `json:"connect_policy,omitempty"` // "", "tunnel_origin", "tunnel_upstream", "mitm", "direct"
	SniPolicy     string           `json:"sni_policy,omitempty"`     // "", "auto", "original", "fake", "upstream", "none"
	Enabled       bool             `json:"enabled"`
	ECHEnabled    bool             `json:"ech_enabled"`
	ECHProfileID  string           `json:"ech_profile_id,omitempty"`
	ECHDomain     string           `json:"ech_domain,omitempty"` // Domain used for ECH DoH lookup
	UseCFPool     bool             `json:"use_cf_pool"`
	CertVerify    CertVerifyConfig `json:"cert_verify,omitempty"`
}

type Upstream struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
	Enabled bool   `json:"enabled"`
}

type ECHProfile struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Config          string `json:"config"`
	DiscoveryDomain string `json:"discovery_domain,omitempty"`
	DoHUpstream     string `json:"doh_upstream,omitempty"`
	AutoUpdate      bool   `json:"auto_update"`
}

type SettingsConfig struct {
	ListenPort                 string            `json:"listen_port"`
	ListenHost                 string            `json:"listen_host,omitempty"`
	SocksAddr                  string            `json:"socks_addr,omitempty"`
	SocksHost                  string            `json:"socks_host,omitempty"`
	SocksPort                  string            `json:"socks_port,omitempty"`
	ServerHost                 string            `json:"server_host,omitempty"`
	ServerAuth                 string            `json:"server_auth,omitempty"`
	CloseToTray                *bool             `json:"close_to_tray,omitempty"`
	AutoStart                  *bool             `json:"auto_start,omitempty"`
	ShowMainWindowOnAutoStart  *bool             `json:"show_main_window_on_auto_start,omitempty"`
	AutoEnableProxyOnAutoStart *bool             `json:"auto_enable_proxy_on_auto_start,omitempty"`
	AutoRouting                AutoRoutingConfig `json:"auto_routing,omitempty"`
	TUN                        TUNConfig         `json:"tun,omitempty"`
	Language                   string            `json:"language,omitempty"`
	Theme                      string            `json:"theme,omitempty"`
	Country                    string            `json:"country,omitempty"`
	CloudflareConfig           CloudflareConfig  `json:"cloudflare_config,omitempty"`
}

type TUNConfig struct {
	Enabled     bool `json:"enabled"`
	MTU         int  `json:"mtu,omitempty"`
	DNSHijack   bool `json:"dns_hijack,omitempty"`
	AutoRoute   bool `json:"auto_route,omitempty"`
	StrictRoute bool `json:"strict_route,omitempty"`
}

type TUNStatus struct {
	Supported bool   `json:"supported"`
	Running   bool   `json:"running"`
	Enabled   bool   `json:"enabled"`
	Driver    string `json:"driver,omitempty"`
	Message   string `json:"message,omitempty"`
}

type RulesConfig struct {
	SiteGroups  []SiteGroup  `json:"site_groups"`
	Upstreams   []Upstream   `json:"upstreams"`
	DNSNodes    []DNSNode    `json:"dns_nodes,omitempty"`
	ECHProfiles []ECHProfile `json:"ech_profiles,omitempty"`
}

// DNSNode defines a DoH upstream with optional SNI obfuscation.
// It reuses the same dial-level concepts as proxy rules (SNI spoofing, ECH, QUIC, static IPs).
type DNSNode struct {
	ID            string           `json:"id"`
	Name          string           `json:"name"`
	URL           string           `json:"url"`                      // DoH endpoint
	SNI           string           `json:"sni,omitempty"`            // Frontend SNI (spoofed domain for TLS ClientHello)
	IPs           []string         `json:"ips,omitempty"`            // Static backend IPs
	ECHEnabled    bool             `json:"ech_enabled"`              // Enable ECH for this DoH connection
	ECHProfileID  string           `json:"ech_profile_id,omitempty"` // ECH profile to use
	ECHAutoUpdate bool             `json:"ech_auto_update"`          // Enable auto refresh
	QUIC          bool             `json:"quic"`                     // Use QUIC/HTTP3 transport
	CertVerify    CertVerifyConfig `json:"cert_verify"`              // Advanced certificate verification
	Enabled       bool             `json:"enabled"`
}

type CloudflareConfig struct {
	PreferredIPs []string `json:"preferred_ips"`
	AutoUpdate   bool     `json:"auto_update"`
	APIKey       string   `json:"api_key"`
}

type trackingListener struct {
	net.Listener
	proxy *ProxyServer
}

type statConn struct {
	net.Conn
	bytesDown   *int64
	bytesUp     *int64
	clientAddr  string
	procMonitor *ProcessMonitor
}

func (c *statConn) Read(p []byte) (n int, err error) {
	n, err = c.Conn.Read(p)
	if n > 0 {
		atomic.AddInt64(c.bytesUp, int64(n))
		if c.procMonitor != nil {
			c.procMonitor.RecordBytes(c.clientAddr, 0, int64(n))
		}
	}
	return n, err
}

func (c *statConn) Write(p []byte) (n int, err error) {
	n, err = c.Conn.Write(p)
	if n > 0 {
		atomic.AddInt64(c.bytesDown, int64(n))
		if c.procMonitor != nil {
			c.procMonitor.RecordBytes(c.clientAddr, int64(n), 0)
		}
	}
	return n, err
}

type singleConnListener struct {
	conn     net.Conn
	once     sync.Once
	done     chan struct{}
	doneOnce sync.Once
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	var accepted bool
	l.once.Do(func() { accepted = true })
	if accepted {
		return &notifyCloseConn{
			Conn: l.conn,
			onClose: func() {
				l.doneOnce.Do(func() { close(l.done) })
			},
		}, nil
	}
	<-l.done
	return nil, io.EOF
}
func (l *singleConnListener) Close() error {
	l.doneOnce.Do(func() { close(l.done) })
	return nil
}
func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

type notifyCloseConn struct {
	net.Conn
	onClose func()
}

func (c *notifyCloseConn) Close() error {
	if c.onClose != nil {
		c.onClose()
	}
	return c.Conn.Close()
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

var hopByHopHeaders = []string{
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
}

func removeHopByHopHeaders(h http.Header) {
	if h == nil {
		return
	}
	// Preserve Connection and Upgrade headers for WebSocket support
	if c := h.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			if name := textproto.TrimString(f); name != "" {
				if !strings.EqualFold(name, "Upgrade") {
					h.Del(name)
				}
			}
		}
	}
	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
}

func (l *trackingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	clientAddr := conn.RemoteAddr().String()
	if pm := l.proxy.procMonitor; pm != nil {
		pm.TrackConnection(clientAddr)
	}
	return &statConn{
		Conn:        conn,
		bytesDown:   &l.proxy.bytesDown,
		bytesUp:     &l.proxy.bytesUp,
		clientAddr:  clientAddr,
		procMonitor: l.proxy.procMonitor,
	}, nil
}

type Rule struct {
	Domain             string
	Upstream           string
	Upstreams          []string
	DNSMode            string
	Mode               string // "mitm", "transparent", "tls-rf", "quic", "server", "direct"
	SniFake            string
	ConnectPolicy      string // "", "tunnel_origin", "tunnel_upstream", "mitm", "direct"
	SniPolicy          string // "", "auto", "original", "fake", "upstream", "none"
	Enabled            bool
	SiteID             string
	ECHEnabled         bool
	ECHProfileID       string
	UseCFPool          bool
	ECHDiscoveryDomain string
	ECHDoHUpstream     string
	ECHAutoUpdate      bool
	CertVerify         CertVerifyConfig
	AutoRouted         bool   // true if generated by AutoRouter
	FallbackMode       string // "server" fallback transport
}

func mergeRule(base, overlay Rule) Rule {
	out := base
	if strings.TrimSpace(overlay.Upstream) != "" {
		out.Upstream = overlay.Upstream
	}
	if len(overlay.Upstreams) > 0 {
		out.Upstreams = append([]string(nil), overlay.Upstreams...)
	}
	if strings.TrimSpace(overlay.DNSMode) != "" {
		out.DNSMode = overlay.DNSMode
	}
	if strings.TrimSpace(overlay.SniFake) != "" {
		out.SniFake = overlay.SniFake
	}
	if strings.TrimSpace(overlay.ConnectPolicy) != "" {
		out.ConnectPolicy = overlay.ConnectPolicy
	}
	if strings.TrimSpace(overlay.SniPolicy) != "" {
		out.SniPolicy = overlay.SniPolicy
	}
	if !overlay.CertVerify.IsZero() {
		out.CertVerify = overlay.CertVerify
	}
	return out
}

type bufferedReadConn struct {
	net.Conn
	reader io.Reader
}

func (c *bufferedReadConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

// WriteTo must be implemented to prevent io.Copy from using the embedded Conn's WriteTo method,
// which would bypass c.reader (and the buffered data) and read directly from the file descriptor.
func (c *bufferedReadConn) WriteTo(w io.Writer) (int64, error) {
	return io.Copy(w, c.reader)
}

func wrapHijackedConn(conn net.Conn, rw *bufio.ReadWriter) net.Conn {
	if rw == nil || rw.Reader == nil || rw.Reader.Buffered() == 0 {
		return conn
	}
	// Extract buffered bytes to avoid sticking with bufio.Reader
	n := rw.Reader.Buffered()
	buffered := make([]byte, n)
	_, _ = rw.Reader.Read(buffered)

	return &bufferedReadConn{
		Conn:   conn,
		reader: io.MultiReader(bytes.NewReader(buffered), conn),
	}
}

func normalizeHost(hostport string) string {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return ""
	}

	host, _, err := net.SplitHostPort(hostport)
	if err == nil {
		return strings.ToLower(strings.TrimSpace(host))
	}

	// Missing port or bracket-only IPv6 literals should still match rules.
	if strings.HasPrefix(hostport, "[") && strings.HasSuffix(hostport, "]") {
		return strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(hostport, "["), "]"))
	}

	return strings.ToLower(hostport)
}

func cleanWebsiteToken(token string) string {
	token = normalizeHost(token)
	token = strings.TrimPrefix(token, "*.")
	token = strings.TrimSuffix(token, "$")
	token = strings.Trim(token, "[]")
	if i := strings.Index(token, ":"); i >= 0 {
		token = token[:i]
	}
	return token
}

func tokenMatchesDomain(token, domain string) bool {
	token = cleanWebsiteToken(token)
	domain = cleanWebsiteToken(domain)
	if token == "" || domain == "" {
		return false
	}
	return token == domain || strings.HasSuffix(token, "."+domain)
}

func inferWebsiteFromSiteGroup(sg SiteGroup) string {
	tokens := []string{sg.Name, sg.Upstream, sg.SniFake}
	tokens = append(tokens, sg.Domains...)

	hasDomain := func(domains ...string) bool {
		for _, t := range tokens {
			for _, d := range domains {
				if tokenMatchesDomain(t, d) {
					return true
				}
			}
		}
		return false
	}

	switch {
	case hasDomain("google.com", "youtube.com", "gstatic.com", "googlevideo.com", "gvt1.com", "ytimg.com", "youtu.be", "ggpht.com"):
		return "google"
	case hasDomain("github.com", "githubusercontent.com", "githubassets.com", "github.io"):
		return "github"
	case hasDomain("telegram.org", "web.telegram.org", "cdn-telegram.org", "t.me", "telesco.pe", "tg.dev", "telegram.me"):
		return "telegram"
	case hasDomain("proton.me"):
		return "proton"
	case hasDomain("pixiv.net", "fanbox.cc", "pximg.net", "pixiv.org"):
		return "pixiv"
	case hasDomain("nyaa.si"):
		return "nyaa"
	case hasDomain("wikipedia.org", "wikimedia.org", "mediawiki.org", "wikibooks.org", "wikidata.org", "wikifunctions.org", "wikinews.org", "wikiquote.org", "wikisource.org", "wikiversity.org", "wikivoyage.org", "wiktionary.org"):
		return "wikipedia"
	case hasDomain("e-hentai.org", "exhentai.org", "ehgt.org", "hentaiverse.org", "ehwiki.org", "ehtracker.org"):
		return "ehentai"
	case hasDomain("facebook.com", "fbcdn.net", "instagram.com", "cdninstagram.com", "instagr.am", "ig.me", "whatsapp.com", "whatsapp.net"):
		return "meta"
	case hasDomain("twitter.com", "x.com", "t.co", "twimg.com"):
		return "x"
	case hasDomain("steamcommunity.com", "steampowered.com"):
		return "steam"
	case hasDomain("mega.nz", "mega.io", "mega.co.nz"):
		return "mega"
	case hasDomain("dailymotion.com"):
		return "dailymotion"
	case hasDomain("duckduckgo.com"):
		return "duckduckgo"
	case hasDomain("reddit.com", "redd.it", "redditmedia.com", "redditstatic.com"):
		return "reddit"
	case hasDomain("twitch.tv"):
		return "twitch"
	case hasDomain("bbc.com", "bbc.co.uk", "bbci.co.uk"):
		return "bbc"
	}

	for _, d := range sg.Domains {
		d = cleanWebsiteToken(d)
		if d == "" || d == "off" {
			continue
		}
		parts := strings.Split(d, ".")
		if len(parts) >= 2 {
			return parts[len(parts)-2]
		}
		return d
	}

	for _, t := range tokens {
		t = cleanWebsiteToken(t)
		if t == "" || t == "off" {
			continue
		}
		parts := strings.Split(t, ".")
		if len(parts) >= 2 {
			return parts[len(parts)-2]
		}
		return t
	}
	return "misc"
}

func ensureAddrWithPort(addr, defaultPort string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}

	host, port, err := net.SplitHostPort(addr)
	if err == nil {
		if port == "" {
			port = defaultPort
		}
		return net.JoinHostPort(host, port)
	}

	if strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]") {
		return net.JoinHostPort(strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]"), defaultPort)
	}

	return net.JoinHostPort(addr, defaultPort)
}

func resolveUpstreamHost(targetHost, upstream string) string {
	upstream = strings.TrimSpace(upstream)
	if upstream == "" {
		return ""
	}
	if strings.Contains(upstream, "$1") {
		firstLabel := targetHost
		if i := strings.Index(firstLabel, "."); i > 0 {
			firstLabel = firstLabel[:i]
		}
		upstream = strings.ReplaceAll(upstream, "$1", firstLabel)
	}
	return upstream
}

func resolveRuleUpstream(targetHost string, rule Rule) string {
	resolved := resolveUpstreamHost(targetHost, rule.Upstream)
	trimmed := strings.TrimSpace(resolved)
	if trimmed == "" && len(rule.Upstreams) > 0 {
		return strings.Join(rule.Upstreams, ",")
	}

	low := strings.ToLower(trimmed)
	if strings.HasPrefix(low, "$backend_ip") || strings.HasPrefix(low, "$upstream_host") || strings.HasPrefix(trimmed, "$") {
		if len(rule.Upstreams) > 0 {
			return strings.Join(rule.Upstreams, ",")
		}
		return net.JoinHostPort(targetHost, "443")
	}

	return resolved
}

func splitUpstreamCandidates(targetHost, upstream, defaultPort string) []string {
	resolved := resolveUpstreamHost(targetHost, upstream)
	if resolved == "" {
		return nil
	}
	parts := strings.Split(resolved, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, p := range parts {
		addr := ensureAddrWithPort(strings.TrimSpace(p), defaultPort)
		if addr == "" {
			continue
		}
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	return out
}

func firstUpstreamHost(targetHost, upstream string) string {
	candidates := splitUpstreamCandidates(targetHost, upstream, "443")
	if len(candidates) == 0 {
		return ""
	}
	host, _, err := net.SplitHostPort(candidates[0])
	if err != nil {
		return normalizeHost(candidates[0])
	}
	return normalizeHost(host)
}

func hostMatchesDomain(host, domain string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	domain = strings.ToLower(strings.TrimSpace(domain))
	if host == "" || domain == "" {
		return false
	}
	domain = strings.TrimPrefix(domain, "*.")
	domain = strings.TrimSuffix(domain, "$")

	// Extended pattern syntax: google.com.* (or any base.*)
	// Matches google.com.sg, www.google.com.sg, google.com.hk, etc.
	if strings.HasSuffix(domain, ".*") {
		base := strings.TrimSuffix(domain, ".*")
		if base == "" {
			return false
		}
		hostParts := strings.Split(host, ".")
		baseParts := strings.Split(base, ".")
		if len(hostParts) < len(baseParts)+1 {
			return false
		}
		for i := 0; i+len(baseParts) < len(hostParts); i++ {
			ok := true
			for j := 0; j < len(baseParts); j++ {
				if hostParts[i+j] != baseParts[j] {
					ok = false
					break
				}
			}
			if ok {
				return true
			}
		}
		return false
	}

	if host == domain {
		return true
	}
	return strings.HasSuffix(host, "."+domain)
}

func domainMatchScore(host, domain string) int {
	host = strings.ToLower(strings.TrimSpace(host))
	domain = strings.ToLower(strings.TrimSpace(domain))
	if host == "" || domain == "" {
		return -1
	}

	if strings.HasPrefix(domain, "~") {
		pattern := strings.TrimSpace(strings.TrimPrefix(domain, "~"))
		if pattern == "" {
			return -1
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return -1
		}
		if re.MatchString(host) {
			return 900 + len(pattern) // exact(1000+) > regex(900+) > suffix/exact-domain
		}
		return -1
	}

	domain = strings.TrimPrefix(domain, "*.")
	domain = strings.TrimSuffix(domain, "$")

	// Pattern base.* => give base length score when matched.
	if strings.HasSuffix(domain, ".*") {
		base := strings.TrimSuffix(domain, ".*")
		if base == "" {
			return -1
		}
		hostParts := strings.Split(host, ".")
		baseParts := strings.Split(base, ".")
		if len(hostParts) < len(baseParts)+1 {
			return -1
		}
		for i := 0; i+len(baseParts) < len(hostParts); i++ {
			ok := true
			for j := 0; j < len(baseParts); j++ {
				if hostParts[i+j] != baseParts[j] {
					ok = false
					break
				}
			}
			if ok {
				return len(base)
			}
		}
		return -1
	}

	// Wildcard "*" matches everything with lowest priority
	if domain == "*" {
		return 1
	}

	if host == domain {
		return len(domain) + 1000 // Prefer exact match over suffix match.
	}
	if strings.HasSuffix(host, "."+domain) {
		return len(domain)
	}
	return -1
}

func isLiteralIP(host string) bool {
	return net.ParseIP(strings.Trim(host, "[]")) != nil
}

func normalizeDNSMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "system":
		return ""
	case "prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only":
		return strings.ToLower(strings.TrimSpace(mode))
	default:
		return ""
	}
}

func reorderIPsByDNSMode(ips []net.IP, mode string) []net.IP {
	if len(ips) == 0 {
		return nil
	}

	mode = normalizeDNSMode(mode)
	if mode == "" {
		out := make([]net.IP, len(ips))
		copy(out, ips)
		return out
	}

	var v4s, v6s []net.IP
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			v4s = append(v4s, ip)
		} else {
			v6s = append(v6s, ip)
		}
	}

	switch mode {
	case "prefer_ipv4":
		return append(append([]net.IP{}, v4s...), v6s...)
	case "prefer_ipv6":
		return append(append([]net.IP{}, v6s...), v4s...)
	case "ipv4_only":
		return append([]net.IP{}, v4s...)
	case "ipv6_only":
		return append([]net.IP{}, v6s...)
	default:
		out := make([]net.IP, len(ips))
		copy(out, ips)
		return out
	}
}

func dedupeDialCandidates(candidates []string) []string {
	if len(candidates) == 0 {
		return nil
	}
	out := make([]string, 0, len(candidates))
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		out = append(out, candidate)
	}
	return out
}

func (p *ProxyServer) resolveDomainCandidates(ctx context.Context, host, port, dnsMode string) []string {
	host = normalizeHost(host)
	if host == "" || isLiteralIP(host) {
		return nil
	}
	if p.dohResolver == nil {
		return nil
	}

	ips, err := p.dohResolver.ResolveIPAddrs(ctx, host)
	if err != nil {
		log.Printf("[DNS] Resolve failed for %s via Failover DNS: %v", host, err)
		return nil
	}

	ordered := reorderIPsByDNSMode(ips, dnsMode)
	if len(ordered) == 0 {
		log.Printf("[DNS] Resolve returned no usable addresses for %s (mode=%s)", host, normalizeDNSMode(dnsMode))
		return nil
	}

	candidates := make([]string, 0, len(ordered))
	for _, ip := range ordered {
		candidates = append(candidates, net.JoinHostPort(ip.String(), port))
	}
	log.Printf("[DNS] Resolved %s via Failover DNS mode=%s -> %v", host, normalizeDNSMode(dnsMode), candidates)
	return dedupeDialCandidates(candidates)
}

func (p *ProxyServer) buildDialCandidates(ctx context.Context, targetHost, targetAddr string, rule Rule, effectiveMode string) []string {
	resolvedUpstream := resolveRuleUpstream(targetHost, rule)
	isWarpRoute := strings.EqualFold(strings.TrimSpace(rule.Upstream), "warp")
	defaultPort := "443"

	if isWarpRoute {
		if resolved := p.resolveDomainCandidates(ctx, targetHost, defaultPort, rule.DNSMode); len(resolved) > 0 {
			return resolved
		}
		return []string{targetAddr}
	}

	if effectiveMode == "mitm" || effectiveMode == "transparent" || effectiveMode == "tls-rf" || effectiveMode == "quic" {
		if strings.TrimSpace(resolvedUpstream) != "" {
			upstreamCandidates := splitUpstreamCandidates(targetHost, resolvedUpstream, defaultPort)
			if len(upstreamCandidates) == 0 {
				return []string{targetAddr}
			}

			firstHost := firstUpstreamHost(targetHost, resolvedUpstream)
			if firstHost != "" && !isLiteralIP(firstHost) {
				// Try DoH first, then fallback to system DNS
				if resolved := p.resolveDomainCandidates(ctx, firstHost, defaultPort, rule.DNSMode); len(resolved) > 0 {
					return resolved
				}
				// DoH failed: resolve via system DNS and return all IPs as candidates
				if sysIPs := resolveSystemDNS(firstHost, defaultPort); len(sysIPs) > 0 {
					log.Printf("[DNS] DoH failed, using system DNS for %s -> %v", firstHost, sysIPs)
					return sysIPs
				}
			}
			return upstreamCandidates
		}

		if rule.UseCFPool && p.cfPool != nil {
			topIPs := p.cfPool.GetTopIPs(5)
			if len(topIPs) > 0 {
				prefs := make([]string, 0, len(topIPs))
				for _, ip := range topIPs {
					prefs = append(prefs, net.JoinHostPort(ip, defaultPort))
				}
				return dedupeDialCandidates(prefs)
			}
		}

		if resolved := p.resolveDomainCandidates(ctx, targetHost, defaultPort, rule.DNSMode); len(resolved) > 0 {
			return resolved
		}
		// DoH failed: fallback to system DNS
		if sysIPs := resolveSystemDNS(targetHost, defaultPort); len(sysIPs) > 0 {
			log.Printf("[DNS] DoH failed, using system DNS for %s -> %v", targetHost, sysIPs)
			return sysIPs
		}
	}

	return []string{targetAddr}
}

func resolveSystemDNS(host, port string) []string {
	ips, err := net.DefaultResolver.LookupIPAddr(context.Background(), host)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(ips))
	seen := make(map[string]struct{})
	for _, ip := range ips {
		addr := ip.IP.String()
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		if ip.IP.To4() != nil {
			out = append(out, net.JoinHostPort(addr, port))
		}
	}
	if len(out) == 0 {
		for _, ip := range ips {
			addr := ip.IP.String()
			if ip.IP.To4() == nil {
				out = append(out, net.JoinHostPort("["+addr+"]", port))
			}
		}
	}
	return out
}

func chooseUpstreamSNI(targetHost string, rule Rule) string {
	targetHost = normalizeHost(targetHost)
	hostAsToken := strings.Trim(targetHost, "[]")
	hostAsToken = strings.ReplaceAll(hostAsToken, ".", "-")
	hostAsToken = strings.ReplaceAll(hostAsToken, ":", "-")
	hostAsToken = strings.TrimSpace(hostAsToken)
	if hostAsToken == "" {
		hostAsToken = "g-cn"
	}
	resolvedUpstream := resolveRuleUpstream(targetHost, rule)

	switch strings.ToLower(strings.TrimSpace(rule.SniPolicy)) {
	case "none":
		// Explicitly disable SNI extension for upstream TLS ClientHello.
		return ""
	case "original":
		return targetHost
	case "fake":
		if strings.TrimSpace(rule.SniFake) != "" {
			return rule.SniFake
		}
		return hostAsToken
	case "upstream":
		if upstreamHost := firstUpstreamHost(targetHost, resolvedUpstream); upstreamHost != "" && !isLiteralIP(upstreamHost) {
			return upstreamHost
		}
		return targetHost
	}

	// MITM mode's core behavior: if fake SNI is configured, always use it.
	if strings.TrimSpace(rule.SniFake) != "" {
		return rule.SniFake
	}
	if resolvedUpstream != "" {
		if upstreamHost := firstUpstreamHost(targetHost, resolvedUpstream); upstreamHost != "" {
			if !isLiteralIP(upstreamHost) && upstreamHost != targetHost {
				return upstreamHost
			}
		}
	}
	// Auto mode should be predictable: when no fake/upstream SNI is available,
	// fall back to original host instead of implicit camouflage.
	return targetHost
}

func NewProxyServer(addr string) *ProxyServer {
	p := &ProxyServer{
		listenAddr:  addr,
		certCache:   make(map[string]*tls.Certificate),
		Fingerprint: "chrome", // default
		mode:        "mitm",   // default
		transport: &http.Transport{
			Proxy: nil, // We are the proxy
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          200,
			IdleConnTimeout:       120 * time.Second,
			TLSHandshakeTimeout:   8 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			MaxIdleConnsPerHost:   50,
			MaxConnsPerHost:       100,
			ResponseHeaderTimeout: 30 * time.Second,
			WriteBufferSize:       64 * 1024,
			ReadBufferSize:        64 * 1024,
		},
		// dohResolver is initialized separately down below to inject proxy reference
		cfPool: NewCloudflarePool([]string{}),
	}
	p.dohResolver = NewFailoverResolver(p)
	p.rules = NewRuleManager("", "")
	return p
}

func (p *ProxyServer) SetRuleManager(rm *RuleManager) {
	p.mu.Lock()
	p.rules = rm
	if rm != nil {
		cfg := rm.GetCloudflareConfig()
		if p.cfPool != nil {
			p.cfPool.UpdateIPs(cfg.PreferredIPs)
		}
	}
	p.mu.Unlock()
}

func (p *ProxyServer) SetCertGenerator(cg CertGenerator) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.certGenerator = cg
}

func (p *ProxyServer) SetLogCallback(cb func(string)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.logCallback = cb
}

func (p *ProxyServer) tracef(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("%s", msg)

	p.mu.RLock()
	cb := p.logCallback
	p.mu.RUnlock()
	if cb != nil {
		cb(msg)
	}
}

func (p *ProxyServer) UpdateCloudflareConfig(cfg CloudflareConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cfPool != nil {
		p.cfPool.UpdateIPs(cfg.PreferredIPs)
	}
}

func (p *ProxyServer) UpdateCloudflareIPPool(ips []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cfPool != nil {
		p.cfPool.UpdateIPs(ips)
	}
}


func (p *ProxyServer) SetGSADialAddr(addr string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gsaDialAddr = addr
	log.Printf("[Proxy] GSA dial address set to: %s", addr)
}

func (p *ProxyServer) SetSOCKSAddr(addr string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.running {
		return fmt.Errorf("cannot change SOCKS5 address while proxy is running")
	}
	p.socksAddr = addr
	log.Printf("[Proxy] SOCKS5 address set to: %s", addr)
	return nil
}

func (p *ProxyServer) GetSOCKSAddr() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.socksAddr
}

func (p *ProxyServer) SetListenAddr(addr string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.running {
		return fmt.Errorf("cannot change address while proxy is running")
	}
	p.listenAddr = addr
	return nil
}

func (p *ProxyServer) TriggerCFHealthCheck() {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.cfPool != nil {
		p.cfPool.TriggerHealthCheck()
	}
}

func (p *ProxyServer) RemoveInvalidCFIPs() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.cfPool != nil {
		return p.cfPool.RemoveInvalidIPs()
	}
	return 0
}

func (p *ProxyServer) GetAllCFIPsWithStats() []*IPStats {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.cfPool != nil {
		return p.cfPool.GetAllIPsWithStats()
	}
	return nil
}

func (p *ProxyServer) GetListenAddr() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.listenAddr
}

func (p *ProxyServer) GetDoHResolver() *FailoverResolver {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.dohResolver
}

func (p *ProxyServer) UpdateECHProfileConfig(profileID string, configBytes []byte) {
	if p.rules == nil {
		return
	}
	_ = p.rules.UpdateECHProfileConfig(profileID, configBytes)
}

func (p *ProxyServer) SetMode(mode string) error {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != "mitm" && mode != "transparent" && mode != "tls-rf" && mode != "quic" && mode != "gsa" {
		return fmt.Errorf("invalid proxy mode: %s", mode)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.mode = mode
	return nil
}

func (p *ProxyServer) GetMode() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.mode
}

func (p *ProxyServer) Start() error {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return nil
	}

	srv := &http.Server{
		Addr: p.listenAddr,
		// Use raw handler instead of ServeMux: CONNECT uses authority-form
		// and may not be routed by path-based muxes.
		Handler:      http.HandlerFunc(p.handleRequest),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	listenAddr := p.listenAddr

	if p.cfPool != nil {
		p.cfPool.Start()
	}

	p.mu.Unlock()

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		if p.cfPool != nil {
			p.cfPool.Stop()
		}
		return fmt.Errorf("failed to listen on %s: %w", listenAddr, err)
	}

	// Start SOCKS5 listener if address is configured
	var socksLn net.Listener
	p.mu.RLock()
	socksAddr := p.socksAddr
	p.mu.RUnlock()
	if socksAddr != "" {
		socksLn, err = net.Listen("tcp", socksAddr)
		if err != nil {
			log.Printf("[Proxy] WARNING: SOCKS5 listen on %s failed: %v", socksAddr, err)
		} else {
			log.Printf("[Proxy] SOCKS5 listening on %s", socksAddr)
		}
	}

	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		_ = ln.Close()
		if socksLn != nil {
			_ = socksLn.Close()
		}
		return nil
	}
	p.Server = srv
	p.running = true
	if socksLn != nil {
		p.socksListener = socksLn
		p.socksRunning = true
	}
	p.mu.Unlock()

	go func() {
		log.Printf("[Proxy] Server started on %s", listenAddr)
		tl := &trackingListener{
			Listener: ln,
			proxy:    p,
		}
		if err := srv.Serve(tl); err != nil && err != http.ErrServerClosed {
			log.Printf("[Proxy] Server error: %v", err)
		}
		p.mu.Lock()
		if p.Server == srv {
			p.running = false
		}
		p.mu.Unlock()
	}()

	if socksLn != nil {
		p.socksWg.Add(1)
		go func() {
			defer p.socksWg.Done()
			p.socksAcceptLoop(socksLn)
		}()
	}

	return nil
}

func (p *ProxyServer) Stop() error {
	p.mu.Lock()
	if !p.running {
		p.mu.Unlock()
		return nil
	}
	p.running = false

	if p.cfPool != nil {
		p.cfPool.Stop()
	}

	socksLn := p.socksListener
	p.socksListener = nil
	p.socksRunning = false
	p.mu.Unlock()

	// Close SOCKS5 listener first to stop accept loop
	if socksLn != nil {
		_ = socksLn.Close()
	}
	p.socksWg.Wait()

	if p.Server != nil {
		return p.Server.Close()
	}
	return nil
}

func (p *ProxyServer) IsRunning() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.running
}

func (p *ProxyServer) handleRequest(w http.ResponseWriter, req *http.Request) {

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	matchHost := normalizeHost(host)
	mode := p.GetMode()
	rule := p.rules.matchRule(matchHost, mode)
	if rule.SiteID != "" {
		p.rules.incrementRuleHit(rule.SiteID)
	}

	p.tracef("[Proxy] Request: %s -> %s (match: %s, runtime-mode: %s, rule-mode: %s)", req.Method, host, matchHost, mode, rule.Mode)

	switch req.Method {
	case http.MethodConnect:
		p.handleConnect(w, req, rule)
	default:
		p.handleHTTP(w, req, rule)
	}
}

func (p *ProxyServer) handleConnect(w http.ResponseWriter, req *http.Request, rule Rule) {

	targetAuthority := req.URL.Host
	if targetAuthority == "" {
		targetAuthority = req.Host
	}
	targetHost := normalizeHost(targetAuthority)
	targetAddr := ensureAddrWithPort(targetAuthority, "443")

	// GSA active: forward ALL traffic through local GSA proxy, no mode processing
	if p.gsaDialAddr != "" {
		p.handleGSAConnect(w, req, targetHost, targetAuthority)
		return
	}

	effectiveMode := rule.Mode
	resolvedUpstream := resolveRuleUpstream(targetHost, rule)

	switch strings.ToLower(strings.TrimSpace(rule.ConnectPolicy)) {
	case "tunnel_origin":
		effectiveMode = "transparent"
		resolvedUpstream = ""
	case "tunnel_upstream":
		effectiveMode = "transparent"
	case "mitm":
		effectiveMode = "mitm"
	case "direct":
		effectiveMode = "direct"
		resolvedUpstream = ""
	}

	if (effectiveMode == "mitm" || effectiveMode == "transparent") && strings.TrimSpace(resolvedUpstream) != "" {
		upHost := firstUpstreamHost(targetHost, resolvedUpstream)
		if upHost != "" {
			upRule := p.rules.matchRule(upHost, effectiveMode)
			if upRule.SiteID != "" {
				baseSite := rule.SiteID
				rule = mergeRule(rule, upRule)
				if strings.TrimSpace(rule.Upstream) != "" {
					resolvedUpstream = resolveRuleUpstream(upHost, rule)
				}
				log.Printf("[Connect] Stage-2 upstream rule applied: host=%s site=%s over base=%s", upHost, upRule.SiteID, baseSite)
			}
		}
	}

	p.tracef("[Connect] target=%s host=%s mode=%s->%s upstream=%s sni_fake=%s", targetAddr, targetHost, rule.Mode, effectiveMode, resolvedUpstream, rule.SniFake)

	// For direct mode, connect directly to target
	if effectiveMode == "direct" {
		p.directConnect(w, req)
		return
	}

	// For server mode, hijack directly and use built-in HTTP service for resolution, no dial to original target
	if effectiveMode == "server" {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "Hijack not supported", http.StatusInternalServerError)
			return
		}
		clientConn, rw, err := hijacker.Hijack()
		if err != nil {
			log.Printf("[Connect] Server hijack failed: %v", err)
			return
		}
		if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			clientConn.Close()
			return
		}
		if err := rw.Flush(); err != nil {
			clientConn.Close()
			return
		}
		clientConn = wrapHijackedConn(clientConn, rw)
		_ = clientConn.SetDeadline(time.Time{})
		p.handleServerMITM(clientConn, targetHost, rule)
		return
	}

	if effectiveMode == "quic" {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "Hijack not supported", http.StatusInternalServerError)
			return
		}
		clientConn, rw, err := hijacker.Hijack()
		if err != nil {
			log.Printf("[Connect] QUIC hijack failed: %v", err)
			return
		}
		if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			clientConn.Close()
			return
		}
		if err := rw.Flush(); err != nil {
			clientConn.Close()
			return
		}
		clientConn = wrapHijackedConn(clientConn, rw)
		_ = clientConn.SetDeadline(time.Time{})
		p.handleQUICMITM(clientConn, targetHost, rule)
		return
	}

	dialCandidates := p.buildDialCandidates(context.Background(), targetHost, targetAddr, rule, effectiveMode)
	if len(dialCandidates) == 0 {
		dialCandidates = []string{targetAddr}
	}
	dialAddr := dialCandidates[0]

	log.Printf("[Connect] Using candidates %v for host %s", dialCandidates, targetHost)

	var conn net.Conn
	var err error

	if effectiveMode != "mitm" {
		// Use private dial method to support Warp
		dial := func(network, addr string) (net.Conn, error) {
			return p.dialWithRule(context.Background(), network, addr, rule)
		}

		// Single-path stability first (with sequential fallback)
		if len(dialCandidates) > 1 {
			var lastErr error
			for _, addr := range dialCandidates {
				conn, err = dial("tcp", addr)
				if err == nil {
					dialAddr = addr
					log.Printf("[Connect] Sequential dial success: %s", dialAddr)

					// If using CF preferred pool, report success status
					if rule.UseCFPool && p.cfPool != nil {
						host, _, _ := net.SplitHostPort(addr)
						if host != "" {
							p.cfPool.ReportSuccess(host)
						}
					}
					break
				}

				log.Printf("[Connect] Connect failed to %s: %v", addr, err)
				lastErr = err

				// If candidate node connection failed and from CF pool, report failure for penalty
				if rule.UseCFPool && p.cfPool != nil {
					host, _, _ := net.SplitHostPort(addr)
					if host != "" {
						p.cfPool.ReportFailure(host)
					}
				}
			}
			if conn == nil {
				err = lastErr
			}
		} else {
			for _, candidate := range dialCandidates {
				conn, err = dial("tcp", candidate)
				if err == nil {
					dialAddr = candidate
					break
				}
				log.Printf("[Connect] Connect failed to %s: %v", candidate, err)
			}
		}
		if err != nil || conn == nil {
			http.Error(w, "Failed to connect to upstream", http.StatusBadGateway)
			p.tracef("[Connect] All upstream connect attempts failed: %v", dialCandidates)
			return
		}
	} else {
		// For MITM we only need a raw TCP connect here so the browser can receive
		// CONNECT 200 quickly; upstream TLS is established inside handleMITM.
		dial := func(network, addr string) (net.Conn, error) {
			return p.dialWithRule(context.Background(), network, addr, rule)
		}
		if len(dialCandidates) > 1 {
			var lastErr error
			for _, addr := range dialCandidates {
				conn, err = dial("tcp", addr)
				if err == nil {
					dialAddr = addr
					log.Printf("[Connect] Sequential dial success: %s", dialAddr)
					if rule.UseCFPool && p.cfPool != nil {
						host, _, _ := net.SplitHostPort(addr)
						if host != "" {
							p.cfPool.ReportSuccess(host)
						}
					}
					break
				}

				log.Printf("[Connect] Connect failed to %s: %v", addr, err)
				lastErr = err
				if rule.UseCFPool && p.cfPool != nil {
					host, _, _ := net.SplitHostPort(addr)
					if host != "" {
						p.cfPool.ReportFailure(host)
					}
				}
			}
			if conn == nil {
				err = lastErr
			}
		} else {
			for _, candidate := range dialCandidates {
				conn, err = dial("tcp", candidate)
				if err == nil {
					dialAddr = candidate
					break
				}
				log.Printf("[Connect] Connect failed to %s: %v", candidate, err)
			}
		}
		if err != nil || conn == nil {
			http.Error(w, "Failed to connect to upstream", http.StatusBadGateway)
			p.tracef("[Connect] All upstream connect attempts failed: %v", dialCandidates)
			return
		}
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijack not supported", http.StatusInternalServerError)
		conn.Close()
		return
	}

	clientConn, rw, err := hijacker.Hijack()
	if err != nil {
		log.Printf("[Connect] Hijack failed: %v", err)
		conn.Close()
		return
	}
	if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		log.Printf("[Connect] Write 200 failed: %v", err)
		clientConn.Close()
		conn.Close()
		return
	}
	if err := rw.Flush(); err != nil {
		log.Printf("[Connect] Flush 200 failed: %v", err)
		clientConn.Close()
		conn.Close()
		return
	}
	clientConn = wrapHijackedConn(clientConn, rw)
	_ = clientConn.SetDeadline(time.Time{})
	_ = conn.SetDeadline(time.Time{})

	// Note: do not use defer after hijack, because we need to keep the connection open
	switch effectiveMode {
	case "mitm":
		p.handleMITM(clientConn, targetHost, rule, dialCandidates, dialAddr)
	case "tls-rf":
		p.handleTLSFragment(clientConn, conn, targetHost, rule)
	default:
		p.handleTransparent(clientConn, conn, targetHost, rule)
	}
}

func (p *ProxyServer) directConnect(w http.ResponseWriter, req *http.Request) {
	targetAuthority := req.URL.Host
	if targetAuthority == "" {
		targetAuthority = req.Host
	}
	targetAddr := ensureAddrWithPort(targetAuthority, "443")

	log.Printf("[Direct] Connecting to %s", targetAddr)

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	conn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		http.Error(w, "Failed to connect", http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijack not supported", http.StatusInternalServerError)
		conn.Close()
		return
	}

	clientConn, rw, err := hijacker.Hijack()
	if err != nil {
		conn.Close()
		return
	}
	if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		clientConn.Close()
		conn.Close()
		return
	}
	if err := rw.Flush(); err != nil {
		clientConn.Close()
		conn.Close()
		return
	}
	clientConn = wrapHijackedConn(clientConn, rw)
	_ = clientConn.SetDeadline(time.Time{})
	_ = conn.SetDeadline(time.Time{})

	// Bidirectional data copy
	var wg sync.WaitGroup
	wg.Add(2)

	// Get buffers from pool to reduce allocation
	buf1 := tunnelBufPool.Get().(*[]byte)
	buf2 := tunnelBufPool.Get().(*[]byte)

	go func() {
		defer wg.Done()
		defer tunnelBufPool.Put(buf1)
		_, _ = io.CopyBuffer(conn, clientConn, *buf1)
		conn.Close()
	}()
	go func() {
		defer wg.Done()
		defer tunnelBufPool.Put(buf2)
		_, _ = io.CopyBuffer(clientConn, conn, *buf2)
		clientConn.Close()
	}()
	wg.Wait()
}


// handleGSAConnect handles a CONNECT request by forwarding it through the local GSA proxy server.
func (p *ProxyServer) handleGSAConnect(w http.ResponseWriter, req *http.Request, targetHost, targetAuthority string) {
	log.Printf("[GSA] handleGSAConnect called: target=%s gsaDialAddr=%s", targetAuthority, p.gsaDialAddr)
	if p.gsaDialAddr == "" {
		log.Printf("[GSA] GSA proxy NOT running (gsaDialAddr is empty) — falling back to direct CONNECT %s", targetAuthority)
		p.tracef("[GSA] WARNING: Falling back to direct connection because GSA proxy is not running")
		p.directConnect(w, req)
		return
	}
	log.Printf("[GSA] Forwarding CONNECT %s through GSA proxy at %s", targetAuthority, p.gsaDialAddr)

	log.Printf("[GSA] Step 1: dialing GSA proxy at %s", p.gsaDialAddr)
	gsaConn, err := net.DialTimeout("tcp", p.gsaDialAddr, 10*time.Second)
	if err != nil {
		log.Printf("[GSA] WARNING: Failed to connect to GSA proxy at %s: %v — falling back to direct", p.gsaDialAddr, err)
		p.directConnect(w, req)
		return
	}
	defer gsaConn.Close()
	log.Printf("[GSA] Step 2: connected to GSA proxy, sending CONNECT")

	// Send CONNECT request through GSA proxy
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAuthority, targetHost)
	if _, err := fmt.Fprint(gsaConn, connectReq); err != nil {
		log.Printf("[GSA] CONNECT write failed: %v", err)
		http.Error(w, "GSA CONNECT failed", http.StatusBadGateway)
		return
	}
	log.Printf("[GSA] Step 3: CONNECT sent, waiting for response")

	// Read GSA proxy response
	gsaReader := bufio.NewReader(gsaConn)
	resp, err := http.ReadResponse(gsaReader, nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		status := http.StatusBadGateway
		if err == nil {
			log.Printf("[GSA] GSA proxy rejected CONNECT: %d", resp.StatusCode)
		} else {
			log.Printf("[GSA] GSA proxy response error: %v", err)
		}
		http.Error(w, "GSA proxy rejected CONNECT", status)
		return
	}
	resp.Body.Close()
	log.Printf("[GSA] Step 4: received 200 from GSA proxy, hijacking client")

	// Hijack client connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijack not supported", http.StatusInternalServerError)
		return
	}
	clientConn, rw, err := hijacker.Hijack()
	if err != nil {
		log.Printf("[GSA] Hijack failed: %v", err)
		return
	}
	defer clientConn.Close()
	log.Printf("[GSA] Step 5: client hijacked, sending 200 to client")

	// Send 200 to client
	if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		log.Printf("[GSA] 200 write to client failed: %v", err)
		return
	}
	if err := rw.Flush(); err != nil {
		log.Printf("[GSA] flush to client failed: %v", err)
		return
	}
	clientConn = wrapHijackedConn(clientConn, rw)
	log.Printf("[GSA] Step 6: starting bidirectional copy between client and GSA proxy")

	// Bidirectional copy
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		n, err := io.Copy(clientConn, gsaConn)
		log.Printf("[GSA] io.Copy gsa->client: %d bytes, err=%v", n, err)
		wg.Done()
	}()
	go func() {
		n, err := io.Copy(gsaConn, clientConn)
		log.Printf("[GSA] io.Copy client->gsa: %d bytes, err=%v", n, err)
		wg.Done()
	}()
	wg.Wait()
	log.Printf("[GSA] Step 7: bidirectional copy finished")
}

// handleGSAHTTP handles a plain HTTP request by forwarding it through the local GSA proxy server.
func (p *ProxyServer) handleGSAHTTP(w http.ResponseWriter, req *http.Request) {
	if p.gsaDialAddr == "" {
		log.Printf("[GSA] GSA proxy NOT running — falling back to direct HTTP %s %s", req.Method, req.URL)
		resp, err := p.transport.RoundTrip(req)
		if err != nil {
			http.Error(w, "GSA fallback failed: "+err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, v := range resp.Header {
			for _, vv := range v {
				w.Header().Add(k, vv)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		return
	}
	log.Printf("[GSA] Forwarding HTTP %s %s through GSA proxy at %s", req.Method, req.URL, p.gsaDialAddr)

	gsaConn, err := net.DialTimeout("tcp", p.gsaDialAddr, 10*time.Second)
	if err != nil {
		log.Printf("[GSA] Failed to connect to GSA proxy: %v", err)
		resp, err := p.transport.RoundTrip(req)
		if err != nil {
			http.Error(w, "GSA fallback failed: "+err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, v := range resp.Header {
			for _, vv := range v {
				w.Header().Add(k, vv)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		return
	}
	defer gsaConn.Close()

	// Send the request as an HTTP proxy request
	if err := req.WriteProxy(gsaConn); err != nil {
		log.Printf("[GSA] Request write failed: %v", err)
		http.Error(w, "GSA proxy request failed", http.StatusBadGateway)
		return
	}

	// Read response from GSA proxy
	resp, err := http.ReadResponse(bufio.NewReader(gsaConn), req)
	if err != nil {
		log.Printf("[GSA] Response read failed: %v", err)
		http.Error(w, "GSA proxy response failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// socksAcceptLoop accepts SOCKS5 connections and spawns a handler goroutine.
func (p *ProxyServer) socksAcceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			p.mu.RLock()
			running := p.running
			p.mu.RUnlock()
			if !running {
				return
			}
			continue
		}
		go p.handleSOCKS5(conn)
	}
}

// handleSOCKS5 handles a single SOCKS5 connection.
// When GSA mode is active (gsaDialAddr is set), it forwards traffic through the GSA proxy.
// Otherwise, it creates a direct TCP tunnel to the target.
func (p *ProxyServer) handleSOCKS5(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		log.Printf("[SOCKS5] read greeting failed: %v", err)
		return
	}
	if buf[0] != 5 {
		log.Printf("[SOCKS5] bad SOCKS version: %d", buf[0])
		return
	}
	methods := make([]byte, int(buf[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		log.Printf("[SOCKS5] read methods failed: %v", err)
		return
	}
	_, _ = conn.Write([]byte{0x05, 0x00})

	request := make([]byte, 4)
	if _, err := io.ReadFull(conn, request); err != nil {
		log.Printf("[SOCKS5] read request failed: %v", err)
		return
	}
	if request[0] != 5 || request[1] != 0x01 {
		log.Printf("[SOCKS5] unsupported command: ver=%d cmd=%d", request[0], request[1])
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	addrType := request[3]
	var host string
	switch addrType {
	case 0x01:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			log.Printf("[SOCKS5] read IPv4 failed: %v", err)
			return
		}
		host = net.IP(ip).String()
	case 0x03:
		ln := make([]byte, 1)
		if _, err := io.ReadFull(conn, ln); err != nil {
			log.Printf("[SOCKS5] read domain length failed: %v", err)
			return
		}
		name := make([]byte, int(ln[0]))
		if _, err := io.ReadFull(conn, name); err != nil {
			log.Printf("[SOCKS5] read domain name failed: %v", err)
			return
		}
		host = string(name)
	case 0x04:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			log.Printf("[SOCKS5] read IPv6 failed: %v", err)
			return
		}
		host = net.IP(ip).String()
	default:
		log.Printf("[SOCKS5] unsupported address type: 0x%02x", addrType)
		_, _ = conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		log.Printf("[SOCKS5] read port failed: %v", err)
		return
	}
	port := int(portBuf[0])<<8 | int(portBuf[1])

	_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	log.Printf("[SOCKS5] CONNECT -> %s:%d", host, port)
	_ = conn.SetDeadline(time.Time{})

	p.socksRelay(host, port, conn)
}

// socksRelay relays a SOCKS5 connection. When GSA is active, it uses a CONNECT
// tunnel through the GSA proxy so that TLS traffic goes through GSA's MITM/relay
// and HTTP traffic goes through GSA's HTTP handler. Otherwise creates a direct TCP tunnel.
func (p *ProxyServer) socksRelay(host string, port int, conn net.Conn) {
	p.mu.RLock()
	gsaAddr := p.gsaDialAddr
	p.mu.RUnlock()

	if gsaAddr == "" {
		log.Printf("[SOCKS5] direct TCP tunnel to %s:%d", host, port)
		p.socksDirect(host, port, conn)
		return
	}

	log.Printf("[SOCKS5] CONNECT tunnel through GSA proxy at %s for %s:%d", gsaAddr, host, port)

	gsaConn, err := net.DialTimeout("tcp", gsaAddr, 10*time.Second)
	if err != nil {
		log.Printf("[SOCKS5] GSA dial failed: %v — direct TCP tunnel to %s:%d", err, host, port)
		p.socksDirect(host, port, conn)
		return
	}
	defer gsaConn.Close()

	// Use CONNECT tunnel through GSA proxy so TLS goes through MITM/relay,
	// HTTP goes through relayHTTPOverTLS, and both end up in Apps Script.
	target := net.JoinHostPort(host, strconv.Itoa(port))
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, host)
	if _, err := fmt.Fprint(gsaConn, connectReq); err != nil {
		log.Printf("[SOCKS5] CONNECT write to GSA failed: %v — direct fallback", err)
		p.socksDirect(host, port, conn)
		return
	}

	resp, err := http.ReadResponse(bufio.NewReader(gsaConn), nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		if err != nil {
			log.Printf("[SOCKS5] GSA CONNECT response error: %v — direct fallback", err)
		} else {
			log.Printf("[SOCKS5] GSA CONNECT rejected %s: %d — direct fallback", target, resp.StatusCode)
		}
		p.socksDirect(host, port, conn)
		return
	}
	resp.Body.Close()

	log.Printf("[SOCKS5] GSA CONNECT tunnel established for %s", target)
	p.socksTunnel(conn, gsaConn)
}

// socksTunnel performs bidirectional copy between two connections.
func (p *ProxyServer) socksTunnel(client, upstream net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		n, err := io.Copy(upstream, client)
		log.Printf("[SOCKS5] io.Copy client->upstream: %d bytes, err=%v", n, err)
		wg.Done()
	}()
	go func() {
		n, err := io.Copy(client, upstream)
		log.Printf("[SOCKS5] io.Copy upstream->client: %d bytes, err=%v", n, err)
		wg.Done()
	}()
	wg.Wait()
}

// socksDirect creates a direct TCP tunnel to the target host:port.
func (p *ProxyServer) socksDirect(host string, port int, client net.Conn) {
	target := net.JoinHostPort(host, strconv.Itoa(port))
	dst, err := net.DialTimeout("tcp", target, 15*time.Second)
	if err != nil {
		log.Printf("[SOCKS5] direct dial failed for %s: %v", target, err)
		return
	}
	defer dst.Close()
	p.socksTunnel(client, dst)
}

func (p *ProxyServer) handleHTTP(w http.ResponseWriter, req *http.Request, rule Rule) {
	// Create new request to avoid modifying original request
	newReq := req.Clone(req.Context())
	newReq.RequestURI = ""
	newReq.Header.Del("Proxy-Connection")

	// GSA active: forward ALL HTTP traffic through local GSA proxy
	if p.gsaDialAddr != "" {
		p.handleGSAHTTP(w, newReq)
		return
	}

	if newReq.URL.Scheme == "" {
		if req.TLS != nil {
			newReq.URL.Scheme = "https"
		} else {
			newReq.URL.Scheme = "http"
		}
	}
	if newReq.URL.Host == "" {
		newReq.URL.Host = req.Host
	}
	if newReq.Host == "" {
		newReq.Host = req.Host
	}
	if newReq.Host == "" {
		newReq.Host = newReq.URL.Host
	}

	// HTTPS so requests enter the CONNECT/TLS handling path instead of the basic
	// HTTP forwarder, which does not implement the full MITM feature set.
	if (rule.Mode == "mitm" || rule.Mode == "quic") && newReq.URL.Scheme == "http" {
		httpsURL := *newReq.URL
		httpsURL.Scheme = "https"
		if httpsURL.Host == "" {
			httpsURL.Host = req.Host
		}
		http.Redirect(w, req, httpsURL.String(), http.StatusMovedPermanently)
		return
	}

	if rule.Mode == "direct" {
		// Direct forward request
		resp, err := p.transport.RoundTrip(newReq)
		if err != nil {
			log.Printf("[HTTP] Direct proxy failed: %v", err)
			http.Error(w, "Failed to proxy", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

	// Copy response headers
		for key, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		return
	}

	transport := http.RoundTripper(p.transport)
	if rule.Upstream != "" {
		defaultPort := "80"
		if strings.EqualFold(newReq.URL.Scheme, "https") {
			defaultPort = "443"
		}
		candidates := p.buildDialCandidates(req.Context(), normalizeHost(newReq.Host), ensureAddrWithPort(newReq.URL.Host, defaultPort), rule, rule.Mode)
		if len(candidates) > 0 {
			newReq.URL.Host = candidates[0]
		}
	} else {
		defaultPort := "80"
		if strings.EqualFold(newReq.URL.Scheme, "https") {
			defaultPort = "443"
		}
		targetAddr := ensureAddrWithPort(newReq.URL.Host, defaultPort)
		dialCandidates := p.buildDialCandidates(req.Context(), normalizeHost(newReq.Host), targetAddr, rule, rule.Mode)
		if len(dialCandidates) > 0 && dialCandidates[0] != targetAddr {
			t := p.transport.Clone()
			candidateSet := dedupeDialCandidates(dialCandidates)
			t.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
				var lastErr error
				for _, candidate := range candidateSet {
					conn, err := p.dialWithRule(ctx, network, candidate, rule)
					if err == nil {
						return conn, nil
					}
					lastErr = err
				}
				return nil, lastErr
			}
			transport = t
		}
	}

	resp, err := transport.RoundTrip(newReq)
	if err != nil {
		log.Printf("[HTTP] Proxy failed: %v", err)
		http.Error(w, "Failed to connect to upstream", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// 复制响应头
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (p *ProxyServer) handleMITM(clientConn net.Conn, host string, rule Rule, dialCandidates []string, initialDialAddr string) {
	defer func() {
		if r := recover(); r != nil {
			p.tracef("[MITM] Panic: %v", r)
			_ = clientConn.Close()
		}
	}()

	p.tracef("[MITM] Handling %s with SNI: %s", host, rule.SniFake)

	if p.certGenerator == nil {
		p.tracef("[MITM] No cert generator, falling back to direct")
		p.directTunnel(clientConn, clientConn)
		return
	}

	p.tracef("[MITM] Cert generator present")
	p.tracef("[MITM] Fetching CA cert")
	caCert := p.certGenerator.GetCACert()
	p.tracef("[MITM] Fetching CA key")
	caKey := p.certGenerator.GetCAKey()
	p.tracef("[MITM] CA fetch done cert=%t key=%t", caCert != nil, caKey != nil)
	if caCert == nil || caKey == nil {
		p.tracef("[MITM] CA cert/key not available")
		clientConn.Close()
		return
	}

	p.tracef("[MITM] Choosing upstream SNI for host=%s", host)
	sniHost := chooseUpstreamSNI(host, rule)
	p.tracef("[MITM] Upstream handshake SNI selected: %s", sniHost)

	orderedCandidates := make([]string, 0, len(dialCandidates)+1)
	if strings.TrimSpace(initialDialAddr) != "" {
		orderedCandidates = append(orderedCandidates, initialDialAddr)
	}
	for _, c := range dialCandidates {
		if strings.TrimSpace(c) == "" || c == initialDialAddr {
			continue
		}
		orderedCandidates = append(orderedCandidates, c)
	}

	p.tracef("[MITM] Establishing upstream via candidates=%v", orderedCandidates)
	upstreamRW, upstreamProtocol, err := p.establishUpstreamConn(host, rule, orderedCandidates, "")
	if err != nil {
		p.tracef("[MITM] Failed to establish upstream: %v", err)
		clientConn.Close()
		return
	}
	defer upstreamRW.Close()

	if upstreamRW == nil {
		log.Printf("[MITM] No usable upstream")
		clientConn.Close()
		return
	}

	p.tracef("[MITM] Upstream negotiated protocol: %s", upstreamProtocol)
	tlsConfig := p.makeMITMTLSConfig(host, caCert, caKey, nextProtosForNegotiatedALPN(upstreamProtocol), "[MITM]")

	clientTls := tls.Server(clientConn, tlsConfig)
	if err := clientTls.Handshake(); err != nil {
		p.tracef("[MITM] Client TLS handshake failed: %v", err)
		clientConn.Close()
		upstreamRW.Close()
		return
	}

	clientALPN := clientTls.ConnectionState().NegotiatedProtocol
	p.tracef("[MITM] Client ALPN: %s, Upstream Protocol: %s", clientALPN, upstreamProtocol)

	p.directTunnel(clientTls, upstreamRW)
}

func (p *ProxyServer) directTunnel(clientConn, upstreamConn net.Conn) {
	p.tracef("[Tunnel] Starting direct tunnel")
	var wg sync.WaitGroup
	wg.Add(2)

	// Get buffers from pool to reduce allocation
	buf1 := tunnelBufPool.Get().(*[]byte)
	buf2 := tunnelBufPool.Get().(*[]byte)

	go func() {
		defer wg.Done()
		defer tunnelBufPool.Put(buf1)
		n, err := io.CopyBuffer(upstreamConn, clientConn, *buf1)
		p.tracef("[Tunnel] Client -> Upstream: %d bytes, err: %v", n, err)
		upstreamConn.Close()
	}()
	go func() {
		defer wg.Done()
		defer tunnelBufPool.Put(buf2)
		n, err := io.CopyBuffer(clientConn, upstreamConn, *buf2)
		p.tracef("[Tunnel] Upstream -> Client: %d bytes, err: %v", n, err)
		clientConn.Close()
	}()
	wg.Wait()
	p.tracef("[Tunnel] Tunnel closed")
}

func (p *ProxyServer) generateCert(host string, caCert *x509.Certificate, caKey interface{}) (*tls.Certificate, error) {
	host = normalizeHost(host)
	p.certCacheMu.RLock()
	if cert, ok := p.certCache[host]; ok && cert != nil {
		p.certCacheMu.RUnlock()
		return cert, nil
	}
	p.certCacheMu.RUnlock()

	serial := big.NewInt(time.Now().UnixNano())
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{host},
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &privKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})

	keyBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	cert, err := tls.X509KeyPair(append(certPEM, caPEM...), keyPEM)
	if err != nil {
		return nil, err
	}

	p.certCacheMu.Lock()
	p.certCache[host] = &cert
	p.certCacheMu.Unlock()
	return &cert, nil
}

func (p *ProxyServer) makeMITMTLSConfig(connectHost string, caCert *x509.Certificate, caKey interface{}, nextProtos []string, logPrefix string) *tls.Config {
	connectHost = normalizeHost(connectHost)
	return &tls.Config{
		NextProtos: append([]string(nil), nextProtos...),
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			clientSNI := normalizeHost(hello.ServerName)
			certHost := connectHost
			if clientSNI != "" {
				certHost = clientSNI
			}

			if clientSNI != "" && connectHost != "" && clientSNI != connectHost {
				log.Printf("%s ClientHello SNI mismatch: connect_host=%s client_sni=%s remote=%s", logPrefix, connectHost, clientSNI, hello.Conn.RemoteAddr())
			} else {
				log.Printf("%s ClientHello: connect_host=%s client_sni=%s remote=%s", logPrefix, connectHost, clientSNI, hello.Conn.RemoteAddr())
			}

			cert, err := p.generateCert(certHost, caCert, caKey)
			if err != nil {
				log.Printf("%s Generate cert failed: cert_host=%s err=%v", logPrefix, certHost, err)
				return nil, err
			}
			log.Printf("%s Serving MITM cert: cert_host=%s alpn=%v", logPrefix, certHost, hello.SupportedProtos)
			return cert, nil
		},
	}
}

func (p *ProxyServer) handleTransparent(clientConn, upstreamConn net.Conn, host string, rule Rule) {
	// Transparent mode should forward raw TLS bytes without terminating TLS.
	// Terminating TLS here would require MITM on the client side as well.
	log.Printf("[Transparent] Tunneling %s -> %s (raw TCP)", host, rule.Upstream)
	p.directTunnel(clientConn, upstreamConn)
}

func (r *RuleManager) SetRules(rules []Rule) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rules = rules
}

func (r *RuleManager) matchRule(host, mode string) Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()

	host = normalizeHost(host)
	mode = strings.ToLower(strings.TrimSpace(mode))

	best := Rule{}
	bestScore := -1
	for _, rule := range r.rules {
		if !rule.Enabled {
			continue
		}

		score := domainMatchScore(host, rule.Domain)
		if score >= 0 && score > bestScore {
			best = rule
			bestScore = score
		}
	}

	// If specific rule matched
	if bestScore >= 0 {
		if mode == "transparent" && best.Mode == "mitm" {
			log.Printf("[RuleMatch] Global Transparent detected: Downgrading MITM rule (%s) to DIRECT to avoid cert errors.", host)
			best.Mode = "direct"
		}
		log.Printf("[Router] %s -> %s", host, best.Mode)
		r.emitRouteEvent(host, best.Mode)
		return best
	}

	// Auto-route layer: when manual rules don't match, query AutoRouter
	if r.autoRouter != nil && r.autoRoutingConfig.Mode != "" {
		autoRule := r.autoRouter.Decide(host)
		if autoRule.Mode != "direct" {
			log.Printf("[Router] %s -> %s (AutoRoute)", host, autoRule.Mode)
			r.emitRouteEvent(host, autoRule.Mode)
			return autoRule
		}
	}

	// No rules matched, use direct connection
	log.Printf("[Router] %s -> direct (Default)", host)
	r.emitRouteEvent(host, "direct")
	return Rule{
		Mode:    "direct",
		Enabled: true,
	}
}

func (p *ProxyServer) GetStats() (int64, int64, int64) {
	return atomic.LoadInt64(&p.bytesDown), atomic.LoadInt64(&p.bytesUp), 0
}

func (p *ProxyServer) InitProcessMonitor() {
	if p.procMonitor != nil {
		return
	}
	port := 0
	if addr := p.listenAddr; addr != "" {
		_, s, _ := net.SplitHostPort(addr)
		if p, err := strconv.Atoi(s); err == nil {
			port = p
		}
	}
	if port == 0 {
		port = 8080
	}
	p.procMonitor = NewProcessMonitor(port)
	p.procMonitor.SetTCPFetcher(newTCPFetcher(port))
	p.procMonitor.SetPIDLister(getAllProcessPIDs)
	go p.procMonitor.Start()
}

func (p *ProxyServer) StopProcessMonitor() {
	if p.procMonitor != nil {
		p.procMonitor.Stop()
		p.procMonitor = nil
	}
}

func (p *ProxyServer) GetProcessMonitor() *ProcessMonitor {
	return p.procMonitor
}

func (p *ProxyServer) ClearCertCache() {
	p.certCacheMu.Lock()
	defer p.certCacheMu.Unlock()
	p.certCache = make(map[string]*tls.Certificate)
}

func (p *ProxyServer) trackAccepted(remote string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.recentIngress) >= 10 {
		p.recentIngress = p.recentIngress[1:]
	}
	p.recentIngress = append(p.recentIngress, remote)
}

func (p *ProxyServer) GetDiagnostics() (int64, int64, int64, []string) {
	return 0, 0, 0, nil
}

func NewRuleManager(settingsPath, rulesPath string) *RuleManager {
	return &RuleManager{
		settingsPath:        settingsPath,
		rulesPath:           rulesPath,
		rules:               []Rule{},
		closeToTray:         true,
		showMainOnAutoStart: true,
	}
}

func findECHProfileByID(profiles []ECHProfile, id string) *ECHProfile {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil
	}
	for i := range profiles {
		if profiles[i].ID == id {
			return &profiles[i]
		}
	}
	return nil
}

func normalizeECHProfile(p *ECHProfile) {
	if p == nil {
		return
	}
	p.ID = strings.TrimSpace(p.ID)
	p.Name = strings.TrimSpace(p.Name)
	p.Config = strings.TrimSpace(p.Config)
	p.DiscoveryDomain = strings.TrimSpace(p.DiscoveryDomain)
	p.DoHUpstream = strings.TrimSpace(p.DoHUpstream)
}

func ensureLegacyCloudflareProfile(profiles *[]ECHProfile) string {
	const profileID = "legacy-cloudflare"
	if existing := findECHProfileByID(*profiles, profileID); existing != nil {
		normalizeECHProfile(existing)
		if existing.Name == "" {
			existing.Name = "Legacy Cloudflare"
		}
		if existing.DiscoveryDomain == "" {
			existing.DiscoveryDomain = "crypto.cloudflare.com"
		}
		return existing.ID
	}

	*profiles = append(*profiles, ECHProfile{
		ID:              profileID,
		Name:            "Legacy Cloudflare",
		DiscoveryDomain: "crypto.cloudflare.com",
		AutoUpdate:      true,
	})
	return profileID
}

func migrateLegacyECHRules(siteGroups []SiteGroup, profiles *[]ECHProfile) bool {
	migrated := false
	for i := range siteGroups {
		siteGroups[i].ECHProfileID = strings.TrimSpace(siteGroups[i].ECHProfileID)
		siteGroups[i].ECHDomain = strings.TrimSpace(siteGroups[i].ECHDomain)
		if siteGroups[i].ECHEnabled && siteGroups[i].ECHProfileID == "" &&
			strings.EqualFold(siteGroups[i].ECHDomain, "crypto.cloudflare.com") {
			siteGroups[i].ECHProfileID = ensureLegacyCloudflareProfile(profiles)
			siteGroups[i].ECHDomain = ""
			migrated = true
		}
	}
	return migrated
}

func (rm *RuleManager) LoadConfig() error {
	if err := rm.loadSettingsConfig(); err != nil {
		return err
	}
	if err := rm.loadRulesConfig(); err != nil {
		return err
	}

	for i := range rm.siteGroups {
		rm.siteGroups[i].DNSMode = normalizeDNSMode(rm.siteGroups[i].DNSMode)
	}
	if rm.upstreams == nil {
		rm.upstreams = []Upstream{}
	}
	if rm.echProfiles == nil {
		rm.echProfiles = []ECHProfile{}
	}
	for i := range rm.echProfiles {
		normalizeECHProfile(&rm.echProfiles[i])
	}
	rm.applySettingsDefaults()

	// Sync Cloudflare Config if ProxyServer is linked
	// Note: In current architecture, RuleManager doesn't have a back-pointer to ProxyServer.
	// ProxyServer.SetRuleManager is used. We might need to update ProxyServer's pool elsewhere.
	// But actually, ProxyServer holds the pool, so when LoadConfig is called via the RuleManager
	// inside ProxyServer, it should be updated.
	// Wait, ProxyServer has a pointer to RuleManager.

	migrated := false
	for i := range rm.siteGroups {
		rm.siteGroups[i].Website = strings.TrimSpace(rm.siteGroups[i].Website)
		if rm.siteGroups[i].Website == "" {
			rm.siteGroups[i].Website = inferWebsiteFromSiteGroup(rm.siteGroups[i])
			migrated = true
		}
	}
	if migrateLegacyECHRules(rm.siteGroups, &rm.echProfiles) {
		migrated = true
	}

	rm.buildRules()
	if migrated {
		if err := rm.saveRulesConfig(); err != nil {
			log.Printf("[Config] migrate website field failed: %v", err)
		} else {
			log.Printf("[Config] migrated website field for existing site groups")
		}
	}
	return nil
}

func (rm *RuleManager) applySettingsDefaults() {
	if rm.listenPort == "" {
		rm.listenPort = "8080"
	}
	if rm.listenHost == "" {
		rm.listenHost = "127.0.0.1"
	}
	if rm.socksAddr == "" {
		rm.socksAddr = "127.0.0.1:1080"
	}
	if rm.socksHost == "" {
		rm.socksHost = "127.0.0.1"
	}
	if rm.socksPort == "" {
		rm.socksPort = "1080"
	}
	rm.tunConfig = normalizeTUNConfig(rm.tunConfig)
}

func normalizeTUNConfig(cfg TUNConfig) TUNConfig {
	if cfg.MTU <= 0 {
		cfg.MTU = 9000
	}
	if runtime.GOOS == "windows" {
		// Windows StrictRoute only protects the current process.
		// In a Wails app, WebView2 helper processes can be cut off immediately,
		// which looks like a flash-crash while the main process is still alive.
		cfg.StrictRoute = false
	}
	return cfg
}

func (rm *RuleManager) loadSettingsConfig() error {
	data, err := os.ReadFile(rm.settingsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return rm.saveDefaultSettingsConfig()
		}
		return err
	}

	var config SettingsConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}

	// 1. Set internal defaults first
	rm.closeToTray = true
	rm.autoStart = false
	rm.showMainOnAutoStart = true
	rm.autoEnableProxyOnAutoStart = false

	// 2. Override with JSON values if they exist
	rm.cloudflareConfig = config.CloudflareConfig
	rm.tunConfig = config.TUN
	rm.serverHost = config.ServerHost
	rm.serverAuth = config.ServerAuth
	if config.ListenPort != "" {
		rm.listenPort = config.ListenPort
	}
	if config.ListenHost != "" {
		rm.listenHost = config.ListenHost
	}
	if config.SocksAddr != "" {
		rm.socksAddr = config.SocksAddr
	}
	if config.SocksHost != "" {
		rm.socksHost = config.SocksHost
	}
	if config.SocksPort != "" {
		rm.socksPort = config.SocksPort
	}
	// Backward compat: if SocksAddr is set but SocksHost/Port aren't, parse them
	if config.SocksAddr != "" && config.SocksHost == "" && config.SocksPort == "" {
		if h, p, err := net.SplitHostPort(config.SocksAddr); err == nil {
			rm.socksHost = h
			rm.socksPort = p
		}
	}
	rm.autoRoutingConfig = config.AutoRouting
	rm.language = config.Language
	rm.theme = config.Theme
	rm.country = config.Country

	if config.CloseToTray != nil {
		rm.closeToTray = *config.CloseToTray
	}
	if config.AutoStart != nil {
		rm.autoStart = *config.AutoStart
	}
	if config.ShowMainWindowOnAutoStart != nil {
		rm.showMainOnAutoStart = *config.ShowMainWindowOnAutoStart
	}
	if config.AutoEnableProxyOnAutoStart != nil {
		rm.autoEnableProxyOnAutoStart = *config.AutoEnableProxyOnAutoStart
	}
	rm.applySettingsDefaults()
	return nil
}

func (rm *RuleManager) loadRulesConfig() error {
	data, err := os.ReadFile(rm.rulesPath)
	if err != nil {
		if os.IsNotExist(err) {
			return rm.saveDefaultRulesConfig()
		}
		return err
	}

	var config RulesConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}

	rm.siteGroups = config.SiteGroups
	rm.upstreams = config.Upstreams
	rm.dnsNodes = config.DNSNodes
	rm.echProfiles = config.ECHProfiles
	// Ensure at least the default Ali DoH bootstrap node exists
	if len(rm.dnsNodes) == 0 {
		rm.dnsNodes = defaultDNSNodes()
	}
	return nil
}

func (rm *RuleManager) saveDefaultSettingsConfig() error {
	rm.closeToTray = true
	rm.autoStart = false
	rm.showMainOnAutoStart = true
	rm.autoEnableProxyOnAutoStart = false
	rm.applySettingsDefaults()
	return rm.saveSettingsConfig()
}

func (rm *RuleManager) saveDefaultRulesConfig() error {
	rm.siteGroups = []SiteGroup{
		{
			ID:       "google-youtube-full",
			Name:     "کامل گوگل و یوتیوب",
			Website:  "google",
			Domains:  defaultGoogleDomains(),
			Mode:     "mitm",
			Upstream: "216.239.38.120:443",
			SniFake:  "www.google.com",
			Enabled:  true,
			CertVerify: CertVerifyConfig{
				Mode: "allow_names",
				Names: []string{
					"*.google.com", "*.youtube.com", "*.googlevideo.com",
					"*.googleapis.com", "*.ytimg.com", "*.ggpht.com",
					"*.gstatic.com", "*.googleusercontent.com", "*.googleadservices.com",
					"*.googlesyndication.com", "*.doubleclick.net", "*.blogger.com",
					"*.blogspot.com", "*.youtu.be", "*.gmail.com",
					"*.android.com", "*.firebase.com", "*.cloud.google.com",
					"*.appspot.com", "*.flutter.dev", "*.dartlang.org",
					"*.golang.org", "*.googlesource.com", "*.1e100.net",
				},
			},
		},
		{
			ID:      "google-direct-rules",
			Name:    "Google Direct Access",
			Website: "google-direct",
			Domains: []string{
				"gemini.google.com", "aistudio.google.com", "notebooklm.google.com",
				"labs.google.com", "meet.google.com", "accounts.google.com",
				"ogs.google.com", "mail.google.com", "calendar.google.com",
				"drive.google.com", "docs.google.com", "chat.google.com",
				"photos.google.com", "maps.google.com", "myaccount.google.com",
				"contacts.google.com", "classroom.google.com", "keep.google.com",
				"play.google.com", "translate.google.com", "assistant.google.com",
				"lens.google.com",
			},
			Mode:     "direct",
			Upstream: "direct",
			SniFake:  "",
			Enabled:  true,
		},
		{
			ID:      "sni-rewrite-domains",
			Name:    "SNI Rewrite Domains",
			Website: "sni-rewrite",
			Domains: []string{
				"*.youtube.com", "*.youtu.be", "*.youtube-nocookie.com",
				"*.ytimg.com", "*.ggpht.com", "*.gvt1.com", "*.gvt2.com",
				"*.doubleclick.net", "*.googlesyndication.com", "*.googleadservices.com",
				"*.google-analytics.com", "*.googletagmanager.com", "*.googletagservices.com",
				"fonts.googleapis.com", "script.google.com",
			},
			Mode:     "mitm",
			Upstream: "216.239.38.120:443",
			SniFake:  "www.google.com",
			Enabled:  true,
		},
	}
	rm.upstreams = []Upstream{}
	rm.dnsNodes = defaultDNSNodes()
	rm.echProfiles = []ECHProfile{}
	rm.buildRules()
	return rm.saveRulesConfig()
}

func defaultDNSNodes() []DNSNode {
	return []DNSNode{}
}

func defaultGoogleDomains() []string {
	return []string{
		"*.google.com", "*.googleapis.com", "*.googlevideo.com",
		"*.youtube.com", "*.ytimg.com", "*.ggpht.com",
		"*.googleusercontent.com", "*.gstatic.com", "*.yt3.ggpht.com",
		"*.googleadservices.com", "*.googlesyndication.com", "*.google-analytics.com",
		"*.doubleclick.net", "*.blogger.com", "*.blogspot.com",
		"*.googleblog.com", "*.youtu.be", "*.gmail.com",
		"*.googlemail.com", "*.withgoogle.com", "*.goo.gl",
		"*.app.goo.gl", "*.chrome.com", "*.chromium.org",
		"*.g.co", "*.android.com", "*.androidify.com",
		"*.waymo.com", "*.nest.com", "*.fitbit.com",
		"*.wearos.com", "*.adsense.com", "*.admob.com",
		"*.firebase.com", "*.firebaseio.com", "*.firebaseapp.com",
		"*.cloud.google.com", "*.appspot.com", "*.googleapi.com",
		"*.googleapiclient.com", "*.googlecode.com", "*.flutter.dev",
		"*.dartlang.org", "*.golang.org", "*.googlesource.com",
		"*.googlehosted.com", "*.googlezip.net", "*.googlecommerce.com",
		"*.googletagmanager.com", "*.googleoptimize.com", "*.googleweblight.com",
		"*.googlelabs.com", "*.google.info", "*.google.net",
		"*.google.org", "*.google.eu", "*.1e100.net",
		"*.withyoutube.com", "*.youtubekids.com", "*.youtubeeducation.com",
		"*.googletraveladservices.com", "*.googlegroups.com", "*.googlechat.com",
		"*.googleplus.com", "*.googlehangouts.com", "*.googleplay.com",
		"*.googledrive.com", "*.googlephotos.com", "*.googlecalendar.com",
		"*.googlekeep.com", "*.googlepodcasts.com", "*.googlebooks.com",
		"*.googlenews.com", "*.googlefinance.com", "*.googletranslate.com",
		"*.googlemaps.com", "*.googleearth.com", "*.googleclassroom.com",
		"*.googlemeet.com", "*.googleforms.com", "*.googleslides.com",
		"*.googlesites.com", "*.googledocs.com", "*.googlesheets.com",
		"*.googleads.google.com", "*.googlehosted.com", "*.googlezip.net",
		"*.googlecommerce.com", "*.googletagmanager.com", "*.googleoptimize.com",
		"*.googleweblight.com", "*.googlelabs.com", "*.google.info",
		"*.google.net", "*.google.org", "*.google.eu",
		"*.google.us", "*.google.co", "*.google.ac",
		"*.google.ad", "*.google.ae", "*.google.af",
		"*.google.ag", "*.google.ai", "*.google.al",
		"*.google.am", "*.google.ao", "*.google.ar",
		"*.google.as", "*.google.at", "*.google.au",
		"*.google.az", "*.google.ba", "*.google.bd",
		"*.google.be", "*.google.bf", "*.google.bg",
		"*.google.bh", "*.google.bi", "*.google.bj",
		"*.google.bn", "*.google.bo", "*.google.br",
		"*.google.bs", "*.google.bt", "*.google.bw",
		"*.google.by", "*.google.bz", "*.google.ca",
		"*.google.cc", "*.google.cd", "*.google.cf",
		"*.google.cg", "*.google.ch", "*.google.ci",
		"*.google.cl", "*.google.cm", "*.google.cn",
		"*.google.co.ao", "*.google.co.bw", "*.google.co.ck",
		"*.google.co.cr", "*.google.co.id", "*.google.co.il",
		"*.google.co.in", "*.google.co.jp", "*.google.co.ke",
		"*.google.co.kr", "*.google.co.ls", "*.google.co.ma",
		"*.google.co.nz", "*.google.co.th", "*.google.co.tz",
		"*.google.co.ug", "*.google.co.uk", "*.google.co.uz",
		"*.google.co.ve", "*.google.co.vi", "*.google.co.za",
		"*.google.co.zm", "*.google.co.zw", "*.google.com.af",
		"*.google.com.ag", "*.google.com.ai", "*.google.com.ar",
		"*.google.com.au", "*.google.com.bd", "*.google.com.bh",
		"*.google.com.bn", "*.google.com.bo", "*.google.com.br",
		"*.google.com.by", "*.google.com.bz", "*.google.com.cn",
		"*.google.com.co", "*.google.com.cu", "*.google.com.cy",
		"*.google.com.do", "*.google.com.ec", "*.google.com.eg",
		"*.google.com.et", "*.google.com.fj", "*.google.com.gh",
		"*.google.com.gi", "*.google.com.gt", "*.google.com.hk",
		"*.google.com.jm", "*.google.com.jo", "*.google.com.kh",
		"*.google.com.kw", "*.google.com.lb", "*.google.com.lc",
		"*.google.com.ly", "*.google.com.mt", "*.google.com.mx",
		"*.google.com.my", "*.google.com.na", "*.google.com.nf",
		"*.google.com.ng", "*.google.com.ni", "*.google.com.np",
		"*.google.com.nr", "*.google.com.om", "*.google.com.pa",
		"*.google.com.pe", "*.google.com.ph", "*.google.com.pk",
		"*.google.com.pl", "*.google.com.pr", "*.google.com.py",
		"*.google.com.qa", "*.google.com.ru", "*.google.com.sa",
		"*.google.com.sb", "*.google.com.sg", "*.google.com.sl",
		"*.google.com.sv", "*.google.com.tj", "*.google.com.tr",
		"*.google.com.tw", "*.google.com.ua", "*.google.com.uy",
		"*.google.com.vc", "*.google.com.ve", "*.google.com.vn",
		"*.google.cv", "*.google.cz", "*.google.de",
		"*.google.dj", "*.google.dk", "*.google.dm",
		"*.google.dz", "*.google.ee", "*.google.es",
		"*.google.fi", "*.google.fm", "*.google.fr",
		"*.google.ga", "*.google.ge", "*.google.gf",
		"*.google.gg", "*.google.gl", "*.google.gn",
		"*.google.gp", "*.google.gr", "*.google.gy",
		"*.google.hn", "*.google.hr", "*.google.ht",
		"*.google.hu", "*.google.ie", "*.google.im",
		"*.google.io", "*.google.iq", "*.google.is",
		"*.google.it", "*.google.je", "*.google.jo",
		"*.google.jobs", "*.google.jp", "*.google.kg",
		"*.google.ki", "*.google.kz", "*.google.la",
		"*.google.li", "*.google.lk", "*.google.lt",
		"*.google.lu", "*.google.lv", "*.google.md",
		"*.google.me", "*.google.mg", "*.google.mk",
		"*.google.ml", "*.google.mn", "*.google.ms",
		"*.google.mu", "*.google.mv", "*.google.mw",
		"*.google.ne", "*.google.nf", "*.google.nl",
		"*.google.no", "*.google.nr", "*.google.nu",
		"*.google.off.ai", "*.google.pk", "*.google.pl",
		"*.google.pn", "*.google.ps", "*.google.pt",
		"*.google.ro", "*.google.rs", "*.google.ru",
		"*.google.rw", "*.google.sc", "*.google.se",
		"*.google.sh", "*.google.si", "*.google.sk",
		"*.google.sm", "*.google.sn", "*.google.so",
		"*.google.st", "*.google.td", "*.google.tg",
		"*.google.tk", "*.google.tl", "*.google.tm",
		"*.google.tn", "*.google.to", "*.google.tt",
		"*.google.us", "*.google.uz", "*.google.vg",
		"*.google.vu", "*.google.ws", "*.google.cat",
		"google.com", "youtube.com", "googleblog.com",
		"blogger.com", "blogspot.com", "youtu.be",
		"gmail.com", "googlemail.com", "ggpht.com",
		"googlevideo.com", "ytimg.com", "googleusercontent.com",
		"googleapis.com", "gstatic.com", "yt3.ggpht.com",
		"googleadservices.com", "googlesyndication.com", "google-analytics.com",
		"doubleclick.net", "withgoogle.com", "goo.gl",
		"app.goo.gl", "chrome.com", "chromium.org",
		"g.co", "android.com", "androidify.com",
		"waymo.com", "nest.com", "fitbit.com",
		"wearos.com", "adsense.com", "admob.com",
		"firebase.com", "firebaseio.com", "firebaseapp.com",
		"cloud.google.com", "appspot.com", "googleapi.com",
		"googleapiclient.com", "googlecode.com", "flutter.dev",
		"dartlang.org", "golang.org", "googlesource.com",
		"googlehosted.com", "googlezip.net", "googlecommerce.com",
		"googletagmanager.com", "googleoptimize.com", "googleweblight.com",
		"googlelabs.com", "google.info", "google.net",
		"google.org", "google.eu",
	}
}

func (rm *RuleManager) buildRules() {
	rm.rules = []Rule{}
	upstreamMap := make(map[string]string)
	for _, up := range rm.upstreams {
		if up.Enabled && up.Address != "" {
			upstreamMap[up.ID] = up.Address
		}
	}

	echProfileMap := make(map[string]ECHProfile)
	for _, profile := range rm.echProfiles {
		echProfileMap[profile.ID] = profile
	}

	for _, sg := range rm.siteGroups {
		if !sg.Enabled {
			continue
		}

		// Resolve upstream ID to actual address
		resolvedUpstream := sg.Upstream
		if addr, ok := upstreamMap[sg.Upstream]; ok {
			resolvedUpstream = addr
		}

		resolvedUpstreams := make([]string, 0, len(sg.Upstreams))
		for _, upId := range sg.Upstreams {
			if addr, ok := upstreamMap[upId]; ok {
				resolvedUpstreams = append(resolvedUpstreams, addr)
			} else {
				resolvedUpstreams = append(resolvedUpstreams, upId)
			}
		}

		var echConfigBytes []byte
		var echProfile ECHProfile
		if sg.ECHProfileID != "" {
			if profile, ok := echProfileMap[sg.ECHProfileID]; ok {
				echProfile = profile
				if configStr := strings.TrimSpace(profile.Config); configStr != "" {
					if decoded, err := base64.StdEncoding.DecodeString(configStr); err == nil {
						echConfigBytes = decoded
						log.Printf("[BuildRules] Successfully loaded ECH Config for SiteGroup %s (%d bytes)", sg.ID, len(echConfigBytes))
					} else {
						log.Printf("[BuildRules] ERROR: Failed to decode ECH Config for SiteGroup %s: %v", sg.ID, err)
					}
				}
			} else {
				log.Printf("[BuildRules] WARNING: ECHProfileID %s linked to SiteGroup %s but profile not found", sg.ECHProfileID, sg.ID)
			}
		}

		for _, domain := range sg.Domains {
			rule := Rule{
				Domain:             domain,
				Mode:               sg.Mode,
				Upstream:           resolvedUpstream,
				Upstreams:          resolvedUpstreams,
				DNSMode:            normalizeDNSMode(sg.DNSMode),
				SniFake:            sg.SniFake,
				ConnectPolicy:      strings.TrimSpace(sg.ConnectPolicy),
				SniPolicy:          strings.TrimSpace(sg.SniPolicy),
				Enabled:            true,
				SiteID:             sg.ID,
				ECHEnabled:         sg.ECHEnabled,
				ECHProfileID:       sg.ECHProfileID,
				UseCFPool:          sg.UseCFPool,
				ECHDiscoveryDomain: echProfile.DiscoveryDomain,
				ECHDoHUpstream:     echProfile.DoHUpstream,
				ECHAutoUpdate:      echProfile.AutoUpdate,
				CertVerify:         sg.CertVerify,
			}
			rm.rules = append(rm.rules, rule)
		}
	}
}

func (rm *RuleManager) incrementRuleHit(siteID string) {
	// No-op after stats removal
}

func (rm *RuleManager) GetRuleHitCounts() map[string]int64 {
	return map[string]int64{}
}

func (rm *RuleManager) GetSiteGroups() []SiteGroup {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.siteGroups
}

func (rm *RuleManager) GetServerHost() string {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.serverHost
}

func (rm *RuleManager) GetServerAuth() string {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.serverAuth
}

func (rm *RuleManager) GetListenPort() string {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.listenPort
}

func (rm *RuleManager) SetListenPort(port string) {
	rm.mu.Lock()
	rm.listenPort = port
	rm.mu.Unlock()
}

func (rm *RuleManager) GetListenHost() string {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.listenHost
}

func (rm *RuleManager) SetListenHost(host string) {
	rm.mu.Lock()
	rm.listenHost = host
	rm.mu.Unlock()
}

func (rm *RuleManager) GetSocksAddr() string {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.socksAddr
}

func (rm *RuleManager) SetSocksAddr(addr string) {
	rm.mu.Lock()
	rm.socksAddr = addr
	if h, p, err := net.SplitHostPort(addr); err == nil {
		rm.socksHost = h
		rm.socksPort = p
	}
	rm.mu.Unlock()
}

func (rm *RuleManager) GetSocksHost() string {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.socksHost
}

func (rm *RuleManager) SetSocksHost(host string) {
	rm.mu.Lock()
	rm.socksHost = host
	rm.mu.Unlock()
}

func (rm *RuleManager) GetSocksPort() string {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.socksPort
}

func (rm *RuleManager) SetSocksPort(port string) {
	rm.mu.Lock()
	rm.socksPort = port
	rm.mu.Unlock()
}

func (rm *RuleManager) SaveConfig() error {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	if err := rm.saveSettingsConfig(); err != nil {
		return err
	}
	return rm.saveRulesConfig()
}

func (rm *RuleManager) UpdateServerConfig(host, auth string) error {
	rm.mu.Lock()
	rm.serverHost = host
	rm.serverAuth = auth
	rm.mu.Unlock()
	return rm.saveSettingsConfig()
}

func (rm *RuleManager) GetCloudflareConfig() CloudflareConfig {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.cloudflareConfig
}

func (rm *RuleManager) GetTUNConfig() TUNConfig {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return normalizeTUNConfig(rm.tunConfig)
}

func (rm *RuleManager) GetCloseToTray() bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.closeToTray
}

func (rm *RuleManager) SetCloseToTray(enabled bool) error {
	rm.mu.Lock()
	rm.closeToTray = enabled
	rm.mu.Unlock()
	return rm.saveSettingsConfig()
}

func (rm *RuleManager) GetAutoStart() bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.autoStart
}

func (rm *RuleManager) SetAutoStart(enabled bool) error {
	rm.mu.Lock()
	rm.autoStart = enabled
	rm.mu.Unlock()
	return rm.saveSettingsConfig()
}

func (rm *RuleManager) GetShowMainWindowOnAutoStart() bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.showMainOnAutoStart
}

func (rm *RuleManager) SetShowMainWindowOnAutoStart(enabled bool) error {
	rm.mu.Lock()
	rm.showMainOnAutoStart = enabled
	rm.mu.Unlock()
	return rm.saveSettingsConfig()
}

func (rm *RuleManager) GetAutoEnableProxyOnAutoStart() bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.autoEnableProxyOnAutoStart
}

func (rm *RuleManager) SetAutoEnableProxyOnAutoStart(enabled bool) error {
	rm.mu.Lock()
	rm.autoEnableProxyOnAutoStart = enabled
	rm.mu.Unlock()
	return rm.saveSettingsConfig()
}

func (r *RuleManager) GetLanguage() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.language
}

func (r *RuleManager) SetLanguage(lang string) error {
	r.mu.Lock()
	r.language = lang
	r.mu.Unlock()
	return r.saveSettingsConfig()
}

func (r *RuleManager) GetTheme() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.theme == "" {
		return "light" // Default to light
	}
	return r.theme
}

func (r *RuleManager) SetTheme(theme string) error {
	r.mu.Lock()
	r.theme = theme
	r.mu.Unlock()
	return r.saveSettingsConfig()
}

func (r *RuleManager) GetCountry() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.country == "" {
		return "iran" // Default to Iran
	}
	return r.country
}

func (r *RuleManager) SetCountry(country string) error {
	r.mu.Lock()
	r.country = country
	r.mu.Unlock()
	return r.saveSettingsConfig()
}

func (rm *RuleManager) UpdateCloudflareConfig(cfg CloudflareConfig) error {
	rm.mu.Lock()
	rm.cloudflareConfig = cfg
	rm.mu.Unlock()
	return rm.saveSettingsConfig()
}

func (rm *RuleManager) UpdateTUNConfig(cfg TUNConfig) error {
	rm.mu.Lock()
	rm.tunConfig = normalizeTUNConfig(cfg)
	rm.mu.Unlock()
	return rm.saveSettingsConfig()
}

func (rm *RuleManager) AddSiteGroup(sg SiteGroup) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	sg.ID = generateID()
	sg.Website = strings.TrimSpace(sg.Website)
	rm.siteGroups = append(rm.siteGroups, sg)
	rm.buildRules()
	return rm.saveRulesConfig()
}

func (rm *RuleManager) UpdateSiteGroup(sg SiteGroup) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	sg.Website = strings.TrimSpace(sg.Website)
	for i, s := range rm.siteGroups {
		if s.ID == sg.ID {
			rm.siteGroups[i] = sg
			break
		}
	}
	rm.buildRules()
	return rm.saveRulesConfig()
}

func (rm *RuleManager) DeleteSiteGroup(id string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	for i, s := range rm.siteGroups {
		if s.ID == id {
			rm.siteGroups = append(rm.siteGroups[:i], rm.siteGroups[i+1:]...)
			break
		}
	}
	rm.buildRules()
	return rm.saveRulesConfig()
}

func (rm *RuleManager) GetUpstreams() []Upstream {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.upstreams
}

func (rm *RuleManager) AddUpstream(u Upstream) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	u.ID = generateID()
	rm.upstreams = append(rm.upstreams, u)
	return rm.saveRulesConfig()
}

func (rm *RuleManager) UpdateUpstream(u Upstream) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	for i, up := range rm.upstreams {
		if up.ID == u.ID {
			rm.upstreams[i] = u
			break
		}
	}
	return rm.saveRulesConfig()
}

func (rm *RuleManager) DeleteUpstream(id string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	for i, up := range rm.upstreams {
		if up.ID == id {
			rm.upstreams = append(rm.upstreams[:i], rm.upstreams[i+1:]...)
			break
		}
	}
	return rm.saveRulesConfig()
}

// --- DNS Node CRUD ---

func (rm *RuleManager) GetDNSNodes() []DNSNode {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	if rm.dnsNodes == nil {
		return []DNSNode{}
	}
	out := make([]DNSNode, len(rm.dnsNodes))
	copy(out, rm.dnsNodes)
	return out
}

func (rm *RuleManager) AddDNSNode(n DNSNode) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	n.ID = generateID()
	rm.dnsNodes = append(rm.dnsNodes, n)
	return rm.saveRulesConfig()
}

func (rm *RuleManager) UpdateDNSNode(n DNSNode) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	for i, node := range rm.dnsNodes {
		if node.ID == n.ID {
			rm.dnsNodes[i] = n
			break
		}
	}
	return rm.saveRulesConfig()
}

func (rm *RuleManager) DeleteDNSNode(id string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	for i, node := range rm.dnsNodes {
		if node.ID == id {
			rm.dnsNodes = append(rm.dnsNodes[:i], rm.dnsNodes[i+1:]...)
			break
		}
	}
	return rm.saveRulesConfig()
}

// SetDNSNodePriority reorders DNS nodes by moving the node with the given ID
// to the specified target index (0-based). Nodes are queried in list order.
func (rm *RuleManager) SetDNSNodePriority(id string, targetIndex int) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	srcIdx := -1
	for i, node := range rm.dnsNodes {
		if node.ID == id {
			srcIdx = i
			break
		}
	}
	if srcIdx < 0 {
		return fmt.Errorf("dns node %s not found", id)
	}
	if targetIndex < 0 {
		targetIndex = 0
	}
	if targetIndex >= len(rm.dnsNodes) {
		targetIndex = len(rm.dnsNodes) - 1
	}
	if srcIdx == targetIndex {
		return nil
	}

	node := rm.dnsNodes[srcIdx]
	rm.dnsNodes = append(rm.dnsNodes[:srcIdx], rm.dnsNodes[srcIdx+1:]...)
	tail := append([]DNSNode{}, rm.dnsNodes[targetIndex:]...)
	rm.dnsNodes = append(rm.dnsNodes[:targetIndex], node)
	rm.dnsNodes = append(rm.dnsNodes, tail...)
	return rm.saveRulesConfig()
}

func (rm *RuleManager) saveSettingsConfig() error {
	listenPort := rm.listenPort
	if listenPort == "" {
		listenPort = "8080"
	}
	listenHost := rm.listenHost
	if listenHost == "" {
		listenHost = "127.0.0.1"
	}
	socksAddr := rm.socksAddr
	if socksAddr == "" {
		socksAddr = "127.0.0.1:1080"
	}
	socksHost := rm.socksHost
	if socksHost == "" {
		socksHost = "127.0.0.1"
	}
	socksPort := rm.socksPort
	if socksPort == "" {
		socksPort = "1080"
	}
	closeToTray := rm.closeToTray
	autoStart := rm.autoStart
	showMainOnAutoStart := rm.showMainOnAutoStart
	autoEnableProxyOnAutoStart := rm.autoEnableProxyOnAutoStart
	cloudflareConfig := rm.cloudflareConfig
	tunConfig := normalizeTUNConfig(rm.tunConfig)
	settings := SettingsConfig{
		ListenPort:                 listenPort,
		ListenHost:                 listenHost,
		SocksAddr:                  socksAddr,
		SocksHost:                  socksHost,
		SocksPort:                  socksPort,
		ServerHost:                 rm.serverHost,
		ServerAuth:                 rm.serverAuth,
		CloseToTray:                &closeToTray,
		AutoStart:                  &autoStart,
		ShowMainWindowOnAutoStart:  &showMainOnAutoStart,
		AutoEnableProxyOnAutoStart: &autoEnableProxyOnAutoStart,
		CloudflareConfig:           cloudflareConfig,
		AutoRouting:                rm.autoRoutingConfig,
		TUN:                        tunConfig,
		Language:                   rm.language,
		Theme:                      rm.theme,
		Country:                    rm.country,
	}

	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(rm.settingsPath), 0755); err != nil {
		return err
	}

	if err := os.WriteFile(rm.settingsPath, data, 0644); err != nil {
		return err
	}
	rm.triggerConfigSaved()
	return nil
}

func (rm *RuleManager) saveRulesConfig() error {
	config := RulesConfig{
		SiteGroups:  rm.siteGroups,
		Upstreams:   rm.upstreams,
		DNSNodes:    rm.dnsNodes,
		ECHProfiles: rm.echProfiles,
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(rm.rulesPath), 0755); err != nil {
		return err
	}

	if err := os.WriteFile(rm.rulesPath, data, 0644); err != nil {
		return err
	}
	rm.triggerConfigSaved()
	return nil
}

func (rm *RuleManager) GetECHProfiles() []ECHProfile {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	if rm.echProfiles == nil {
		return []ECHProfile{}
	}
	return rm.echProfiles
}

func (rm *RuleManager) UpsertECHProfile(p ECHProfile) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	normalizeECHProfile(&p)
	if p.ID == "" {
		p.ID = generateID()
		rm.echProfiles = append(rm.echProfiles, p)
	} else {
		found := false
		for i, x := range rm.echProfiles {
			if x.ID == p.ID {
				rm.echProfiles[i] = p
				found = true
				break
			}
		}
		if !found {
			rm.echProfiles = append(rm.echProfiles, p)
		}
	}
	return rm.saveRulesConfig()
}

func (rm *RuleManager) DeleteECHProfile(id string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	for i, x := range rm.echProfiles {
		if x.ID == id {
			rm.echProfiles = append(rm.echProfiles[:i], rm.echProfiles[i+1:]...)
			break
		}
	}
	return rm.saveRulesConfig()
}

func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func (r *RuleManager) GetBinaryECHConfig(id string) []byte {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, p := range r.echProfiles {
		if p.ID == id {
			data, err := base64.StdEncoding.DecodeString(p.Config)
			if err == nil && len(data) > 0 {
				return data
			}
			break
		}
	}
	return nil
}

func (r *RuleManager) UpdateECHProfileConfig(profileID string, configBytes []byte) error {
	if profileID == "" || len(configBytes) == 0 {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	found := false
	configBase64 := base64.StdEncoding.EncodeToString(configBytes)
	for i := range r.echProfiles {
		if r.echProfiles[i].ID == profileID {
			if r.echProfiles[i].Config == configBase64 {
				return nil // No change
			}
			r.echProfiles[i].Config = configBase64
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("profile %s not found", profileID)
	}

	log.Printf("[RuleManager] ECH Profile %s updated via sync", profileID)
	return r.saveRulesConfig()
}

func chooseUTLSClientHelloID(alpn string) utls.ClientHelloID {
	if strings.EqualFold(strings.TrimSpace(alpn), "http/1.1") {
		return utls.HelloFirefox_120
	}
	return utls.HelloChrome_120
}

// nextProtosForNegotiatedALPN returns the ALPN protocols to advertise to the client,
// matching whatever the upstream negotiated. Both sides speaking the same protocol
// is safe for directTunnel because the uTLS handshake does not pre-send h2 preface.
func nextProtosForNegotiatedALPN(alpn string) []string {
	if strings.EqualFold(strings.TrimSpace(alpn), "h2") {
		return []string{"h2"}
	}
	return []string{"http/1.1"}
}

func rewriteUTLSALPN(spec *utls.ClientHelloSpec, nextProtos []string) {
	if spec == nil {
		return
	}
	for _, ext := range spec.Extensions {
		if alpnExt, ok := ext.(*utls.ALPNExtension); ok {
			alpnExt.AlpnProtocols = append([]string(nil), nextProtos...)
			return
		}
	}
	spec.Extensions = append(spec.Extensions, &utls.ALPNExtension{
		AlpnProtocols: append([]string(nil), nextProtos...),
	})
}

func (p *ProxyServer) GetUConn(conn net.Conn, sni string, verifyName string, rule Rule, allowInsecure bool, alpn string, echConfig []byte) *utls.UConn {
	nextProtos := []string{"h2", "http/1.1"}
	if strings.EqualFold(strings.TrimSpace(alpn), "http/1.1") {
		nextProtos = []string{"http/1.1"}
	}

	verifyConn := buildVerifyConnection(verifyName, rule.CertVerify)

	serverName := sni
	if serverName == "" {
		serverName = verifyName
	}

	skipVerify := allowInsecure
	if rule.CertVerify.Mode != "" {
		skipVerify = true
	}

	// Manual bypass check
	if _, ok := p.certBypassMap.Load(normalizeHost(verifyName)); ok {
		skipVerify = true
		verifyConn = nil
	}

	// ECH mode verification:
	// uTLS verifyServerCertificate has two branches:
	//   echRejected=true  → outer cert (e.g. cloudflare-ech.com) is verified
	//   echRejected=false → inner cert (e.g. cloudflare.com) is verified
	//
	// In both cases we set InsecureServerNameToVerify = "*" which tells uTLS
	// to verify the CA trust chain but skip DNSName matching.
	// This is correct because:
	//   - The outer public_name is embedded in the ECH config (unknown to us)
	//   - The inner name is authenticated by the ECH crypto binding itself
	//   - We still want a valid CA chain to prevent MITM with rogue certs
	if len(echConfig) > 0 {
		skipVerify = false
		verifyConn = nil
	}

	config := &utls.Config{
		ServerName:                     serverName,
		InsecureSkipVerify:             skipVerify,
		EncryptedClientHelloConfigList: echConfig,
		NextProtos:                     nextProtos,
		VerifyConnection:               verifyConn,
	}

	if len(echConfig) > 0 {
		config.InsecureServerNameToVerify = "*"
	}

	clientHelloID := chooseUTLSClientHelloID(alpn)
	uconn := utls.UClient(conn, config, utls.HelloCustom)
	if spec, err := utls.UTLSIdToSpec(clientHelloID); err == nil {
		rewriteUTLSALPN(&spec, nextProtos)
		if err := uconn.ApplyPreset(&spec); err == nil {
			return uconn
		}
	}
	uconn = utls.UClient(conn, config, clientHelloID)
	return uconn
}

func (p *ProxyServer) resolveRuleECHConfig(host string, rule Rule) []byte {
	if !rule.ECHEnabled {
		return nil
	}

	// 1. Load manually selected global Profile
	if rule.ECHProfileID != "" {
		data := p.rules.GetBinaryECHConfig(rule.ECHProfileID)
		if len(data) > 0 {
			log.Printf("[Upstream] Using manual ECH profile %s for %s", rule.ECHProfileID, host)
			return data
		}
	}

	// 2. Auto-update logic
	if rule.ECHAutoUpdate {
		lookupDomain := strings.TrimSpace(rule.ECHDiscoveryDomain)
		if lookupDomain == "" {
			lookupDomain = host
		}

		echCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		echConfig, err := p.FetchECH(echCtx, lookupDomain, strings.TrimSpace(rule.ECHDoHUpstream))
		if err == nil && len(echConfig) > 0 {
			log.Printf("[Upstream] Initial ECH fetch success for %s, syncing to profile %s", host, rule.ECHProfileID)
			if rule.ECHProfileID != "" {
				p.UpdateECHProfileConfig(rule.ECHProfileID, echConfig)
			}
			return echConfig
		}
	}

	return nil
}

func (p *ProxyServer) newQUICRoundTripper(host string, rule Rule) (*http3.Transport, error) {
	targetAddr := net.JoinHostPort(host, "443")
	dialCandidates := p.buildDialCandidates(context.Background(), host, targetAddr, rule, "quic")
	if len(dialCandidates) == 0 {
		dialCandidates = []string{targetAddr}
	}

	sniHost := chooseUpstreamSNI(host, rule)
	if sniHost == "" {
		sniHost = host
	}

	// Resolve ECH configuration
	var echConfig []byte
	if rule.ECHEnabled {
		echConfig = p.resolveRuleECHConfig(host, rule)
	}

	// In ECH mode, ServerName must be the inner (real) target domain.
	// The outer SNI is automatically derived from the ECH config's public name.
	// In non-ECH mode, ServerName uses the chosen upstream SNI (which may be fake).
	innerSNI := host
	if len(echConfig) == 0 {
		innerSNI = sniHost
	}

	verifyConn := buildVerifyConnection(host, rule.CertVerify)
	tlsConfig := &tls.Config{
		ServerName:         innerSNI,
		NextProtos:         []string{"h3", "h3-29", "h3-32"},
		InsecureSkipVerify: true,
	}

	// Enable ECH if configuration is available
	if len(echConfig) > 0 {
		tlsConfig.EncryptedClientHelloConfigList = echConfig
		tlsConfig.InsecureSkipVerify = false
		log.Printf("[QUIC] ECH enabled host=%s innerSNI=%s echLen=%d", host, innerSNI, len(echConfig))
	}

	if verifyConn != nil && len(echConfig) == 0 {
		tlsConfig.VerifyConnection = func(cs tls.ConnectionState) error {
			peer := make([]*x509.Certificate, len(cs.PeerCertificates))
			copy(peer, cs.PeerCertificates)
			return verifyConn(utls.ConnectionState{
				Version:                     cs.Version,
				HandshakeComplete:           cs.HandshakeComplete,
				DidResume:                   cs.DidResume,
				CipherSuite:                 cs.CipherSuite,
				NegotiatedProtocol:          cs.NegotiatedProtocol,
				NegotiatedProtocolIsMutual:  cs.NegotiatedProtocolIsMutual,
				ServerName:                  cs.ServerName,
				PeerCertificates:            peer,
				VerifiedChains:              cs.VerifiedChains,
				SignedCertificateTimestamps: cs.SignedCertificateTimestamps,
				OCSPResponse:                cs.OCSPResponse,
				TLSUnique:                   cs.TLSUnique,
				ECHAccepted:                 cs.ECHAccepted,
			})
		}
	}

	return &http3.Transport{
		TLSClientConfig: tlsConfig,
		QUICConfig: &quic.Config{
			HandshakeIdleTimeout: 10 * time.Second,
		},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			var errs []string
			for _, candidate := range dialCandidates {
				conn, err := quic.DialAddr(ctx, candidate, tlsCfg, cfg)
				if err == nil {
					cs := conn.ConnectionState().TLS
					log.Printf("[QUIC] H3 dial success host=%s addr=%s sni=%s alpn=%s echAccepted=%v", host, candidate, tlsCfg.ServerName, cs.NegotiatedProtocol, cs.ECHAccepted)
					return conn, nil
				}
				errs = append(errs, fmt.Sprintf("%s: %v", candidate, err))
				log.Printf("[QUIC] H3 dial failed host=%s addr=%s err=%v", host, candidate, err)
			}
			if len(errs) == 0 {
				return nil, fmt.Errorf("no QUIC dial candidates for %s", host)
			}
			return nil, fmt.Errorf("all QUIC dial candidates failed for %s: %s", host, strings.Join(errs, "; "))
		},
	}, nil
}

func (p *ProxyServer) handleQUICMITM(clientConn net.Conn, host string, rule Rule) {
	defer clientConn.Close()
	log.Printf("[QUICMode] Handling %s via local H3 replay", host)

	if p.certGenerator == nil {
		log.Printf("[QUICMode] No cert generator available")
		return
	}
	caCert := p.certGenerator.GetCACert()
	caKey := p.certGenerator.GetCAKey()
	tlsConfig := p.makeMITMTLSConfig(host, caCert, caKey, []string{"http/1.1"}, "[QUICMode]")
	clientTLS := tls.Server(clientConn, tlsConfig)
	if err := clientTLS.Handshake(); err != nil {
		log.Printf("[QUICMode] Client TLS handshake failed: %v", err)
		return
	}

	quicTransport, err := p.newQUICRoundTripper(host, rule)
	if err != nil {
		log.Printf("[QUICMode] Failed to create HTTP/3 transport: %v", err)
		return
	}
	defer quicTransport.Close()

	client := &http.Client{
		Transport: quicTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			path := req.URL.EscapedPath()
			if path == "" || !strings.HasPrefix(path, "/") {
				path = "/" + strings.TrimPrefix(path, "/")
			}

			targetURL := "https://" + host + path
			if req.URL.RawQuery != "" {
				targetURL += "?" + req.URL.RawQuery
			}

			newReq, err := http.NewRequestWithContext(req.Context(), req.Method, targetURL, req.Body)
			if err != nil {
				http.Error(w, "Bad request", http.StatusInternalServerError)
				return
			}
			for k, vv := range req.Header {
				for _, v := range vv {
					newReq.Header.Add(k, v)
				}
			}
			removeHopByHopHeaders(newReq.Header)
			newReq.Host = host

			resp, err := client.Do(newReq)
			if err != nil {
				log.Printf("[QUICMode] Forwarding error method=%s host=%s target=%s err=%v", req.Method, host, targetURL, err)
				http.Error(w, "Proxy error", http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()

			removeHopByHopHeaders(resp.Header)
			for k, vv := range resp.Header {
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(resp.StatusCode)
			_, _ = io.Copy(w, resp.Body)
		}),
	}

	_ = srv.Serve(&singleConnListener{conn: clientTLS, done: make(chan struct{})})
}

func (p *ProxyServer) handleServerMITM(clientConn net.Conn, host string, rule Rule) {
	defer clientConn.Close()
	log.Printf("[ServerMode] Handling %s via Server", host)

	if p.certGenerator == nil {
		log.Printf("[ServerMode] No cert generator available")
		return
	}
	caCert := p.certGenerator.GetCACert()
	caKey := p.certGenerator.GetCAKey()
	tlsConfig := p.makeMITMTLSConfig(host, caCert, caKey, []string{"http/1.1"}, "[ServerMode]")
	clientTls := tls.Server(clientConn, tlsConfig)
	if err := clientTls.Handshake(); err != nil {
		log.Printf("[ServerMode] TLS handshake failed: %v", err)
		return
	}

	serverHost := p.rules.serverHost
	if serverHost == "" {
		log.Printf("[ServerMode] ServerHost not configured")
		return
	}

	dialCandidates := []string{}
	seen := map[string]struct{}{}
	if rule.UseCFPool && p.cfPool != nil {
		topIPs := p.cfPool.GetTopIPs(5)
		for _, ip := range topIPs {
			addr := net.JoinHostPort(ip, "443")
			if _, ok := seen[addr]; ok {
				continue
			}
			seen[addr] = struct{}{}
			dialCandidates = append(dialCandidates, addr)
		}
	}
	serverAddr := net.JoinHostPort(serverHost, "443")
	if _, ok := seen[serverAddr]; !ok {
		dialCandidates = append(dialCandidates, serverAddr)
	}

	upstreamConn, upstreamProtocol, err := p.establishUpstreamConn(serverHost, rule, dialCandidates, "")
	if err != nil {
		log.Printf("[ServerMode] Failed to establish upstream connection: %v", err)
		return
	}
	defer upstreamConn.Close()

	log.Printf("[ServerMode] Upstream protocol: %s", upstreamProtocol)

	var uconn *utls.UConn
	if uc, ok := upstreamConn.(*utls.UConn); ok {
		uconn = uc
	}

	var transport http.RoundTripper
	if upstreamProtocol == "h2" || (uconn != nil && uconn.ConnectionState().NegotiatedProtocol == "h2") {
		cs := uconn.ConnectionState()
		peerCN := ""
		if len(cs.PeerCertificates) > 0 {
			peerCN = cs.PeerCertificates[0].Subject.CommonName
		}
		log.Printf("[ServerMode] Upstream uTLS negotiated: alpn=%s echAccepted=%v peerCN=%s", cs.NegotiatedProtocol, cs.ECHAccepted, peerCN)
		t2 := &http2.Transport{}
		c2, err := t2.NewClientConn(uconn)
		if err != nil {
			log.Printf("[ServerMode] H2 wrapper failed: %v", err)
			return
		}
		transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return c2.RoundTrip(req)
		})
	} else {
		transport = &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return upstreamConn, nil
			},
		}
	}

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			targetUrl := "https://" + host + req.URL.Path
			if req.URL.RawQuery != "" {
				targetUrl += "?" + req.URL.RawQuery
			}

			path := req.URL.EscapedPath()
			if path == "" || !strings.HasPrefix(path, "/") {
				path = "/" + strings.TrimPrefix(path, "/")
			}

			workerUrlStr := "https://" + serverHost + "/" + p.rules.serverAuth + "/" + host + path
			if req.URL.RawQuery != "" {
				workerUrlStr += "?" + req.URL.RawQuery
			}

			newReq, err := http.NewRequest(req.Method, workerUrlStr, req.Body)
			if err != nil {
				http.Error(w, "Bad request", http.StatusInternalServerError)
				return
			}

			for k, vv := range req.Header {
				for _, v := range vv {
					newReq.Header.Add(k, v)
				}
			}
			newReq.Host = serverHost
			log.Printf("[ServerMode] Forward request method=%s workerURL=%s host=%s target=%s contentLength=%d", req.Method, workerUrlStr, newReq.Host, targetUrl, req.ContentLength)

			removeHopByHopHeaders(newReq.Header)

			resp, err := client.Do(newReq)
			if err != nil {
				log.Printf("[ServerMode] Forwarding error method=%s workerURL=%s host=%s target=%s err=%v", req.Method, workerUrlStr, newReq.Host, targetUrl, err)
				http.Error(w, "Proxy error", http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()
			log.Printf("[ServerMode] Upstream response status=%d target=%s", resp.StatusCode, targetUrl)

			removeHopByHopHeaders(resp.Header)
			for k, vv := range resp.Header {
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(resp.StatusCode)
			io.Copy(w, resp.Body)
		}),
	}
	_ = srv.Serve(&singleConnListener{conn: clientTls, done: make(chan struct{})})
}

// establishUpstreamConn integrates multi-node dialing, IP preference, uTLS handshake and ECH auto-extraction logic
func (p *ProxyServer) establishUpstreamConn(host string, rule Rule, dialCandidates []string, initialALPN string) (net.Conn, string, error) {
	// 1. Determine dial address
	ordered := dialCandidates
	if len(ordered) == 0 {
		ordered = []string{net.JoinHostPort(host, "443")}
	}

	// 2. Pre-calculate handshake parameters (retry handshake for each candidate)
	sniHost := chooseUpstreamSNI(host, rule)

	upstreamALPN := initialALPN
	if upstreamALPN == "" {
		upstreamALPN = "h2_h1"
	}
	// 3. 按候选逐个拨号+握手（关键：握手失败也要尝试下一个候选）
	var errs []string
	for _, addr := range ordered {
		// [Fix] Each IP candidate gets 2 chances (initial try + 1 retry with correction)
		for attempt := 0; attempt < 2; attempt++ {
			// [Fix] Dynamically parse ECH config to use error-correction cache from previous attempt
			var echConfig []byte
			if rule.ECHEnabled {
				echConfig = p.resolveRuleECHConfig(host, rule)
			}

			rawConn, dialErr := p.dialWithRule(context.Background(), "tcp", addr, rule)
			if dialErr != nil {
				errs = append(errs, fmt.Sprintf("%s dial: %v", addr, dialErr))
				if rule.UseCFPool && p.cfPool != nil {
					h, _, _ := net.SplitHostPort(addr)
					if h != "" {
						p.cfPool.ReportFailure(h)
					}
				}
				break // dial failed, switch to next IP, no retry
			}

			targetSNI := sniHost
			if len(echConfig) > 0 {
				targetSNI = host
				if attempt == 0 {
					log.Printf("[Upstream] ECH ACTIVE: Setting Inner SNI = %s for addr %s", targetSNI, addr)
				}
			} else if rule.ECHEnabled {
				log.Printf("[Upstream] WARNING: ECH is enabled for %s but NO ECH config available. Handshake will LEAK domain!", host)
			}

			allowInsecure := len(echConfig) == 0 && rule.CertVerify.IsZero()
			uconn := p.GetUConn(rawConn, targetSNI, host, rule, allowInsecure, upstreamALPN, echConfig)
			utlsErr := uconn.Handshake()
			if utlsErr == nil {
				// Handshake successful, log and return
				cs := uconn.ConnectionState()
				peerCN := ""
				peerSAN := ""
				if len(cs.PeerCertificates) > 0 {
					peerCN = cs.PeerCertificates[0].Subject.CommonName
					if len(cs.PeerCertificates[0].DNSNames) > 0 {
						peerSAN = cs.PeerCertificates[0].DNSNames[0]
					}
				}
				log.Printf("[Upstream] uTLS handshake ok host=%s addr=%s outerSNI=%s alpn=%s echAccepted=%v peerCN=%s peerSAN0=%s", host, addr, sniHost, cs.NegotiatedProtocol, cs.ECHAccepted, peerCN, peerSAN)
				if rule.UseCFPool && p.cfPool != nil {
					h, _, _ := net.SplitHostPort(addr)
					if h != "" {
						p.cfPool.ReportSuccess(h)
					}
				}
				return uconn, cs.NegotiatedProtocol, nil
			}

			// Handshake failed, cleanup resources
			rawConn.Close()

			// [ECH error correction and local retry logic]
			var echErr *utls.ECHRejectionError
			if errors.As(utlsErr, &echErr) {
				if attempt == 0 && rule.ECHEnabled && p.dohResolver != nil {
					log.Printf("[Upstream] ECH REJECTED by %s. Attempting proactive DNS refresh for %s...", addr, host)

					// 1. Try synchronous ECH config refresh
					refreshCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					lookupDomain := rule.ECHDiscoveryDomain
					if lookupDomain == "" {
						lookupDomain = host
					}
					newECH, refreshErr := p.dohResolver.ResolveECHSafe(refreshCtx, lookupDomain)
					cancel()

					if refreshErr == nil && len(newECH) > 0 {
						log.Printf("[Upstream] Successfully refreshed ECH for %s via DNS. Syncing to profile and retrying...", host)
						if rule.ECHProfileID != "" {
							p.UpdateECHProfileConfig(rule.ECHProfileID, newECH)
						}
						// 第二次尝试将自动从 Profile 读取新配置
						continue
					}

					// 2. If DNS refresh fails, try using uTLS provided RetryConfigList (if exists)
					if len(echErr.RetryConfigList) > 0 {
						log.Printf("[Upstream] DNS refresh failed, but RetryConfigs available. Retrying once with server-provided configs...")
						// Note: since resolveRuleECHConfig is called at loop start,
						// this in-place continue cannot directly inject RetryConfigList,
						// unless we modify loop structure. For safety, we prioritize DNS refresh.
						// If DNS didn't refresh, we choose to try next IP or report error,
						// because RetryConfigList is only valid for current handshake, cannot be persisted.
					}
				}
			}

			// 最终失败处理
			errs = append(errs, fmt.Sprintf("%s utls: %v", addr, utlsErr))
			if rule.UseCFPool && p.cfPool != nil {
				h, _, _ := net.SplitHostPort(addr)
				if h != "" {
					p.cfPool.ReportFailure(h)
				}
			}
			break // 换下一个 IP
		}
	}

	if len(errs) == 0 {
		return nil, "", fmt.Errorf("all candidates failed with unknown error")
	}

	finalErr := fmt.Errorf("all candidates failed: %s", strings.Join(errs, "; "))

	// Safe fallback logic: only support fallback to secure protocols
	fallback := strings.ToLower(strings.TrimSpace(rule.FallbackMode))
	if (fallback == "tls-rf" || fallback == "quic") && fallback != rule.Mode {
		log.Printf("[Upstream] ECH/Primary connection failed for %s, falling back to secure mode: %s", host, fallback)
		fallbackRule := rule
		fallbackRule.Mode = fallback
		fallbackRule.ECHEnabled = false 	// Since we already fell back, usually don't try ECH or let new mode handle it
		return p.establishUpstreamConn(host, fallbackRule, dialCandidates, initialALPN)
	}

	return nil, "", finalErr
}

func (p *ProxyServer) dialWithRule(ctx context.Context, network, addr string, rule Rule) (net.Conn, error) {
	// Default direct dialer
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	return dialer.DialContext(ctx, network, addr)
}

// FetchECH performs a one-off ECH resolution via DoH for a specific domain and upstream
func (p *ProxyServer) FetchECH(ctx context.Context, domain string, dohURL string) ([]byte, error) {
	if p.dohResolver == nil {
		return nil, fmt.Errorf("no DoH resolver available")
	}

	// Now FetchECH ignores dohURL and just tries to resolve it with the global FailoverResolver.
	// But we must prevent resolving Alidns or other bootstrap nodes themselves.
	return p.dohResolver.ResolveECH(ctx, domain)
}

// --- Auto Routing ---

func (rm *RuleManager) GetAutoRoutingConfig() AutoRoutingConfig {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.autoRoutingConfig
}

func (rm *RuleManager) UpdateAutoRoutingConfig(cfg AutoRoutingConfig) error {
	rm.mu.Lock()
	rm.autoRoutingConfig = cfg
	if rm.autoRouter != nil {
		rm.autoRouter.UpdateConfig(cfg)
	}
	rm.mu.Unlock()
	return rm.saveSettingsConfig()
}

func (rm *RuleManager) GetAutoRouter() *AutoRouter {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.autoRouter
}

func (rm *RuleManager) InitAutoRouter(resolver *FailoverResolver) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.autoRouter = NewAutoRouter(rm.autoRoutingConfig, resolver)

	// Try loading cached GFW list
	cachePath := gfwListCachePath(rm.rulesPath)
	if count, err := rm.autoRouter.GetGFWList().LoadFromFile(cachePath); err == nil {
		log.Printf("[AutoRoute] Loaded %d domains from cache: %s", count, cachePath)
	} else {
		log.Printf("[AutoRoute] No cached GFW list at %s: %v", cachePath, err)
	}
}

func (rm *RuleManager) RefreshGFWList() (int, error) {
	rm.mu.RLock()
	ar := rm.autoRouter
	cfg := rm.autoRoutingConfig
	rulesPath := rm.rulesPath
	rm.mu.RUnlock()

	if ar == nil {
		return 0, fmt.Errorf("auto router not initialized")
	}

	url := cfg.GFWListURL
	if url == "" {
		url = defaultGFWListURL
	}

	count, err := ar.GetGFWList().LoadFromURL(url)
	if err != nil {
		return 0, err
	}

	// Save to local cache
	cachePath := gfwListCachePath(rulesPath)
	if saveErr := ar.GetGFWList().SaveToFile(cachePath); saveErr != nil {
		log.Printf("[AutoRoute] Failed to save GFW list cache: %v", saveErr)
	}

	// Update last update time
	rm.mu.Lock()
	rm.autoRoutingConfig.LastUpdate = time.Now().Format("2006-01-02 15:04:05")
	cfg = rm.autoRoutingConfig
	if rm.autoRouter != nil {
		rm.autoRouter.UpdateConfig(cfg)
	}
	rm.mu.Unlock()
	_ = rm.saveSettingsConfig()

	return count, nil
}

func (rm *RuleManager) GetAutoRoutingStatus() GFWListStatus {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	if rm.autoRouter != nil {
		return rm.autoRouter.GetStatus()
	}
	return GFWListStatus{
		Enabled: false,
		Mode:    string(rm.autoRoutingConfig.Mode),
	}
}
