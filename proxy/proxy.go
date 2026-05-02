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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

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
	dohResolver   *DoHResolver
	cfPool        *CloudflarePool
	transport     *http.Transport
	warpMgr       *WarpManager
	logCallback   func(string)
	bytesDown     int64
	bytesUp       int64
}

type RuleManager struct {
	rules                      []Rule
	siteGroups                 []SiteGroup
	upstreams                  []Upstream
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
	echProfiles                []ECHProfile
	autoRouter                 *AutoRouter
	autoRoutingConfig          AutoRoutingConfig
	mu                         sync.RWMutex
	routeEventCallback         func(domain, mode string)
	onConfigSaved              func()
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
	AutoUpdate      bool   `json:"auto_update,omitempty"`
}

type SettingsConfig struct {
	ListenPort                 string            `json:"listen_port"`
	ServerHost                 string            `json:"server_host,omitempty"`
	ServerAuth                 string            `json:"server_auth,omitempty"`
	CloseToTray                *bool             `json:"close_to_tray,omitempty"`
	AutoStart                  *bool             `json:"auto_start,omitempty"`
	ShowMainWindowOnAutoStart  *bool             `json:"show_main_window_on_auto_start,omitempty"`
	AutoEnableProxyOnAutoStart *bool             `json:"auto_enable_proxy_on_auto_start,omitempty"`
	CloudflareConfig           CloudflareConfig  `json:"cloudflare_config"`
	AutoRouting                AutoRoutingConfig `json:"auto_routing,omitempty"`
	TUN                        TUNConfig         `json:"tun,omitempty"`
}

type TUNConfig struct {
	Enabled     bool   `json:"enabled"`
	Stack       string `json:"stack,omitempty"`
	MTU         int    `json:"mtu,omitempty"`
	DNSHijack   bool   `json:"dns_hijack,omitempty"`
	AutoRoute   bool   `json:"auto_route,omitempty"`
	StrictRoute bool   `json:"strict_route,omitempty"`
}

type TUNStatus struct {
	Supported bool   `json:"supported"`
	Running   bool   `json:"running"`
	Enabled   bool   `json:"enabled"`
	Stack     string `json:"stack,omitempty"`
	Driver    string `json:"driver,omitempty"`
	Message   string `json:"message,omitempty"`
}

type RulesConfig struct {
	SiteGroups  []SiteGroup  `json:"site_groups"`
	Upstreams   []Upstream   `json:"upstreams"`
	ECHProfiles []ECHProfile `json:"ech_profiles,omitempty"`
}

type CloudflareConfig struct {
	PreferredIPs  []string `json:"preferred_ips"`
	DoHURL        string   `json:"doh_url"`
	AutoUpdate    bool     `json:"auto_update"`
	APIKey        string   `json:"api_key"`
	WarpEnabled   bool     `json:"warp_enabled"`
	WarpSocksPort int      `json:"warp_socks_port"`
	WarpEndpoint  string   `json:"warp_endpoint"`
}

type trackingListener struct {
	net.Listener
	proxy *ProxyServer
}

type statConn struct {
	net.Conn
	bytesDown *int64
	bytesUp   *int64
}

func (c *statConn) Read(p []byte) (n int, err error) {
	n, err = c.Conn.Read(p)
	if n > 0 {
		atomic.AddInt64(c.bytesUp, int64(n))
	}
	return n, err
}

func (c *statConn) Write(p []byte) (n int, err error) {
	n, err = c.Conn.Write(p)
	if n > 0 {
		atomic.AddInt64(c.bytesDown, int64(n))
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
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func removeHopByHopHeaders(h http.Header) {
	if h == nil {
		return
	}
	if c := h.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			if name := textproto.TrimString(f); name != "" {
				h.Del(name)
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
	return &statConn{
		Conn:      conn,
		bytesDown: &l.proxy.bytesDown,
		bytesUp:   &l.proxy.bytesUp,
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
	ECHDomain          string
	UseCFPool          bool
	ECHConfig          []byte
	ECHDiscoveryDomain string
	ECHDoHUpstream     string
	ECHAutoUpdate      bool
	CertVerify         CertVerifyConfig
	AutoRouted         bool   // true if generated by AutoRouter
	FallbackMode       string // "warp" or "server" fallback transport
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
		log.Printf("[DNS] Resolve failed for %s via %s: %v", host, p.dohResolver.ServerURL, err)
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
	log.Printf("[DNS] Resolved %s via DoH (%s) mode=%s -> %v", host, p.dohResolver.ServerURL, normalizeDNSMode(dnsMode), candidates)
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
				if resolved := p.resolveDomainCandidates(ctx, firstHost, defaultPort, rule.DNSMode); len(resolved) > 0 {
					return resolved
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
	}

	return []string{targetAddr}
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
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			MaxIdleConnsPerHost:   10,
		},
		dohResolver: NewDoHResolver(""),
		cfPool:      NewCloudflarePool([]string{}),
	}
	p.rules = NewRuleManager("", "")
	return p
}

func (p *ProxyServer) SetRuleManager(rm *RuleManager) {
	p.mu.Lock()
	p.rules = rm
	if rm != nil {
		cfg := rm.GetCloudflareConfig()
		if p.dohResolver != nil {
			p.dohResolver.ServerURL = cfg.DoHURL
			if p.dohResolver.ServerURL == "" {
				p.dohResolver.ServerURL = "https://223.5.5.5/dns-query"
			}
		}
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

func (p *ProxyServer) SetWarpManager(wm *WarpManager) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.warpMgr = wm
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
	if p.dohResolver != nil {
		p.dohResolver.ServerURL = cfg.DoHURL
		if p.dohResolver.ServerURL == "" {
			p.dohResolver.ServerURL = "https://223.5.5.5/dns-query"
		}
	}
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

func (p *ProxyServer) GetDoHResolver() *DoHResolver {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.dohResolver
}

func (p *ProxyServer) SetMode(mode string) error {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != "mitm" && mode != "transparent" && mode != "tls-rf" && mode != "quic" {
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

	if p.cfPool != nil {
		p.cfPool.Start()
	}

	p.mu.Unlock()

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		// Clean up pool if listen fails
		if p.cfPool != nil {
			p.cfPool.Stop()
		}
		return fmt.Errorf("failed to listen on %s: %w", listenAddr, err)
	}

	p.mu.Lock()
	// Re-check state in case Stop/Start race happened while binding.
	if p.running {
		p.mu.Unlock()
		_ = ln.Close()
		return nil
	}
	p.Server = srv
	p.running = true
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

	return nil
}

func (p *ProxyServer) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.running {
		return nil
	}
	p.running = false

	if p.cfPool != nil {
		p.cfPool.Stop()
	}

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
	effectiveMode := rule.Mode
	resolvedUpstream := resolveRuleUpstream(targetHost, rule)
	isWarpRoute := strings.EqualFold(strings.TrimSpace(rule.Upstream), "warp")

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

	// Warp routes should tunnel the original destination via SOCKS5, not enter
	// the dedicated server-mode path that expects a configured Worker/VPS host.
	if isWarpRoute && effectiveMode == "server" {
		effectiveMode = "transparent"
		resolvedUpstream = ""
	}

	// Stage-2 match: if stage-1 produced a dynamic upstream host (eg. *.gvt1.com),
	// allow that upstream host to hit another rule and override policies.
	if !isWarpRoute && (effectiveMode == "mitm" || effectiveMode == "transparent") && strings.TrimSpace(resolvedUpstream) != "" {
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

	// For direct mode, connect directly to the target
	if effectiveMode == "direct" {
		p.directConnect(w, req)
		return
	}

	// For server mode, hijack directly and use built-in HTTP service for parsing, no dialing to original target
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

		// Single-path stability priority (combined with sequential fallback)
		if len(dialCandidates) > 1 {
			var lastErr error
			for _, addr := range dialCandidates {
				conn, err = dial("tcp", addr)
				if err == nil {
					dialAddr = addr
					log.Printf("[Connect] Sequential dial success: %s", dialAddr)

					// If CF optimized pool is used, report success status
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

				// If this candidate connection fails and comes from CF pool, report failure for penalty
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

	// Note: Do not use defer after hijack, as we need to keep the connection open
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
	go func() {
		defer wg.Done()
		buf := make([]byte, 128*1024)
		_, _ = io.CopyBuffer(conn, clientConn, buf)
		conn.Close()
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 128*1024)
		_, _ = io.CopyBuffer(clientConn, conn, buf)
		clientConn.Close()
	}()
	wg.Wait()
}

func (p *ProxyServer) handleHTTP(w http.ResponseWriter, req *http.Request, rule Rule) {
	// Create a new request to avoid modifying the original request
	newReq := req.Clone(req.Context())
	newReq.RequestURI = ""
	newReq.Header.Del("Proxy-Connection")

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

	// MITM rules are designed around HTTPS interception. Redirect plain HTTP to
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
		// Forward request directly
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
	if strings.EqualFold(strings.TrimSpace(rule.Upstream), "warp") {
		t := p.transport.Clone()
		t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return p.dialWithRule(ctx, network, addr, rule)
		}
		transport = t
	} else if rule.Upstream != "" {
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
		log.Printf("[HTTP] HTTPS proxy failed: %v", err)
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
	go func() {
		defer wg.Done()
		buf := make([]byte, 128*1024)
		n, err := io.CopyBuffer(upstreamConn, clientConn, buf)
		p.tracef("[Tunnel] Client -> Upstream: %d bytes, err: %v", n, err)
		upstreamConn.Close()
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 128*1024)
		n, err := io.CopyBuffer(clientConn, upstreamConn, buf)
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

	keyBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
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

	// If a specific rule matched
	if bestScore >= 0 {
		if mode == "transparent" && best.Mode == "mitm" {
			log.Printf("[RuleMatch] Global Transparent detected: Downgrading MITM rule (%s) to DIRECT to avoid cert errors.", host)
			best.Mode = "direct"
		}
		log.Printf("[Router] %s -> %s", host, best.Mode)
		r.emitRouteEvent(host, best.Mode)
		return best
	}

	// Auto-routing layer: when manual rules don't match, query AutoRouter
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
		existing.AutoUpdate = true
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
	if rm.cloudflareConfig.WarpEndpoint == "" {
		rm.cloudflareConfig.WarpEndpoint = "162.159.199.2"
	}
	if rm.cloudflareConfig.WarpSocksPort == 0 {
		rm.cloudflareConfig.WarpSocksPort = 1080
	}
	rm.tunConfig = normalizeTUNConfig(rm.tunConfig)
}

func normalizeTUNStack(stack string) string {
	switch strings.ToLower(strings.TrimSpace(stack)) {
	case "":
		return "gvisor"
	case "mixed":
		return "mixed"
	case "system", "gvisor":
		return strings.ToLower(strings.TrimSpace(stack))
	default:
		return "gvisor"
	}
}

func normalizeTUNConfig(cfg TUNConfig) TUNConfig {
	cfg.Stack = normalizeTUNStack(cfg.Stack)
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

	rm.cloudflareConfig = config.CloudflareConfig
	rm.tunConfig = config.TUN
	rm.serverHost = config.ServerHost
	rm.serverAuth = config.ServerAuth
	rm.listenPort = config.ListenPort
	rm.autoRoutingConfig = config.AutoRouting
	rm.closeToTray = true
	rm.autoStart = false
	rm.showMainOnAutoStart = true
	rm.autoEnableProxyOnAutoStart = false
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
	rm.echProfiles = config.ECHProfiles
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
	rm.siteGroups = []SiteGroup{}
	rm.upstreams = []Upstream{}
	rm.echProfiles = []ECHProfile{}
	rm.buildRules()
	return rm.saveRulesConfig()
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
				ECHDomain:          sg.ECHDomain,
				UseCFPool:          sg.UseCFPool,
				ECHConfig:          echConfigBytes,
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

func (rm *RuleManager) saveSettingsConfig() error {
	listenPort := rm.listenPort
	if listenPort == "" {
		listenPort = "8080"
	}
	closeToTray := rm.closeToTray
	autoStart := rm.autoStart
	showMainOnAutoStart := rm.showMainOnAutoStart
	autoEnableProxyOnAutoStart := rm.autoEnableProxyOnAutoStart
	cloudflareConfig := rm.cloudflareConfig
	tunConfig := normalizeTUNConfig(rm.tunConfig)
	if cloudflareConfig.WarpEndpoint == "" {
		cloudflareConfig.WarpEndpoint = "162.159.199.2"
	}
	if cloudflareConfig.WarpSocksPort == 0 {
		cloudflareConfig.WarpSocksPort = 1080
	}
	config := SettingsConfig{
		ListenPort:                 listenPort,
		ServerHost:                 rm.serverHost,
		ServerAuth:                 rm.serverAuth,
		CloseToTray:                &closeToTray,
		AutoStart:                  &autoStart,
		ShowMainWindowOnAutoStart:  &showMainOnAutoStart,
		AutoEnableProxyOnAutoStart: &autoEnableProxyOnAutoStart,
		CloudflareConfig:           cloudflareConfig,
		AutoRouting:                rm.autoRoutingConfig,
		TUN:                        tunConfig,
	}

	data, err := json.MarshalIndent(config, "", "  ")
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

func chooseUTLSClientHelloID(alpn string) utls.ClientHelloID {
	if strings.EqualFold(strings.TrimSpace(alpn), "http/1.1") {
		return utls.HelloFirefox_120
	}
	return utls.HelloChrome_120
}

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

	config := &utls.Config{
		// ECH 下这里必须是内层真实 SNI。外层公开名由 ECHConfig 的 PublicName 驱动。
		ServerName:                     sni,
		InsecureSkipVerify:             allowInsecure,
		EncryptedClientHelloConfigList: echConfig,
		NextProtos:                     nextProtos,
		VerifyConnection:               verifyConn,
	}

	if len(echConfig) > 0 {
		// In ECH mode, if the server rejects ECH, it will present the Public Name certificate instead of the real host's.
		// We allow the verification to continue through this hook so we can extract retry configuration.
		config.EncryptedClientHelloRejectionVerify = func(cs utls.ConnectionState) error {
			// Return nil to allow verification of the outer Public Name certificate when ECH is rejected.
			// utls internally validates certificate legitimacy against RootCAs, so security is maintained.
			return nil
		}
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
	// 1. 优先检查内存中是否已有纠错后的热配置
	if p.dohResolver != nil {
		cacheKey := strings.TrimSpace(rule.ECHDomain)
		if cacheKey == "" {
			cacheKey = host
		}
		if val, ok := p.dohResolver.echCache.Load(cacheKey); ok {
			if ech, ok := val.([]byte); ok && len(ech) > 0 {
				log.Printf("[Upstream] Using hot-patched ECH config for %s (via %s)", host, cacheKey)
				return ech
			}
		}
	}

	if rule.ECHAutoUpdate {
		lookupDomain := strings.TrimSpace(rule.ECHDiscoveryDomain)
		if lookupDomain == "" {
			lookupDomain = strings.TrimSpace(rule.ECHDomain)
		}
		if lookupDomain == "" {
			lookupDomain = host
		}

		echCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		echConfig, err := p.FetchECH(echCtx, lookupDomain, strings.TrimSpace(rule.ECHDoHUpstream))
		cancel()
		if err == nil && len(echConfig) > 0 {
			log.Printf("[Upstream] Refreshed ECH profile %s for %s via %s (%d bytes)", rule.ECHProfileID, host, lookupDomain, len(echConfig))
			return echConfig
		}
		if err != nil {
			log.Printf("[Upstream] ECH profile refresh failed for %s via %s: %v", host, lookupDomain, err)
		}
	}

	if len(rule.ECHConfig) > 0 {
		log.Printf("[Upstream] Using stored ECH profile %s for %s (%d bytes)", rule.ECHProfileID, host, len(rule.ECHConfig))
		return rule.ECHConfig
	}

	if p.dohResolver == nil {
		return nil
	}

	echLookupDomain := strings.TrimSpace(rule.ECHDomain)
	if echLookupDomain == "" {
		echLookupDomain = host
	}
	log.Printf("[Upstream] Fetching ECH for %s (via %s)", host, echLookupDomain)
	echCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	echConfig, err := p.dohResolver.ResolveECH(echCtx, echLookupDomain)
	cancel()
	if err != nil {
		log.Printf("[Upstream] ECH lookup failed for %s via %s: %v", host, echLookupDomain, err)
		return nil
	}
	if len(echConfig) > 0 {
		log.Printf("[Upstream] ECH fetched for %s via %s (%d bytes)", host, echLookupDomain, len(echConfig))
	}
	return echConfig
}

func (p *ProxyServer) newQUICRoundTripper(host string, rule Rule) (*http3.Transport, error) {
	targetAddr := net.JoinHostPort(host, "443")
	dialCandidates := p.buildDialCandidates(context.Background(), host, targetAddr, rule, "quic")
	if len(dialCandidates) == 0 {
		dialCandidates = []string{targetAddr}
	}

	sniHost := chooseUpstreamSNI(host, rule)
	if strings.TrimSpace(sniHost) == "" {
		sniHost = host
	}

	verifyConn := buildVerifyConnection(host, rule.CertVerify)
	tlsConfig := &tls.Config{
		ServerName:         sniHost,
		NextProtos:         []string{"h3", "h3-29", "h3-32"},
		InsecureSkipVerify: true,
	}
	if verifyConn != nil {
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
					log.Printf("[QUIC] H3 dial success host=%s addr=%s sni=%s alpn=%s", host, candidate, tlsCfg.ServerName, conn.ConnectionState().TLS.NegotiatedProtocol)
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

// establishUpstreamConn integrates multi-node dialing, optimized IP, uTLS handshake, and ECH auto-extraction logic
func (p *ProxyServer) establishUpstreamConn(host string, rule Rule, dialCandidates []string, initialALPN string) (net.Conn, string, error) {
	// 1. 确定拨号地址
	ordered := dialCandidates
	if len(ordered) == 0 {
		ordered = []string{net.JoinHostPort(host, "443")}
	}

	// 2. Pre-compute handshake parameters (retry handshake per candidate sequentially)
	sniHost := chooseUpstreamSNI(host, rule)

	upstreamALPN := initialALPN
	if upstreamALPN == "" {
		upstreamALPN = "h2_h1"
	}
	// 3. 按候选逐个拨号+握手（关键：握手失败也要尝试下一个候选）
	var errs []string
	for _, addr := range ordered {
		// [修正] 每个 IP 候选人都有 2 次机会（初始尝试 + 1 次原地纠错重试）
		for attempt := 0; attempt < 2; attempt++ {
			// [Fix] Dynamically resolve ECH config to consume error-correction cache from previous attempt
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
				break // Dial failed, move to next IP without retry
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

			allowInsecure := len(echConfig) == 0
			uconn := p.GetUConn(rawConn, targetSNI, host, rule, allowInsecure, upstreamALPN, echConfig)
			utlsErr := uconn.Handshake()
			if utlsErr == nil {
				// 握手成功，记录日志并返回
				cs := uconn.ConnectionState()
				peerCN := ""
				peerSAN := ""
				if len(cs.PeerCertificates) > 0 {
					peerCN = cs.PeerCertificates[0].Subject.CommonName
					if len(cs.PeerCertificates[0].DNSNames) > 0 {
						peerSAN = cs.PeerCertificates[0].DNSNames[0]
					}
				}
				log.Printf("[Upstream] uTLS handshake ok host=%s addr=%s targetSNI=%s alpn=%s echAccepted=%v peerCN=%s peerSAN0=%s", host, addr, targetSNI, cs.NegotiatedProtocol, cs.ECHAccepted, peerCN, peerSAN)
				if rule.UseCFPool && p.cfPool != nil {
					h, _, _ := net.SplitHostPort(addr)
					if h != "" {
						p.cfPool.ReportSuccess(h)
					}
				}
				return uconn, cs.NegotiatedProtocol, nil
			}

			// 握手失败，清理资源
			rawConn.Close()

			// [ECH error correction and in-place retry logic]
			var echErr *utls.ECHRejectionError
			if errors.As(utlsErr, &echErr) && len(echErr.RetryConfigList) > 0 {
				cacheKey := strings.TrimSpace(rule.ECHDomain)
				if cacheKey == "" {
					cacheKey = host
				}
				if p.dohResolver != nil {
					log.Printf("[Upstream] ECH REJECTED by %s. Server provided RetryConfigs. Hot-patching cache for %s...", addr, cacheKey)
					p.dohResolver.echCache.Store(cacheKey, echErr.RetryConfigList)

					// If retry attempts remain and failure was due to ECH rejection, retry in-place on same IP
					if attempt == 0 {
						log.Printf("[Upstream] Retrying connection to %s with updated ECH config (Attempt 2)...", addr)
						continue
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
			break // Move to next IP
		}
	}

	if len(errs) == 0 {
		return nil, "", fmt.Errorf("all candidates failed with unknown error")
	}
	return nil, "", fmt.Errorf("all candidates failed: %s", strings.Join(errs, "; "))
}

func (p *ProxyServer) dialWithRule(ctx context.Context, network, addr string, rule Rule) (net.Conn, error) {
	p.mu.RLock()
	wm := p.warpMgr
	p.mu.RUnlock()

	useWarp := false
	if strings.ToLower(strings.TrimSpace(rule.Upstream)) == "warp" || strings.ToLower(strings.TrimSpace(rule.Mode)) == "warp" {
		useWarp = true
	}

	if useWarp && wm != nil && p.rules.GetCloudflareConfig().WarpEnabled {
		status := wm.GetStatus()
		if !status.Running || !wm.IsReady() {
			if !status.Running {
				log.Printf("[Dial] Warp route requested for %s but tunnel is not running", addr)
				return nil, fmt.Errorf("warp tunnel not running")
			}

			// Loop probing until ready (max wait ~2 seconds)
			ready := false
			for i := 0; i < 10; i++ {
				if wm.IsReady() {
					ready = true
					break
				}
				time.Sleep(200 * time.Millisecond)
			}

			if !ready {
				log.Printf("[Dial] Warp tunnel NOT ready after wait for %s", addr)
				return nil, fmt.Errorf("warp tunnel not ready")
			}
			status = wm.GetStatus()
		}

		if status.Running {
			proxyAddr := fmt.Sprintf("127.0.0.1:%d", wm.SocksPort)
			dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
			if err == nil {
				log.Printf("[Dial] Routing %s via Warp SOCKS5 (%s)", addr, proxyAddr)
				return dialer.Dial(network, addr)
			}
			log.Printf("[Dial] Warp SOCKS5 dialer creation failed: %v", err)
		} else {
			log.Printf("[Dial] Warp is configured but NOT running for %s", addr)
		}
	}

	// Default direct dialer
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	return dialer.DialContext(ctx, network, addr)
}

// FetchECH performs a one-off ECH resolution via DoH for a specific domain and upstream
func (p *ProxyServer) FetchECH(ctx context.Context, domain string, dohURL string) ([]byte, error) {
	if dohURL == "" {
		if p.dohResolver != nil {
			return p.dohResolver.ResolveECH(ctx, domain)
		}
		return nil, fmt.Errorf("no default DoH resolver available")
	}

	// Create a temporary resolver for the specific upstream
	tempResolver := NewDoHResolver(dohURL)
	return tempResolver.ResolveECH(ctx, domain)
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

func (rm *RuleManager) InitAutoRouter(dohResolver *DoHResolver) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.autoRouter = NewAutoRouter(rm.autoRoutingConfig, dohResolver)

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
		Mode:    string(rm.autoRoutingConfig.Mod            