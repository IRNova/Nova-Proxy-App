package proxy

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// AutoRoutingMode defines the auto-routing preset.
type AutoRoutingMode string

const (
	AutoRoutingOff            AutoRoutingMode = ""
	AutoRoutingDefault        AutoRoutingMode = "default" // ECH / TLS-RF / direct
	AutoRoutingWarpFallback   AutoRoutingMode = "warp"    // + Warp fallback
	AutoRoutingServerFallback AutoRoutingMode = "server"  // + Server fallback
)

// AutoRoutingConfig is persisted in settings.json.
type AutoRoutingConfig struct {
	Mode       AutoRoutingMode `json:"mode"`
	GFWListURL string          `json:"gfwlist_url,omitempty"`
	LastUpdate string          `json:"last_update,omitempty"`
}

// Cloudflare IPv4 CIDR ranges — https://www.cloudflare.com/ips-v4/
var cloudflareCIDRStrings = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
	"103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
	"190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
	"198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
}

// AutoRouter makes per-request routing decisions for domains not covered by
// manual SiteGroup rules.
type AutoRouter struct {
	config      AutoRoutingConfig
	gfwList     *GFWList
	cfNets      []*net.IPNet
	cfCache     map[string]cfCacheEntry
	cfCacheMu   sync.RWMutex
	dohResolver *DoHResolver
}

type cfCacheEntry struct {
	isCF      bool
	checkedAt time.Time
}

const cfCacheTTL = 30 * time.Minute

func NewAutoRouter(config AutoRoutingConfig, dohResolver *DoHResolver) *AutoRouter {
	ar := &AutoRouter{
		config:      config,
		gfwList:     NewGFWList(),
		cfCache:     make(map[string]cfCacheEntry),
		dohResolver: dohResolver,
	}
	ar.cfNets = make([]*net.IPNet, 0, len(cloudflareCIDRStrings))
	for _, cidr := range cloudflareCIDRStrings {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("[AutoRoute] Bad CF CIDR %s: %v", cidr, err)
			continue
		}
		ar.cfNets = append(ar.cfNets, network)
	}
	return ar
}

func (ar *AutoRouter) isCloudflareIP(ip net.IP) bool {
	for _, n := range ar.cfNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// IsCloudflare resolves the host via DoH and checks if any returned IP falls
// within Cloudflare CIDR ranges. Results are cached for cfCacheTTL.
func (ar *AutoRouter) IsCloudflare(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}

	// Cache lookup
	ar.cfCacheMu.RLock()
	if entry, ok := ar.cfCache[host]; ok && time.Since(entry.checkedAt) < cfCacheTTL {
		ar.cfCacheMu.RUnlock()
		return entry.isCF
	}
	ar.cfCacheMu.RUnlock()

	isCF := false
	if ar.dohResolver != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ips, err := ar.dohResolver.ResolveIPAddrs(ctx, host)
		if err == nil {
			for _, ip := range ips {
				if ar.isCloudflareIP(ip) {
					isCF = true
					break
				}
			}
		}
	}

	ar.cfCacheMu.Lock()
	ar.cfCache[host] = cfCacheEntry{isCF: isCF, checkedAt: time.Now()}
	ar.cfCacheMu.Unlock()

	if isCF {
		log.Printf("[AutoRoute] %s → Cloudflare", host)
	}
	return isCF
}

// Decide returns a synthetic Rule for a GFWList-matched domain.
// Returns a "direct" rule if the domain is not in the GFW list.
func (ar *AutoRouter) Decide(host string) Rule {
	if ar.config.Mode == AutoRoutingOff || ar.config.Mode == "" {
		return Rule{Mode: "direct", Enabled: true}
	}

	if !ar.gfwList.IsBlocked(host) {
		return Rule{Mode: "direct", Enabled: true}
	}

	// Domain is in GFWList — check if Cloudflare
	if ar.IsCloudflare(host) {
		return Rule{
			Mode:               "mitm",
			ECHEnabled:         true,
			ECHProfileID:       "legacy-cloudflare",
			ECHDiscoveryDomain: "crypto.cloudflare.com",
			ECHAutoUpdate:      true,
			UseCFPool:          true,
			Enabled:            true,
			AutoRouted:         true,
		}
	}

	// Non-CF blocked domain → TLS-RF, optionally with fallback
	rule := Rule{
		Mode:       "tls-rf",
		Enabled:    true,
		AutoRouted: true,
	}
	switch ar.config.Mode {
	case AutoRoutingWarpFallback:
		rule.FallbackMode = "warp"
	case AutoRoutingServerFallback:
		rule.FallbackMode = "server"
	}
	return rule
}

func (ar *AutoRouter) GetGFWList() *GFWList {
	return ar.gfwList
}

func (ar *AutoRouter) UpdateConfig(config AutoRoutingConfig) {
	ar.config = config
}

func (ar *AutoRouter) GetConfig() AutoRoutingConfig {
	return ar.config
}

// GFWListStatus is returned to the frontend.
type GFWListStatus struct {
	Enabled     bool   `json:"enabled"`
	Mode        string `json:"mode"`
	DomainCount int    `json:"domain_count"`
	LastUpdate  string `json:"last_update"`
	GFWListURL  string `json:"gfwlist_url"`
}

func (ar *AutoRouter) GetStatus() GFWListStatus {
	return GFWListStatus{
		Enabled:     ar.config.Mode != "" && ar.config.Mode != AutoRoutingOff,
		Mode:        string(ar.config.Mode),
		DomainCount: ar.gfwList.Count(),
		LastUpdate:  ar.config.LastUpdate,
		GFWListURL:  ar.config.GFWListURL,
	}
}

// DialFallback dials targetAddr through the specified fallback transport.
func DialFallback(fallbackMode string, targetAddr string, warpMgr *WarpManager, cfConfig CloudflareConfig, serverHost string) (net.Conn, error) {
	switch fallbackMode {
	case "warp":
		if warpMgr == nil || !warpMgr.GetStatus().Running {
			return nil, fmt.Errorf("warp not running")
		}
		warpAddr := fmt.Sprintf("127.0.0.1:%d", warpMgr.SocksPort)
		dialer, err := proxy.SOCKS5("tcp", warpAddr, nil, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("warp SOCKS5 dial: %w", err)
		}
		return dialer.Dial("tcp", targetAddr)

	case "server":
		if serverHost == "" {
			return nil, fmt.Errorf("server host not configured")
		}
		d := &net.Dialer{Timeout: 10 * time.Second}
		return d.Dial("tcp", ensureAddrWithPort(serverHost, "443"))

	default:
		return nil, fmt.Errorf("unknown fallback: %s", fallbackMode)
	}
}
