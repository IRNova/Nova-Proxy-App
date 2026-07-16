package proxy

import (
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"
)

type ConnectionLayer int

const (
	LayerDirect ConnectionLayer = iota
	LayerREALITY
	LayerXHTTP
	LayerGSA
	LayerDNSTunnel
	LayerTLSFragment
	LayerNone
)

func (l ConnectionLayer) String() string {
	switch l {
	case LayerDirect:
		return "direct"
	case LayerREALITY:
		return "reality"
	case LayerXHTTP:
		return "xhttp"
	case LayerGSA:
		return "gsa"
	case LayerDNSTunnel:
		return "dns-tunnel"
	case LayerTLSFragment:
		return "tls-fragment"
	case LayerNone:
		return "none"
	}
	return "unknown"
}

type LayerStatus struct {
	Layer     ConnectionLayer `json:"layer"`
	Available bool            `json:"available"`
	Latency   time.Duration   `json:"latency_ms"`
	LastCheck time.Time       `json:"last_check"`
	Error     string          `json:"error,omitempty"`
}

type ConnectionManager struct {
	mu       sync.RWMutex
	statuses map[ConnectionLayer]LayerStatus
	active   ConnectionLayer
	config   *ConnectionConfig

	// Health check
	stopCh chan struct{}
	wg     sync.WaitGroup
}

type ConnectionConfig struct {
	// REALITY config
	RealityServer  string `json:"reality_server"`
	RealityPort    string `json:"reality_port"`
	RealityUUID    string `json:"reality_uuid"`
	RealitySNI     string `json:"reality_sni"`
	RealityPubKey  string `json:"reality_pubkey"`
	RealityShortID string `json:"reality_short_id"`

	// GSA config
	GSAScriptIDs []string `json:"gsa_script_ids"`
	GSAAuthKey   string   `json:"gsa_auth_key"`
	GSAFrontDomain string `json:"gsa_front_domain"`

	// DNS Tunnel config
	DNSTunnelDomain   string   `json:"dns_tunnel_domain"`
	DNSTunnelKey      string   `json:"dns_tunnel_key"`
	DNSTunnelResolvers []string `json:"dns_tunnel_resolvers"`

	// Auto deploy
	GASGoogleToken string `json:"gas_google_token"`
	CFAPIToken     string `json:"cf_api_token"`
	CFAccountID    string `json:"cf_account_id"`
}

func NewConnectionManager(cfg *ConnectionConfig) *ConnectionManager {
	cm := &ConnectionManager{
		statuses: make(map[ConnectionLayer]LayerStatus),
		active:   LayerNone,
		config:   cfg,
		stopCh:   make(chan struct{}),
	}
	return cm
}

func (cm *ConnectionManager) Start() {
	cm.wg.Add(1)
	go cm.healthLoop()
}

func (cm *ConnectionManager) Stop() {
	close(cm.stopCh)
	cm.wg.Wait()
}

func (cm *ConnectionManager) healthLoop() {
	defer cm.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Initial check
	cm.checkAllLayers()

	for {
		select {
		case <-ticker.C:
			cm.checkAllLayers()
			cm.selectBestLayer()
		case <-cm.stopCh:
			return
		}
	}
}

func (cm *ConnectionManager) checkAllLayers() {
	var wg sync.WaitGroup
	check := func(layer ConnectionLayer) {
		defer wg.Done()
		status := cm.checkLayer(layer)
		cm.mu.Lock()
		cm.statuses[layer] = status
		cm.mu.Unlock()
	}

	// Always check these
	wg.Add(1)
	go check(LayerDirect)

	if cm.config != nil {
		if cm.config.RealityServer != "" {
			wg.Add(1)
			go check(LayerREALITY)
		}
		if len(cm.config.GSAScriptIDs) > 0 {
			wg.Add(1)
			go check(LayerGSA)
		}
		if cm.config.DNSTunnelDomain != "" {
			wg.Add(1)
			go check(LayerDNSTunnel)
		}
	}

	wg.Wait()
}

func (cm *ConnectionManager) checkLayer(layer ConnectionLayer) LayerStatus {
	status := LayerStatus{
		Layer:     layer,
		LastCheck: time.Now(),
	}

	timeout := 5 * time.Second
	start := time.Now()

	switch layer {
	case LayerDirect:
		conn, err := net.DialTimeout("tcp", "8.8.8.8:443", timeout)
		if err != nil {
			status.Error = err.Error()
			return status
		}
		conn.Close()
		status.Available = true

	case LayerREALITY:
		addr := net.JoinHostPort(cm.config.RealityServer, cm.config.RealityPort)
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			status.Error = err.Error()
			return status
		}
		conn.Close()
		status.Available = true

	case LayerGSA:
		if len(cm.config.GSAScriptIDs) == 0 {
			status.Error = "no GSA scripts configured"
			return status
		}
		scriptID := cm.config.GSAScriptIDs[rand.Intn(len(cm.config.GSAScriptIDs))]
		url := fmt.Sprintf("https://script.google.com/macros/s/%s/exec", scriptID)
		client := &http.Client{Timeout: timeout}
		resp, err := client.Get(url)
		if err != nil {
			status.Error = err.Error()
			return status
		}
		resp.Body.Close()
		status.Available = resp.StatusCode == 200

	case LayerDNSTunnel:
		if cm.config == nil || cm.config.DNSTunnelDomain == "" {
			status.Error = "no DNS tunnel configured"
			return status
		}
		resolvers := cm.config.DNSTunnelResolvers
		if len(resolvers) == 0 {
			resolvers = []string{"8.8.8.8:53", "1.1.1.1:53"}
		}
		for _, resolver := range resolvers {
			conn, err := net.DialTimeout("udp", resolver, timeout)
			if err != nil {
				continue
			}
			conn.SetDeadline(time.Now().Add(timeout))
			// Simple DNS query to verify
			msg := []byte{0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
			msg = append(msg, []byte(cm.config.DNSTunnelDomain)...)
			msg = append(msg, 0x00, 0x00, 0x01, 0x00, 0x01)
			conn.Write(msg)
			reply := make([]byte, 512)
			n, _ := conn.Read(reply)
			conn.Close()
			if n > 0 && len(reply) > 4 && reply[2]&0x80 != 0 {
				status.Available = true
				break
			}
		}

	case LayerTLSFragment:
		conn, err := net.DialTimeout("tcp", "8.8.8.8:443", timeout)
		if err != nil {
			status.Error = err.Error()
			return status
		}
		conn.Close()
		status.Available = true
	}

	status.Latency = time.Since(start)
	return status
}

func (cm *ConnectionManager) selectBestLayer() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Priority order: REALITY > XHTTP > GSA > TLS-Fragment > DNS-Tunnel > Direct
	priority := []ConnectionLayer{
		LayerREALITY,
		LayerXHTTP,
		LayerGSA,
		LayerTLSFragment,
		LayerDNSTunnel,
		LayerDirect,
	}

	best := LayerNone
	for _, layer := range priority {
		if status, ok := cm.statuses[layer]; ok && status.Available {
			best = layer
			break
		}
	}

	if best != cm.active {
		oldLayer := cm.active
		cm.active = best
		fmt.Printf("[connman] switched: %s -> %s\n", oldLayer, best)
	}
}

func (cm *ConnectionManager) GetActiveLayer() ConnectionLayer {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.active
}

func (cm *ConnectionManager) GetStatuses() []LayerStatus {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	result := make([]LayerStatus, 0, len(cm.statuses))
	for _, s := range cm.statuses {
		result = append(result, s)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Layer < result[j].Layer
	})
	return result
}

func (cm *ConnectionManager) SetConfig(cfg *ConnectionConfig) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.config = cfg
}
