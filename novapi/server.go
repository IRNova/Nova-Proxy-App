package novapi

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/TheCanniball/CipherGate/src/core"
)

type Server struct {
	cfg       *core.Config
	relayCtrl RelayController
	mu        sync.RWMutex
	logs      []string
	logsMu    sync.Mutex
	started   bool
}

type RelayController interface {
	Start()
	Stop()
	Stats() map[string]any
	IsRunning() bool
}

type simpleRelayCtrl struct {
	startFn  func()
	stopFn   func()
	statsFn  func() map[string]any
	running  bool
}

func (s *simpleRelayCtrl) Start()                { s.startFn(); s.running = true }
func (s *simpleRelayCtrl) Stop()                 { s.stopFn(); s.running = false }
func (s *simpleRelayCtrl) Stats() map[string]any { return s.statsFn() }
func (s *simpleRelayCtrl) IsRunning() bool       { return s.running }

func NewServer(cfg *core.Config, relayCtrl RelayController) *Server {
	return &Server{cfg: cfg, relayCtrl: relayCtrl}
}

func NewRelayController(start, stop func(), stats func() map[string]any) RelayController {
	return &simpleRelayCtrl{startFn: start, stopFn: stop, statsFn: stats}
}

func (s *Server) Start(port int) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/__nova/", s.handleNova)
	mux.HandleFunc("/__nova/api/", s.handleAPI)

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if port == 0 {
		addr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	_ = port // ignore unused
	go http.Serve(ln, mux)
	return nil
}

func (s *Server) AddLog(level, msg string) {
	s.logsMu.Lock()
	s.logs = append(s.logs, fmt.Sprintf("[%s] %s: %s", time.Now().Format("15:04:05"), level, msg))
	if len(s.logs) > 500 {
		s.logs = s.logs[len(s.logs)-500:]
	}
	s.logsMu.Unlock()
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		http.Redirect(w, r, "/__nova/", http.StatusFound)
		return
	}
	http.NotFound(w, r)
}

func (s *Server) handleNova(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/__nova")
	path = strings.TrimSuffix(path, "/")

	if path == "" || path == "/dashboard" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(adminHTML))
		return
	}
	http.NotFound(w, r)
}

func (s *Server) handleAPI(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/__nova/api")
	path = strings.TrimSuffix(path, "/")

	switch {
	case path == "/status" || path == "/status/":
		s.apiStatus(w, r)
	case path == "/start":
		s.apiStart(w, r)
	case path == "/stop":
		s.apiStop(w, r)
	case path == "/logs" || path == "/logs/":
		s.apiLogs(w, r)
	case path == "/logs-clear":
		s.apiLogsClear(w, r)
	case path == "/layers":
		s.apiLayers(w, r)
	case path == "/tunnel":
		s.apiTunnel(w, r)
	case path == "/config":
		s.apiConfig(w, r)
	case path == "/settings/get":
		s.apiSettingsGet(w, r)
	case path == "/settings/set":
		s.apiSettingsSet(w, r)
	case path == "/mode/switch":
		s.apiModeSwitch(w, r)
	case strings.HasPrefix(path, "/mitm/"):
		s.apiMITMStub(w, r)
	case strings.HasPrefix(path, "/dns/"):
		s.apiDNSStub(w, r)
	case path == "/pac":
		s.apiPACStub(w, r)
	case path == "/client-config":
		s.apiClientConfig(w, r)
	case strings.HasPrefix(path, "/deploy/"):
		s.apiDeployStub(w, r)
	default:
		writeJSON(w, map[string]string{"error": "unknown endpoint"})
	}
}

func (s *Server) apiStatus(w http.ResponseWriter, r *http.Request) {
	stats := s.relayCtrl.Stats()
	scriptIDs := ""
	if len(s.cfg.ScriptIDs) > 0 && s.cfg.ScriptIDs[0] != "" {
		scriptIDs = fmt.Sprintf("%d script(s)", len(s.cfg.ScriptIDs))
	} else {
		scriptIDs = "not configured"
	}
	writeJSON(w, map[string]any{
		"running":    s.relayCtrl.IsRunning(),
		"mode":       "MHR",
		"engine":     "MasterHttpRelayVPN",
		"addr":       fmt.Sprintf("127.0.0.1:%d", s.cfg.Proxy.Port),
		"google_ip":  s.cfg.GoogleIP,
		"front":      s.cfg.FrontDomain,
		"scripts":    scriptIDs,
		"socks5":     fmt.Sprintf("127.0.0.1:%d", s.cfg.Proxy.SOCKS5.Port),
		"stats":      stats,
		"time":       time.Now().Unix(),
	})
}

func (s *Server) apiStart(w http.ResponseWriter, r *http.Request) {
	go s.relayCtrl.Start()
	s.started = true
	s.AddLog("INFO", "relay engine started")
	writeJSON(w, map[string]string{"status": "started"})
}

func (s *Server) apiStop(w http.ResponseWriter, r *http.Request) {
	s.relayCtrl.Stop()
	s.started = false
	s.AddLog("INFO", "relay engine stopped")
	writeJSON(w, map[string]string{"status": "stopped"})
}

func (s *Server) apiLogs(w http.ResponseWriter, r *http.Request) {
	s.logsMu.Lock()
	out := s.logs
	if len(out) > 200 {
		out = out[len(out)-200:]
	}
	s.logsMu.Unlock()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(strings.Join(out, "\n")))
}

func (s *Server) apiLogsClear(w http.ResponseWriter, r *http.Request) {
	s.logsMu.Lock()
	s.logs = nil
	s.logsMu.Unlock()
	writeJSON(w, map[string]string{"status": "cleared"})
}

func (s *Server) apiLayers(w http.ResponseWriter, r *http.Request) {
	mhrLatency := int64(0)
	if stats, ok := s.relayCtrl.Stats()["latency_ms"]; ok {
		mhrLatency = toInt64(stats)
	}
	writeJSON(w, map[string]any{
		"active": "MasterHttpRelayVPN",
		"layers": []map[string]any{
			{"layer": "MasterHttpRelayVPN (GAS)", "available": true, "latency": mhrLatency},
		},
	})
}

func (s *Server) apiTunnel(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{"state": "idle"})
}

func (s *Server) apiConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.cfg)
}

func (s *Server) apiSettingsGet(w http.ResponseWriter, r *http.Request) {
	frontDomains := ""
	if len(s.cfg.FrontDomains) > 0 {
		frontDomains = strings.Join(s.cfg.FrontDomains, ",")
	}
	scriptIDs := strings.Join(s.cfg.ScriptIDs, ",")

	writeJSON(w, map[string]any{
		"general": []map[string]any{
			{"key": "google_ip", "label": "Google IP", "value": s.cfg.GoogleIP, "type": "string", "description": "Target Google IP for domain fronting"},
			{"key": "front_domain", "label": "Front Domain (SNI)", "value": s.cfg.FrontDomain, "type": "string", "description": "SNI host for TLS handshake"},
			{"key": "front_domains", "label": "Front Domains (fallback)", "value": frontDomains, "type": "string", "description": "Comma-separated SNI pool"},
			{"key": "script_ids", "label": "GAS Script IDs", "value": scriptIDs, "type": "string", "description": "Comma-separated Apps Script deployment IDs"},
			{"key": "auth_key", "label": "Auth Key", "value": s.cfg.AuthKey, "type": "password"},
		},
		"relay": []map[string]any{
			{"key": "relay_timeout", "label": "Relay Timeout (s)", "value": fmt.Sprintf("%d", s.cfg.Relay.Timeout), "type": "string"},
			{"key": "max_body", "label": "Max Response Body (bytes)", "value": fmt.Sprintf("%d", s.cfg.Relay.MaxResponseBody), "type": "string"},
			{"key": "parallel", "label": "Parallel Relays", "value": fmt.Sprintf("%d", s.cfg.Relay.ParallelRelay), "type": "string"},
			{"key": "pool_max", "label": "Connection Pool Max", "value": fmt.Sprintf("%d", s.cfg.Relay.PoolMax), "type": "string"},
			{"key": "verify_ssl", "label": "Verify SSL", "value": s.cfg.Relay.VerifySSL, "type": "bool"},
			{"key": "sni_probe", "label": "SNI Probing", "value": s.cfg.Relay.SNIProbeEnabled, "type": "bool"},
			{"key": "sub_batch", "label": "Sub-Batching", "value": s.cfg.Relay.SubBatch, "type": "bool"},
		},
		"proxy": []map[string]any{
			{"key": "proxy_port", "label": "HTTP Proxy Port", "value": fmt.Sprintf("%d", s.cfg.Proxy.Port), "type": "string"},
			{"key": "socks_port", "label": "SOCKS5 Port", "value": fmt.Sprintf("%d", s.cfg.Proxy.SOCKS5.Port), "type": "string"},
		},
	})
}

func (s *Server) apiSettingsSet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) apiModeSwitch(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{"status": "switched"})
}

func (s *Server) apiMITMStub(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{"message": "MITM not available in this build"})
}

func (s *Server) apiDNSStub(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) apiPACStub(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("function FindProxyForURL(url, host) { return 'PROXY 127.0.0.1:8080'; }"))
}

func (s *Server) apiClientConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"content":  "# CipherGate Client Config\nlisten: 127.0.0.1:8080\nsocks5: 127.0.0.1:1080",
		"filename": "ciphergate-config.txt",
	})
}

func (s *Server) apiDeployStub(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"success": false,
		"message": "Deployment not available in Desktop mode. Use the CLI version instead.",
	})
}

func toInt64(v any) int64 {
	switch t := v.(type) {
	case int64:
		return t
	case float64:
		return int64(t)
	case int:
		return int64(t)
	}
	return 0
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
