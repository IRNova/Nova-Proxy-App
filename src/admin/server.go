package admin

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/TheCanniball/CipherGate/src/core"
)

type Server struct {
	cfg     *core.AdminConfig
	relay   interface{ Stats() map[string]any }
	ln      net.Listener
	wg      sync.WaitGroup
	stopCh  chan struct{}
}

func NewServer(cfg *core.AdminConfig, relay interface{ Stats() map[string]any }) *Server {
	return &Server{
		cfg:    cfg,
		relay:  relay,
		stopCh: make(chan struct{}),
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleDashboard)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/config", s.handleConfig)

	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("admin listen: %w", err)
	}
	s.ln = ln
	srv := &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		srv.Serve(ln)
	}()
	fmt.Printf("Admin panel at http://%s\n", addr)
	return nil
}

func (s *Server) Stop() {
	close(s.stopCh)
	if s.ln != nil {
		s.ln.Close()
	}
	s.wg.Wait()
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.New("dash").Parse(indexHTML))
	tmpl.Execute(w, nil)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := s.relay.Stats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

const indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>CipherGate Admin</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f0f1a;color:#e0e0e0;padding:24px}
.card{background:#1a1a2e;border-radius:12px;padding:24px;margin-bottom:16px}
h1{font-size:24px;margin-bottom:16px;color:#7c3aed}
.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
.stat{text-align:center;padding:16px;background:#16213e;border-radius:8px}
.stat-value{font-size:28px;font-weight:700;color:#7c3aed}
.stat-label{font-size:12px;color:#888;margin-top:4px}
</style>
</head>
<body>
<h1>CipherGate</h1>
<div class="card">
<h2>Relay Statistics</h2>
<div class="stat-grid">
<div class="stat"><div class="stat-value" id="reqs">0</div><div class="stat-label">Requests</div></div>
<div class="stat"><div class="stat-value" id="latency">0ms</div><div class="stat-label">Latency</div></div>
<div class="stat"><div class="stat-value" id="bw">0 B</div><div class="stat-label">Bandwidth</div></div>
<div class="stat"><div class="stat-value" id="fails">0</div><div class="stat-label">Fails</div></div>
</div>
</div>
<script>
function fetchStats(){fetch('/api/stats').then(r=>r.json()).then(d=>{document.getElementById('reqs').textContent=d.requests||0;document.getElementById('latency').textContent=(d.latency_ms||0)+'ms';document.getElementById('bw').textContent=formatBytes(d.bandwidth||0);document.getElementById('fails').textContent=d.relay_fails||0}).catch(()=>{})}
function formatBytes(b){if(b<1024)return b+' B';if(b<1048576)return (b/1024).toFixed(1)+' KB';return (b/1048576).toFixed(1)+' MB'}
setInterval(fetchStats,2000);fetchStats()
</script>
</body>
</html>`
