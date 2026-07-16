package proxy

import (
	"encoding/json"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

type AdminServer struct {
	mu     sync.RWMutex
	proxy  *ProxyServer
	config *ConnectionConfig
	cm     *ConnectionManager
	start  func() error
	stop   func() error
}

func NewAdminServer(proxy *ProxyServer) *AdminServer {
	return &AdminServer{
		proxy: proxy,
	}
}

func (a *AdminServer) SetConnectionManager(cm *ConnectionManager) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cm = cm
}

func (a *AdminServer) SetConfig(cfg *ConnectionConfig) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config = cfg
}

func (a *AdminServer) SetControlHandlers(start, stop func() error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.start = start
	a.stop = stop
}

func (a *AdminServer) Handle(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/__nova")
	path = strings.TrimSuffix(path, "/")

	switch {
	case path == "" || path == "/dashboard":
		a.serveDashboard(w, r)
	case path == "/api/status":
		a.apiStatus(w, r)
	case path == "/api/start":
		a.apiStart(w, r)
	case path == "/api/stop":
		a.apiStop(w, r)
	case path == "/api/layers":
		a.apiLayers(w, r)
	case path == "/api/config":
		a.apiConfig(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (a *AdminServer) serveDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	tmpl.Execute(w, nil)
}

func (a *AdminServer) apiStatus(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{
		"running": a.proxy != nil && a.proxy.IsRunning(),
		"mode":    a.proxy.GetMode(),
		"addr":    a.proxy.GetListenAddr(),
		"time":    time.Now().Unix(),
	}
	if a.config != nil {
		resp["config"] = a.config
	}
	writeJSON(w, resp)
}

func (a *AdminServer) apiStart(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	fn := a.start
	a.mu.RUnlock()
	if fn == nil {
		writeJSON(w, map[string]string{"error": "no start handler"})
		return
	}
	if err := fn(); err != nil {
		writeJSON(w, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, map[string]string{"status": "started"})
}

func (a *AdminServer) apiStop(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	fn := a.stop
	a.mu.RUnlock()
	if fn == nil {
		writeJSON(w, map[string]string{"error": "no stop handler"})
		return
	}
	if err := fn(); err != nil {
		writeJSON(w, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, map[string]string{"status": "stopped"})
}

func (a *AdminServer) apiLayers(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	cm := a.cm
	a.mu.RUnlock()

	if cm == nil {
		writeJSON(w, map[string]string{"error": "no connection manager"})
		return
	}

	statuses := cm.GetStatuses()
	sort.Slice(statuses, func(i, j int) bool {
		return statuses[i].Layer < statuses[j].Layer
	})

	active := cm.GetActiveLayer()
	writeJSON(w, map[string]interface{}{
		"active": active.String(),
		"layers": statuses,
	})
}

func (a *AdminServer) apiConfig(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	cfg := a.config
	a.mu.RUnlock()

	switch r.Method {
	case http.MethodGet:
		if cfg == nil {
			writeJSON(w, map[string]string{"error": "no config"})
			return
		}
		writeJSON(w, cfg)

	case http.MethodPost:
		var newCfg ConnectionConfig
		if err := json.NewDecoder(r.Body).Decode(&newCfg); err != nil {
			writeJSON(w, map[string]string{"error": err.Error()})
			return
		}
		a.mu.Lock()
		a.config = &newCfg
		a.mu.Unlock()
		if a.cm != nil {
			a.cm.SetConfig(&newCfg)
		}
		writeJSON(w, map[string]string{"status": "updated"})

	default:
		http.Error(w, "method not allowed", 405)
	}
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// Embedded admin template
var tmpl = template.Must(template.New("admin").Parse(adminHTML))

const adminHTML = `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>نواپروکسی</title>
<link rel="icon" href="/__novaproxy_favicon__">
<style>
:root{--bg:#0a0a0a;--card:#141414;--text:#e5e5e5;--muted:#a3a3a3;--green:#22c55e;--red:#ef4444;--yellow:#eab308;--blue:#3b82f6;--border:rgba(255,255,255,.08)}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
.nav{background:var(--card);border-bottom:1px solid var(--border);padding:12px 24px;display:flex;align-items:center;gap:16px}
.nav h1{font-size:18px;font-weight:700}
.nav .badge{padding:4px 12px;border-radius:999px;font-size:12px;font-weight:600}
.badge.on{background:rgba(34,197,94,.15);color:var(--green)}
.badge.off{background:rgba(239,68,68,.15);color:var(--red)}
.container{max-width:960px;margin:0 auto;padding:24px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px;margin-bottom:24px}
.card{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:20px}
.card h3{font-size:14px;color:var(--muted);margin-bottom:8px;font-weight:500}
.card .val{font-size:24px;font-weight:700}
.card .sub{font-size:12px;color:var(--muted);margin-top:4px}
.layers{display:flex;flex-direction:column;gap:8px}
.layer{display:flex;align-items:center;justify-content:space-between;padding:12px 16px;background:var(--bg);border-radius:12px;border:1px solid var(--border)}
.layer .name{font-size:14px;font-weight:500}
.layer .status{font-size:12px;padding:4px 10px;border-radius:999px}
.status-up{background:rgba(34,197,94,.15);color:var(--green)}
.status-down{background:rgba(239,68,68,.15);color:var(--red)}
.status-active{background:rgba(59,130,246,.15);color:var(--blue)}
.actions{display:flex;gap:8px;margin-bottom:24px}
.btn{padding:10px 24px;border:none;border-radius:12px;font-size:14px;font-weight:600;cursor:pointer;transition:opacity .2s}
.btn:hover{opacity:.8}
.btn-start{background:var(--green);color:#000}
.btn-stop{background:var(--red);color:#fff}
.btn-config{background:var(--card);color:var(--text);border:1px solid var(--border)}
.logs{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:16px;font-family:monospace;font-size:12px;line-height:1.6;max-height:300px;overflow-y:auto;white-space:pre-wrap;color:var(--muted)}
</style>
</head>
<body>
<div class="nav">
  <h1>🛡️ نواپروکسی</h1>
  <span id="badge" class="badge off">خاموش</span>
  <span style="flex:1"></span>
  <span id="mode" style="font-size:13px;color:var(--muted)">متصل نشده</span>
</div>
<div class="container">
  <div class="actions">
    <button class="btn btn-start" onclick="startProxy()">شروع</button>
    <button class="btn btn-stop" onclick="stopProxy()">توقف</button>
    <button class="btn btn-config" onclick="refresh()">🔄 بروزرسانی</button>
  </div>
  <div class="grid">
    <div class="card">
      <h3>وضعیت</h3>
      <div class="val" id="statusVal">--</div>
      <div class="sub" id="statusSub">در حال بررسی...</div>
    </div>
    <div class="card">
      <h3>لایه فعال</h3>
      <div class="val" id="activeLayer">--</div>
      <div class="sub">بهترین مسیر موجود</div>
    </div>
    <div class="card">
      <h3>آدرس پروکسی</h3>
      <div class="val" id="proxyAddr">--</div>
      <div class="sub">HTTP/S Proxy</div>
    </div>
  </div>
  <h2 style="font-size:16px;margin-bottom:12px">🌐 لایه‌های اتصال</h2>
  <div id="layers" class="layers"></div>
  <h2 style="font-size:16px;margin:24px 0 12px">📋 لاگ</h2>
  <div id="logs" class="logs">در حال بارگیری...</div>
</div>
<script>
let logInterval;
async function api(path){const r=await fetch(path);return r.json()}
function renderLayer(l,isActive){
  const cls=isActive?'status-active':l.available?'status-up':'status-down';
  const label=isActive?'فعال':l.available?'متصل':'قطع';
  return '<div class="layer"><span class="name">'+l.layer+'</span><span class="status '+cls+'">'+label+(l.latency>0?' '+l.latency+'ms':'')+'</span></div>'
}
async function refresh(){
  try{
    const s=await api('/__nova/api/status');
    const badge=document.getElementById('badge');
    if(s.running){badge.className='badge on';badge.textContent='روشن'}
    else{badge.className='badge off';badge.textContent='خاموش'}
    document.getElementById('mode').textContent='حالت: '+s.mode;
    document.getElementById('statusVal').textContent=s.running?'✅ فعال':'⛔ غیرفعال';
    document.getElementById('statusSub').textContent=s.running?'پروکسی در حال کار':'پروکسی متوقف است';
    document.getElementById('proxyAddr').textContent=s.addr||'--';
  }catch(e){
    document.getElementById('statusVal').textContent='❌ خطا';
    document.getElementById('statusSub').textContent='عدم ارتباط با هسته';
  }
  try{
    const l=await api('/__nova/api/layers');
    document.getElementById('activeLayer').textContent=l.active||'--';
    if(l.layers){document.getElementById('layers').innerHTML=l.layers.map(x=>renderLayer(x,x.layer==l.active)).join('')}
  }catch(e){}
}
async function startProxy(){const r=await api('/__nova/api/start');refresh()}
async function stopProxy(){const r=await api('/__nova/api/stop');refresh()}
refresh()
</script>
</body>
</html>`
