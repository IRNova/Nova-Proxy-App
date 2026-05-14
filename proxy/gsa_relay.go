package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/net/http2"
)

const (
	gsaRelayTimeout      = 25
	gsaTLSConnectTimeout = 15
	gsaMaxRespBody       = 200 * 1024 * 1024
	gsaPoolMax           = 50
	gsaConnTTL           = 45.0
	gsaCacheMaxMB        = 50
	gsaCacheTTLLong      = 3600
	gsaCacheTTLMed       = 1800
	gsaCacheTTLMax       = 86400
	gsaBatchMax          = 50
	gsaBatchWindow       = 5 * time.Millisecond
)

var gsaStaticExts = []string{
	".css", ".js", ".mjs", ".woff", ".woff2", ".ttf", ".eot",
	".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
	".mp3", ".mp4", ".webm", ".wasm", ".avif",
}

type gsaHostStat struct {
	Requests       int
	CacheHits      int
	Bytes          int
	TotalLatencyNs int64
	Errors         int
}

type gsaRelay struct {
	connectHost string
	sniHost     string
	sniHosts    []string
	sniIdx      uint32
	httpHost    string
	scriptIDs   []string
	scriptIdx   int

	authKey   string
	verifySSL bool
	relayTO   time.Duration
	tlsTO     time.Duration

	h2Mu     sync.Mutex
	h2Client *http.Client

	poolMu sync.Mutex
	pool   []gsaPooledConn

	batchMu      sync.Mutex
	batchPending []gsaBatchItem
	batchTimer   *time.Timer

	coalesceMu sync.Mutex
	coalesce   map[string][]chan []byte

	cache *gsaResponseCache

	perSite   map[string]*gsaHostStat
	statsMu   sync.RWMutex
	statsStop chan struct{}

	reqCount    int64
	bwBytes     int64
	cacheHits   int64
	cacheMisses int64
	latencyAvg  int64
	lastLatency int64

	heartbeatStop chan struct{}
	lastRelayOK   bool
	relayFail     int
}

type gsaPooledConn struct {
	conn    net.Conn
	created time.Time
}

type gsaBatchItem struct {
	payload map[string]any
	respCh  chan []byte
}

type gsaResponseCache struct {
	mu    sync.Mutex
	store map[string]gsaCacheEntry
	order []string
	size  int
	max   int
}

type gsaCacheEntry struct {
	raw     []byte
	expires time.Time
}

func newGSARelay(cfg GSAConfig) *gsaRelay {
	fronts := buildGSASNIPool(cfg.FrontDomain, cfg.FrontDomains)
	ids := cfg.ScriptIDs
	if len(ids) == 0 && cfg.ScriptID != "" {
		ids = []string{cfg.ScriptID}
	}

	r := &gsaRelay{
		connectHost:   cfg.GoogleIP,
		sniHost:       cfg.FrontDomain,
		sniHosts:      fronts,
		httpHost:      "script.google.com",
		scriptIDs:     ids,
		authKey:       cfg.AuthKey,
		verifySSL:     cfg.VerifySSL,
		relayTO:       time.Duration(cfg.RelayTimeout) * time.Second,
		tlsTO:         time.Duration(cfg.TLSConnectTimeout) * time.Second,
		coalesce:      map[string][]chan []byte{},
		cache:         newGSACache(gsaCacheMaxMB),
		perSite:       map[string]*gsaHostStat{},
		statsStop:     make(chan struct{}),
		heartbeatStop: make(chan struct{}),
	}
	if cfg.RelayTimeout <= 0 {
		r.relayTO = gsaRelayTimeout * time.Second
	}
	if cfg.TLSConnectTimeout <= 0 {
		r.tlsTO = gsaTLSConnectTimeout * time.Second
	}
	log.Printf("[GSA] Relay initialized: connect=%s front=%s ids=%d", cfg.GoogleIP, cfg.FrontDomain, len(ids))
	go r.heartbeatLoop()
	return r
}

func buildGSASNIPool(frontDomain string, overrides []string) []string {
	if len(overrides) > 0 {
		seen := map[string]bool{}
		out := []string{}
		for _, item := range overrides {
			host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(item), "."))
			if host != "" && !seen[host] {
				seen[host] = true
				out = append(out, host)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	fd := strings.ToLower(strings.TrimSuffix(frontDomain, "."))
	if fd == "" {
		return []string{"www.google.com"}
	}
	pool := []string{fd}
	extra := []string{"www.google.com", "mail.google.com", "accounts.google.com"}
	for _, h := range extra {
		if h != fd {
			pool = append(pool, h)
		}
	}
	return pool
}

func (r *gsaRelay) nextSNI() string {
	idx := atomic.AddUint32(&r.sniIdx, 1)
	return r.sniHosts[int(idx)%len(r.sniHosts)]
}

func (r *gsaRelay) ensureH2() {
	r.h2Mu.Lock()
	defer r.h2Mu.Unlock()
	if r.h2Client != nil {
		return
	}
	tr := &http2.Transport{
		AllowHTTP: false,
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			sni := r.nextSNI()
			tlsCfg := &tls.Config{
				ServerName:         sni,
				InsecureSkipVerify: !r.verifySSL,
				NextProtos:         []string{"h2", "http/1.1"},
			}
			dialer := &net.Dialer{Timeout: r.tlsTO}
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(r.connectHost, "443"))
			if err != nil {
				return nil, err
			}
			if tcp, ok := conn.(*net.TCPConn); ok {
				_ = tcp.SetNoDelay(true)
			}
			tlsConn := tls.Client(conn, tlsCfg)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = conn.Close()
				return nil, err
			}
			if tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
				_ = tlsConn.Close()
				return nil, fmt.Errorf("h2 ALPN negotiation failed")
			}
			return tlsConn, nil
		},
	}
	r.h2Client = &http.Client{Transport: tr}
	log.Printf("[GSA] H2 transport ready -> %s", r.connectHost)
}

func (r *gsaRelay) resetH2() {
	r.h2Mu.Lock()
	defer r.h2Mu.Unlock()
	if r.h2Client != nil {
		if tr, ok := r.h2Client.Transport.(*http2.Transport); ok {
			tr.CloseIdleConnections()
		}
	}
	r.h2Client = nil
}

func (r *gsaRelay) h2Request(ctx context.Context, method, path, host string, headers map[string]string, body []byte, timeout time.Duration) (int, map[string]string, []byte, error) {
	r.ensureH2()
	tH2Start := time.Now()
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	u := &url.URL{Scheme: "https", Host: host, Path: path}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Host = host

	ctx, cancel := context.WithTimeout(req.Context(), timeout)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := r.h2Client.Do(req)
	dH2 := time.Since(tH2Start)
	if err != nil {
		log.Printf("[GSA-H2] %s %s failed after %v: %v", method, path, dH2, err)
		r.resetH2()
		return 0, nil, nil, err
	}
	defer resp.Body.Close()

	if dH2 > 3*time.Second {
		log.Printf("[GSA-H2] %s %s slow response: %v (status=%d)", method, path, dH2, resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, nil, err
	}
	respHeaders := map[string]string{}
	for k, v := range resp.Header {
		if len(v) > 0 {
			respHeaders[strings.ToLower(k)] = v[0]
		}
	}
	if enc := respHeaders["content-encoding"]; enc != "" {
		data = gsaDecodeContent(data, enc)
	}
	return resp.StatusCode, respHeaders, data, nil
}

func (r *gsaRelay) relayRequest(method, urlStr string, headers map[string]string, body []byte) []byte {
	start := time.Now()
	payload := r.buildPayload(method, urlStr, headers, body)
	errored := false

	defer func() {
		r.recordStats(urlStr, len(payload), start, errored)
	}()

	if r.isStatefulRequest(method, urlStr, headers, body) {
		resp, err := r.relaySingle(payload)
		if err != nil {
			errored = true
			return gsaErrorResponse(502, err.Error())
		}
		return resp
	}

	key := r.coalesceKey(urlStr, headers)
	if strings.ToUpper(method) == "GET" && len(body) == 0 {
		if v := headerValue(headers, "range"); v == "" {
			if resp, ok := r.tryCoalesce(key, payload); ok {
				return resp
			}
		}
	}

	resp, err := r.batchSubmit(payload)
	dReq := time.Since(start)
	if dReq > 10*time.Second {
		log.Printf("[GSA-WATCHDOG] relayRequest %s %s took %v (errored=%v)", method, urlStr, dReq, err != nil)
	}
	if err != nil {
		errored = true
		return gsaErrorResponse(502, err.Error())
	}
	return resp
}

func (r *gsaRelay) buildPayload(method, urlStr string, headers map[string]string, body []byte) map[string]any {
	p := map[string]any{
		"m": method,
		"u": urlStr,
		"r": false,
	}
	if headers != nil {
		p["h"] = headers
	}
	if len(body) > 0 {
		p["b"] = base64.StdEncoding.EncodeToString(body)
		if ct := headerValue(headers, "content-type"); ct != "" {
			p["ct"] = ct
		}
	}
	return p
}

func (r *gsaRelay) scriptIDForKey(key string) string {
	if len(r.scriptIDs) <= 1 {
		if len(r.scriptIDs) == 1 {
			return r.scriptIDs[0]
		}
		return ""
	}
	if key == "" {
		r.scriptIdx = (r.scriptIdx + 1) % len(r.scriptIDs)
		return r.scriptIDs[r.scriptIdx]
	}
	h := sha1.Sum([]byte(key))
	idx := int(h[0]) % len(r.scriptIDs)
	return r.scriptIDs[idx]
}

func (r *gsaRelay) execPath(urlOrHost any) string {
	sid := r.scriptIDForKey(gsaHostKey(fmt.Sprint(urlOrHost)))
	return "/macros/s/" + sid + "/exec"
}

func gsaHostKey(urlOrHost string) string {
	if urlOrHost == "" {
		return ""
	}
	if strings.Contains(urlOrHost, "://") {
		parsed, err := url.Parse(urlOrHost)
		if err == nil {
			return strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
		}
	}
	return strings.ToLower(strings.TrimSuffix(urlOrHost, "."))
}

func (r *gsaRelay) relaySingle(payload map[string]any) ([]byte, error) {
	full := map[string]any{}
	for k, v := range payload {
		full[k] = v
	}
	full["k"] = r.authKey
	jsonBody, _ := json.Marshal(full)
	path := r.execPath(payload["u"])

	_, _, body, err := r.h2Request(context.Background(), "POST", path, r.httpHost,
		map[string]string{"content-type": "application/json"}, jsonBody, r.relayTO)
	if err == nil {
		return r.parseRelayResponse(body), nil
	}

	resp, err := r.relayHTTP1(path, jsonBody)
	if err != nil {
		return nil, err
	}
	return r.parseRelayResponse(resp), nil
}

func (r *gsaRelay) batchSubmit(payload map[string]any) ([]byte, error) {
	respCh := make(chan []byte, 1)
	item := gsaBatchItem{payload: payload, respCh: respCh}

	r.batchMu.Lock()
	r.batchPending = append(r.batchPending, item)
	if len(r.batchPending) >= gsaBatchMax {
		pending := r.batchPending
		r.batchPending = nil
		if r.batchTimer != nil {
			r.batchTimer.Stop()
			r.batchTimer = nil
		}
		r.batchMu.Unlock()
		go r.flushBatch(pending)
		return <-respCh, nil
	}
	if r.batchTimer == nil {
		r.batchTimer = time.AfterFunc(gsaBatchWindow, func() {
			r.batchMu.Lock()
			pending := r.batchPending
			r.batchPending = nil
			r.batchTimer = nil
			r.batchMu.Unlock()
			if len(pending) > 0 {
				r.flushBatch(pending)
			}
		})
	}
	r.batchMu.Unlock()
	return <-respCh, nil
}

func (r *gsaRelay) flushBatch(batch []gsaBatchItem) {
	if len(batch) == 1 {
		resp, err := r.relaySingle(batch[0].payload)
		if err != nil {
			resp = gsaErrorResponse(502, err.Error())
		}
		batch[0].respCh <- resp
		return
	}
	results, err := r.relayBatch(batch)
	if err != nil {
		for _, item := range batch {
			item.respCh <- gsaErrorResponse(502, err.Error())
		}
		return
	}
	for i, item := range batch {
		item.respCh <- results[i]
	}
}

func (r *gsaRelay) relayBatch(batch []gsaBatchItem) ([][]byte, error) {
	payloads := []map[string]any{}
	for _, item := range batch {
		payloads = append(payloads, item.payload)
	}
	full := map[string]any{
		"k": r.authKey,
		"q": payloads,
	}
	jsonBody, _ := json.Marshal(full)
	path := r.execPath(payloads[0]["u"])

	_, _, body, err := r.h2Request(context.Background(), "POST", path, r.httpHost,
		map[string]string{"content-type": "application/json"}, jsonBody, 30*time.Second)
	if err == nil {
		return r.parseBatchBody(body, len(batch))
	}
	resp, err := r.relayHTTP1(path, jsonBody)
	if err != nil {
		return nil, err
	}
	return r.parseBatchBody(resp, len(batch))
}

func (r *gsaRelay) relayHTTP1(path string, body []byte) ([]byte, error) {
	tHTTP1 := time.Now()
	conn, err := r.acquireConn()
	if err != nil {
		log.Printf("[GSA-H1] acquireConn failed for %s: %v", path, err)
		return nil, err
	}
	defer r.releaseConn(conn)

	req := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nAccept-Encoding: gzip\r\nConnection: keep-alive\r\n\r\n", path, r.httpHost, len(body))
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(body); err != nil {
		return nil, err
	}

	status, _, respBody, err := gsaReadHTTPResponse(conn, gsaMaxRespBody)
	if err != nil {
		log.Printf("[GSA-H1] read failed for %s: %v", path, err)
		return nil, err
	}
	if status >= 300 && status < 400 {
		return nil, fmt.Errorf("unexpected redirect: %d", status)
	}
	dH1 := time.Since(tHTTP1)
	if dH1 > 3*time.Second {
		log.Printf("[GSA-H1] slow: %s took %v (status=%d)", path, dH1, status)
	}
	log.Printf("[GSA-H1] %s: %v (status=%d)", path, dH1, status)
	return respBody, nil
}

func (r *gsaRelay) acquireConn() (net.Conn, error) {
	r.poolMu.Lock()
	for len(r.pool) > 0 {
		pc := r.pool[len(r.pool)-1]
		r.pool = r.pool[:len(r.pool)-1]
		if time.Since(pc.created) < time.Duration(gsaConnTTL*float64(time.Second)) {
			r.poolMu.Unlock()
			return pc.conn, nil
		}
		_ = pc.conn.Close()
	}
	r.poolMu.Unlock()

	dialer := &net.Dialer{Timeout: r.tlsTO}
	conn, err := dialer.Dial("tcp", net.JoinHostPort(r.connectHost, "443"))
	if err != nil {
		return nil, err
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
	tlsConn := tls.Client(conn, &tls.Config{ServerName: r.nextSNI(), InsecureSkipVerify: !r.verifySSL})
	if err := tlsConn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func (r *gsaRelay) releaseConn(conn net.Conn) {
	r.poolMu.Lock()
	defer r.poolMu.Unlock()
	if len(r.pool) >= gsaPoolMax {
		_ = conn.Close()
		return
	}
	r.pool = append(r.pool, gsaPooledConn{conn: conn, created: time.Now()})
}

func (r *gsaRelay) tryCoalesce(key string, payload map[string]any) ([]byte, bool) {
	r.coalesceMu.Lock()
	if waiters, ok := r.coalesce[key]; ok {
		ch := make(chan []byte, 1)
		r.coalesce[key] = append(waiters, ch)
		r.coalesceMu.Unlock()
		resp := <-ch
		return resp, true
	}
	r.coalesce[key] = []chan []byte{}
	r.coalesceMu.Unlock()

	resp, err := r.batchSubmit(payload)
	if err != nil {
		resp = gsaErrorResponse(502, err.Error())
	}

	r.coalesceMu.Lock()
	waiters := r.coalesce[key]
	delete(r.coalesce, key)
	r.coalesceMu.Unlock()
	for _, ch := range waiters {
		ch <- resp
	}
	return resp, true
}

func (r *gsaRelay) isStatefulRequest(method, urlStr string, headers map[string]string, body []byte) bool {
	method = strings.ToUpper(method)
	if method != "GET" && method != "HEAD" {
		return true
	}
	if len(body) > 0 {
		return true
	}
	statefulHeaders := []string{"cookie", "authorization", "proxy-authorization",
		"origin", "referer", "if-none-match", "if-modified-since", "cache-control", "pragma"}
	for _, name := range statefulHeaders {
		if headerValue(headers, name) != "" {
			return true
		}
	}
	accept := strings.ToLower(headerValue(headers, "accept"))
	if strings.Contains(accept, "text/html") || strings.Contains(accept, "application/json") {
		return true
	}
	fetchMode := strings.ToLower(headerValue(headers, "sec-fetch-mode"))
	if fetchMode == "navigate" || fetchMode == "cors" {
		return true
	}
	return !gsaIsStaticAsset(urlStr)
}

func gsaIsStaticAsset(urlStr string) bool {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	path := strings.ToLower(parsed.Path)
	for _, ext := range gsaStaticExts {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

func (r *gsaRelay) coalesceKey(urlStr string, headers map[string]string) string {
	key := []string{urlStr}
	if headers != nil {
		for _, name := range []string{"accept", "accept-language", "user-agent", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site"} {
			if v := headerValue(headers, name); v != "" {
				key = append(key, name+"="+v)
			}
		}
	}
	return strings.Join(key, "\n")
}

func (r *gsaRelay) parseRelayResponse(body []byte) []byte {
	text := strings.TrimSpace(string(body))
	if text == "" {
		return gsaErrorResponse(502, "Empty response from relay")
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(text), &data); err != nil {
		m := regexp.MustCompile(`\{.*\}`).FindString(text)
		if m == "" {
			return gsaErrorResponse(502, "No JSON: "+gsaTruncate(text, 200))
		}
		if err := json.Unmarshal([]byte(m), &data); err != nil {
			return gsaErrorResponse(502, "Bad JSON: "+gsaTruncate(text, 200))
		}
	}
	return r.parseRelayJSON(data)
}

func (r *gsaRelay) parseRelayJSON(data map[string]any) []byte {
	if e, ok := data["e"]; ok {
		return gsaErrorResponse(502, fmt.Sprintf("Relay error: %v", e))
	}
	status := gsaIntVal(data["s"], 200)
	headers := map[string]any{}
	if h, ok := data["h"].(map[string]any); ok {
		headers = h
	}
	bodyRaw := ""
	if b, ok := data["b"].(string); ok {
		bodyRaw = b
	}
	decodedBody, _ := base64.StdEncoding.DecodeString(bodyRaw)
	if len(decodedBody) > gsaMaxRespBody {
		return gsaErrorResponse(502, "Relay response exceeds cap")
	}

	statusText := "OK"
	switch status {
	case 206:
		statusText = "Partial Content"
	case 301:
		statusText = "Moved"
	case 302:
		statusText = "Found"
	case 304:
		statusText = "Not Modified"
	case 400:
		statusText = "Bad Request"
	case 403:
		statusText = "Forbidden"
	case 404:
		statusText = "Not Found"
	case 500:
		statusText = "Internal Server Error"
	}

	buf := bytes.NewBufferString(fmt.Sprintf("HTTP/1.1 %d %s\r\n", status, statusText))
	skip := map[string]bool{
		"transfer-encoding": true,
		"connection":        true,
		"keep-alive":        true,
		"content-length":    true,
		"content-encoding":  true,
	}
	for k, v := range headers {
		lk := strings.ToLower(k)
		if skip[lk] {
			continue
		}
		switch val := v.(type) {
		case []any:
			for _, item := range val {
				buf.WriteString(fmt.Sprintf("%s: %v\r\n", k, item))
			}
		default:
			buf.WriteString(fmt.Sprintf("%s: %v\r\n", k, val))
		}
	}
	buf.WriteString(fmt.Sprintf("Content-Length: %d\r\n\r\n", len(decodedBody)))
	buf.Write(decodedBody)
	return buf.Bytes()
}

func (r *gsaRelay) parseBatchBody(body []byte, expected int) ([][]byte, error) {
	text := strings.TrimSpace(string(body))
	var data map[string]any
	if err := json.Unmarshal([]byte(text), &data); err != nil {
		return nil, err
	}
	if e, ok := data["e"]; ok {
		return nil, fmt.Errorf("batch error: %v", e)
	}
	arr, ok := data["q"].([]any)
	if !ok || len(arr) != expected {
		return nil, fmt.Errorf("batch size mismatch: got %d, expected %d", len(arr), expected)
	}
	results := make([][]byte, 0, len(arr))
	for _, item := range arr {
		if obj, ok := item.(map[string]any); ok {
			results = append(results, r.parseRelayJSON(obj))
		}
	}
	return results, nil
}

func (r *gsaRelay) recordStats(urlStr string, bodyLen int, start time.Time, errored bool) {
	latency := time.Since(start).Nanoseconds()
	atomic.AddInt64(&r.reqCount, 1)
	atomic.AddInt64(&r.bwBytes, int64(bodyLen))
	atomic.StoreInt64(&r.lastLatency, latency/1e6)

	host := gsaHostKey(urlStr)
	if host == "" {
		return
	}
	r.statsMu.Lock()
	stat, ok := r.perSite[host]
	if !ok {
		stat = &gsaHostStat{}
		r.perSite[host] = stat
	}
	stat.Requests++
	stat.Bytes += bodyLen
	stat.TotalLatencyNs += latency
	if errored {
		stat.Errors++
	}
	r.statsMu.Unlock()

	avg := atomic.LoadInt64(&r.latencyAvg)
	if avg == 0 {
		atomic.StoreInt64(&r.latencyAvg, latency/1e6)
	} else {
		atomic.StoreInt64(&r.latencyAvg, (avg+latency/1e6)/2)
	}
}

func (r *gsaRelay) recordCacheHit() {
	atomic.AddInt64(&r.cacheHits, 1)
}

func (r *gsaRelay) recordCacheMiss() {
	atomic.AddInt64(&r.cacheMisses, 1)
}

func (r *gsaRelay) heartbeatLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.heartbeatStop:
			return
		case <-ticker.C:
			r.pingRelay()
		}
	}
}

func (r *gsaRelay) pingRelay() {
	tStart := time.Now()
	path := r.execPath("ping")
	body := map[string]any{"k": r.authKey, "m": "GET", "u": "https://ping/", "r": false}
	jsonBody, _ := json.Marshal(body)

	_, _, resp, err := r.h2Request(context.Background(), "POST", path, r.httpHost,
		map[string]string{"content-type": "application/json"}, jsonBody, 10*time.Second)
	if err != nil {
		resp, err = r.relayHTTP1(path, jsonBody)
	}
	d := time.Since(tStart)

	r.relayFail++
	if err != nil {
		log.Printf("[GSA-HEARTBEAT] FAIL after %v: %v (consecutive=%d)", d, err, r.relayFail)
		r.lastRelayOK = false
		if r.relayFail >= 3 {
			log.Printf("[GSA-HEARTBEAT] CRITICAL: %d consecutive relay failures!", r.relayFail)
		}
		r.resetH2()
		return
	}

	r.lastRelayOK = true
	r.relayFail = 0
	parsed := r.parseRelayResponse(resp)
	if len(parsed) == 0 {
		log.Printf("[GSA-HEARTBEAT] OK (%v) but empty response", d)
		return
	}
	log.Printf("[GSA-HEARTBEAT] OK (%v)", d)
}

func (r *gsaRelay) close() {
	close(r.statsStop)
	close(r.heartbeatStop)
	if r.h2Client != nil {
		if tr, ok := r.h2Client.Transport.(*http2.Transport); ok {
			tr.CloseIdleConnections()
		}
	}
	r.poolMu.Lock()
	for _, pc := range r.pool {
		_ = pc.conn.Close()
	}
	r.pool = nil
	r.poolMu.Unlock()
}

func newGSACache(maxMB int) *gsaResponseCache {
	return &gsaResponseCache{
		store: map[string]gsaCacheEntry{},
		order: []string{},
		max:   maxMB * 1024 * 1024,
	}
}

func (c *gsaResponseCache) get(url string) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.store[url]
	if !ok {
		return nil
	}
	if time.Now().After(entry.expires) {
		c.size -= len(entry.raw)
		delete(c.store, url)
		for i, u := range c.order {
			if u == url {
				c.order = append(c.order[:i], c.order[i+1:]...)
				break
			}
		}
		return nil
	}
	return entry.raw
}

func (c *gsaResponseCache) put(url string, raw []byte, ttl int) {
	if len(raw) == 0 {
		return
	}
	size := len(raw)
	if size > c.max/4 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for c.size+size > c.max && len(c.store) > 0 {
		oldURL := c.order[0]
		c.size -= len(c.store[oldURL].raw)
		delete(c.store, oldURL)
		c.order = c.order[1:]
	}
	if old, ok := c.store[url]; ok {
		for i, u := range c.order {
			if u == url {
				c.order = append(c.order[:i], c.order[i+1:]...)
				break
			}
		}
		c.size -= len(old.raw)
	}
	c.store[url] = gsaCacheEntry{raw: raw, expires: time.Now().Add(time.Duration(ttl) * time.Second)}
	c.order = append(c.order, url)
	c.size += size
}

func (c *gsaResponseCache) parseTTL(raw []byte, urlStr string) int {
	sep := []byte("\r\n\r\n")
	idx := bytes.Index(raw, sep)
	if idx < 0 {
		return 0
	}
	head := strings.ToLower(string(raw[:idx]))
	if !strings.HasPrefix(string(raw[:20]), "HTTP/1.1 200") {
		return 0
	}
	if strings.Contains(head, "no-store") || strings.Contains(head, "private") || strings.Contains(head, "set-cookie:") {
		return 0
	}
	re := regexp.MustCompile(`max-age=(\d+)`)
	if m := re.FindStringSubmatch(head); len(m) == 2 {
		v, _ := strconv.Atoi(m[1])
		if v > gsaCacheTTLMax {
			return gsaCacheTTLMax
		}
		return v
	}
	path := strings.ToLower(strings.Split(urlStr, "?")[0])
	for _, ext := range gsaStaticExts {
		if strings.HasSuffix(path, ext) {
			return gsaCacheTTLLong
		}
	}
	if strings.Contains(head, "image/") || strings.Contains(head, "font/") {
		return gsaCacheTTLLong
	}
	if strings.Contains(head, "text/css") || strings.Contains(head, "javascript") {
		return gsaCacheTTLMed
	}
	if strings.Contains(head, "text/html") || strings.Contains(head, "application/json") {
		return 0
	}
	return 0
}

func gsaDecodeContent(body []byte, encoding string) []byte {
	if len(body) == 0 {
		return body
	}
	enc := strings.TrimSpace(strings.ToLower(encoding))
	if enc == "" || enc == "identity" {
		return body
	}
	if strings.Contains(enc, ",") {
		parts := strings.Split(enc, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			body = gsaDecodeContent(body, strings.TrimSpace(parts[i]))
		}
		return body
	}
	switch enc {
	case "gzip":
		return gsaDecodeGzip(body)
	case "deflate":
		return gsaDecodeDeflate(body)
	case "br":
		return gsaDecodeBrotli(body)
	case "zstd":
		return gsaDecodeZstd(body)
	}
	return body
}

func gsaDecodeGzip(data []byte) []byte {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return data
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		return data
	}
	return out
}

func gsaDecodeDeflate(data []byte) []byte {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return data
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		return data
	}
	return out
}

func gsaDecodeBrotli(data []byte) []byte {
	r := brotli.NewReader(bytes.NewReader(data))
	out, err := io.ReadAll(r)
	if err != nil {
		return data
	}
	return out
}

func gsaDecodeZstd(data []byte) []byte {
	r, err := zstd.NewReader(bytes.NewReader(data))
	if err != nil {
		return data
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		return data
	}
	return out
}

func gsaReadHTTPResponse(conn net.Conn, maxBody int) (int, map[string]string, []byte, error) {
	reader := bufio.NewReaderSize(conn, 4096)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return 0, nil, nil, err
	}
	status := 0
	if m := regexp.MustCompile(`\d{3}`).FindString(statusLine); m != "" {
		status, _ = strconv.Atoi(m)
	}
	headers := map[string]string{}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return status, headers, nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			headers[strings.ToLower(strings.TrimSpace(parts[0]))] = strings.TrimSpace(parts[1])
		}
	}

	cl := 0
	if v := headers["content-length"]; v != "" {
		cl, _ = strconv.Atoi(v)
	}
	var body []byte
	if cl > 0 {
		if cl > maxBody {
			return status, headers, nil, fmt.Errorf("response exceeds cap: %d", cl)
		}
		buf := make([]byte, cl)
		_, err = io.ReadFull(reader, buf)
		if err != nil {
			return status, headers, nil, err
		}
		body = buf
	} else {
		body, _ = io.ReadAll(reader)
	}
	if enc := headers["content-encoding"]; enc != "" {
		body = gsaDecodeContent(body, enc)
	}
	return status, headers, body, nil
}

func gsaErrorResponse(status int, message string) []byte {
	body := fmt.Sprintf("<html><body><h1>%d</h1><p>%s</p></body></html>", status, message)
	return []byte(fmt.Sprintf("HTTP/1.1 %d Error\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n%s", status, len(body), body))
}

func gsaTruncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

func gsaIntVal(v any, def int) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case string:
		if i, err := strconv.Atoi(t); err == nil {
			return i
		}
	}
	return def
}

func headerValue(headers map[string]string, name string) string {
	for k, v := range headers {
		if strings.ToLower(k) == name {
			return v
		}
	}
	return ""
}

func gsaCORSPreflight(origin, acrMethod, acrHeaders string) []byte {
	allowOrigin := origin
	if allowOrigin == "" {
		allowOrigin = "*"
	}
	allowMethods := "GET, POST, PUT, DELETE, PATCH, OPTIONS"
	if acrMethod != "" {
		allowMethods = acrMethod + ", " + allowMethods
	}
	allowHeaders := acrHeaders
	if allowHeaders == "" {
		allowHeaders = "*"
	}
	resp := "HTTP/1.1 204 No Content\r\n" +
		"Access-Control-Allow-Origin: " + allowOrigin + "\r\n" +
		"Access-Control-Allow-Methods: " + allowMethods + "\r\n" +
		"Access-Control-Allow-Headers: " + allowHeaders + "\r\n" +
		"Access-Control-Allow-Credentials: true\r\n" +
		"Access-Control-Max-Age: 86400\r\n" +
		"Vary: Origin\r\n" +
		"Content-Length: 0\r\n\r\n"
	return []byte(resp)
}

func gsaInjectCORS(response []byte, origin string) []byte {
	sep := []byte("\r\n\r\n")
	idx := bytes.Index(response, sep)
	if idx < 0 {
		return response
	}
	head := string(response[:idx])
	body := response[idx+4:]
	lines := strings.Split(head, "\r\n")
	filtered := []string{}
	for _, ln := range lines {
		low := strings.ToLower(ln)
		if strings.HasPrefix(low, "access-control-") {
			continue
		}
		filtered = append(filtered, ln)
	}
	allowOrigin := origin
	if allowOrigin == "" {
		allowOrigin = "*"
	}
	filtered = append(filtered,
		"Access-Control-Allow-Origin: "+allowOrigin,
		"Access-Control-Allow-Credentials: true",
		"Access-Control-Allow-Methods: GET, POST, PUT, DELETE, PATCH, OPTIONS",
		"Access-Control-Allow-Headers: *",
		"Access-Control-Expose-Headers: *",
		"Vary: Origin",
	)
	newHead := strings.Join(filtered, "\r\n") + "\r\n\r\n"
	return append([]byte(newHead), body...)
}

type gsaMITMManager struct {
	mu     sync.Mutex
	caKey  crypto.Signer
	caCert *x509.Certificate
	cache  map[string]*tls.Certificate
}

func newGSAMITMManager() *gsaMITMManager {
	m := &gsaMITMManager{cache: map[string]*tls.Certificate{}}
	m.ensureCA()
	return m
}

func (m *gsaMITMManager) ensureCA() {
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now().UTC()
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, _ := rand.Int(rand.Reader, serialLimit)
	ca := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "nova-gsa",
			Organization: []string{"NovaProxy GSA"},
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}
	der, _ := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	cert, _ := x509.ParseCertificate(der)
	m.caKey = caKey
	m.caCert = cert
}

// useCA replaces the internal self-generated CA with an external one (e.g. Nova's CA).
// This lets GSA sign per-host certs with the same CA that Nova uses for MITM,
// so the user only needs to install one root CA.
func (m *gsaMITMManager) useCA(caCert *x509.Certificate, caKey crypto.Signer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.caCert = caCert
	m.caKey = caKey
	// Clear cache so new per-host certs are signed with the new CA
	m.cache = map[string]*tls.Certificate{}
}

func (m *gsaMITMManager) getCert(domain string) (*tls.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cert, ok := m.cache[domain]; ok {
		return cert, nil
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now().UTC()
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, _ := rand.Int(rand.Reader, serialLimit)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    now,
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(domain); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{domain}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, m.caCert, &key.PublicKey, m.caKey)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.caCert.Raw})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	tlsCert, err := tls.X509KeyPair(append(certPEM, caPEM...), keyPEM)
	if err != nil {
		return nil, err
	}
	m.cache[domain] = &tlsCert
	return &tlsCert, nil
}

type gsaProxyServer struct {
	relay    *gsaRelay
	host     string
	port     int
	listener net.Listener
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	started  chan struct{}
	mitm     *gsaMITMManager
}

func newGSAProxyServer(cfg GSAConfig, relay *gsaRelay, certGen CertGenerator) *gsaProxyServer {
	host := cfg.ListenHost
	if host == "" {
		host = "127.0.0.1"
	}
	if cfg.LANSharing && host == "127.0.0.1" {
		host = "0.0.0.0"
	}
	mitm := newGSAMITMManager()

	log.Printf("[GSA-MITM] newGSAProxyServer: certGen=%v", certGen != nil)

	// If Nova's CA is available, use it (so user installs only one root CA)
	if certGen != nil {
		caCert := certGen.GetCACert()
		caKey := certGen.GetCAKey()
		log.Printf("[GSA-MITM] certGen: caCert=%v caKey=%v", caCert != nil, caKey != nil)

		if caCert != nil && caKey != nil {
			log.Printf("[GSA-MITM] Nova CA CN: %s", caCert.Subject.CommonName)

			if signer, ok := caKey.(crypto.Signer); ok {
				log.Printf("[GSA-MITM] CA key type: %T - using Nova CA for GSA MITM", caKey)
				mitm.useCA(caCert, signer)
			} else {
				log.Printf("[GSA-MITM] WARNING: CA key type %T does not implement crypto.Signer - GSA will use its own self-generated CA!", caKey)
				log.Printf("[GSA-MITM] This will cause TLS handshake failures unless you also install GSA's CA certificate.")
			}
		}
	} else {
		log.Printf("[GSA-MITM] WARNING: certGen is nil - GSA will use its own self-generated CA!")
	}

	log.Printf("[GSA-MITM] GSA MITM CA CN: %s", mitm.caCert.Subject.CommonName)

	return &gsaProxyServer{
		relay:   relay,
		host:    host,
		port:    cfg.ListenPort,
		started: make(chan struct{}),
		mitm:    mitm,
	}
}

func (s *gsaProxyServer) start() error {
	s.ctx, s.cancel = context.WithCancel(context.Background())

	ln, err := net.Listen("tcp", net.JoinHostPort(s.host, strconv.Itoa(s.port)))
	if err != nil {
		return fmt.Errorf("gsa listen failed: %w", err)
	}
	s.listener = ln
	log.Printf("[GSA] HTTP proxy listening on %s:%d", s.host, s.port)

	close(s.started)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.acceptLoop(ln, s.handleHTTP)
	}()

	<-s.ctx.Done()
	_ = ln.Close()
	s.wg.Wait()
	return nil
}

func (s *gsaProxyServer) stop() {
	if s.cancel != nil {
		s.cancel()
	}
}

func (s *gsaProxyServer) acceptLoop(ln net.Listener, handler func(net.Conn)) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				continue
			}
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			handler(conn)
		}()
	}
}

func (s *gsaProxyServer) handleHTTP(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(120 * time.Second))

	reader := bufio.NewReaderSize(conn, 4096)
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	var headers []string
	headers = append(headers, line)
	totalLen := len(line)
	for {
		ln, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		headers = append(headers, ln)
		totalLen += len(ln)
		if totalLen > 65536 {
			return
		}
		if ln == "\r\n" || ln == "\n" {
			break
		}
	}

	parts := strings.SplitN(strings.TrimSpace(line), " ", 3)
	if len(parts) < 2 {
		return
	}
	method := strings.ToUpper(parts[0])

	if method == "CONNECT" {
		s.handleCONNECT(conn, reader, parts[1])
		return
	}

	urlStr := parts[1]
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		urlStr = "http://" + urlStr
	}

	// Check if destination should bypass GSA relay (e.g. Google sensitive services)
	if host := gsaExtractHost(urlStr); gsaShouldDirectConnect(host) {
		gsaTraceHost(host, urlStr, method)
		_ = conn.SetDeadline(time.Time{})
		s.relayRawTCP(host, 80, conn)
		return
	}

	headerMap := gsaParseHeaders(headers[1:])
	body := gsaReadBody(reader, headers)

	origin := headerValue(headerMap, "origin")
	acrMethod := headerValue(headerMap, "access-control-request-method")
	acrHeaders := headerValue(headerMap, "access-control-request-headers")
	if method == "OPTIONS" && acrMethod != "" {
		_, _ = conn.Write(gsaCORSPreflight(origin, acrMethod, acrHeaders))
		return
	}

	gsaTraceHost(gsaExtractHost(urlStr), urlStr, method)

	response := s.relay.relayRequest(method, urlStr, headerMap, body)
	if origin != "" {
		response = gsaInjectCORS(response, origin)
	}
	_, _ = conn.Write(response)
}

// gsaExtractHost extracts the hostname from a URL string.
func gsaExtractHost(urlStr string) string {
	if strings.Contains(urlStr, "://") {
		parsed, err := url.Parse(urlStr)
		if err == nil {
			return strings.ToLower(parsed.Hostname())
		}
	}
	return strings.ToLower(strings.Split(urlStr, ":")[0])
}

// gsaShouldDirectConnect returns true if the host should bypass GSA relay
// and connect directly (e.g. sensitive Google services like Gmail, Drive, Gemini).
func gsaShouldDirectConnect(host string) bool {
	if host == "" {
		return false
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))

	if _, ok := gsaGoogleDirectExactExclude[host]; ok {
		return true
	}
	for _, suffix := range gsaGoogleDirectSuffixExclude {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

// gsaNeedsSNIRewrite returns true if the host's SNI should be rewritten
// (e.g. YouTube, DoubleClick, Google Analytics).
func gsaNeedsSNIRewrite(host string) bool {
	if host == "" {
		return false
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, suffix := range gsaSNIRewriteSuffixes {
		if strings.HasSuffix(host, suffix) || host == suffix {
			return true
		}
	}
	return false
}

func gsaTraceHost(host, urlStr, method string) {
	for _, suffix := range gsaTraceHostSuffixes {
		if strings.Contains(host, suffix) {
			log.Printf("[GSA-TRACE] %s %s (host=%s)", method, urlStr, host)
			return
		}
	}
}

func (s *gsaProxyServer) handleCONNECT(conn net.Conn, reader *bufio.Reader, target string) {
	host, port := gsaSplitHostPort(target, 443)
	gsaTraceHost(host, target, "CONNECT")

	// Direct connect for excluded Google services
	if gsaShouldDirectConnect(host) {
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		_ = conn.SetDeadline(time.Time{})
		s.relayRawTCP(host, port, conn)
		return
	}

	if port == 443 {
		t0 := time.Now()
		tlsCert, err := s.mitm.getCert(host)
		if err != nil {
			log.Printf("[GSA] getCert failed for %s: %v", host, err)
			_, _ = conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}
		dCert := time.Since(t0)

		sni := host
		if gsaNeedsSNIRewrite(host) {
			sni = s.relay.sniHost
			log.Printf("[GSA] SNI rewrite for %s -> %s", host, sni)
		}

		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{*tlsCert},
			NextProtos:   []string{"http/1.1"},
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		t1 := time.Now()
		tlsConn := tls.Server(conn, tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			log.Printf("[GSA] TLS handshake failed for %s: %v (getCert=%v) - falling back to raw TCP", host, err, dCert)
			_ = conn.SetDeadline(time.Time{})
			s.relayRawTCP(host, port, conn)
			return
		}
		log.Printf("[GSA] CONNECT %s (getCert=%v, TLS=%v)", host, dCert, time.Since(t1))
		s.relayHTTPOverTLS(host, port, tlsConn)
		return
	}

	_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	_ = conn.SetDeadline(time.Time{})
	s.relayHTTPOverTLS(host, port, conn)
}

func (s *gsaProxyServer) relayRawTCP(host string, port int, client net.Conn) {
	dst, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 15*time.Second)
	if err != nil {
		log.Printf("[GSA] raw TCP dial failed for %s:%d: %v", host, port, err)
		return
	}
	defer dst.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, err := io.Copy(dst, client)
		log.Printf("[GSA] raw TCP client->dst %s:%d: %d bytes, err=%v", host, port, n, err)
	}()
	go func() {
		defer wg.Done()
		n, err := io.Copy(client, dst)
		log.Printf("[GSA] raw TCP dst->client %s:%d: %d bytes, err=%v", host, port, n, err)
	}()
	wg.Wait()
}

func (s *gsaProxyServer) relayHTTPOverTLS(host string, port int, conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(120 * time.Second))
	relayReader := bufio.NewReaderSize(conn, 4096)
	for {
		line, err := relayReader.ReadString('\n')
		if err != nil {
			return
		}
		if line == "\r\n" || line == "\n" {
			continue
		}

		var reqHeaders []string
		reqHeaders = append(reqHeaders, line)
		totalLen := len(line)
		for {
			ln, err := relayReader.ReadString('\n')
			if err != nil {
				return
			}
			reqHeaders = append(reqHeaders, ln)
			totalLen += len(ln)
			if totalLen > 65536 {
				return
			}
			if ln == "\r\n" || ln == "\n" {
				break
			}
		}

		method, path := gsaParseRequestLine(line)
		body := gsaReadBody(relayReader, reqHeaders)
		headerMap := gsaParseHeaders(reqHeaders[1:])

		origin := headerValue(headerMap, "origin")
		acrMethod := headerValue(headerMap, "access-control-request-method")
		acrHeaders := headerValue(headerMap, "access-control-request-headers")
		if strings.ToUpper(method) == "OPTIONS" && acrMethod != "" {
			_, _ = conn.Write(gsaCORSPreflight(origin, acrMethod, acrHeaders))
			continue
		}

		urlStr := gsaNormalizeURL(host, port, path)
		tReq := time.Now()
		response := s.relay.relayRequest(method, urlStr, headerMap, body)
		dReq := time.Since(tReq)
		if dReq > 5*time.Second {
			log.Printf("[GSA] SLOW relay: %s %s took %v", method, urlStr, dReq)
		}
		if origin != "" {
			response = gsaInjectCORS(response, origin)
		}
		_, _ = conn.Write(response)
	}
}



func gsaParseHeaders(lines []string) map[string]string {
	h := map[string]string{}
	for _, ln := range lines {
		ln = strings.TrimRight(ln, "\r\n")
		if ln == "" {
			continue
		}
		parts := strings.SplitN(ln, ":", 2)
		if len(parts) != 2 {
			continue
		}
		h[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	return h
}

func gsaReadBody(reader *bufio.Reader, headers []string) []byte {
	cl := 0
	for _, ln := range headers {
		if strings.HasPrefix(strings.ToLower(ln), "content-length:") {
			v := strings.TrimSpace(strings.TrimPrefix(strings.ToLower(ln), "content-length:"))
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return nil
			}
			cl = n
		}
	}
	if cl > 100*1024*1024 {
		return nil
	}
	if cl == 0 {
		return nil
	}
	buf := make([]byte, cl)
	_, err := io.ReadFull(reader, buf)
	if err != nil {
		return nil
	}
	return buf
}

func gsaParseRequestLine(line string) (string, string) {
	parts := strings.Split(strings.TrimSpace(line), " ")
	if len(parts) < 2 {
		return "GET", "/"
	}
	return parts[0], parts[1]
}

func gsaNormalizeURL(host string, port int, path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	scheme := "http"
	if port == 443 {
		scheme = "https"
	}
	if port == 80 || port == 443 {
		return fmt.Sprintf("%s://%s%s", scheme, host, path)
	}
	return fmt.Sprintf("%s://%s:%d%s", scheme, host, port, path)
}

func gsaSplitHostPort(target string, defPort int) (string, int) {
	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		if len(parts) >= 2 {
			port, _ := strconv.Atoi(parts[len(parts)-1])
			return strings.Join(parts[:len(parts)-1], ":"), port
		}
	}
	return target, defPort
}
