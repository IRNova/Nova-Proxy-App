package relay

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TheCanniball/CipherGate/src/core"
	"golang.org/x/net/http2"
)

type Engine struct {
	cfg *core.Config

	connectHost string
	sniHost     string
	sniHosts    []string
	sniIdx      uint32
	httpHost    string
	scriptIDs   []string
	parallelNum int
	authKey     string
	verifySSL   bool

	h2Mu          sync.Mutex
	h2Client      *http.Client
	h2FailCount   int
	h2BackoffUntil time.Time

	poolMu sync.Mutex
	pool   []net.Conn

	batchMu      sync.Mutex
	batchPending []batchItem
	batchTimer   *time.Timer

	sidBlacklist map[string]time.Time
	blacklistTTL time.Duration

	exitNode *exitNodeState

	reqCount    int64
	bwBytes     int64
	lastLatency int64
	relayFail   int
	lastRelayOK bool

	stopCh chan struct{}
	wg     sync.WaitGroup
}

type batchItem struct {
	payload map[string]any
	respCh  chan []byte
}

type exitNodeState struct {
	cfg       core.ExitNodeConfig
	hostSet   map[string]struct{}
	client    *http.Client
}

func NewEngine(cfg *core.Config) *Engine {
	fronts := buildSNIPool(cfg.FrontDomain, cfg.FrontDomains)
	ids := cfg.ScriptIDs
	if len(ids) == 0 {
		ids = []string{""}
	}

	e := &Engine{
		cfg:         cfg,
		connectHost: cfg.GoogleIP,
		sniHost:     cfg.FrontDomain,
		sniHosts:    fronts,
		httpHost:    "script.google.com",
		scriptIDs:   ids,
		parallelNum: cfg.Relay.ParallelRelay,
		authKey:     cfg.AuthKey,
		verifySSL:   cfg.Relay.VerifySSL,
		sidBlacklist: make(map[string]time.Time),
		blacklistTTL: 600 * time.Second,
		stopCh:      make(chan struct{}),
	}

	if cfg.ExitNode.Enabled {
		hostSet := make(map[string]struct{})
		for _, h := range cfg.ExitNode.Hosts {
			hostSet[strings.ToLower(h)] = struct{}{}
		}
		e.exitNode = &exitNodeState{
			cfg:     cfg.ExitNode,
			hostSet: hostSet,
			client:  &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}},
		}
	}
	return e
}

func (e *Engine) Start() {
	e.wg.Add(1)
	go e.warmUp()
	go e.heartbeatLoop()
	<-e.stopCh
}

func (e *Engine) Stop() {
	close(e.stopCh)
	e.wg.Wait()
	if e.h2Client != nil {
		if tr, ok := e.h2Client.Transport.(*http2.Transport); ok {
			tr.CloseIdleConnections()
		}
	}
	e.poolMu.Lock()
	for _, c := range e.pool {
		c.Close()
	}
	e.pool = nil
	e.poolMu.Unlock()
}

func (e *Engine) Relay(method, urlStr string, headers map[string]string, body []byte) []byte {
	start := time.Now()
	payload := e.buildPayload(method, urlStr, headers, body)
	errored := false
	defer func() {
		e.recordStats(urlStr, len(payload), start, errored)
	}()

	if e.exitNode != nil && e.exitNode.shouldUse(urlStr) {
		if resp := e.relayViaExitNode(payload); resp != nil {
			return resp
		}
	}

	resp, err := e.relaySingle(payload)
	if err != nil {
		errored = true
		return errorResponse(502, err.Error())
	}
	return resp
}

func (e *Engine) buildPayload(method, urlStr string, headers map[string]string, body []byte) map[string]any {
	p := map[string]any{"m": method, "u": urlStr, "r": false}
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

func (e *Engine) relaySingle(payload map[string]any) ([]byte, error) {
	full := map[string]any{}
	for k, v := range payload {
		full[k] = v
	}
	full["k"] = e.authKey
	jsonBody, _ := json.Marshal(full)

	path := e.execPath(fmt.Sprint(payload["u"]))
	_, _, body, err := e.h2Request(context.Background(), "POST", path, e.httpHost,
		map[string]string{"content-type": "application/json"}, jsonBody,
		time.Duration(e.cfg.Relay.Timeout)*time.Second)
	if err == nil {
		resp := e.parseResponse(body)
		if !isErrorResponse(resp) {
			return resp, nil
		}
		e.blacklistSID(path)
	}

	resp, err := e.h1Relay(path, jsonBody)
	if err != nil {
		return nil, err
	}
	return e.parseResponse(resp), nil
}

func (e *Engine) h2Request(ctx context.Context, method, path, host string, headers map[string]string, body []byte, timeout time.Duration) (int, map[string]string, []byte, error) {
	return e.doH2Request(ctx, method, path, host, headers, body, timeout)
}

func (e *Engine) h1Relay(path string, body []byte) ([]byte, error) {
	e.poolMu.Lock()
	var conn net.Conn
	for len(e.pool) > 0 {
		conn = e.pool[len(e.pool)-1]
		e.pool = e.pool[:len(e.pool)-1]
		if time.Since(time.Now()) < 0 {
			e.poolMu.Unlock()
			break
		}
		conn.Close()
		conn = nil
	}
	if conn == nil {
		e.poolMu.Unlock()
		dialer := &net.Dialer{Timeout: 15 * time.Second}
		var err error
		raw, err := dialer.Dial("tcp", net.JoinHostPort(e.connectHost, "443"))
		if err != nil {
			return nil, err
		}
		if tcp, ok := raw.(*net.TCPConn); ok {
			tcp.SetNoDelay(true)
		}
		tlsConn := tls.Client(raw, &tls.Config{
			ServerName:         e.nextSNI(),
			InsecureSkipVerify: !e.verifySSL,
		})
		if err := tlsConn.Handshake(); err != nil {
			raw.Close()
			return nil, err
		}
		conn = tlsConn
	} else {
		e.poolMu.Unlock()
	}

	req := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n", path, e.httpHost, len(body))
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}
	if _, err := conn.Write(body); err != nil {
		conn.Close()
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		return nil, err
	}
	e.poolMu.Lock()
	if len(e.pool) < e.cfg.Relay.PoolMax {
		e.pool = append(e.pool, conn)
	} else {
		conn.Close()
	}
	e.poolMu.Unlock()
	return buf[:n], nil
}

func (e *Engine) parseResponse(body []byte) []byte {
	text := strings.TrimSpace(string(body))
	if text == "" {
		return errorResponse(502, "empty response")
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(text), &data); err != nil {
		re := regexp.MustCompile(`\{.*\}`)
		if m := re.FindString(text); m != "" {
			if err := json.Unmarshal([]byte(m), &data); err != nil {
				return errorResponse(502, "bad JSON")
			}
		} else {
			return errorResponse(502, "no JSON")
		}
	}
	return e.parseJSON(data)
}

func (e *Engine) parseJSON(data map[string]any) []byte {
	if errMsg, ok := data["e"]; ok {
		return errorResponse(502, fmt.Sprintf("relay: %v", errMsg))
	}
	status := intVal(data["s"], 200)
	headers := map[string]any{}
	if h, ok := data["h"].(map[string]any); ok {
		headers = h
	}
	bodyRaw := ""
	if b, ok := data["b"].(string); ok {
		bodyRaw = b
	}
	decoded, err := base64.StdEncoding.DecodeString(bodyRaw)
	if err != nil {
		return errorResponse(502, "base64 error")
	}
	if gz, ok := data["gz"]; ok {
		if v, _ := gz.(float64); v == 1 {
			decoded = core.DecodeContent(decoded, "gzip")
		}
	}
	if len(decoded) > e.cfg.Relay.MaxResponseBody {
		return errorResponse(502, "response too large")
	}
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("HTTP/1.1 %d OK\r\n", status))
	skip := map[string]bool{"transfer-encoding": true, "connection": true, "keep-alive": true, "content-length": true}
	for k, v := range headers {
		if skip[strings.ToLower(k)] {
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
	buf.WriteString(fmt.Sprintf("Content-Length: %d\r\n\r\n", len(decoded)))
	buf.Write(decoded)
	return buf.Bytes()
}

func (e *Engine) nextSNI() string {
	idx := atomic.AddUint32(&e.sniIdx, 1)
	return e.sniHosts[int(idx)%len(e.sniHosts)]
}

func (e *Engine) execPath(key string) string {
	sid := e.pickScriptID(key)
	return "/macros/s/" + sid + "/exec"
}

func (e *Engine) pickScriptID(key string) string {
	if len(e.scriptIDs) <= 1 {
		if len(e.scriptIDs) == 1 {
			return e.scriptIDs[0]
		}
		return ""
	}
	n := len(e.scriptIDs)
	for i := 0; i < n; i++ {
		var sid string
		if key == "" {
			sid = e.scriptIDs[i]
		} else {
			h := sha1.Sum([]byte(key))
			sid = e.scriptIDs[int(h[0])%n]
		}
		if _, blacklisted := e.sidBlacklist[sid]; !blacklisted {
			return sid
		}
		if expiry, ok := e.sidBlacklist[sid]; ok && time.Now().After(expiry) {
			delete(e.sidBlacklist, sid)
			return sid
		}
	}
	return e.scriptIDs[0]
}

func (e *Engine) blacklistSID(path string) {
	if len(e.scriptIDs) <= 1 {
		return
	}
	for _, sid := range e.scriptIDs {
		if strings.Contains(path, sid) {
			e.sidBlacklist[sid] = time.Now().Add(e.blacklistTTL)
			return
		}
	}
}

func (e *Engine) relayViaExitNode(payload map[string]any) []byte {
	if e.exitNode == nil {
		return nil
	}
	exitURL := strings.TrimRight(e.exitNode.cfg.URL, "/")
	apiURL := exitURL + "/relay"
	reqPayload := map[string]any{"m": payload["m"], "u": payload["u"]}
	if h, ok := payload["h"]; ok {
		reqPayload["h"] = h
	}
	if b, ok := payload["b"]; ok {
		reqPayload["b"] = b
	}
	if e.exitNode.cfg.PSK != "" {
		reqPayload["psk"] = e.exitNode.cfg.PSK
	}
	jsonBody, _ := json.Marshal(reqPayload)
	req, err := http.NewRequest("POST", apiURL, bytes.NewReader(jsonBody))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.exitNode.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return e.parseResponse(respBody)
}

func (e *Engine) recordStats(urlStr string, bodyLen int, start time.Time, errored bool) {
	atomic.AddInt64(&e.reqCount, 1)
	atomic.AddInt64(&e.bwBytes, int64(bodyLen))
	atomic.StoreInt64(&e.lastLatency, time.Since(start).Milliseconds())
}

func (e *Engine) Stats() map[string]any {
	return map[string]any{
		"requests":    atomic.LoadInt64(&e.reqCount),
		"bandwidth":   atomic.LoadInt64(&e.bwBytes),
		"latency_ms":  atomic.LoadInt64(&e.lastLatency),
		"relay_fails": e.relayFail,
		"alive":       e.lastRelayOK,
	}
}

func (e *Engine) warmUp() {
	for i := 0; i < 2; i++ {
		e.ping()
		time.Sleep(500 * time.Millisecond)
	}
}

func (e *Engine) heartbeatLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-e.stopCh:
			return
		case <-ticker.C:
			e.ping()
		}
	}
}

func (e *Engine) ping() {
	// Simple keepalive
}

func buildSNIPool(frontDomain string, overrides []string) []string {
	if len(overrides) > 0 {
		seen := map[string]bool{}
		out := []string{}
		for _, item := range overrides {
			host := strings.ToLower(strings.TrimSpace(item))
			if host != "" && !seen[host] {
				seen[host] = true
				out = append(out, host)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	base := strings.ToLower(strings.TrimSpace(frontDomain))
	if base == "" {
		return []string{"www.google.com"}
	}
	pool := []string{base}
	for _, h := range core.FRONT_SNI_POOL {
		if h != base {
			pool = append(pool, h)
		}
	}
	return pool
}

func headerValue(headers map[string]string, name string) string {
	for k, v := range headers {
		if strings.ToLower(k) == name {
			return v
		}
	}
	return ""
}

func errorResponse(status int, message string) []byte {
	body := fmt.Sprintf("<html><body><h1>%d</h1><p>%s</p></body></html>", status, message)
	return []byte(fmt.Sprintf("HTTP/1.1 %d Error\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n%s", status, len(body), body))
}

func isErrorResponse(resp []byte) bool {
	return bytes.HasPrefix(resp, []byte("HTTP/1.1 502")) || bytes.HasPrefix(resp, []byte("HTTP/1.1 503"))
}

func intVal(v any, def int) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	}
	return def
}

func (e *exitNodeState) shouldUse(urlStr string) bool {
	if !e.cfg.Enabled || e.cfg.URL == "" {
		return false
	}
	if e.cfg.Mode == "full" {
		return true
	}
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	if _, ok := e.hostSet[host]; ok {
		return true
	}
	for pattern := range e.hostSet {
		if strings.HasPrefix(pattern, ".") && strings.HasSuffix(host, pattern) {
			return true
		}
	}
	return false
}
