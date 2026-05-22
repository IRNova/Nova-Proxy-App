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
	"math/big"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/net/http2"

	"novaproxy/logging"
)

var (
	relayLog      = logging.Get("GAS")
	h2Log         = logging.Get("GAS-H2")
	h1Log         = logging.Get("GAS-H1")
	mitmLog       = logging.Get("GAS-MITM")
	statsLog      = logging.Get("GAS-STATS")
	gasCodecEncodings = "gzip, deflate, br, zstd"
)

const (
	gasRelayTimeout      = 25
	gasTLSConnectTimeout = 15
	gasMaxRespBody       = 200 * 1024 * 1024
	gasMaxPayloadSize    = 512 * 1024
	gasPoolMax           = 50
	gasConnTTL           = 45.0
	gasCacheMaxMB        = 50
	gasCacheTTLLong      = 3600
	gasCacheTTLMed       = 1800
	gasCacheTTLMax       = 86400
	gasBatchMax            = 50
	gasBatchWindow         = 5 * time.Millisecond
	gasParallelRelay       = 3
	chunkedMinSize         = 5 * 1024 * 1024
	chunkedMaxParallel     = 3
	chunkedChunkSize       = 2 * 1024 * 1024
	gasStatsLogInterval    = 300
	gasStatsLogTopN        = 10
	gasScriptBlacklistTTL  = 600.0
)

var gasStaticExts = []string{
	".css", ".js", ".mjs", ".woff", ".woff2", ".ttf", ".eot",
	".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
	".mp3", ".mp4", ".webm", ".wasm", ".avif",
}

var gasJSONRegex = regexp.MustCompile(`\{.*\}`)

type gasHostStat struct {
	Requests       int
	CacheHits      int
	Bytes          int
	TotalLatencyNs int64
	Errors         int
}

type gasRelay struct {
	connectHost string
	sniHost     string
	sniHosts    []string
	sniIdx      uint32
	httpHost    string
	scriptIDs   []string
	scriptIdx   int
	parallelNum int

	authKey   string
	verifySSL bool
	relayTO   time.Duration
	tlsTO     time.Duration

	maxRespBody int

	h2Mu          sync.Mutex
	h2Client      *http.Client
	h2FailCount   int
	h2BackoffUntil time.Time

	poolMu sync.Mutex
	pool   []gasPooledConn

	batchMu      sync.Mutex
	batchPending []gasBatchItem
	batchTimer   *time.Timer

	coalesceMu sync.Mutex
	coalesce   map[string][]chan []byte

	cache *gasResponseCache

	perSite   map[string]*gasHostStat
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

	sidBlacklist  map[string]time.Time
	blacklistTTL  time.Duration
	devAvail      bool

	closeMu sync.Mutex
	closed  bool
}

type gasPooledConn struct {
	conn    net.Conn
	created time.Time
}

type gasBatchItem struct {
	payload map[string]any
	respCh  chan []byte
}

type gasResponseCache struct {
	mu    sync.Mutex
	store map[string]gasCacheEntry
	order []string
	size  int
	max   int
}

type gasCacheEntry struct {
	raw     []byte
	expires time.Time
}

func newGASRelay(cfg GASConfig) *gasRelay {
	fronts := buildGASSNIPool(cfg.FrontDomain, cfg.FrontDomains)
	ids := cfg.ScriptIDs
	if len(ids) == 0 && cfg.ScriptID != "" {
		ids = []string{cfg.ScriptID}
	}

	r := &gasRelay{
		connectHost:   cfg.GoogleIP,
		sniHost:       cfg.FrontDomain,
		sniHosts:      fronts,
		httpHost:      "script.google.com",
		scriptIDs:     ids,
		parallelNum:   gasParallelRelay,
		authKey:       cfg.AuthKey,
		verifySSL:     cfg.VerifySSL,
		relayTO:       time.Duration(cfg.RelayTimeout) * time.Second,
		tlsTO:         time.Duration(cfg.TLSConnectTimeout) * time.Second,
		coalesce:      map[string][]chan []byte{},
		cache:         newGASCache(gasCacheMaxMB),
		perSite:       map[string]*gasHostStat{},
		statsStop:     make(chan struct{}),
		heartbeatStop: make(chan struct{}),
		sidBlacklist:  map[string]time.Time{},
		blacklistTTL:  time.Duration(gasScriptBlacklistTTL * float64(time.Second)),
	}
	if cfg.RelayTimeout <= 0 {
		r.relayTO = gasRelayTimeout * time.Second
	}
	if cfg.TLSConnectTimeout <= 0 {
		r.tlsTO = gasTLSConnectTimeout * time.Second
	}
	if cfg.MaxResponseBody > 0 {
		r.maxRespBody = int(cfg.MaxResponseBody)
	} else {
		r.maxRespBody = int(gasMaxRespBody)
	}
	relayLog.Infof("Relay initialized: connect=%s front=%s ids=%d maxBody=%d",
		cfg.GoogleIP, cfg.FrontDomain, len(ids), r.maxRespBody)
	go r.heartbeatLoop()
	go r.statsLoop()
	go r.warmUp()
	return r
}

func buildGASSNIPool(frontDomain string, overrides []string) []string {
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

func (r *gasRelay) nextSNI() string {
	idx := atomic.AddUint32(&r.sniIdx, 1)
	if len(r.sniHosts) == 0 {
		return "www.google.com"
	}
	return r.sniHosts[int(idx)%len(r.sniHosts)]
}

func (r *gasRelay) h2BackoffLeft() time.Duration {
	r.h2Mu.Lock()
	defer r.h2Mu.Unlock()
	if r.h2Client != nil {
		return 0
	}
	left := time.Until(r.h2BackoffUntil)
	if left < 0 {
		return 0
	}
	return left
}

func (r *gasRelay) ensureH2() {
	r.h2Mu.Lock()
	defer r.h2Mu.Unlock()
	if r.h2Client != nil {
		return
	}
	if time.Now().Before(r.h2BackoffUntil) {
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
			dialer := &net.Dialer{
				Timeout:   r.tlsTO,
				KeepAlive: 15 * time.Second,
			}
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(r.connectHost, "443"))
			if err != nil {
				return nil, err
			}
			if tcp, ok := conn.(*net.TCPConn); ok {
				_ = tcp.SetNoDelay(true)
				_ = tcp.SetKeepAlive(true)
				_ = tcp.SetKeepAlivePeriod(15 * time.Second)
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
	relayLog.Infof("H2 transport ready -> %s", r.connectHost)
}

func (r *gasRelay) resetH2() {
	r.h2Mu.Lock()
	defer r.h2Mu.Unlock()
	if r.h2Client != nil {
		if tr, ok := r.h2Client.Transport.(*http2.Transport); ok {
			tr.CloseIdleConnections()
		}
	}
	r.h2Client = nil
	r.h2FailCount++
	backoff := time.Duration(1<<min(r.h2FailCount, 5)) * time.Second
	if backoff > 30*time.Second {
		backoff = 30 * time.Second
	}
	r.h2BackoffUntil = time.Now().Add(backoff)
	h2Log.Warnf("Circuit breaker: backoff %v (fail #%d)", backoff, r.h2FailCount)
}

func (r *gasRelay) h2Request(ctx context.Context, method, path, host string, headers map[string]string, body []byte, timeout time.Duration) (int, map[string]string, []byte, error) {
	if r.h2BackoffLeft() > 0 {
		return 0, nil, nil, fmt.Errorf("H2 circuit breaker open (backoff %v)", r.h2BackoffLeft())
	}
	r.ensureH2()
	r.h2Mu.Lock()
	client := r.h2Client
	r.h2Mu.Unlock()
	if client == nil {
		return 0, nil, nil, fmt.Errorf("H2 client not available (circuit breaker)")
	}
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
	req.Header.Set("accept-encoding", gasCodecEncodings)
	req.Host = host

	ctx, cancel := context.WithTimeout(req.Context(), timeout)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := client.Do(req)
	dH2 := time.Since(tH2Start)
	if err != nil {
		h2Log.Errorf("%s %s failed after %v: %v", method, path, dH2, err)
		r.resetH2()
		return 0, nil, nil, err
	}
	// Success — reset circuit breaker
	r.h2Mu.Lock()
	r.h2FailCount = 0
	r.h2BackoffUntil = time.Time{}
	r.h2Mu.Unlock()
	defer resp.Body.Close()

	if dH2 > 3*time.Second {
		h2Log.Warnf("%s %s slow response: %v (status=%d)", method, path, dH2, resp.StatusCode)
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
		data = gasDecodeContent(data, enc)
	}
	return resp.StatusCode, respHeaders, data, nil
}

func (r *gasRelay) relayRequest(method, urlStr string, headers map[string]string, body []byte) []byte {
	start := time.Now()
	payload := r.buildPayload(method, urlStr, headers, body)
	errored := false

	// Estimate final payload size (with auth key)
	if len(body) > 0 {
		encodedSize := len(body) * 4 / 3
		if encodedSize > gasMaxPayloadSize {
			relayLog.Infof("Large request body %d bytes (encoded ~%d) for %s %s",
				len(body), encodedSize, method, urlStr)
		}
	}

	defer func() {
		r.recordStats(urlStr, len(payload), start, errored)
	}()

	if r.isStatefulRequest(method, urlStr, headers, body) {
		resp, err := r.relaySingle(payload)
		if err != nil {
			errored = true
			return gasErrorResponse(502, err.Error())
		}
		return resp
	}

	// Skip batching for large payloads (file downloads, streams) to avoid GAS timeout
	if len(body) > gasMaxPayloadSize/4 {
		resp, err := r.relaySingle(payload)
		if err != nil {
			errored = true
			return gasErrorResponse(502, err.Error())
		}
		dReq := time.Since(start)
		if dReq > 10*time.Second {
			relayLog.Warnf("relayRequest(single) %s %s took %v (errored=%v)", method, urlStr, dReq, err != nil)
		}
		return resp
	}

	// Chunked download for large file extensions with multiple script IDs
	if strings.ToUpper(method) == "GET" && len(body) == 0 && len(r.scriptIDs) > 1 {
		if v := headerValue(headers, "range"); v == "" && gasIsLargeFileExt(urlStr) {
			if resp := r.relayChunked(payload, urlStr, headers); resp != nil {
				return resp
			}
		}
	}

	// Use parallel fan-out for GET requests with multiple script IDs
	useParallel := strings.ToUpper(method) == "GET" && len(body) == 0 && r.parallelNum > 1 && len(r.scriptIDs) > 1
	if !useParallel {
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
			relayLog.Warnf("relayRequest %s %s took %v (errored=%v)", method, urlStr, dReq, err != nil)
		}
		if err != nil {
			errored = true
			return gasErrorResponse(502, err.Error())
		}
		return resp
	}

	key := r.coalesceKey(urlStr, headers)
	if resp, ok := r.tryCoalesce(key, payload); ok {
		return resp
	}
	if resp, pErr := r.relaySingleParallel(payload, r.parallelNum); pErr == nil {
		return resp
	} else {
		relayLog.Infof("All parallel failed, falling back to batch: %v", pErr)
	}
	errored = true

	resp, err := r.batchSubmit(payload)
	dReq := time.Since(start)
	if dReq > 10*time.Second {
		relayLog.Warnf("relayRequest %s %s took %v (errored=%v)", method, urlStr, dReq, err != nil)
	}
	if err != nil {
		errored = true
		return gasErrorResponse(502, err.Error())
	}
	return resp
}

func (r *gasRelay) buildPayload(method, urlStr string, headers map[string]string, body []byte) map[string]any {
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

func (r *gasRelay) scriptIDForKey(key string) string {
	if len(r.scriptIDs) <= 1 {
		if len(r.scriptIDs) == 1 {
			return r.scriptIDs[0]
		}
		return ""
	}
	for i := 0; i < len(r.scriptIDs); i++ {
		var sid string
		if key == "" {
			r.scriptIdx = (r.scriptIdx + 1) % len(r.scriptIDs)
			sid = r.scriptIDs[r.scriptIdx]
		} else {
			h := sha1.Sum([]byte(key))
			idx := int(h[0]) % len(r.scriptIDs)
			sid = r.scriptIDs[idx]
		}
		if _, blacklisted := r.sidBlacklist[sid]; !blacklisted {
			return sid
		}
		// Check if blacklist has expired
		if expiry, ok := r.sidBlacklist[sid]; ok && time.Now().After(expiry) {
			delete(r.sidBlacklist, sid)
			return sid
		}
	}
	// All blacklisted — return the first one anyway
	return r.scriptIDs[0]
}

func (r *gasRelay) execPath(urlOrHost any) string {
	sid := r.scriptIDForKey(gasHostKey(fmt.Sprint(urlOrHost)))
	if sid == "" {
		return "/macros/s/dev"
	}
	if r.devAvail {
		return "/macros/s/" + sid + "/dev"
	}
	return "/macros/s/" + sid + "/exec"
}

func gasIsLargeFileExt(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	for ext := range gasLargeFileExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// relayChunked downloads a large file in parallel chunks using multiple script IDs.
func (r *gasRelay) relayChunked(payload map[string]any, urlStr string, headers map[string]string) []byte {
	if len(r.scriptIDs) <= 1 {
		return nil
	}
	headPayload := r.buildPayload("HEAD", urlStr, headers, nil)
	headResp, err := r.relaySingle(headPayload)
	if err != nil {
		return nil
	}
	cl := gasParseContentLength(headResp)
	if cl <= chunkedMinSize {
		return nil
	}
	rangeVal := headerValue(headers, "range")
	if rangeVal != "" {
		return nil
	}

	numChunks := int((cl + chunkedChunkSize - 1) / chunkedChunkSize)
	if numChunks > chunkedMaxParallel {
		numChunks = chunkedMaxParallel
	}
	chunkSize := cl / int64(numChunks)
	if chunkSize < chunkedChunkSize {
		chunkSize = chunkedChunkSize
		numChunks = int((cl + chunkSize - 1) / chunkSize)
		if numChunks > chunkedMaxParallel {
			numChunks = chunkedMaxParallel
			chunkSize = cl / int64(numChunks)
		}
	}

	type chunkResult struct {
		data []byte
		idx  int
		err  error
	}
	ch := make(chan chunkResult, numChunks)

	n := len(r.scriptIDs)
	for i := 0; i < numChunks; i++ {
		start := int64(i) * chunkSize
		end := start + chunkSize - 1
		if i == numChunks-1 {
			end = cl - 1
		}
		rangeHdr := fmt.Sprintf("bytes=%d-%d", start, end)
		chunkHeaders := make(map[string]string, len(headers)+1)
		for k, v := range headers {
			chunkHeaders[k] = v
		}
		chunkHeaders["range"] = rangeHdr

		idx := (r.scriptIdx + i) % n
		sid := r.scriptIDs[idx]
		path := "/macros/s/" + sid + "/exec"
		go func(p string, ci int) {
			fullPayload := r.buildPayload("GET", urlStr, chunkHeaders, nil)
			fullPayload["k"] = r.authKey
			jsonBody, _ := json.Marshal(fullPayload)
			resp, err := r.relayHTTP1(p, jsonBody)
			if err != nil {
				ch <- chunkResult{nil, ci, err}
				return
			}
			parsed := r.parseRelayResponse(resp)
			if gasResponseBytesIsError(parsed) {
				ch <- chunkResult{nil, ci, fmt.Errorf("chunk %d error: relay error", ci)}
				return
			}
			body := gasExtractBody(parsed)
			ch <- chunkResult{body, ci, nil}
		}(path, i)
	}
	r.scriptIdx = (r.scriptIdx + numChunks) % n

	chunks := make([][]byte, numChunks)
	for i := 0; i < numChunks; i++ {
		res := <-ch
		if res.err != nil {
			relayLog.Infof("Chunk %d failed: %v", res.idx, res.err)
			return nil
		}
		chunks[res.idx] = res.data
	}

	var full []byte
	for _, c := range chunks {
		full = append(full, c...)
	}
	relayLog.Infof("Assembled %d chunks (%d bytes) for %s", numChunks, len(full), urlStr)

	statusLine := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n", len(full))
	if ct := headerValue(headers, "content-type"); ct != "" {
		statusLine += fmt.Sprintf("Content-Type: %s\r\n", ct)
	}
	statusLine += "\r\n"
	return append([]byte(statusLine), full...)
}

func gasParseContentLength(resp []byte) int64 {
	text := string(resp)
	for _, line := range strings.Split(text, "\r\n") {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "content-length:") {
			val := strings.TrimSpace(strings.TrimPrefix(line[16:], " "))
			n, _ := strconv.ParseInt(val, 10, 64)
			return n
		}
	}
	return 0
}

func gasExtractBody(resp []byte) []byte {
	idx := bytes.Index(resp, []byte("\r\n\r\n"))
	if idx < 0 {
		return nil
	}
	return resp[idx+4:]
}

func gasHostKey(urlOrHost string) string {
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

func (r *gasRelay) retryWithNextScript(path string) string {
	if len(r.scriptIDs) <= 1 {
		return path
	}
	// Cycle to next script ID
	r.scriptIdx = (r.scriptIdx + 1) % len(r.scriptIDs)
	sid := r.scriptIDs[r.scriptIdx]
	newPath := "/macros/s/" + sid + "/exec"
	relayLog.Warnf("Switching to script %s...", sid[:min(8, len(sid))])
	return newPath
}

func (r *gasRelay) blacklistSID(path string) {
	if len(r.scriptIDs) <= 1 {
		return
	}
	for _, sid := range r.scriptIDs {
		if strings.Contains(path, sid) {
			r.blacklistTTL = time.Duration(gasScriptBlacklistTTL * float64(time.Second))
			r.sidBlacklist[sid] = time.Now().Add(r.blacklistTTL)
			relayLog.Warnf("Script %s blacklisted for %v", sid[:min(8, len(sid))], r.blacklistTTL)
			return
		}
	}
}

func (r *gasRelay) relaySingle(payload map[string]any) ([]byte, error) {
	full := map[string]any{}
	for k, v := range payload {
		full[k] = v
	}
	full["k"] = r.authKey
	jsonBody, _ := json.Marshal(full)

	// Log warning for large payloads
	if len(jsonBody) > gasMaxPayloadSize {
		relayLog.Infof("Large payload %d bytes for %v", len(jsonBody), payload["u"])
	}

	path := r.execPath(payload["u"])

	_, _, body, err := r.h2Request(context.Background(), "POST", path, r.httpHost,
		map[string]string{"content-type": "application/json"}, jsonBody, r.relayTO)
	if err == nil {
		resp := r.parseRelayResponse(body)
		if !gasResponseBytesIsError(resp) {
			return resp, nil
		}
		// Error response — blacklist this script ID and retry
		relayLog.Warnf("relaySingle got error, retrying with different script")
		r.blacklistSID(path)
		path = r.retryWithNextScript(path)
		r.resetH2()
		_, _, body, err = r.h2Request(context.Background(), "POST", path, r.httpHost,
			map[string]string{"content-type": "application/json"}, jsonBody, r.relayTO)
		if err == nil {
			return r.parseRelayResponse(body), nil
		}
	}

	resp, err := r.relayHTTP1(path, jsonBody)
	if err != nil {
		r.blacklistSID(path)
		return nil, err
	}
	parsed := r.parseRelayResponse(resp)
	if gasResponseBytesIsError(parsed) {
		// Retry HTTP/1.1 with next script
		relayLog.Warnf("relayHTTP1 got error, retrying with different script")
		r.blacklistSID(path)
		path = r.retryWithNextScript(path)
		resp, err = r.relayHTTP1(path, jsonBody)
		if err != nil {
			return nil, err
		}
		return r.parseRelayResponse(resp), nil
	}
	return parsed, nil
}

// relaySingleParallel sends the request to multiple script IDs simultaneously
// and returns the first successful response. Falls back to relaySingle if only one script.
func (r *gasRelay) relaySingleParallel(payload map[string]any, numParallel int) ([]byte, error) {
	if len(r.scriptIDs) <= 1 || numParallel <= 1 {
		return r.relaySingle(payload)
	}
	if numParallel > len(r.scriptIDs) {
		numParallel = len(r.scriptIDs)
	}

	full := map[string]any{}
	for k, v := range payload {
		full[k] = v
	}
	full["k"] = r.authKey
	jsonBody, _ := json.Marshal(full)

	if len(jsonBody) > gasMaxPayloadSize {
		relayLog.Infof("Large payload %d bytes for %v", len(jsonBody), payload["u"])
	}

	type parResult struct {
		resp []byte
		err  error
	}
	resultCh := make(chan parResult, numParallel)

	n := len(r.scriptIDs)
	r.scriptIdx = (r.scriptIdx + 1) % n
	for i := 0; i < numParallel; i++ {
		idx := (r.scriptIdx + i) % n
		sid := r.scriptIDs[idx]
		path := "/macros/s/" + sid + "/exec"
		go func(p string) {
			resp, err := r.relayHTTP1(p, jsonBody)
			if err != nil {
				resultCh <- parResult{nil, err}
				return
			}
			parsed := r.parseRelayResponse(resp)
			if gasResponseBytesIsError(parsed) {
				p2 := r.retryWithNextScript(p)
				resp2, err2 := r.relayHTTP1(p2, jsonBody)
				if err2 != nil {
					resultCh <- parResult{nil, err2}
					return
				}
				resultCh <- parResult{r.parseRelayResponse(resp2), nil}
				return
			}
			resultCh <- parResult{parsed, nil}
		}(path)
	}
	r.scriptIdx = (r.scriptIdx + numParallel) % n

	var lastErr error
	for i := 0; i < numParallel; i++ {
		res := <-resultCh
		if res.err == nil {
			return res.resp, nil
		}
		lastErr = res.err
	}
	return nil, lastErr
}

func (r *gasRelay) batchSubmit(payload map[string]any) ([]byte, error) {
	respCh := make(chan []byte, 1)
	item := gasBatchItem{payload: payload, respCh: respCh}

	r.batchMu.Lock()
	r.batchPending = append(r.batchPending, item)
	if len(r.batchPending) >= gasBatchMax {
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
		r.batchTimer = time.AfterFunc(gasBatchWindow, func() {
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

func (r *gasRelay) flushBatch(batch []gasBatchItem) {
	if len(batch) == 1 {
		resp, err := r.relaySingle(batch[0].payload)
		if err != nil {
			resp = gasErrorResponse(502, err.Error())
		}
		batch[0].respCh <- resp
		return
	}
	results, err := r.relayBatch(batch)
	if err != nil {
		for _, item := range batch {
			item.respCh <- gasErrorResponse(502, err.Error())
		}
		return
	}
	for i, item := range batch {
		item.respCh <- results[i]
	}
}

func (r *gasRelay) relayBatch(batch []gasBatchItem) ([][]byte, error) {
	payloads := []map[string]any{}
	for _, item := range batch {
		payloads = append(payloads, item.payload)
	}
	full := map[string]any{
		"k": r.authKey,
		"q": payloads,
	}
	jsonBody, _ := json.Marshal(full)

	if len(jsonBody) > gasMaxPayloadSize {
		relayLog.Infof("Large batch payload %d bytes for %d items (consider increasing script count)",
			len(jsonBody), len(batch))
	}

	path := r.execPath(payloads[0]["u"])

	_, _, body, err := r.h2Request(context.Background(), "POST", path, r.httpHost,
		map[string]string{"content-type": "application/json"}, jsonBody, 30*time.Second)
	if err == nil {
		results, parseErr := r.parseBatchBody(body, len(batch))
		if parseErr == nil {
			return results, nil
		}
		// Try with next script ID
		relayLog.Warnf("relayBatch parse error: %v — retrying with different script", parseErr)
		path = r.retryWithNextScript(path)
		_, _, body, err = r.h2Request(context.Background(), "POST", path, r.httpHost,
			map[string]string{"content-type": "application/json"}, jsonBody, 30*time.Second)
		if err == nil {
			results, parseErr = r.parseBatchBody(body, len(batch))
			if parseErr == nil {
				return results, nil
			}
			return nil, parseErr
		}
	}
	resp, err := r.relayHTTP1(path, jsonBody)
	if err != nil {
		return nil, err
	}
	return r.parseBatchBody(resp, len(batch))
}

func (r *gasRelay) relayHTTP1(path string, body []byte) ([]byte, error) {
	tHTTP1 := time.Now()
	conn, err := r.acquireConn()
	if err != nil {
		h1Log.Infof("acquireConn failed for %s: %v", path, err)
		return nil, err
	}
	released := false
	defer func() {
		if !released {
			r.releaseConn(conn)
		}
	}()

	header := []byte(fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nAccept-Encoding: gzip\r\nConnection: keep-alive\r\n\r\n", path, r.httpHost, len(body)))
	req := append(header, body...)

	_, err = conn.Write(req)
	if err != nil {
		_ = conn.Close()
		h1Log.Infof("write failed for %s: %v — retrying with new connection", path, err)
		conn, err = r.acquireConn()
		if err != nil {
			return nil, err
		}
		_, err = conn.Write(req)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
	}

	status, respHeaders, respBody, err := gasReadHTTPResponse(conn, r.maxRespBody)
	if err != nil {
		_ = conn.Close()
		h1Log.Infof("read failed for %s: %v — retrying with new connection", path, err)
		conn2, err2 := r.acquireConn()
		if err2 != nil {
			return nil, err2
		}
		_, err2 = conn2.Write(req)
		if err2 != nil {
			_ = conn2.Close()
			return nil, err2
		}
		var h2 map[string]string
		status, h2, respBody, err = gasReadHTTPResponse(conn2, r.maxRespBody)
		if err != nil {
			_ = conn2.Close()
			return nil, err
		}
		respHeaders = h2
		conn = conn2
	}
	r.releaseConn(conn)
	released = true

	if status >= 300 && status < 400 {
		loc := respHeaders["location"]
		if loc != "" {
			parsed, parseErr := url.Parse(loc)
			if parseErr == nil {
				rpath := parsed.Path
				if parsed.RawQuery != "" {
					rpath += "?" + parsed.RawQuery
				}
				h1Log.Infof("Following redirect %d: %s -> %s", status, path, rpath)
				return r.relayHTTP1(rpath, body)
			}
		}
		return nil, fmt.Errorf("unexpected redirect: %d", status)
	}
	dH1 := time.Since(tHTTP1)
	if dH1 > 3*time.Second {
		h1Log.Infof("slow: %s took %v (status=%d)", path, dH1, status)
	}
	h1Log.Infof("%s: %v (status=%d)", path, dH1, status)
	return respBody, nil
}

func (r *gasRelay) acquireConn() (net.Conn, error) {
	r.poolMu.Lock()
	for len(r.pool) > 0 {
		pc := r.pool[len(r.pool)-1]
		r.pool = r.pool[:len(r.pool)-1]
		if time.Since(pc.created) < time.Duration(gasConnTTL*float64(time.Second)) {
			r.poolMu.Unlock()
			// Quick keep-alive check: set a 2-second peek deadline
			_ = pc.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, _ := pc.conn.Read(make([]byte, 1))
			_ = pc.conn.SetReadDeadline(time.Time{})
			if n > 0 {
				_ = pc.conn.Close()
				break
			}
			return pc.conn, nil
		}
		_ = pc.conn.Close()
	}
	r.poolMu.Unlock()

	dialer := &net.Dialer{
		Timeout:   r.tlsTO,
		KeepAlive: 15 * time.Second,
	}
	conn, err := dialer.Dial("tcp", net.JoinHostPort(r.connectHost, "443"))
	if err != nil {
		return nil, err
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(15 * time.Second)
	}
	tlsConn := tls.Client(conn, &tls.Config{ServerName: r.nextSNI(), InsecureSkipVerify: !r.verifySSL})
	if err := tlsConn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func (r *gasRelay) releaseConn(conn net.Conn) {
	r.poolMu.Lock()
	defer r.poolMu.Unlock()
	if len(r.pool) >= gasPoolMax {
		_ = conn.Close()
		return
	}
	r.pool = append(r.pool, gasPooledConn{conn: conn, created: time.Now()})
}

func (r *gasRelay) tryCoalesce(key string, payload map[string]any) ([]byte, bool) {
	r.coalesceMu.Lock()
	if waiters, ok := r.coalesce[key]; ok {
		ch := make(chan []byte, 1)
		r.coalesce[key] = append(waiters, ch)
		r.coalesceMu.Unlock()
		select {
		case resp := <-ch:
			return resp, true
		case <-time.After(30 * time.Second):
			return nil, false
		}
	}
	r.coalesce[key] = []chan []byte{}
	r.coalesceMu.Unlock()

	resp, err := r.batchSubmit(payload)
	if err != nil {
		resp = gasErrorResponse(502, err.Error())
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

func (r *gasRelay) isStatefulRequest(method, urlStr string, headers map[string]string, body []byte) bool {
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
	return !gasIsStaticAsset(urlStr)
}

func gasIsStaticAsset(urlStr string) bool {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	path := strings.ToLower(parsed.Path)
	for _, ext := range gasStaticExts {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

func (r *gasRelay) coalesceKey(urlStr string, headers map[string]string) string {
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

func gasLooksLikeHTMLError(body []byte) bool {
	if len(body) < 50 {
		return false
	}
	trimmed := strings.TrimSpace(strings.ToLower(string(body)))
	return strings.Contains(trimmed, "<html") &&
		(strings.Contains(trimmed, "error") ||
			strings.Contains(trimmed, "try again") ||
			strings.Contains(trimmed, "timeout") ||
			strings.Contains(trimmed, "unavailable"))
}

func gasResponseBytesIsError(resp []byte) bool {
	return len(resp) > 0 && (bytes.HasPrefix(resp, []byte("HTTP/1.1 502")) || bytes.HasPrefix(resp, []byte("HTTP/1.1 503")))
}

func (r *gasRelay) parseRelayResponse(body []byte) []byte {
	text := strings.TrimSpace(string(body))
	if text == "" {
		return gasErrorResponse(502, "Empty response from relay")
	}
	if gasLooksLikeHTMLError(body) {
		return gasErrorResponse(502, "GAS HTML error: "+gasTruncate(text, 200))
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(text), &data); err != nil {
		m := gasJSONRegex.FindString(text)
		if m == "" {
			return gasErrorResponse(502, "No JSON: "+gasTruncate(text, 200))
		}
		if err := json.Unmarshal([]byte(m), &data); err != nil {
			return gasErrorResponse(502, "Bad JSON: "+gasTruncate(text, 200))
		}
	}
	return r.parseRelayJSON(data)
}

func (r *gasRelay) parseRelayJSON(data map[string]any) []byte {
	if e, ok := data["e"]; ok {
		return gasErrorResponse(502, fmt.Sprintf("Relay error: %v", e))
	}
	status := gasIntVal(data["s"], 200)
	headers := map[string]any{}
	if h, ok := data["h"].(map[string]any); ok {
		headers = h
	}
	bodyRaw := ""
	if b, ok := data["b"].(string); ok {
		bodyRaw = b
	}
	decodedBody, err := base64.StdEncoding.DecodeString(bodyRaw)
	if err != nil {
		return gasErrorResponse(502, "Relay base64 decode error: "+err.Error())
	}
	if len(decodedBody) > r.maxRespBody {
		return gasErrorResponse(502, "Relay response exceeds cap ("+humanSize(r.maxRespBody)+")")
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

func (r *gasRelay) parseBatchBody(body []byte, expected int) ([][]byte, error) {
	text := strings.TrimSpace(string(body))
	if gasLooksLikeHTMLError(body) {
		return nil, fmt.Errorf("batch HTML error: %s", gasTruncate(text, 200))
	}
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

func (r *gasRelay) recordStats(urlStr string, bodyLen int, start time.Time, errored bool) {
	latency := time.Since(start).Nanoseconds()
	atomic.AddInt64(&r.reqCount, 1)
	atomic.AddInt64(&r.bwBytes, int64(bodyLen))
	atomic.StoreInt64(&r.lastLatency, latency/1e6)

	host := gasHostKey(urlStr)
	if host == "" {
		return
	}
	r.statsMu.Lock()
	stat, ok := r.perSite[host]
	if !ok {
		stat = &gasHostStat{}
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

func (r *gasRelay) recordCacheHit() {
	atomic.AddInt64(&r.cacheHits, 1)
}

func (r *gasRelay) recordCacheMiss() {
	atomic.AddInt64(&r.cacheMisses, 1)
}

func (r *gasRelay) statsLoop() {
	ticker := time.NewTicker(gasStatsLogInterval * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.statsStop:
			return
		case <-ticker.C:
			r.logStats()
		}
	}
}

func (r *gasRelay) logStats() {
	r.statsMu.RLock()
	count := len(r.perSite)
	if count == 0 {
		r.statsMu.RUnlock()
		return
	}
	entries := make([]struct {
		host string
		stat *gasHostStat
	}, 0, count)
	for host, stat := range r.perSite {
		entries = append(entries, struct {
			host string
			stat *gasHostStat
		}{host: host, stat: stat})
	}
	r.statsMu.RUnlock()

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].stat.Bytes > entries[j].stat.Bytes
	})
	n := gasStatsLogTopN
	if n > len(entries) {
		n = len(entries)
	}
	statsLog.Infof("Per-host stats (top %d by bytes, %d total hosts):", n, count)
	for i := 0; i < n; i++ {
		e := entries[i]
		avgLatency := time.Duration(0)
		if e.stat.Requests > 0 {
			avgLatency = time.Duration(e.stat.TotalLatencyNs / int64(e.stat.Requests))
		}
		statsLog.Infof("  %s: %d reqs, %.2fMB, %s avg, %d errs",
			e.host, e.stat.Requests, float64(e.stat.Bytes)/1024/1024, avgLatency, e.stat.Errors)
	}
}

func (r *gasRelay) warmUp() {
	relayLog.Infof("Starting warm-up...")
	// Force H2 client creation and pre-warm with quick pings
	for i := 0; i < 2; i++ {
		if i > 0 {
			time.Sleep(500 * time.Millisecond)
		}
		r.pingRelay()
		r.nextSNI()
	}
	relayLog.Infof("Warm-up complete")
}

func (r *gasRelay) heartbeatLoop() {
	ticker := time.NewTicker(60 * time.Second)
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

func (r *gasRelay) pingRelay() {
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

	if err != nil {
		r.relayFail++
		relayLog.Infof("FAIL after %v: %v (consecutive=%d)", d, err, r.relayFail)
		r.lastRelayOK = false
		if r.relayFail >= 5 {
			relayLog.Infof("CRITICAL: %d consecutive failures — full relay restart", r.relayFail)
			r.restart()
			return
		}
		if r.relayFail >= 3 {
			relayLog.Infof("WARNING: %d consecutive relay failures", r.relayFail)
		}
		r.resetH2()
		return
	}

	r.lastRelayOK = true
	r.relayFail = 0
	parsed := r.parseRelayResponse(resp)
	if len(parsed) == 0 {
		relayLog.Infof("OK (%v) but empty response", d)
		return
	}
	relayLog.Infof("OK (%v)", d)
}

func (r *gasRelay) close() {
	r.closeMu.Lock()
	if r.closed {
		r.closeMu.Unlock()
		return
	}
	r.closed = true
	r.closeMu.Unlock()

	close(r.statsStop)
	close(r.heartbeatStop)

	r.h2Mu.Lock()
	if r.h2Client != nil {
		if tr, ok := r.h2Client.Transport.(*http2.Transport); ok {
			tr.CloseIdleConnections()
		}
	}
	r.h2Mu.Unlock()

	r.poolMu.Lock()
	for _, pc := range r.pool {
		_ = pc.conn.Close()
	}
	r.pool = nil
	r.poolMu.Unlock()

	r.sidBlacklist = map[string]time.Time{}
}

func (r *gasRelay) restart() {
	relayLog.Infof("Full restart initiated...")

	r.h2Mu.Lock()
	if r.h2Client != nil {
		if tr, ok := r.h2Client.Transport.(*http2.Transport); ok {
			tr.CloseIdleConnections()
		}
	}
	r.h2Client = nil
	r.h2FailCount = 0
	r.h2BackoffUntil = time.Time{}
	r.h2Mu.Unlock()

	r.poolMu.Lock()
	for _, pc := range r.pool {
		_ = pc.conn.Close()
	}
	r.pool = nil
	r.poolMu.Unlock()

	r.batchMu.Lock()
	r.batchPending = nil
	if r.batchTimer != nil {
		r.batchTimer.Stop()
		r.batchTimer = nil
	}
	r.batchMu.Unlock()

	r.relayFail = 0
	r.lastRelayOK = false
	r.sidBlacklist = map[string]time.Time{}

	relayLog.Infof("Full restart complete")
}

func newGASCache(maxMB int) *gasResponseCache {
	return &gasResponseCache{
		store: map[string]gasCacheEntry{},
		order: []string{},
		max:   maxMB * 1024 * 1024,
	}
}

func (c *gasResponseCache) get(url string) []byte {
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

func (c *gasResponseCache) put(url string, raw []byte, ttl int) {
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
	c.store[url] = gasCacheEntry{raw: raw, expires: time.Now().Add(time.Duration(ttl) * time.Second)}
	c.order = append(c.order, url)
	c.size += size
}

func (c *gasResponseCache) parseTTL(raw []byte, urlStr string) int {
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
		if v > gasCacheTTLMax {
			return gasCacheTTLMax
		}
		return v
	}
	path := strings.ToLower(strings.Split(urlStr, "?")[0])
	for _, ext := range gasStaticExts {
		if strings.HasSuffix(path, ext) {
			return gasCacheTTLLong
		}
	}
	if strings.Contains(head, "image/") || strings.Contains(head, "font/") {
		return gasCacheTTLLong
	}
	if strings.Contains(head, "text/css") || strings.Contains(head, "javascript") {
		return gasCacheTTLMed
	}
	if strings.Contains(head, "text/html") || strings.Contains(head, "application/json") {
		return 0
	}
	return 0
}

func gasDecodeContent(body []byte, encoding string) []byte {
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
			body = gasDecodeContent(body, strings.TrimSpace(parts[i]))
		}
		return body
	}
	switch enc {
	case "gzip":
		return gasDecodeGzip(body)
	case "deflate":
		return gasDecodeDeflate(body)
	case "br":
		return gasDecodeBrotli(body)
	case "zstd":
		return gasDecodeZstd(body)
	}
	return body
}

func gasDecodeGzip(data []byte) []byte {
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

func gasDecodeDeflate(data []byte) []byte {
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

func gasDecodeBrotli(data []byte) []byte {
	r := brotli.NewReader(bytes.NewReader(data))
	out, err := io.ReadAll(r)
	if err != nil {
		return data
	}
	return out
}

func gasDecodeZstd(data []byte) []byte {
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

func gasReadHTTPResponse(conn net.Conn, maxBody int) (int, map[string]string, []byte, error) {
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
		body = gasDecodeContent(body, enc)
	}
	return status, headers, body, nil
}

func gasErrorResponse(status int, message string) []byte {
	body := fmt.Sprintf("<html><body><h1>%d</h1><p>%s</p></body></html>", status, message)
	return []byte(fmt.Sprintf("HTTP/1.1 %d Error\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n%s", status, len(body), body))
}

func gasTruncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

func gasIntVal(v any, def int) int {
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

func humanSize(bytes int) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func headerValue(headers map[string]string, name string) string {
	for k, v := range headers {
		if strings.ToLower(k) == name {
			return v
		}
	}
	return ""
}

func gasCORSPreflight(origin, acrMethod, acrHeaders string) []byte {
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

func gasInjectCORS(response []byte, origin string) []byte {
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

type gasMITMManager struct {
	mu     sync.Mutex
	caKey  crypto.Signer
	caCert *x509.Certificate
	cache  map[string]*tls.Certificate
}

func newGASMITMManager() *gasMITMManager {
	m := &gasMITMManager{cache: map[string]*tls.Certificate{}}
	m.ensureCA()
	return m
}

func (m *gasMITMManager) ensureCA() {
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now().UTC()
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, _ := rand.Int(rand.Reader, serialLimit)
	ca := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "nova-gas",
			Organization: []string{"NovaProxy GAS"},
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
// This lets GAS sign per-host certs with the same CA that Nova uses for MITM,
// so the user only needs to install one root CA.
func (m *gasMITMManager) useCA(caCert *x509.Certificate, caKey crypto.Signer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.caCert = caCert
	m.caKey = caKey
	// Clear cache so new per-host certs are signed with the new CA
	m.cache = map[string]*tls.Certificate{}
}

func (m *gasMITMManager) getCert(domain string) (*tls.Certificate, error) {
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

type gasProxyServer struct {
	relay    *gasRelay
	host     string
	port     int
	listener net.Listener
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	started  chan struct{}
	mitm     *gasMITMManager
}

func newGASProxyServer(cfg GASConfig, relay *gasRelay, certGen CertGenerator) *gasProxyServer {
	host := cfg.ListenHost
	if host == "" {
		host = "127.0.0.1"
	}
	if cfg.LANSharing && host == "127.0.0.1" {
		host = "0.0.0.0"
	}
	mitm := newGASMITMManager()

	mitmLog.Infof("newGASProxyServer: certGen=%v", certGen != nil)

	// If Nova's CA is available, use it (so user installs only one root CA)
	if certGen != nil {
		caCert := certGen.GetCACert()
		caKey := certGen.GetCAKey()
		mitmLog.Infof("certGen: caCert=%v caKey=%v", caCert != nil, caKey != nil)

		if caCert != nil && caKey != nil {
			mitmLog.Infof("Nova CA CN: %s", caCert.Subject.CommonName)

			if signer, ok := caKey.(crypto.Signer); ok {
				mitmLog.Infof("CA key type: %T - using Nova CA for GAS MITM", caKey)
				mitm.useCA(caCert, signer)
			} else {
				mitmLog.Infof("WARNING: CA key type %T does not implement crypto.Signer - GAS will use its own self-generated CA!", caKey)
				mitmLog.Infof("This will cause TLS handshake failures unless you also install GAS's CA certificate.")
			}
		}
	} else {
		mitmLog.Infof("WARNING: certGen is nil - GAS will use its own self-generated CA!")
	}

	mitmLog.Infof("GAS MITM CA CN: %s", mitm.caCert.Subject.CommonName)

	return &gasProxyServer{
		relay:   relay,
		host:    host,
		port:    cfg.ListenPort,
		started: make(chan struct{}),
		mitm:    mitm,
	}
}

func (s *gasProxyServer) start() error {
	s.ctx, s.cancel = context.WithCancel(context.Background())

	ln, err := net.Listen("tcp", net.JoinHostPort(s.host, strconv.Itoa(s.port)))
	if err != nil {
		return fmt.Errorf("gas listen failed: %w", err)
	}
	s.listener = ln
	relayLog.Infof("HTTP proxy listening on %s:%d", s.host, s.port)

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

func (s *gasProxyServer) stop() {
	if s.cancel != nil {
		s.cancel()
	}
}

func (s *gasProxyServer) acceptLoop(ln net.Listener, handler func(net.Conn)) {
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
			defer func() {
				if r := recover(); r != nil {
					relayLog.Errorf("handler recovered: %v", r)
				}
			}()
			handler(conn)
		}()
	}
}

func (s *gasProxyServer) handleHTTP(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(120 * time.Second))

	reader := bufio.NewReaderSize(conn, 4096)
	line, err := reader.ReadString('\n')
	if err != nil {
		_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}

	var headers []string
	headers = append(headers, line)
	totalLen := len(line)
	for {
		ln, err := reader.ReadString('\n')
		if err != nil {
			_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			return
		}
		headers = append(headers, ln)
		totalLen += len(ln)
		if totalLen > 65536 {
			_, _ = conn.Write([]byte("HTTP/1.1 413 Request Entity Too Large\r\n\r\n"))
			return
		}
		if ln == "\r\n" || ln == "\n" {
			break
		}
	}

	parts := strings.SplitN(strings.TrimSpace(line), " ", 3)
	if len(parts) < 2 {
		_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
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

	// Check if destination should bypass GAS relay (e.g. Google sensitive services)
	if host := gasExtractHost(urlStr); gasShouldDirectConnect(host) {
		gasTraceHost(host, urlStr, method)
		_ = conn.SetDeadline(time.Time{})
		s.relayRawTCP(host, 80, conn)
		return
	}

	headerMap := gasParseHeaders(headers[1:])
	body := gasReadBody(reader, headers)

	origin := headerValue(headerMap, "origin")
	acrMethod := headerValue(headerMap, "access-control-request-method")
	acrHeaders := headerValue(headerMap, "access-control-request-headers")
	if method == "OPTIONS" && acrMethod != "" {
		_, _ = conn.Write(gasCORSPreflight(origin, acrMethod, acrHeaders))
		return
	}

	gasTraceHost(gasExtractHost(urlStr), urlStr, method)

	response := s.relay.relayRequest(method, urlStr, headerMap, body)
	if origin != "" {
		response = gasInjectCORS(response, origin)
	}
	_, _ = conn.Write(response)
}

// gasExtractHost extracts the hostname from a URL string.
func gasExtractHost(urlStr string) string {
	if strings.Contains(urlStr, "://") {
		parsed, err := url.Parse(urlStr)
		if err == nil {
			return strings.ToLower(parsed.Hostname())
		}
	}
	return strings.ToLower(strings.Split(urlStr, ":")[0])
}

// gasShouldDirectConnect returns true if the host should bypass GAS relay
// and connect directly (e.g. sensitive Google services like Gmail, Drive, Gemini).
func gasShouldDirectConnect(host string) bool {
	if host == "" {
		return false
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))

	if _, ok := gasGoogleDirectExactExclude[host]; ok {
		return true
	}
	for _, suffix := range gasGoogleDirectSuffixExclude {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

// gasNeedsSNIRewrite returns true if the host's SNI should be rewritten
// (e.g. YouTube, DoubleClick, Google Analytics).
func gasNeedsSNIRewrite(host string) bool {
	if host == "" {
		return false
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, suffix := range gasSNIRewriteSuffixes {
		if strings.HasSuffix(host, suffix) || host == suffix {
			return true
		}
	}
	return false
}

func gasTraceHost(host, urlStr, method string) {
	for _, suffix := range gasTraceHostSuffixes {
		if strings.Contains(host, suffix) {
			relayLog.Debugf("%s %s (host=%s)", method, urlStr, host)
			return
		}
	}
}

func (s *gasProxyServer) handleCONNECT(conn net.Conn, reader *bufio.Reader, target string) {
	host, port := gasSplitHostPort(target, 443)
	gasTraceHost(host, target, "CONNECT")

	// Direct connect for excluded Google services
	if gasShouldDirectConnect(host) {
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		_ = conn.SetDeadline(time.Time{})
		s.relayRawTCP(host, port, conn)
		return
	}

	if port == 443 {
		t0 := time.Now()
		tlsCert, err := s.mitm.getCert(host)
		if err != nil {
			relayLog.Infof("getCert failed for %s: %v", host, err)
			_, _ = conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}
		dCert := time.Since(t0)

		sni := host
		if gasNeedsSNIRewrite(host) {
			sni = s.relay.sniHost
			relayLog.Infof("SNI rewrite for %s -> %s", host, sni)
		}

		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{*tlsCert},
			NextProtos:   []string{"http/1.1"},
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		t1 := time.Now()
		tlsConn := tls.Server(conn, tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			relayLog.Infof("TLS handshake failed for %s: %v (getCert=%v) - falling back to raw TCP", host, err, dCert)
			_ = conn.SetDeadline(time.Time{})
			s.relayRawTCP(host, port, conn)
			return
		}
		relayLog.Infof("CONNECT %s (getCert=%v, TLS=%v)", host, dCert, time.Since(t1))
		s.relayHTTPOverTLS(host, port, tlsConn)
		return
	}

	_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	_ = conn.SetDeadline(time.Time{})
	s.relayRawTCP(host, port, conn)
}

func (s *gasProxyServer) relayRawTCP(host string, port int, client net.Conn) {
	dst, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 15*time.Second)
	if err != nil {
		relayLog.Infof("raw TCP dial failed for %s:%d: %v", host, port, err)
		return
	}
	defer dst.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, err := io.Copy(dst, client)
		relayLog.Infof("raw TCP client->dst %s:%d: %d bytes, err=%v", host, port, n, err)
	}()
	go func() {
		defer wg.Done()
		n, err := io.Copy(client, dst)
		relayLog.Infof("raw TCP dst->client %s:%d: %d bytes, err=%v", host, port, n, err)
	}()
	wg.Wait()
}

func (s *gasProxyServer) relayHTTPOverTLS(host string, port int, conn net.Conn) {
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

		method, path := gasParseRequestLine(line)
		body := gasReadBody(relayReader, reqHeaders)
		headerMap := gasParseHeaders(reqHeaders[1:])

		origin := headerValue(headerMap, "origin")
		acrMethod := headerValue(headerMap, "access-control-request-method")
		acrHeaders := headerValue(headerMap, "access-control-request-headers")
		if strings.ToUpper(method) == "OPTIONS" && acrMethod != "" {
			_, _ = conn.Write(gasCORSPreflight(origin, acrMethod, acrHeaders))
			continue
		}

		urlStr := gasNormalizeURL(host, port, path)
		tReq := time.Now()
		response := s.relay.relayRequest(method, urlStr, headerMap, body)
		dReq := time.Since(tReq)
		if dReq > 5*time.Second {
			relayLog.Infof("SLOW relay: %s %s took %v", method, urlStr, dReq)
		}
		if origin != "" {
			response = gasInjectCORS(response, origin)
		}
		_, _ = conn.Write(response)
	}
}



func gasParseHeaders(lines []string) map[string]string {
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

func gasReadBody(reader *bufio.Reader, headers []string) []byte {
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

func gasParseRequestLine(line string) (string, string) {
	parts := strings.Split(strings.TrimSpace(line), " ")
	if len(parts) < 2 {
		return "GET", "/"
	}
	return parts[0], parts[1]
}

func gasNormalizeURL(host string, port int, path string) string {
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

func gasSplitHostPort(target string, defPort int) (string, int) {
	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		if len(parts) >= 2 {
			port, _ := strconv.Atoi(parts[len(parts)-1])
			return strings.Join(parts[:len(parts)-1], ":"), port
		}
	}
	return target, defPort
}
