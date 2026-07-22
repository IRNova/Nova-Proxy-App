package relay

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/TheCanniball/CipherGate/src/core"
	"golang.org/x/net/http2"
)

func (e *Engine) doH2Request(ctx context.Context, method, path, host string, headers map[string]string, body []byte, timeout time.Duration) (int, map[string]string, []byte, error) {
	if e.h2BackoffLeft() > 0 {
		return 0, nil, nil, fmt.Errorf("h2 backoff")
	}
	e.ensureH2()
	e.h2Mu.Lock()
	client := e.h2Client
	e.h2Mu.Unlock()
	if client == nil {
		return 0, nil, nil, fmt.Errorf("h2 unavailable")
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

	ctx2, cancel := context.WithTimeout(req.Context(), timeout)
	defer cancel()
	req = req.WithContext(ctx2)

	resp, err := client.Do(req)
	if err != nil {
		e.resetH2()
		return 0, nil, nil, err
	}
	defer resp.Body.Close()

	e.h2Mu.Lock()
	e.h2FailCount = 0
	e.h2BackoffUntil = time.Time{}
	e.h2Mu.Unlock()

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
		data = core.DecodeContent(data, enc)
	}
	return resp.StatusCode, respHeaders, data, nil
}

func (e *Engine) ensureH2() {
	e.h2Mu.Lock()
	defer e.h2Mu.Unlock()
	if e.h2Client != nil {
		return
	}
	if time.Now().Before(e.h2BackoffUntil) {
		return
	}
	tr := &http2.Transport{
		AllowHTTP: false,
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			sni := e.nextSNI()
			tlsCfg := &tls.Config{
				ServerName:         sni,
				InsecureSkipVerify: !e.verifySSL,
				NextProtos:         []string{"h2", "http/1.1"},
			}
			dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 15 * time.Second}
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(e.connectHost, "443"))
			if err != nil {
				return nil, err
			}
			if tcp, ok := conn.(*net.TCPConn); ok {
				tcp.SetNoDelay(true)
				tcp.SetKeepAlive(true)
				tcp.SetKeepAlivePeriod(15 * time.Second)
			}
			tlsConn := tls.Client(conn, tlsCfg)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, err
			}
			if tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
				tlsConn.Close()
				return nil, fmt.Errorf("h2 alpn failed")
			}
			return tlsConn, nil
		},
	}
	e.h2Client = &http.Client{Transport: tr}
}

func (e *Engine) resetH2() {
	e.h2Mu.Lock()
	defer e.h2Mu.Unlock()
	if e.h2Client != nil {
		if tr, ok := e.h2Client.Transport.(*http2.Transport); ok {
			tr.CloseIdleConnections()
		}
	}
	e.h2Client = nil
	e.h2FailCount++
	backoff := time.Duration(1<<min(e.h2FailCount, 5)) * time.Second
	if backoff > 30*time.Second {
		backoff = 30 * time.Second
	}
	e.h2BackoffUntil = time.Now().Add(backoff)
}

func (e *Engine) h2BackoffLeft() time.Duration {
	e.h2Mu.Lock()
	defer e.h2Mu.Unlock()
	if e.h2Client != nil {
		return 0
	}
	left := time.Until(e.h2BackoffUntil)
	if left < 0 {
		return 0
	}
	return left
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
