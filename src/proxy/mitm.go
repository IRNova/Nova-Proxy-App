package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/TheCanniball/CipherGate/src/core"
	"github.com/TheCanniball/CipherGate/src/relay"
)

type MITM struct {
	cfg       *core.MITMConfig
	ca        *CA
	certCache sync.Map
	relay     *relay.Engine
}

type CA struct {
	Cert tls.Certificate
}

func NewMITM(cfg *core.MITMConfig) *MITM {
	return &MITM{
		cfg: cfg,
	}
}

func (m *MITM) SetRelay(r *relay.Engine) {
	m.relay = r
}

func (m *MITM) HandleTunnel(clientConn *net.TCPConn, target string) {
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	tlsConn := tls.Server(clientConn, &tls.Config{
		GetCertificate: m.getCert,
	})
	if err := tlsConn.Handshake(); err != nil {
		clientConn.Close()
		return
	}

	for {
		_ = tlsConn.SetDeadline(time.Now().Add(60 * time.Second))
		req, err := http.ReadRequest(bufio.NewReader(tlsConn))
		if err != nil {
			break
		}

		targetURL := fmt.Sprintf("https://%s%s", target, req.URL.RequestURI())
		headers := make(map[string]string)
		for k, v := range req.Header {
			if len(v) > 0 {
				headers[k] = v[0]
			}
		}
		// Remove hop-by-hop
		for _, h := range []string{"proxy-connection", "keep-alive", "transfer-encoding"} {
			delete(headers, h)
		}

		body, _ := io.ReadAll(req.Body)
		req.Body.Close()

		if m.relay != nil {
			resp := m.relay.Relay(req.Method, targetURL, headers, body)
			if len(resp) > 0 {
				tlsConn.Write(resp)
			}
		} else {
			resp := fmt.Sprintf("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
			tlsConn.Write([]byte(resp))
		}
	}
	tlsConn.Close()
}

func (m *MITM) getCert(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if cached, ok := m.certCache.Load(hello.ServerName); ok {
		return cached.(*tls.Certificate), nil
	}
	cert, err := generateCert(hello.ServerName)
	if err != nil {
		return nil, err
	}
	m.certCache.Store(hello.ServerName, cert)
	return cert, nil
}

func generateCert(host string) (*tls.Certificate, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MITM) InstallCA(certFile, keyFile string) error {
	return nil
}
