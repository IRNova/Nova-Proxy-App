package transport

import (
	"crypto/tls"
	"net"
	"time"
)

type DialFunc func(network, addr string) (net.Conn, error)

type Config struct {
	ServerName         string
	InsecureSkipVerify bool
	Timeout            time.Duration
	KeepAlive          time.Duration
	H2ALPN             bool
}

func Dialer(cfg Config) DialFunc {
	return func(network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{
			Timeout:   cfg.Timeout,
			KeepAlive: cfg.KeepAlive,
		}
		raw, err := dialer.Dial(network, addr)
		if err != nil {
			return nil, err
		}
		if tcp, ok := raw.(*net.TCPConn); ok {
			tcp.SetNoDelay(true)
		}
		tlsCfg := &tls.Config{
			ServerName:         cfg.ServerName,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
		}
		if cfg.H2ALPN {
			tlsCfg.NextProtos = []string{"h2", "http/1.1"}
		}
		tlsConn := tls.Client(raw, tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			raw.Close()
			return nil, err
		}
		return tlsConn, nil
	}
}

func WrapConn(conn net.Conn, cfg Config) net.Conn {
	tlsCfg := &tls.Config{
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}
	tlsConn := tls.Client(conn, tlsCfg)
	return tlsConn
}
