package proxy

import (
	"encoding/json"
	"strings"
)

// GenerateXrayCoreJSON generates Xray-core compatible JSON config
// Supports: VLESS+REALITY, VMESS+TLS, Trojan, Shadowsocks, XHTTP, gRPC
func GenerateXrayCoreJSON(cfg V2RayConfig, socksPort, httpPort int) (string, error) {
	config := map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": "warning",
		},
		"inbounds": []map[string]interface{}{
			{
				"port":     socksPort,
				"listen":   "127.0.0.1",
				"protocol": "socks",
				"settings": map[string]interface{}{"udp": true},
				"tag":      "socks-in",
			},
			{
				"port":     httpPort,
				"listen":   "127.0.0.1",
				"protocol": "http",
				"settings": map[string]interface{}{},
				"tag":      "http-in",
			},
		},
	}

	outbound := map[string]interface{}{
		"protocol": cfg.Protocol,
		"settings": map[string]interface{}{},
		"tag":      "proxy",
	}

	streamSettings := map[string]interface{}{}

	switch cfg.Protocol {
	case "vless":
		vnext := []map[string]interface{}{
			{
				"address": cfg.Server,
				"port":    parsePort(cfg.Port),
				"users": []map[string]interface{}{
					{
						"id":         cfg.UUID,
						"encryption": ifEmpty(cfg.Encryption, "none"),
						"flow":       cfg.Flow,
					},
				},
			},
		}
		outbound["settings"] = map[string]interface{}{"vnext": vnext}

		// REALITY support
		if cfg.Security == "reality" {
			streamSettings["security"] = "reality"
			realitySettings := map[string]interface{}{
				"serverName":  cfg.Sni,
				"fingerprint": ifEmpty(cfg.Fingerprint, "chrome"),
				"publicKey":   cfg.PublicKey,
				"shortId":     cfg.ShortID,
			}
			if cfg.Sni == "" {
				realitySettings["serverName"] = cfg.Server
			}
			streamSettings["realitySettings"] = realitySettings

			// REALITY works over TCP
			if cfg.Type == "" || cfg.Type == "tcp" {
				streamSettings["network"] = "tcp"
				tcpSettings := map[string]interface{}{
					"header": map[string]interface{}{
						"type": "none",
					},
				}
				streamSettings["tcpSettings"] = tcpSettings
			}
		} else if cfg.Security == "tls" || cfg.TLS == "tls" {
			streamSettings["security"] = "tls"
			streamSettings["tlsSettings"] = buildTLSSettings(cfg)
		} else {
			streamSettings["security"] = "none"
		}

	case "vmess":
		vnext := []map[string]interface{}{
			{
				"address": cfg.Server,
				"port":    parsePort(cfg.Port),
				"users": []map[string]interface{}{
					{
						"id":       cfg.UUID,
						"security": ifEmpty(cfg.Security, "auto"),
					},
				},
			},
		}
		outbound["settings"] = map[string]interface{}{"vnext": vnext}

		if cfg.TLS == "tls" || cfg.Security == "tls" {
			streamSettings["security"] = "tls"
			streamSettings["tlsSettings"] = buildTLSSettings(cfg)
		}

	case "trojan":
		servers := []map[string]interface{}{
			{
				"address":  cfg.Server,
				"port":     parsePort(cfg.Port),
				"password": cfg.Password,
			},
		}
		outbound["settings"] = map[string]interface{}{"servers": servers}
		streamSettings["security"] = "tls"
		streamSettings["tlsSettings"] = buildTLSSettings(cfg)

	case "shadowsocks":
		servers := []map[string]interface{}{
			{
				"address":  cfg.Server,
				"port":     parsePort(cfg.Port),
				"method":   cfg.Method,
				"password": cfg.Password,
			},
		}
		outbound["settings"] = map[string]interface{}{"servers": servers}
	}

	// Transport layer (XHTTP, WebSocket, gRPC, etc.)
	if cfg.Type != "" && cfg.Type != "tcp" {
		applyTransport(cfg, streamSettings)
	}

	if len(streamSettings) > 0 {
		outbound["streamSettings"] = streamSettings
	}

	config["outbounds"] = []map[string]interface{}{outbound}
	config["routing"] = map[string]interface{}{
		"domainStrategy": "AsIs",
		"rules": []map[string]interface{}{
			{
				"type":        "field",
				"inboundTag":  []string{"socks-in", "http-in"},
				"outboundTag": "proxy",
			},
		},
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func applyTransport(cfg V2RayConfig, streamSettings map[string]interface{}) {
	streamSettings["network"] = cfg.Type

	switch cfg.Type {
	case "ws", "websocket":
		wsSettings := map[string]interface{}{}
		if cfg.Path != "" {
			wsSettings["path"] = cfg.Path
		}
		if cfg.Host != "" {
			wsSettings["headers"] = map[string]string{"Host": cfg.Host}
		}
		streamSettings["wsSettings"] = wsSettings

	case "grpc":
		grpcSettings := map[string]interface{}{}
		if cfg.Host != "" {
			grpcSettings["serviceName"] = cfg.Host
		}
		grpcSettings["multiMode"] = true
		streamSettings["grpcSettings"] = grpcSettings

	case "xhttp", "splithttp":
		xhttpSettings := map[string]interface{}{
			"mode": "auto",
		}
		if cfg.Path != "" {
			xhttpSettings["path"] = cfg.Path
		}
		if cfg.Host != "" {
			xhttpSettings["host"] = cfg.Host
		}
		streamSettings["xhttpSettings"] = xhttpSettings

	case "quic":
		quicSettings := map[string]interface{}{}
		streamSettings["quicSettings"] = quicSettings

	case "httpupgrade", "http-upgrade":
		httpUpgradeSettings := map[string]interface{}{}
		if cfg.Path != "" {
			httpUpgradeSettings["path"] = cfg.Path
		}
		if cfg.Host != "" {
			httpUpgradeSettings["host"] = cfg.Host
		}
		streamSettings["httpupgradeSettings"] = httpUpgradeSettings

	case "tcp":
		tcpSettings := map[string]interface{}{
			"header": map[string]interface{}{
				"type": "none",
			},
		}
		streamSettings["tcpSettings"] = tcpSettings
	}

	// Apply TLS if not REALITY
	if cfg.Security != "reality" {
		if cfg.TLS == "tls" || cfg.Security == "tls" {
			streamSettings["security"] = "tls"
			streamSettings["tlsSettings"] = buildTLSSettings(cfg)
		}
	}
}

func buildTLSSettings(cfg V2RayConfig) map[string]interface{} {
	tlsSettings := map[string]interface{}{
		"serverName": cfg.Sni,
	}
	if cfg.Sni == "" {
		tlsSettings["serverName"] = cfg.Server
	}
	if cfg.Alpn != "" {
		tlsSettings["alpn"] = strings.Split(cfg.Alpn, ",")
	}
	if cfg.Fingerprint != "" {
		tlsSettings["fingerprint"] = cfg.Fingerprint
	}
	return tlsSettings
}

func ifEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
