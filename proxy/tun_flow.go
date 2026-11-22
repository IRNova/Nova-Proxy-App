// Third-party notice: this file contains material shared with historical
// MIT-licensed SniShaper source. The following grant covers that material,
// without assigning other authors' contributions to SniShaper.
//
// MIT License
//
// Copyright (c) 2026 SniShaper
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package proxy

import (
	"context"
	"fmt"
	"net"
	"strings"
)

type TUNFlow struct {
	Protocol string `json:"protocol"`
	Host     string `json:"host,omitempty"`
	SNI      string `json:"sni,omitempty"`
	DestAddr string `json:"dest_addr,omitempty"`
	DestPort int    `json:"dest_port,omitempty"`
}

type TUNFlowPlan struct {
	Protocol       string   `json:"protocol"`
	Host           string   `json:"host,omitempty"`
	MatchHost      string   `json:"match_host,omitempty"`
	RuleMode       string   `json:"rule_mode"`
	EffectiveMode  string   `json:"effective_mode"`
	Upstream       string   `json:"upstream,omitempty"`
	DialCandidates []string `json:"dial_candidates,omitempty"`
	UDPStrategy    string   `json:"udp_strategy,omitempty"`
	CanMITM        bool     `json:"can_mitm"`
	NeedsSniffing  bool     `json:"needs_sniffing"`
	Notes          []string `json:"notes,omitempty"`
}

func (p *ProxyServer) PlanTUNFlow(flow TUNFlow) TUNFlowPlan {
	protocol := strings.ToLower(strings.TrimSpace(flow.Protocol))
	if protocol == "" {
		protocol = "tcp"
	}

	host := normalizeHost(flow.Host)
	if host == "" {
		host = normalizeHost(flow.SNI)
	}
	if host == "" {
		host = normalizeHost(flow.DestAddr)
	}

	port := flow.DestPort
	if port <= 0 || port > 65535 {
		switch protocol {
		case "udp":
			port = 443
		default:
			port = 443
		}
	}

	matchMode := "mitm"
	if protocol == "udp" {
		matchMode = "transparent"
	}

	rule := p.rules.matchRule(host, matchMode)
	effectiveMode := strings.ToLower(strings.TrimSpace(rule.Mode))
	if effectiveMode == "" {
		effectiveMode = "direct"
	}

	notes := make([]string, 0, 4)
	canMITM := protocol == "tcp"
	udpStrategy := ""

	switch protocol {
	case "udp":
		canMITM = false
		switch effectiveMode {
		case "mitm", "tls-rf", "server":
			notes = append(notes, fmt.Sprintf("%s is TCP-oriented in the current TUN path; downgrade UDP handling to transparent passthrough", effectiveMode))
			effectiveMode = "transparent"
		case "quic":
			udpStrategy = "native-quic"
			notes = append(notes, "QUIC-specific UDP handling can be attached here later")
		case "warp":
			udpStrategy = "warp"
			notes = append(notes, "Warp-selected UDP will need a dedicated UDP associate path")
		default:
			udpStrategy = "passthrough"
			if effectiveMode == "direct" {
				notes = append(notes, "Direct UDP flow will bypass HTTP proxy semantics and use transparent forwarding")
			}
		}
	case "tcp":
		switch effectiveMode {
		case "quic":
			notes = append(notes, "QUIC mode selected for TCP flow; preserve rule but dataplane may remap it later")
		case "transparent":
			canMITM = false
			notes = append(notes, "Transparent TCP flow can reuse existing upstream dial logic without TLS termination")
		case "direct":
			canMITM = false
		default:
			notes = append(notes, "TCP flow can reuse existing rule matching and upstream candidate selection")
		}
	default:
		notes = append(notes, "Unknown protocol; treating as direct")
		effectiveMode = "direct"
	}

	targetHost := host
	if targetHost == "" {
		notes = append(notes, "No host/SNI available yet; dataplane should sniff TLS or correlate DNS before advanced routing")
	}
	targetAddr := flow.DestAddr
	if strings.TrimSpace(targetAddr) == "" {
		if targetHost != "" {
			targetAddr = net.JoinHostPort(targetHost, fmt.Sprintf("%d", port))
		}
	}
	if targetAddr == "" {
		targetAddr = net.JoinHostPort("0.0.0.0", fmt.Sprintf("%d", port))
	}

	dialCandidates := p.buildDialCandidates(context.Background(), targetHost, ensureAddrWithPort(targetAddr, fmt.Sprintf("%d", port)), rule, effectiveMode)
	if protocol == "udp" && len(dialCandidates) == 0 && targetAddr != "" {
		dialCandidates = []string{ensureAddrWithPort(targetAddr, fmt.Sprintf("%d", port))}
	}

	return TUNFlowPlan{
		Protocol:       protocol,
		Host:           host,
		MatchHost:      host,
		RuleMode:       rule.Mode,
		EffectiveMode:  effectiveMode,
		Upstream:       resolveRuleUpstream(targetHost, rule),
		DialCandidates: dialCandidates,
		UDPStrategy:    udpStrategy,
		CanMITM:        canMITM,
		NeedsSniffing:  host == "",
		Notes:          notes,
	}
}
