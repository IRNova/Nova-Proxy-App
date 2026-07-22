package relay

import (
	"strings"
	"unicode"
)

type exitNodeRule struct {
	Host  string `json:"host"`
	Port  int    `json:"port"`
	TLS   bool   `json:"tls"`
}

func parseExitNodeHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimRight(host, ".")
	host = strings.TrimLeftFunc(host, unicode.IsSpace)
	return strings.ToLower(host)
}

func isExitNodeHost(host string, ruleSet map[string]struct{}) bool {
	host = parseExitNodeHost(host)
	if host == "" {
		return false
	}
	if _, exact := ruleSet[host]; exact {
		return true
	}
	if _, wildcard := ruleSet["."+host]; wildcard {
		return true
	}
	for pattern := range ruleSet {
		if strings.HasPrefix(pattern, ".") {
			if strings.HasSuffix(host, pattern) {
				return true
			}
		}
	}
	return false
}

func extractExitNodeHosts(configHosts []string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, h := range configHosts {
		h = parseExitNodeHost(h)
		if h != "" {
			out[h] = struct{}{}
		}
	}
	return out
}

func buildExitNodeList(hosts []string) string {
	set := extractExitNodeHosts(hosts)
	if len(set) == 0 {
		return ""
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	return strings.Join(keys, ", ")
}
