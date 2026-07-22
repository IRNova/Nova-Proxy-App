package relay

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

type relayResponse struct {
	Status    int                 `json:"s"`
	Body      string              `json:"b"`
	Headers   map[string]any      `json:"h"`
	Error     string              `json:"e,omitempty"`
	Encoding  string              `json:"enc,omitempty"`
	Gzip      int                 `json:"gz,omitempty"`
	Trace     []map[string]any    `json:"trace,omitempty"`
	Profile   string              `json:"profile,omitempty"`
}

func safeParseRelayResponse(raw []byte) *relayResponse {
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return &relayResponse{Status: 502, Error: "empty response"}
	}
	var rr relayResponse
	if err := json.Unmarshal([]byte(text), &rr); err != nil {
		re := regexp.MustCompile(`\{.*\}`)
		if m := re.FindString(text); m != "" {
			if err := json.Unmarshal([]byte(m), &rr); err != nil {
				return &relayResponse{Status: 502, Error: "JSON parse error"}
			}
		} else {
			return &relayResponse{Status: 502, Error: "no JSON in response"}
		}
	}
	if rr.Error != "" {
		rr.Status = 502
	}
	if rr.Status == 0 {
		rr.Status = 200
	}
	return &rr
}

func classifyRelayError(rr *relayResponse) string {
	if rr.Error == "" {
		return ""
	}
	errLower := strings.ToLower(rr.Error)
	switch {
	case strings.Contains(errLower, "timeout"), strings.Contains(errLower, "timed out"):
		return "TIMEOUT"
	case strings.Contains(errLower, "dns"), strings.Contains(errLower, "resolve"):
		return "DNS_FAIL"
	case strings.Contains(errLower, "refused"), strings.Contains(errLower, "reset"):
		return "CONN_REFUSED"
	case strings.Contains(errLower, "ssl"), strings.Contains(errLower, "tls"), strings.Contains(errLower, "certificate"):
		return "TLS_ERROR"
	case strings.Contains(errLower, "quota"), strings.Contains(errLower, "429"), strings.Contains(errLower, "rate limit"):
		return "QUOTA_EXCEEDED"
	case strings.Contains(errLower, "not found"), strings.Contains(errLower, "404"):
		return "NOT_FOUND"
	case strings.Contains(errLower, "deploy"), strings.Contains(errLower, "unpublished"):
		return "DEPLOY_NEEDED"
	case strings.Contains(errLower, "overflow"), strings.Contains(errLower, "too large"):
		return "OVERFLOW"
	default:
		return "UNKNOWN"
	}
}

func fmtResponseTrace(trace []map[string]any) string {
	if len(trace) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("relay_trace:\n")
	for i, hop := range trace {
		b.WriteString(fmt.Sprintf("  %d: ", i+1))
		parts := []string{}
		if v, ok := hop["t"]; ok {
			parts = append(parts, fmt.Sprintf("type=%v", v))
		}
		if v, ok := hop["ip"]; ok {
			parts = append(parts, fmt.Sprintf("ip=%v", v))
		}
		if v, ok := hop["ms"]; ok {
			parts = append(parts, fmt.Sprintf("ms=%v", v))
		}
		if v, ok := hop["e"]; ok {
			parts = append(parts, fmt.Sprintf("err=%v", v))
		}
		b.WriteString(strings.Join(parts, " "))
		b.WriteString("\n")
	}
	return b.String()
}
