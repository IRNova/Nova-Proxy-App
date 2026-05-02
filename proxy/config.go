package proxy

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

type ConfigFile struct {
	Version string       `json:"version"`
	Type    string       `json:"type"`
	Rules   []ConfigRule `json:"rules"`
}

type ConfigRule struct {
	Name          string           `json:"name"`
	Website       string           `json:"website,omitempty"`
	Mode          string           `json:"mode,omitempty"`
	Enabled       bool             `json:"enabled"`
	Domains       []string         `json:"domains"`
	Upstream      string           `json:"upstream,omitempty"`
	Upstreams     []string         `json:"upstreams,omitempty"`
	DNSMode       string           `json:"dns_mode,omitempty"`
	SniFake       string           `json:"sni_fake,omitempty"`
	ConnectPolicy string           `json:"connect_policy,omitempty"`
	SniPolicy     string           `json:"sni_policy,omitempty"`
	ECHEnabled    bool             `json:"ech_enabled,omitempty"`
	ECHProfileID  string           `json:"ech_profile_id,omitempty"`
	ECHDomain     string           `json:"ech_domain,omitempty"`
	UseCFPool     bool             `json:"use_cf_pool,omitempty"`
	CertVerify    CertVerifyConfig `json:"cert_verify,omitempty"`
}

type ImportSummary struct {
	Total       int `json:"total"`
	Added       int `json:"added"`
	Overwritten int `json:"overwritten"`
	Skipped     int `json:"skipped"`
}

func (rm *RuleManager) ExportConfig() (string, error) {
	var mitmRules, transRules []ConfigRule

	rm.mu.RLock()
	for _, sg := range rm.siteGroups {
		rule := ConfigRule{
			Name:          sg.Name,
			Website:       sg.Website,
			Mode:          sg.Mode,
			Enabled:       sg.Enabled,
			Domains:       sg.Domains,
			Upstream:      sg.Upstream,
			Upstreams:     append([]string(nil), sg.Upstreams...),
			DNSMode:       sg.DNSMode,
			SniFake:       sg.SniFake,
			ConnectPolicy: sg.ConnectPolicy,
			SniPolicy:     sg.SniPolicy,
			ECHEnabled:    sg.ECHEnabled,
			ECHProfileID:  sg.ECHProfileID,
			ECHDomain:     sg.ECHDomain,
			UseCFPool:     sg.UseCFPool,
			CertVerify:    sg.CertVerify,
		}

		if sg.Mode == "mitm" {
			mitmRules = append(mitmRules, rule)
		} else {
			transRules = append(transRules, rule)
		}
	}
	rm.mu.RUnlock()

	result := make(map[string]interface{})
	result["exported"] = time.Now().Format("2006-01-02 15:04:05")

	if len(mitmRules) > 0 {
		mitmConfig := ConfigFile{
			Version: "1.0",
			Type:    "mitm",
			Rules:   mitmRules,
		}
		mitmJSON, _ := json.MarshalIndent(mitmConfig, "", "  ")
		result["mitm"] = string(mitmJSON)
	}

	if len(transRules) > 0 {
		transConfig := ConfigFile{
			Version: "1.0",
			Type:    "transparent",
			Rules:   transRules,
		}
		transJSON, _ := json.MarshalIndent(transConfig, "", "  ")
		result["transparent"] = string(transJSON)
	}

	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}

	return string(output), nil
}

func normalizeDomainsForKey(domains []string) string {
	if len(domains) == 0 {
		return ""
	}
	seen := make(map[string]struct{}, len(domains))
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		n := strings.ToLower(strings.TrimSpace(d))
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func importMergeKey(sg SiteGroup) string {
	mode := strings.ToLower(strings.TrimSpace(sg.Mode))
	return mode + "|" + normalizeDomainsForKey(sg.Domains)
}

func (rm *RuleManager) ImportConfig(content string) error {
	_, err := rm.ImportConfigWithSummary(content)
	return err
}

func (rm *RuleManager) ImportConfigWithSummary(content string) (ImportSummary, error) {
	content = strings.TrimSpace(content)
	if content == "" {
		return ImportSummary{}, fmt.Errorf("empty config content")
	}

	parseConfigPayload := func(payload []byte, forcedType string) ([]SiteGroup, int, error) {
		var cfg ConfigFile
		if err := json.Unmarshal(payload, &cfg); err != nil {
			return nil, 0, err
		}

		mode := strings.ToLower(strings.TrimSpace(cfg.Type))
		if mode == "" {
			mode = strings.ToLower(strings.TrimSpace(forcedType))
		}
		if mode != "mitm" && mode != "transparent" {
			return nil, 0, fmt.Errorf("invalid or missing config type")
		}

		out := make([]SiteGroup, 0, len(cfg.Rules))
		skipped := 0
		for _, rule := range cfg.Rules {
			if len(rule.Domains) == 0 {
				skipped++
				continue
			}
			ruleMode := strings.ToLower(strings.TrimSpace(rule.Mode))
			if ruleMode == "" {
				ruleMode = mode
			}
			if ruleMode != "mitm" && ruleMode != "transparent" && ruleMode != "server" && ruleMode != "tls-rf" && ruleMode != "quic" && ruleMode != "warp" {
				skipped++
				continue
			}
			sg := SiteGroup{
				ID:            generateID(),
				Name:          strings.TrimSpace(rule.Name),
				Website:       strings.TrimSpace(rule.Website),
				Domains:       rule.Domains,
				Mode:          ruleMode,
				Upstream:      strings.TrimSpace(rule.Upstream),
				Upstreams:     append([]string(nil), rule.Upstreams...),
				DNSMode:       normalizeDNSMode(rule.DNSMode),
				SniFake:       strings.TrimSpace(rule.SniFake),
				ConnectPolicy: strings.ToLower(strings.TrimSpace(rule.ConnectPolicy)),
				SniPolicy:     strings.ToLower(strings.TrimSpace(rule.SniPolicy)),
				Enabled:       rule.Enabled,
				ECHEnabled:    rule.ECHEnabled,
				ECHProfileID:  rule.ECHProfileID,
				ECHDomain:     rule.ECHDomain,
				UseCFPool:     rule.UseCFPool,
				CertVerify:    rule.CertVerify,
			}
			if sg.Name == "" {
				sg.Name = sg.Domains[0]
			}
			if !sg.Enabled {
				sg.Enabled = true
			}
			out = append(out, sg)
		}
		return out, skipped, nil
	}

	imported := make([]SiteGroup, 0, 64)
	total := 0
	skipped := 0

	var wrapper map[string]interface{}
	if err := json.Unmarshal([]byte(content), &wrapper); err == nil {
		for _, key := range []string{"mitm", "transparent"} {
			raw, ok := wrapper[key]
			if !ok {
				continue
			}
			switch v := raw.(type) {
			case string:
				sgs, partSkipped, err := parseConfigPayload([]byte(v), key)
				if err != nil {
					continue
				}
				total += len(sgs) + partSkipped
				skipped += partSkipped
				imported = append(imported, sgs...)
			default:
				payload, err := json.Marshal(v)
				if err != nil {
					continue
				}
				sgs, partSkipped, err := parseConfigPayload(payload, key)
				if err != nil {
					continue
				}
				total += len(sgs) + partSkipped
				skipped += partSkipped
				imported = append(imported, sgs...)
			}
		}
	}

	// Fallback: support direct single config file format:
	// {"version":"2.0","type":"mitm","rules":[...]}
	if len(imported) == 0 {
		sgs, partSkipped, err := parseConfigPayload([]byte(content), "")
		if err == nil {
			total += len(sgs) + partSkipped
			skipped += partSkipped
			imported = append(imported, sgs...)
		}
	}

	if len(imported) == 0 {
		return ImportSummary{}, fmt.Errorf("no valid rules found")
	}

	rm.mu.Lock()
	merged := append([]SiteGroup(nil), rm.siteGroups...)
	index := make(map[string]int, len(merged))
	for i, sg := range merged {
		key := importMergeKey(sg)
		if key == "|" {
			continue
		}
		index[key] = i
	}

	added := 0
	overwritten := 0
	for _, sg := range imported {
		key := importMergeKey(sg)
		if key == "|" {
			skipped++
			continue
		}
		if idx, ok := index[key]; ok {
			sg.ID = merged[idx].ID
			merged[idx] = sg
			overwritten++
			continue
		}
		merged = append(merged, sg)
		index[key] = len(merged) - 1
		added++
	}

	rm.siteGroups = merged
	rm.buildRules()
	rm.mu.Unlock()

	if err := rm.saveRulesConfig(); err != nil {
		return ImportSummary{}, err
	}

	if total == 0 {
		total = len(imported) + skipped
	}
	return ImportSummary{
		Total:       total,
		Added:       added,
		Overwritten: overwritten,
		Skipped:     skipped,
	}, nil
}
