package proxy

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

type CertVerifyConfig struct {
	Mode                  string   `json:"mode,omitempty"`
	Names                 []string `json:"names,omitempty"`
	Suffixes              []string `json:"suffixes,omitempty"`
	SPKISHA256            []string `json:"spki_sha256,omitempty"`
	AllowUnknownAuthority bool     `json:"allow_unknown_authority,omitempty"`
}

func (c CertVerifyConfig) IsZero() bool {
	return strings.TrimSpace(c.Mode) == "" &&
		len(c.Names) == 0 &&
		len(c.Suffixes) == 0 &&
		len(c.SPKISHA256) == 0 &&
		!c.AllowUnknownAuthority
}

func normalizeCertVerifyConfig(cfg CertVerifyConfig, verifyName string) CertVerifyConfig {
	out := cfg
	out.Mode = strings.TrimSpace(out.Mode)
	if out.Mode == "" {
		switch {
		case len(out.Names) > 0:
			out.Mode = "allow_names"
		case len(out.Suffixes) > 0:
			out.Mode = "allow_suffixes"
		case len(out.SPKISHA256) > 0:
			out.Mode = "allow_spki"
		default:
			out.Mode = ""
		}
	}
	for i := range out.Names {
		out.Names[i] = normalizeHost(out.Names[i])
	}
	for i := range out.Suffixes {
		out.Suffixes[i] = strings.ToLower(strings.TrimSpace(out.Suffixes[i]))
	}
	for i := range out.SPKISHA256 {
		out.SPKISHA256[i] = strings.TrimSpace(out.SPKISHA256[i])
	}
	if out.Mode == "strict_real" && verifyName != "" && len(out.Names) == 0 {
		out.Names = []string{normalizeHost(verifyName)}
	}
	return out
}

func buildVerifyConnection(realName string, cfg CertVerifyConfig) func(utls.ConnectionState) error {
	cfg = normalizeCertVerifyConfig(cfg, realName)
	if cfg.Mode == "" {
		return nil
	}

	return func(cs utls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("no peer certificates")
		}

		verifyChain := func(withDNSName bool) error {
			roots, err := x509.SystemCertPool()
			if err != nil || roots == nil {
				roots = x509.NewCertPool()
			}
			intermediates := x509.NewCertPool()
			for _, cert := range cs.PeerCertificates[1:] {
				intermediates.AddCert(cert)
			}
			opts := x509.VerifyOptions{
				Roots:         roots,
				Intermediates: intermediates,
				CurrentTime:   time.Now(),
			}
			if withDNSName {
				opts.DNSName = realName
			}
			_, err = cs.PeerCertificates[0].Verify(opts)
			return err
		}

		switch cfg.Mode {
		case "strict_real":
			return maybeIgnoreUnknownAuthority(verifyChain(true), cfg)
		case "chain_only":
			return maybeIgnoreUnknownAuthority(verifyChain(false), cfg)
		case "allow_names":
			if err := maybeIgnoreUnknownAuthority(verifyChain(false), cfg); err != nil {
				return err
			}
			if !matchesAllowedNames(cs.PeerCertificates[0], cfg.Names) {
				return fmt.Errorf("certificate names do not match configured allow_names")
			}
			return nil
		case "allow_suffixes":
			if err := maybeIgnoreUnknownAuthority(verifyChain(false), cfg); err != nil {
				return err
			}
			if !matchesAllowedSuffixes(cs.PeerCertificates[0], cfg.Suffixes) {
				return fmt.Errorf("certificate names do not match configured allow_suffixes")
			}
			return nil
		case "allow_spki":
			if err := maybeIgnoreUnknownAuthority(verifyChain(false), cfg); err != nil {
				return err
			}
			if !matchesSPKI(cs.PeerCertificates[0], cfg.SPKISHA256) {
				return fmt.Errorf("leaf spki %s not in allowlist", spkiHashBase64(cs.PeerCertificates[0]))
			}
			return nil
		default:
			return fmt.Errorf("unknown cert_verify mode: %s", cfg.Mode)
		}
	}
}

func maybeIgnoreUnknownAuthority(err error, cfg CertVerifyConfig) error {
	if err == nil || !cfg.AllowUnknownAuthority {
		return err
	}
	var unknownErr x509.UnknownAuthorityError
	if errors.As(err, &unknownErr) {
		return nil
	}
	return err
}

func matchesAllowedNames(cert *x509.Certificate, names []string) bool {
	if cert == nil || len(names) == 0 {
		return false
	}
	candidates := certNames(cert)
	for _, allowed := range names {
		allowed = strings.ToLower(strings.TrimSpace(allowed))
		if allowed == "" {
			continue
		}
		for _, candidate := range candidates {
			if dnsMatch(candidate, allowed) || dnsMatch(allowed, candidate) {
				return true
			}
		}
	}
	return false
}

func matchesAllowedSuffixes(cert *x509.Certificate, suffixes []string) bool {
	if cert == nil || len(suffixes) == 0 {
		return false
	}
	candidates := certNames(cert)
	for _, suffix := range suffixes {
		suffix = strings.ToLower(strings.TrimSpace(suffix))
		if suffix == "" {
			continue
		}
		for _, candidate := range candidates {
			candidate = strings.ToLower(candidate)
			if candidate == suffix || strings.HasSuffix(candidate, suffix) {
				return true
			}
			if strings.HasPrefix(candidate, "*.") {
				base := strings.TrimPrefix(candidate, "*")
				if base == suffix || strings.HasSuffix(base, suffix) {
					return true
				}
			}
		}
	}
	return false
}

func matchesSPKI(cert *x509.Certificate, allowed []string) bool {
	hash := spkiHashBase64(cert)
	for _, item := range allowed {
		if strings.EqualFold(strings.TrimSpace(item), hash) {
			return true
		}
	}
	return false
}

func spkiHashBase64(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

func certNames(cert *x509.Certificate) []string {
	seen := map[string]struct{}{}
	var out []string
	appendName := func(v string) {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	appendName(cert.Subject.CommonName)
	for _, name := range cert.DNSNames {
		appendName(name)
	}
	return out
}

func dnsMatch(certName, host string) bool {
	certName = strings.ToLower(strings.TrimSpace(certName))
	host = strings.ToLower(strings.TrimSpace(host))
	if certName == "" || host == "" {
		return false
	}
	if certName == host {
		return true
	}
	if strings.HasPrefix(certName, "*.") {
		base := strings.TrimPrefix(certName, "*.")
		if strings.HasSuffix(host, "."+base) && strings.Count(host, ".") >= strings.Count(base, ".")+1 {
			return true
		}
	}
	return false
}
