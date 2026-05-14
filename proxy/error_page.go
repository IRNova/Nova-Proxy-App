package proxy

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"
)

type ErrorContext struct {
	TargetHost  string
	RemoteIP    string
	UpstreamSNI string
	WorkMode    string
	ECHStatus   string
	DNSNode     string
	RawError    string
	RequestURL  string
}

func (p *ProxyServer) ServeErrorPage(conn net.Conn, host, ip, sni string, rule Rule, err error) {
	// Set a deadline for the whole operation
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer conn.Close()

	// Try to read the first request to see if they want to bypass or just to clear the buffer
	// We don't strictly need it if we're just going to send a 502.
	br := bufio.NewReader(conn)
	req, _ := http.ReadRequest(br)

	lang := p.rules.GetLanguage()
	if lang == "" {
		lang = "fa"
	}

	// Check for bypass request
	if req != nil && strings.Contains(req.URL.Path, "__novaproxy_bypass_cert__") {
		p.certBypassMap.Store(normalizeHost(host), true)
		title, msg := "Bypass Enabled", "Temporary certificate bypass enabled for this domain. Please refresh to continue."
		if lang == "en" {
			title, msg = "Bypass Enabled", "Temporary certificate bypass enabled for this domain. Please refresh to continue."
		}
		html := fmt.Sprintf("<html><body style='background:#1a1a1a;color:white;font-family:sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh'><h1>%s</h1><p>%s</p><script>setTimeout(()=>history.back(), 2000)</script></body></html>", title, msg)
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(html), html)
		return
	}

	ctx := ErrorContext{
		TargetHost:  host,
		RemoteIP:    ip,
		UpstreamSNI: sni,
		WorkMode:    rule.Mode,
		ECHStatus:   "Disabled",
		RawError:    err.Error(),
	}
	if rule.ECHEnabled {
		ctx.ECHStatus = "Enabled"
		if rule.ECHProfileID != "" {
			ctx.ECHStatus += fmt.Sprintf(" (Profile: %s)", rule.ECHProfileID)
		}
	}
	if req != nil {
		ctx.RequestURL = req.URL.String()
	}

	html := p.renderErrorPage(lang, ctx)
	fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(html), html)

	// Graceful close: give browser time to read the 502
	if tcp, ok := conn.(*net.TCPConn); ok {
		tcp.CloseWrite()
		time.Sleep(100 * time.Millisecond)
	}
}

func (p *ProxyServer) ServeErrorPageHTTP(w http.ResponseWriter, host, ip, sni string, rule Rule, err error) {
	lang := p.rules.GetLanguage()
	if lang == "" {
		lang = "fa"
	}

	ctx := ErrorContext{
		TargetHost:  host,
		RemoteIP:    ip,
		UpstreamSNI: sni,
		WorkMode:    rule.Mode,
		ECHStatus:   "Disabled",
		RawError:    err.Error(),
	}
	if rule.ECHEnabled {
		ctx.ECHStatus = "Enabled"
	}

	html := p.renderErrorPage(lang, ctx)
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusBadGateway)
	w.Write([]byte(html))
}

func (p *ProxyServer) renderErrorPage(lang string, ctx ErrorContext) string {
	title := "Connection Error"
	analysis := "Unable to connect to the target server."
	suggest := "Please check your network connection or proxy settings."

	errLower := strings.ToLower(ctx.RawError)

	if lang == "fa" {
		title = "خطا در اتصال"
		analysis = "امکان اتصال به سرور مقصد وجود ندارد."
		suggest = "لطفاً اتصال شبکه یا تنظیمات پروکسی را بررسی کنید."
	}

	if lang == "fa" {
		if strings.Contains(errLower, "connection reset") || strings.Contains(errLower, "remote error: tls: internal error") {
			title = "مسدود شدن احتمالی SNI"
			analysis = "اتصال در مرحله دست دادن بازنشانی شد. این معمولاً زمانی رخ می‌دهد که فایروال دامنه حساس را تشخیص داده و بسته RST ارسال می‌کند."
			suggest = "تلاش کنید ECH را فعال کنید یا SNI جعلی را تغییر دهید."
		} else if strings.Contains(errLower, "timeout") {
			title = "انقضای زمان اتصال"
			analysis = "در زمان تعیین شده امکان برقراری اتصال وجود ندارد. ممکن است سرور کند باشد یا بسته‌های شبکه در حال افت کردن باشند."
			suggest = "محیط شبکه خود را بررسی کنید یا گره دیگری امتحان کنید."
		} else if strings.Contains(errLower, "connection refused") {
			title = "خطای وب‌سایت یا مسدود شدن IP"
			analysis = "سرور مقصد درخواست اتصال را رد کرد. ممکن است سایت از دسترس خارج باشد یا آدرس IP در لیست سیاه فایروال قرار داشته باشد."
			suggest = "بررسی کنید وب‌سایت در دسترس هست یا IP خروجی دیگری امتحان کنید."
		} else if strings.Contains(errLower, "ech rejection") || strings.Contains(errLower, "ech_required") {
			title = "رد شدن ECH"
			analysis = "سرور پیکربندی Encrypted ClientHello (ECH) را رد کرد. معمولاً به این معنی است که کلید ECH به‌روز شده است."
			suggest = "پروفایل ECH را در تنظیمات بازنشانی کنید یا موقتاً ECH را غیرفعال کنید."
		} else if strings.Contains(errLower, "no such host") || ctx.DNSNode != "" {
			title = "خطای حل DNS"
			analysis = fmt.Sprintf("عدم موفقیت در حل دامنه از طریق گره DNS پیکربندی شده [%s].", ctx.DNSNode)
			suggest = "پیکربندی DNS را بررسی کنید یا از ارائه‌دهنده پایدارتر استفاده کنید."
		}
	} else {
		// English
		title = "Connection Error"
		analysis = "Unable to connect to the target server."
		suggest = "Please check your network connection or proxy settings."

		if strings.Contains(errLower, "connection reset") || strings.Contains(errLower, "remote error: tls: internal error") {
			title = "Suspected SNI Blockage"
			analysis = "The connection was reset during the handshake. This often happens when a firewall detects a sensitive domain and sends a RST packet."
			suggest = "Try enabling ECH or changing the spoofed SNI."
		} else if strings.Contains(errLower, "timeout") {
			title = "Connection Timeout"
			analysis = "Could not establish connection within the allotted time. The server might be slow or network packets are being dropped."
			suggest = "Check your network environment or try another node."
		} else if strings.Contains(errLower, "connection refused") {
			title = "Website Error or IP Blocked"
			analysis = "The target server refused the connection. The site might be down, or the IP address is blacklisted by a firewall."
			suggest = "Verify if the website is accessible elsewhere or try a different egress IP."
		} else if strings.Contains(errLower, "ech rejection") || strings.Contains(errLower, "ech_required") {
			title = "ECH Rejected"
			analysis = "The server rejected the Encrypted ClientHello (ECH) configuration. This usually means the ECH key has expired."
			suggest = "Refresh the ECH Profile in settings or temporarily disable ECH."
		} else if strings.Contains(errLower, "no such host") || ctx.DNSNode != "" {
			title = "DNS Resolution Error"
			analysis = fmt.Sprintf("Failed to resolve domain via configured DNS node [%s].", ctx.DNSNode)
			suggest = "Check your DNS configuration or use a more stable DNS provider."
		}
	}

	return p.generateHTML(lang, title, analysis, suggest, ctx)
}

func (p *ProxyServer) generateHTML(lang, title, analysis, suggest string, ctx ErrorContext) string {
	bgGradient := "linear-gradient(135deg, #1a1a1a 0%, #0d0d0d 100%)"
	accentColor := "#3b82f6"

	labels := map[string]string{
		"target": "هدف",
		"mode":   "حالت کار",
		"ip":     "IP هدف",
		"sni":    "نام میزبان",
		"ech":    "وضعیت ECH",
		"raw":    "خطای خام",
		"diag":   "تحلیل تشخیصی",
		"action": "عملیات پیشنهادی",
		"detail": "جزئیات اتصال",
	}

	if lang == "en" {
		labels = map[string]string{
			"target": "Target",
			"mode":   "Work Mode",
			"ip":     "Remote IP",
			"sni":    "Upstream SNI",
			"ech":    "ECH Status",
			"raw":    "Raw Error",
			"diag":   "Diagnosis",
			"action": "Suggested Action",
			"detail": "Connection Details",
		}
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>NovaProxy Diagnostic</title>
    <style>
        :root {
            --bg: #0a0a0a;
            --card: #141414;
            --text: #e5e5e5;
            --text-muted: #a3a3a3;
            --accent: %s;
            --border: rgba(255, 255, 255, 0.08);
        }
        body {
            margin: 0;
            padding: 0;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: var(--bg);
            background-image: %s;
            color: var(--text);
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
        }
        .container {
            width: 90%%;
            max-width: 500px;
            animation: fadeIn 0.6s ease-out;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 24px;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.4);
            backdrop-filter: blur(10px);
        }
        .icon {
            width: 56px;
            height: 56px;
            background: var(--accent);
            border-radius: 18px;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 24px;
            box-shadow: 0 10px 20px rgba(59, 130, 246, 0.2);
        }
        h1 {
            font-size: 24px;
            font-weight: 800;
            margin: 0 0 12px 0;
            letter-spacing: -0.02em;
        }
        .analysis {
            font-size: 15px;
            line-height: 1.6;
            color: var(--text-muted);
            margin-bottom: 32px;
        }
        .section-title {
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            color: var(--accent);
            margin-bottom: 12px;
        }
        .suggest-card {
            background: rgba(255, 255, 255, 0.03);
            border-radius: 16px;
            padding: 16px;
            margin-bottom: 32px;
            font-size: 14px;
            border-left: 3px solid var(--accent);
        }
        .details {
            display: grid;
            grid-template-cols: auto 1fr;
            gap: 12px 20px;
            font-size: 13px;
        }
        .details-label {
            color: var(--text-muted);
            font-weight: 500;
        }
        .details-value {
            font-weight: 600;
            word-break: break-all;
            font-family: 'JetBrains Mono', 'SF Mono', monospace;
        }
        .raw-error {
            margin-top: 24px;
            padding-top: 24px;
            border-top: 1px solid var(--border);
            font-size: 11px;
            color: rgba(255, 255, 255, 0.3);
            font-family: monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="icon">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="m10.27 2 1.01 2.02a2 2 0 0 0 1.44 1.1L15 6h5a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h5a2 2 0 0 1 .27.02Z"/><path d="M12 11v4"/><path d="M12 17h.01"/></svg>
            </div>
            <h1>%s</h1>
            <div class="analysis">%s</div>

            <div class="section-title">%s</div>
            <div class="suggest-card">%s</div>

            <div class="section-title">%s</div>
            <div class="details">
                <div class="details-label">%s:</div><div class="details-value">%s</div>
                <div class="details-label">%s:</div><div class="details-value">%s</div>
                <div class="details-label">%s:</div><div class="details-value">%s</div>
                <div class="details-label">%s:</div><div class="details-value">%s</div>
                <div class="details-label">%s:</div><div class="details-value">%s</div>
            </div>

            <div class="raw-error">
                %s: %s
            </div>
        </div>
    </div>
</body>
</html>`, accentColor, bgGradient, title, analysis, labels["action"], suggest, labels["detail"],
		labels["target"], ctx.TargetHost, labels["mode"], ctx.WorkMode, labels["ip"], ctx.RemoteIP, labels["sni"], ctx.UpstreamSNI, labels["ech"], ctx.ECHStatus, labels["raw"], ctx.RawError)
}

func (p *ProxyServer) renderCertErrorPage(lang string, ctx ErrorContext) string {
	title := "اتصال شما خصوصی نیست"
	analysis := "NovaProxy ریسک‌هایی را در گواهی سایت تشخیص داد که ممکن است به دلیل انقضاء، عدم تطابق دامنه یا رهگیری باشد."
	suggest := "توصیه می‌شود به حالت امن برگردید. اگر به این سایت اعتماد دارید، روی 'پیشرفته' کلیک کنید."
	advanced := "پیشرفته"
	proceed := "ادامه به %s (غیرامن)"
	back := "بازگشت به حالت امن"

	if lang == "en" {
		title = "Your connection is not private"
		analysis = "NovaProxy detected potential risks with the site's certificate, which could be due to expiration, mismatch, or interception."
		suggest = "We recommend returning to safety. If you trust this site, click 'Advanced' to proceed."
		advanced = "Advanced"
		proceed = "Proceed to %s (unsafe)"
		back = "Back to safety"
	}

	bypassURL := fmt.Sprintf("https://%s/__novaproxy_bypass_cert__?host=%s&url=%s", ctx.TargetHost, ctx.TargetHost, ctx.RequestURL)

	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Privacy Error</title>
    <style>
        body { background: #d32f2f; color: white; font-family: 'Segoe UI', Tahoma, sans-serif; margin: 0; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
        .container { max-width: 600px; padding: 40px; }
        .icon { font-size: 64px; margin-bottom: 20px; }
        h1 { font-size: 32px; margin: 0 0 20px 0; font-weight: 400; }
        p { line-height: 1.6; opacity: 0.9; margin-bottom: 30px; }
        .btns { display: flex; gap: 20px; align-items: center; }
        button { background: white; color: #d32f2f; border: none; padding: 10px 24px; border-radius: 4px; font-weight: bold; cursor: pointer; }
        .advanced-btn { background: transparent; color: white; opacity: 0.8; font-size: 14px; }
        #advanced-panel { display: none; margin-top: 30px; background: rgba(0,0,0,0.1); padding: 20px; border-radius: 4px; font-size: 13px; }
        a { color: white; text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">⚠</div>
        <h1>%s</h1>
        <p>%s</p>
        <div class="btns">
            <button onclick="history.back()">%s</button>
            <div class="advanced-btn" style="cursor:pointer" onclick="document.getElementById('advanced-panel').style.display='block'">%s</div>
        </div>
        <div id="advanced-panel">
            <p>%s</p>
            <p><a href="%s">%s</a></p>
            <div style="font-family: monospace; opacity: 0.6; margin-top: 10px;">Error: CERT_VALIDATION_FAILED<br>Detail: %s</div>
        </div>
    </div>
</body>
</html>`, title, analysis, back, advanced, suggest, bypassURL, fmt.Sprintf(proceed, ctx.TargetHost), ctx.RawError)
}

func isRSTError(err error) bool {
	if err == nil {
		return false
	}
	if opErr, ok := err.(*net.OpError); ok {
		if syscallErr, ok := opErr.Err.(*syscall.Errno); ok {
			return *syscallErr == syscall.ECONNRESET || *syscallErr == syscall.WSAECONNRESET
		}
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "connection reset") || strings.Contains(errStr, "remote error: tls: internal error")
}
