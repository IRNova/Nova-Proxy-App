// Cloudflare Worker Nova Proxy Relay

const WORKER_URL = "Your-Cloudflare-worker-address";

const DEFAULT_UPSTREAM_TIMEOUT_MS = 25000;

export default {
    async fetch(request, env) {
        try {
            const hop = request.headers.get("x-relay-hop");
            const fwdHop = request.headers.get("x-fwd-hop");
            if (hop === "1" || fwdHop === "1") {
                return json({ e: "loop detected" }, 508);
            }

            if (request.method == "GET") {
                const actualHost = new URL(request.url).hostname;
                return new Response(getHTML(actualHost), {
                    status: 200,
                    headers: { "content-type": "text/html; charset=utf-8" }
                });
            }

            if (request.method !== "POST") {
                return json({ e: "Method not allowed." }, 405);
            }

            const req = await request.json();

            if (!req.u) {
                return json({ e: "missing url" }, 400);
            }

            const targetUrl = new URL(req.u);

            const BLOCKED_HOSTS = [
                WORKER_URL,
            ];

            if (BLOCKED_HOSTS.some(h => targetUrl.hostname.endsWith(h))) {
                return json({ e: "self-fetch blocked" }, 400);
            }

            const upstreamUrl = (env && env.UPSTREAM_FORWARDER_URL) || "";
            if (upstreamUrl) {
                const upstreamResp = await forwardViaUpstream(req, env, upstreamUrl);
                if (upstreamResp) return upstreamResp;
                // fall through to direct fetch only when fail-mode is open
            }

            const headers = new Headers();
            if (req.h && typeof req.h === "object") {
                for (const [k, v] of Object.entries(req.h)) {
                    headers.set(k, v);
                }
            }

            headers.set("x-relay-hop", "1");

            const fetchOptions = {
                method: (req.m || "GET").toUpperCase(),
                headers,
                redirect: req.r === false ? "manual" : "follow"
            };

            if (req.b) {
                const binary = Uint8Array.from(atob(req.b), c => c.charCodeAt(0));
                fetchOptions.body = binary;
            }

            const resp = await fetch(targetUrl.toString(), fetchOptions);

            // Read response safely (no stack overflow)
            const buffer = await resp.arrayBuffer();
            const uint8 = new Uint8Array(buffer);

            let binary = "";
            const chunkSize = 0x8000; // prevent call stack overflow

            for (let i = 0; i < uint8.length; i += chunkSize) {
                binary += String.fromCharCode.apply(
                    null,
                    uint8.subarray(i, i + chunkSize)
                );
            }

            const base64 = btoa(binary);

            const responseHeaders = {};
            resp.headers.forEach((v, k) => {
                responseHeaders[k] = v;
            });

            return json({
                s: resp.status,
                h: responseHeaders,
                b: base64
            });

        } catch (err) {
            return json({ e: String(err) }, 500);
        }
    }
};

async function forwardViaUpstream(req, env, upstreamUrl) {
    const failMode = (env.UPSTREAM_FAIL_MODE || "closed").toLowerCase();
    const timeoutMs = parseInt(env.UPSTREAM_TIMEOUT_MS, 10) || DEFAULT_UPSTREAM_TIMEOUT_MS;
    const authKey = env.UPSTREAM_AUTH_KEY || "";

    let parsed;
    try {
        parsed = new URL(upstreamUrl);
    } catch (_) {
        return upstreamFailure("invalid UPSTREAM_FORWARDER_URL", failMode);
    }
    if (parsed.protocol !== "https:") {
        return upstreamFailure("UPSTREAM_FORWARDER_URL must be https://", failMode);
    }
    if (parsed.hostname.endsWith(WORKER_URL)) {
        return upstreamFailure("self-forward blocked", failMode);
    }
    if (!authKey) {
        return upstreamFailure("UPSTREAM_AUTH_KEY missing", failMode);
    }

    const payload = {
        u: req.u,
        m: req.m,
        h: req.h,
        b: req.b,
        ct: req.ct,
        r: req.r
    };

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
        const resp = await fetch(upstreamUrl, {
            method: "POST",
            headers: {
                "content-type": "application/json",
                "x-upstream-auth": authKey
            },
            body: JSON.stringify(payload),
            signal: controller.signal
        });

        if (!resp.ok) {
            return upstreamFailure("forwarder status " + resp.status, failMode);
        }

        // Pass body straight through without parsing â€” saves CPU and memory.
        const body = await resp.text();
        return new Response(body, {
            status: 200,
            headers: { "content-type": "application/json" }
        });
    } catch (err) {
        return upstreamFailure(String(err && err.message || err), failMode);
    } finally {
        clearTimeout(timer);
    }
}

function upstreamFailure(reason, failMode) {
    if (failMode === "open") {
        console.warn("upstream forwarder failed (falling back to direct):", reason);
        return null; // signals caller to fall through to direct fetch
    }
    return json({ e: "upstream forwarder failed: " + reason }, 502);
}

function json(obj, status = 200) {
    return new Response(JSON.stringify(obj), {
        status,
        headers: {
            "content-type": "application/json"
        }
    });
}

function getHTML(actualHost) {
    const expectedHost = WORKER_URL;
    const hostMismatch = actualHost && expectedHost && actualHost !== expectedHost;
    const logoUrl = "https://raw.githubusercontent.com/IRNova/Nova-Proxy-App/main/logo.svg";
    return `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Nova Proxy Relay</title>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;700;900&display=swap" rel="stylesheet">
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: 'Vazirmatn', sans-serif;
    background: #fff;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    text-align: center;
    padding: 20px;
  }
  .logo {
    width: 120px;
    height: 120px;
    border-radius: 50%;
    object-fit: cover;
    animation: pulse 2s ease-in-out infinite;
    box-shadow: 0 0 0 0 rgba(231, 76, 60, 0.4);
  }
  @keyframes pulse {
    0% { transform: scale(1); box-shadow: 0 0 0 0 rgba(231, 76, 60, 0.4); }
    50% { transform: scale(1.05); box-shadow: 0 0 0 15px rgba(231, 76, 60, 0); }
    100% { transform: scale(1); box-shadow: 0 0 0 0 rgba(231, 76, 60, 0); }
  }
  .heart {
    display: inline-block;
    font-size: 28px;
    animation: heartBeat 1.2s ease-in-out infinite;
    color: #e74c3c;
  }
  @keyframes heartBeat {
    0%, 100% { transform: scale(1); }
    15% { transform: scale(1.25); }
    30% { transform: scale(1); }
    45% { transform: scale(1.15); }
    60% { transform: scale(1); }
  }
  h1 {
    font-size: 36px;
    font-weight: 900;
    color: #2c3e50;
    margin-top: 20px;
  }
  .status {
    font-size: 20px;
    color: #27ae60;
    font-weight: 700;
    margin-top: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
  }
  .status-dot {
    width: 10px;
    height: 10px;
    background: #27ae60;
    border-radius: 50%;
    display: inline-block;
    animation: blink 1.4s ease-in-out infinite;
  }
  @keyframes blink {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.2; }
  }
  .subtitle {
    font-size: 14px;
    color: #95a5a6;
    margin-top: 6px;
  }
  .footer {
    margin-top: 40px;
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .footer a {
    text-decoration: none;
    color: #333;
    font-size: 14px;
    display: flex;
    align-items: center;
    gap: 6px;
    transition: color 0.2s;
  }
  .footer a:hover { color: #e74c3c; }
  .github-icon svg { width: 22px; height: 22px; fill: #333; transition: fill 0.2s; }
  .footer a:hover .github-icon svg { fill: #e74c3c; }
  .mismatch-warning {
    background: #fff3cd;
    border: 2px solid #ffc107;
    border-radius: 12px;
    padding: 12px 20px;
    margin-top: 16px;
    display: flex;
    align-items: center;
    gap: 12px;
    text-align: right;
    font-size: 14px;
    color: #856404;
    max-width: 420px;
  }
  .mismatch-icon { font-size: 28px; }
  .mismatch-detail { font-size: 12px; opacity: 0.8; }
</style>
</head>
<body>
  <img class="logo" src="${logoUrl}" alt="نوا پروکسی">
  <h1>نوا پروکسی</h1>
  ${hostMismatch ? `
  <div class="mismatch-warning">
    <div class="mismatch-icon">⚡</div>
    <div>
      <strong>خطا: نام ورکر متفاوت است</strong><br>
      <span class="mismatch-detail">ورکر فعلی: ${actualHost}</span><br>
      <span class="mismatch-detail">ورکر مورد انتظار: ${expectedHost}</span>
    </div>
  </div>` : ''}
  <div class="status">
    <span class="status-dot"></span>
    رله نوا فعال است
    <span class="heart">♥</span>
  </div>
  <div class="subtitle">Nova Proxy Relay</div>
  <div class="footer">
    <a href="https://github.com/IRNova/Nova-Proxy-App" target="_blank" rel="noopener">
      <span class="github-icon">
        <svg viewBox="0 0 16 16"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
      </span>
      Nova Proxy Relay
    </a>
  </div>
</body>
</html>`;
}



