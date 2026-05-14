<div align="center">
  <img src="https://raw.githubusercontent.com/IRNova/Nova-Proxy-App/main/logo.svg" width="120" height="120" alt="NovaProxy Logo">
  <h1>NovaProxy</h1>
  <p><strong>Cloudflare IP Shaper — Domain Fronting Proxy with MITM + GSA Relay Engines</strong></p>
  <p>عبور از فیلترینگ هوشمند با دامنه‌فرانتینگ مبتنی بر Google Apps Script و Cloudflare Worker</p>
</div>

---

## معرفی

NovaProxy یک پروکسی دسکتاپ (Wails v3 / Go) است که ترافیک اینترنت را از طریق زیرساخت Google و Cloudflare عبور می‌دهد. از دید سیستم DPI، همه ترافیک شبیه ارتباط عادی با `www.google.com` است، در حالی که درخواست واقعی به هر سایتی ارسال می‌شود.

دو هسته اصلی:

| هسته | وظیفه |
|------|--------|
| **MITM Engine** | خاتمه TLS، گواهی‌سازی داینامیک، SNI spoofing، fragmentation |
| **GSA Relay** | رله ترافیک از Google Apps Script → Cloudflare Worker با H2 multiplexing |

---



---

## MITM Engine

هسته MITM وظیفه **خاتمه TLS و بازرمزگذاری** را بر عهده دارد تا ترافیک HTTPS قابل بازرسی و مسیریابی باشد.

```
Client → CONNECT tunnel → TLS Termination (MITM Cert) → Upstream TLS (SNI spoofed) → Target
                            │
                     Dynamic Cert Generation
                     (ECDSA P256 signed by Root CA)
```

### معماری MITM

```
ProxyServer.handleConnect()
    │
    ├── direct        → TCP tunnel خام
    ├── transparent   → انتقال بایت‌های TLS بدون خاتمه
    ├── tls-rf        → تکه‌تکه کردن ClientHello + tunnel
    ├── quic          → MITM روی QUIC/HTTP3
    └── mitm          ──► handleMITM()
                            │
                    ┌───────▼────────┐
                    │  establishUpstreamConn()
                    │  - resolve candidates
                    │  - uTLS handshake (fingerprint randomization)
                    │  - ALPN negotiation (h2 / http/1.1)
                    │  - ECH support
                    └───────┬────────┘
                            │
                    ┌───────▼────────┐
                    │  makeMITMTLSConfig()
                    │  - generateCert(host, CA cert, CA key)
                    │  - ECDSA P256 per-host cert
                    │  - cache certs in memory
                    │  - serve to client via tls.Server()
                    └───────┬────────┘
                            │
                    ┌───────▼────────┐
                    │  directTunnel()
                    │  - bidirectional copy (pooled buffers)
                    │  - client ↔ upstream
                    └────────────────┘
```

### امکانات MITM

| قابلیت | توضیح |
|---------|---------|
| **گواهی‌سازی داینامیک** | تولید گواهی ECDSA P256 برای هر دامنه در لحظه، امضا شده توسط Root CA (RSA 2048) |
| **مدیریت Root CA** | ایجاد، نصب و مدیریت CA روی Windows / macOS / Linux / Firefox |
| **خاتمه TLS** | قطع اتصال TLS کلاینت، اتصال مجدد به سرور مقصد با SNI جعلی |
| **SNI Spoofing** | جایگزینی SNI واقعی با دامنهٔ جلویی (مثلاً `www.google.com`) |
| **uTLS Fingerprint** | تقلید اثر انگشت TLS مرورگر Chrome یا Firefox با `refraction-networking/utls` |
| **TLS Fragmentation** | تکه‌تکه کردن ClientHello به چند segment با تأخیر قابل تنظیم برای عبور از DPI |
| **QUIC/HTTP3 MITM** | پشتیبانی از MITM روی QUIC با `quic-go` |
| **ECG (Encrypted ClientHello)** | پشتیبانی از ECH برای مخفی‌سازی SNI |
| **تأیید گواهی پیشرفته** | حالت‌های `allow_names` (لیست سفید)، Custom CA pinning |

### فایل‌های MITM

```
cert/
├── cert.go           # تولید CA، بارگذاری، خروجی PEM، بازتولید
├── installer.go      # نصب/حذف/بررسی CA در سیستم‌عامل
└── exec_windows.go   # اجرای فرمان در ویندوز (hidden/elevated)

proxy/
├── proxy.go          # هندلر MITM، تونل CONNECT، کانفیگ TLS
├── tls_fragment.go   # fragmentation برای دور زدن DPI
├── cert_verify.go    # تأیید گواهی پیشرفته
└── cf_pool.go        # مخزن IP های کلودفلر
```

---

## GSA Relay Engine

هسته GSA ترافیک را از طریق **زیرساخت Google** با تکنیک Domain Fronting رله می‌کند. از دید فیلترینگ، همه ترافیک به نظر `www.google.com` می‌رسد.

```
Browser
    │
    ▼
GSA Proxy (127.0.0.1:8085)
    │  ← TLS Termination (MITM cert)
    ▼
H2 Connection → Google IP (SNI: www.google.com)
    │  ← از دید DPI: ترافیک عادی گوگل
    ▼
Google Apps Script (script.google.com)
    │  ← رله JSON داخل زیرساخت گوگل
    ▼
Cloudflare Worker
    │  ← خروج با IP کلودفلر
    ▼
Site Target
```

### معماری GSA

```
gsaProxyServer.start()
    │
    ├── acceptLoop() → handleHTTP(conn)
    │       │
    │       ├── CONNECT → handleCONNECT()
    │       │       ├── gsaShouldDirectConnect() → relayRawTCP()
    │       │       └── TLS: mitm.getCert() → TLS Server → relayHTTPOverTLS()
    │       │
    │       ├── OPTIONS + access-control-request → CORS Preflight
    │       │
    │       └── GET/POST → relayRequest()
    │               │
    │               ▼
    │          gsaRelay
    │               │
    │               ├── isStatefulRequest()? → relaySingle() (no cache/batch)
    │               │
    │               ├── GET (no range, no stateful) → tryCoalesce()
    │               │       └── waiters share one response
    │               │
    │               ├── بچینگ: batchSubmit() → flushBatch()
    │               │       └── 5ms window, max 50 items
    │               │
    │               ├── کش: cache.get() / cache.put()
    │               │       └── LRU 50MB, TTL: 1h/30min/max-age
    │               │
    │               └── Transport Layer
    │                       ├── H2 Client (HTTP/2 multiplexed)
    │                       │   └── TLS → Google IP (SNI pool rotation)
    │                       │
    │                       └── H1.1 Pool (fallback)
    │                           └── Conn pool (max 50, TTL 45s)
    │
    │
    ├── GSAManager (مدیریت چرخه حیات)
    │       ├── Start/Stop
    │       ├── Auto-Failover (نظارت بر خطا، اسکن IP جدید)
    │       ├── SNI Rotation (چرخش خودکار دامنه جلویی)
    │       ├── Heartbeat (پینگ هر ۳۰ ثانیه)
    │       ├── Google IP Scanner (۲۶ IP ثابت + DNS)
    │       ├── Speed Test (دانلود واقعی)
    │       └── Connection Test (TCP+TLS)
    │
    └── Server Side
            ├── Google Apps Script (Code.gs)
            │       ├── doPost() → دریافت JSON → UrlFetchApp → Worker
            │       ├── doGet() → صفحه وضعیت
            │       └── Batch: doBatch() → UrlFetchApp.fetchAll()
            │
            └── Cloudflare Worker (worker.js)
                    ├── POST → fetch() به مقصد
                    ├── GET → صفحه وضعیت
                    └── Upstream Forwarder (اختیاری)
```

### امکانات GSA

| قابلیت | توضیح |
|---------|--------|
| **Domain Fronting** | اتصال به IP های گوگل با SNI=گوگل، Host واقعی = script.google.com |
| **H2 Multiplexing** | یک اتصال H2 پایدار για همه درخواست‌ها |
| **Connection Pooling** | مخزن ۵۰ تایی اتصال TLS با TTL ۴۵ ثانیه، fallback به H1.1 |
| **Request Batching** | تجمیع درخواست‌ها در پنجره ۵ms (حداکثر ۵۰ تا) و ارسال یکجا |
| **Request Coalescing** | درخواست‌های GET یکسان یک پاسخ مشترک می‌گیرند |
| **Response Caching** | کش LRU با حداکثر ۵۰ مگابایت، TTL هوشمند (۱ ساعت فایل ایستا، ۳۰ دقیقه CSS/JS) |
| **SNI Rotation** | چرخش خودکار SNI در دامنه‌های `www.google.com`، `mail.google.com`، `accounts.google.com` |
| **Auto-Failover** | تشخیص خطاهای متوالی → اسکن خودکار IP جدید → تعویض |
| **Google IP Scanner** | پروب ۲۶ IP ثابت + IP های DNS با هم‌روندی ۸ تایی |
| **Smart Routing** | سرویس‌های حساس گوگل (Gmail, Drive, Meet) مستقیم وصل می‌شوند |
| **SNI Rewrite** | یوتیوب و دابل‌کلیک به طور خودکار SNI بازنویسی می‌شوند |
| **CORS** | هندلر OPTIONS + تزریق هدرهای CORS |
| **Content Decoding** | دیکد خودکار gzip, deflate, brotli, zstd |
| **LAN Sharing** | تشخیص IP های شبکه محلی و اشتراک پروکسی |
| **Split Tunnel** | مسیریابی بر اساس نام برنامه (allowlist) |
| **Speed Test** | اندازه‌گیری سرعت واقعی دانلود از طریق تونل |

### فایل‌های GSA

```
proxy/
├── gsa.go             # GSAManager: config, start/stop, status, IP scan, speed test
├── gsa_relay.go       # gsaRelay: H2/H1.1 transport, batching, caching, coalescing
├── gsa_lan.go         # تشخیص IP های LAN
├── gsa_constants.go   # IP های گوگل، جدول مسیریابی، لیست SNI rewrite
└── config.go          # مدل GSAConfig

server/
├── Code.gs            # Google Apps Script
└── worker.js          # Cloudflare Worker
```

---

## راه‌اندازی سرور

### ۱. Cloudflare Worker

۱. وارد [dash.cloudflare.com](https://dash.cloudflare.com) شوید
۲. منوی چپ → **Compute (Workers)** → **Workers & Pages**
۳. دکمه **Create** → **Start with Hello World**
۴. نام worker را بگذارید (مثلاً `my-nova-relay`)
۵. **Deploy** کنید، سپس **Edit code**
۶. تمام محتوای `server/worker.js` را کپی و جایگزین کنید
۷. خط زیر را پیدا کنید:
```js
const WORKER_URL = "Your-Cloudflare-worker-address";
```
۸. مقدار را با آدرس واقعی worker خود جایگزین کنید:
```js
const WORKER_URL = "my-nova-relay.yourname.workers.dev";
```
۹. **Deploy** را بزنید و آدرس worker را یادداشت کنید

### ۲. Google Apps Script

۱. وارد [script.google.com](https://script.google.com) شوید
۲. **New project**
۳. تمام محتوای `server/Code.gs` را کپی و جایگزین کنید
۴. دو خط زیر را پیدا کنید:
```js
const AUTH_KEY = "Novaproxy";
const WORKER_URL = "https://nova3.altramax083.workers.dev";
```
۵. تغییر دهید:
   - `AUTH_KEY` ← یک رمز دلخواه قوی (مثلاً `mY$tr0nGK3y2024x`)
   - `WORKER_URL` ← آدرس worker که در مرحله قبل یادداشت کردید
۶. **Ctrl+S** ذخیره کنید
۷. منوی بالا → **Deploy** → **New deployment**
۸. ⚙️ → **Web app** را انتخاب کنید
۹. تنظیمات:
   - **Execute as**: `Me`
   - **Who has access**: `Anyone`
۱۰. **Deploy** کنید
۱۱. در صورت درخواست دسترسی:
    - **Authorize access**
    - حساب گوگل خود را انتخاب کنید
    - **Advanced** → **Go to [project name] (unsafe)** → **Allow**
۱۲. **Deployment ID** را کپی کنید (شبیه `AKfycbz...`)

### ۳. کانفیگ نرم‌افزار

فایل `data/gsa/config.json` را با این مقادیر پر کنید:

```json
{
  "auth_key": "همان AUTH_KEY که در Code.gs گذاشتید",
  "google_ip": "216.239.38.120",
  "front_domain": "www.google.com",
  "script_id": "Deployment ID مرحله قبل",
  "listen_host": "127.0.0.1",
  "listen_port": 8085,
  "verify_ssl": true,
  "worker_url": "https://my-nova-relay.yourname.workers.dev"
}
```

### ۴. اجرا

```bash
# حالت گرافیکی
novaproxy

# حالت بدون رابط کاربری (هسته)
novaproxy --core
```

مرورگر را روی پروکسی تنظیم کنید:
- **HTTP Proxy**: `127.0.0.1:8085` (GSA) یا `127.0.0.1:8080` (MITM)
- **SOCKS5**: `127.0.0.1:1080`

---

## پیش‌نیازها

- Go 1.25.5+
- Node.js (برای build فرانت)
- Wails v3
- حساب Google (برای Apps Script)
- حساب Cloudflare (برای Worker)

---

## قدردانی

بخش **GSA** این پروژه بر پایه نسخه اولیه [mhr-cfw-go](https://github.com/denuitt1/mhr-cfw-go) ساخته شده است. از این پروژه به عنوان نقطه شروع برای هسته رله Google Apps Script استفاده شده، اما پس از آن ارتقاهای اساسی شامل HTTP/2 multiplexing، connection pooling، request batching، caching، coalescing، auto-failover، SNI rotation، CORS support، content decoding، و ده‌ها قابلیت دیگر به آن اضافه شده است.

فرمت مستندات و ساختار راهنما از پروژه [SniShaper](https://github.com/SniShaper/SniShaper) الهام گرفته شده است. از团队 SniShaper برای این کار تشکر می‌شود. توجه داشته باشید که **SniShaper** برای دور زدن محدودیت‌های اینترنت چین (GFW) طراحی شده و معماری، هسته MITM و هسته GSA پروژه Nova هیچ ارتباط کدبیس یا وابستگی با آن پروژه ندارند. NovaProxy به طور خاص برای رفع محدودیت‌های اینترنت ایران توسعه یافته است.

---

## سلب مسئولیت

این نرم‌افزار فقط برای اهداف آموزشی، تحقیقاتی و تست ارائه شده است.

- نرم‌افزار «همانطور که هست» (AS IS) ارائه می‌شود بدون هیچ ضمانتی
- توسعه‌دهندگان مسئولیتی در قبال خسارات احتمالی ندارند
- رعایت قوانین محلی، ملی و بین‌المللی بر عهده کاربر است
- رعایت شرایط استفاده از سرویس‌های Google و Cloudflare بر عهده کاربر است

---

## Stargazers over time

[![Stargazers over time](https://starchart.cc/IRNova/Nova-Proxy-App.svg?variant=adaptive)](https://starchart.cc/IRNova/Nova-Proxy-App)
