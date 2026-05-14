<div align="center">
  <img src="https://raw.githubusercontent.com/IRNova/Nova-Proxy-App/main/logo.svg" width="120" height="120" alt="NovaProxy Logo">
  <h1>NovaProxy</h1>
  <p><strong>Cloudflare IP Shaper — Domain Fronting Proxy with MITM + GSA Relay Engines</strong></p>
  <p>عبور از فیلترینگ هوشمند با دامنه‌فرانتینگ مبتنی بر Google Apps Script و Cloudflare Worker</p>
  <p>
    <a href="#fa">🇮🇷 فارسی</a> &nbsp;|&nbsp; <a href="#en">🇬🇧 English</a>
  </p>
</div>

---

<a name="fa"></a>

## معرفی

NovaProxy یک پروکسی دسکتاپ (Wails v3 / Go) است که ترافیک اینترنت را از طریق زیرساخت Google و Cloudflare عبور می‌دهد. از دید سیستم DPI، همه ترافیک شبیه ارتباط عادی با `www.google.com` است، در حالی که درخواست واقعی به هر سایتی ارسال می‌شود.

دو هسته اصلی:

| هسته | وظیفه |
|------|--------|
| **MITM Engine** | خاتمه TLS، گواهی‌سازی داینامیک، SNI spoofing، fragmentation |
| **GSA Relay** | رله ترافیک از Google Apps Script → Cloudflare Worker با H2 multiplexing |

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
├── installer.go      # نصب/حذف/بررسی CA در سیستمعامل
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
const WORKER_URL = "https://my-nova-relay.yourname.workers.dev";
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

### ۳. آموزش استفاده از نرم‌افزار

#### مرحله اول — راه‌اندازی اولیه

.
فایل `novaproxy.exe` را با دو کلیک باز کنید.
.
صفحه خوش‌آمدگویی نمایش داده می‌شود. یک **پاپ‌آپ** برای نصب گواهی (Certificate) مربوط به دو قابلیت نمایش داده می‌شود — آن را نصب کنید.
.
بعد از نصب گواهی:
   - **کشور** را روی **Iran** قرار دهید.
   - **زبان** و **تم** مورد نظر را انتخاب کنید.
   - دکمه **Start** را بزنید.

#### بدون GSA — فقط MITM

اگر فقط دکمه Start را بزنید و قابلیت **Google Apps Script** را فعال نکنید:
- پروکسی و پروکسی سیستم روشن می‌شود.
- از بخش **قوانین**، قوانین موجود خوانده می‌شود.
- سایت‌هایی که در لیست MITM هستند (مثل تمام سایت‌های زیرمجموعه گوگل، یوتیوب و...) باز می‌شوند.
- **نکته:** فیلم‌های یوتیوب به دلیل اینکه سرور ویدیو خارج از دامنه گوگل است، باز نمی‌شوند.

#### فعال‌سازی GSA

برای استفاده از قابلیت **Google Apps Script**:

.
به صفحه **پروکسی** بروید.
.
در بخش مربوط به GSA، اطلاعات پیش‌فرض را ویرایش کرده و مقادیر جدید (Auth Key، Script ID، Worker URL) را وارد کنید.
.
دکمه **ذخیره** را بزنید.
.
به صفحه **مسیریابی** بروید و مسیریابی را روی **خودکار GSA** تنظیم کنید. سیستم به صورت خودکار بهترین IP را برای شما انتخاب می‌کند.
.
به صفحه **تنظیمات GSA** بروید و دکمه **اسکن IP** را بزنید تا بین IP‌های موجود، بهترین‌ها برای کار پیدا شوند.

#### شروع کار با GSA

به صفحه **داشبورد** بروید و مراحل زیر را به ترتیب انجام دهید:

.
**پروکسی** را روشن کنید.
.
**پروکسی سیستم** را روشن کنید.
.
**کلید GSA** را روشن کنید.

حالا می‌توانید از مرورگر همه سایت‌ها را باز کنید — حتی **تلگرام وب** به خوبی کار می‌کند.

> **توجه:** در حال حاضر برنامه‌های دسکتاپ مثل تلگرام ویندوز از داخل خود سیستمعامل از طریق GSA قابل استفاده نیستند، اما همه سایت‌ها در مرورگر به خوبی باز می‌شوند.

---

## پیش‌نیازها

- حساب Google (برای Apps Script)
- حساب Cloudflare (برای Worker)

---

## قدردانی

بخش **GSA** این پروژه بر پایه نسخه اولیه [mhr-cfw-go](https://github.com/denuitt1/mhr-cfw-go) ساخته شده است. از این پروژه به عنوان نقطه شروع برای هسته رله Google Apps Script استفاده شده، اما پس از آن ارتقاهای اساسی پیدا کرده و کلی قابلیت به آن اضافه شده است.

از [denuitt1](https://github.com/denuitt1) بابت ارائه این پروژه تشکر می‌شود.

فرانت‌اند (بخش UI) این پروژه از فرانت‌اند پروژه [SniShaper](https://github.com/SniShaper/SniShaper) گرفته شده است. توجه داشته باشید که **SniShaper** برای دور زدن محدودیت‌های اینترنت چین طراحی شده و معماری، هسته MITM و هسته GSA پروژه Nova هیچ ارتباط کدبیس یا وابستگی با آن پروژه ندارند. NovaProxy به طور خاص برای رفع محدودیت‌های اینترنت ایران توسعه یافته است.

از [SniShaper](https://github.com/SniShaper) بابت ارائه این فرانت‌اند تشکر می‌شود.

### مقایسه SniShaper و NovaProxy

| شاخص | SniShaper | نوا پروکسی (Nova-Proxy-App) |
|------|-----------|---------------------------|
| **زبان اصلی** | Go 87%, TypeScript | Go, TypeScript (Wails v3) |
| **پشتیبانی از TUN Mode** | خیر | بله |
| **پشتیبانی از Google Apps Script** | خیر | بله (GSA Relay) |
| **تکنیک اصلی Bypass** | دستکاری ClientHello | MITM + Domain Fronting (GSA) |

### تفاوت‌های کلیدی (منحصربه‌فرد بودن Nova)

Nova تنها یک کپی ساده نیست و قابلیت‌های پیشرفته‌ای دارد که در SniShaper دیده نمی‌شود:

- **موتور GSA (Google Apps Script):** مهم‌ترین تفاوت، وجود این موتور است که ترافیک را از طریق سرورهای گوگل رله می‌کند. SniShaper چنین قابلیتی ندارد.
- **اپتیمایزیشن اختصاصی:** Nova به طور ویژه برای عبور از فیلترینگ ایران بهینه‌سازی شده و از Pool آیپی‌های کلودفلر و WARP Masque پشتیبانی می‌کند.
- **حالت TUN:** حالت TUN در Nova به شما اجازه می‌دهد کل ترافیک سیستمعامل را بدون تنظیم دستی مدیریت کنید، در حالی که SniShaper چنین قابلیتی ندارد.

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

---

<a name="en"></a>

## Introduction

NovaProxy is a desktop proxy (Wails v3 / Go) that routes internet traffic through Google and Cloudflare infrastructure. From the DPI's perspective, all traffic looks like normal communication with `www.google.com`, while actual requests are sent to any target site.

Two main cores:

| Core | Function |
|------|----------|
| **MITM Engine** | TLS termination, dynamic certificate generation, SNI spoofing, fragmentation |
| **GSA Relay** | Relay traffic through Google Apps Script → Cloudflare Worker with H2 multiplexing |

---

## MITM Engine

The MITM Engine handles **TLS termination and re-encryption**, making HTTPS traffic inspectable and routable.

```
Client → CONNECT tunnel → TLS Termination (MITM Cert) → Upstream TLS (SNI spoofed) → Target
                            │
                     Dynamic Cert Generation
                     (ECDSA P256 signed by Root CA)
```

### MITM Architecture

```
ProxyServer.handleConnect()
    │
    ├── direct        → Raw TCP tunnel
    ├── transparent   → Forward TLS bytes without termination
    ├── tls-rf        → Fragment ClientHello + tunnel
    ├── quic          → MITM over QUIC/HTTP3
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

### MITM Capabilities

| Feature | Description |
|---------|-------------|
| **Dynamic Certificate Generation** | Generate ECDSA P256 certificate per domain on-the-fly, signed by Root CA (RSA 2048) |
| **Root CA Management** | Create, install, and manage CA on Windows / macOS / Linux / Firefox |
| **TLS Termination** | Terminate client TLS, reconnect to target with spoofed SNI |
| **SNI Spoofing** | Replace real SNI with front domain (e.g. `www.google.com`) |
| **uTLS Fingerprint** | Mimic Chrome or Firefox TLS fingerprint via `refraction-networking/utls` |
| **TLS Fragmentation** | Fragment ClientHello into multiple segments with configurable delay to bypass DPI |
| **QUIC/HTTP3 MITM** | MITM support over QUIC via `quic-go` |
| **ECH (Encrypted ClientHello)** | ECH support to hide SNI |
| **Advanced Certificate Verification** | `allow_names` whitelist modes, Custom CA pinning |

### MITM Files

```
cert/
├── cert.go           # CA generation, loading, PEM output, regeneration
├── installer.go      # Install/remove/check CA on OS
└── exec_windows.go   # Execute commands on Windows (hidden/elevated)

proxy/
├── proxy.go          # MITM handler, CONNECT tunnel, TLS config
├── tls_fragment.go   # Fragmentation for DPI bypass
├── cert_verify.go    # Advanced certificate verification
└── cf_pool.go        # Cloudflare IP pool
```

---

## GSA Relay Engine

The GSA Relay routes traffic through **Google infrastructure** using the Domain Fronting technique. From the DPI's perspective, all traffic appears to be destined for `www.google.com`.

```
Browser
    │
    ▼
GSA Proxy (127.0.0.1:8085)
    │  ← TLS Termination (MITM cert)
    ▼
H2 Connection → Google IP (SNI: www.google.com)
    │  ← From DPI perspective: normal Google traffic
    ▼
Google Apps Script (script.google.com)
    │  ← JSON relay inside Google infrastructure
    ▼
Cloudflare Worker
    │  ← Exit with Cloudflare IP
    ▼
Site Target
```

### GSA Architecture

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
    │               ├── batching: batchSubmit() → flushBatch()
    │               │       └── 5ms window, max 50 items
    │               │
    │               ├── cache: cache.get() / cache.put()
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
    ├── GSAManager (lifecycle management)
    │       ├── Start/Stop
    │       ├── Auto-Failover (error monitoring, new IP scan)
    │       ├── SNI Rotation (automatic front domain rotation)
    │       ├── Heartbeat (ping every 30s)
    │       ├── Google IP Scanner (26 static IPs + DNS)
    │       ├── Speed Test (real download)
    │       └── Connection Test (TCP+TLS)
    │
    └── Server Side
            ├── Google Apps Script (Code.gs)
            │       ├── doPost() → receive JSON → UrlFetchApp → Worker
            │       ├── doGet() → status page
            │       └── Batch: doBatch() → UrlFetchApp.fetchAll()
            │
            └── Cloudflare Worker (worker.js)
                    ├── POST → fetch() to target
                    ├── GET → status page
                    └── Upstream Forwarder (optional)
```

### GSA Capabilities

| Feature | Description |
|---------|-------------|
| **Domain Fronting** | Connect to Google IPs with SNI=google, actual Host=script.google.com |
| **H2 Multiplexing** | Single persistent H2 connection for all requests |
| **Connection Pooling** | 50-connection TLS pool with 45s TTL, H1.1 fallback |
| **Request Batching** | Aggregate requests in 5ms window (max 50), send as batch |
| **Request Coalescing** | Identical GET requests share a single response |
| **Response Caching** | LRU cache up to 50MB, smart TTL (1h static, 30min CSS/JS) |
| **SNI Rotation** | Automatic SNI rotation across `www.google.com`, `mail.google.com`, `accounts.google.com` |
| **Auto-Failover** | Detect consecutive errors → automatic new IP scan → switch |
| **Google IP Scanner** | Probe 26 static IPs + DNS IPs with 8-way concurrency |
| **Smart Routing** | Sensitive Google services (Gmail, Drive, Meet) connect directly |
| **SNI Rewrite** | YouTube and DoubleClick SNI auto-rewritten |
| **CORS** | OPTIONS handler + CORS header injection |
| **Content Decoding** | Auto-decode gzip, deflate, brotli, zstd |
| **LAN Sharing** | LAN IP detection and proxy sharing |
| **Split Tunnel** | Route by application name (allowlist) |
| **Speed Test** | Real download speed measurement through tunnel |

### GSA Files

```
proxy/
├── gsa.go             # GSAManager: config, start/stop, status, IP scan, speed test
├── gsa_relay.go       # gsaRelay: H2/H1.1 transport, batching, caching, coalescing
├── gsa_lan.go         # LAN IP detection
├── gsa_constants.go   # Google IPs, routing table, SNI rewrite list
└── config.go          # GSAConfig model

server/
├── Code.gs            # Google Apps Script
└── worker.js          # Cloudflare Worker
```

---

## Server Setup

### 1. Cloudflare Worker

1. Go to [dash.cloudflare.com](https://dash.cloudflare.com)
2. Left menu → **Compute (Workers)** → **Workers & Pages**
3. Click **Create** → **Start with Hello World**
4. Name your worker (e.g. `my-nova-relay`)
5. Click **Deploy**, then **Edit code**
6. Copy all contents of `server/worker.js` and replace
7. Find this line:
```js
const WORKER_URL = "Your-Cloudflare-worker-address";
```
8. Replace with your actual worker address:
```js
const WORKER_URL = "my-nova-relay.yourname.workers.dev";
```
9. Click **Deploy** and note your worker URL

### 2. Google Apps Script

1. Go to [script.google.com](https://script.google.com)
2. **New project**
3. Copy all contents of `server/Code.gs` and replace
4. Find these two lines:
```js
const AUTH_KEY = "Novaproxy";
const WORKER_URL = "https://my-nova-relay.yourname.workers.dev";
```
5. Change:
   - `AUTH_KEY` ← a strong custom password (e.g. `mY$tr0nGK3y2024x`)
   - `WORKER_URL` ← your worker URL from the previous step
6. **Ctrl+S** to save
7. Top menu → **Deploy** → **New deployment**
8. ⚙️ → Select **Web app**
9. Settings:
   - **Execute as**: `Me`
   - **Who has access**: `Anyone`
10. Click **Deploy**
11. If prompted for access:
    - **Authorize access**
    - Select your Google account
    - **Advanced** → **Go to [project name] (unsafe)** → **Allow**
12. Copy the **Deployment ID** (looks like `AKfycbz...`)

### 3. Usage Tutorial

#### Step 1 — Initial Setup

1. Double-click `novaproxy.exe` to launch.
2. The welcome screen appears. A **popup** for certificate installation will show — install it.
3. After installing the certificate:
   - Set **Country** to **Iran**.
   - Choose your preferred **Language** and **Theme**.
   - Click **Start**.

#### Without GSA — MITM Only

If you just click Start without activating the **Google Apps Script** feature:
- Proxy and system proxy will be enabled.
- Rules from the **Rules** section will be loaded.
- Sites in the MITM whitelist (e.g. all Google subdomains, YouTube, etc.) will open.
- **Note:** YouTube videos won't play because video servers are outside Google's domains.

#### Activating GSA

To use the **Google Apps Script** feature:

1. Go to the **Proxy** page.
2. In the GSA section, edit the default values and enter your new data (Auth Key, Script ID, Worker URL).
3. Click **Save**.
4. Go to the **Routing** page and set routing to **Auto GSA**.
   - The system will automatically select the best IP for you.
5. Go to **GSA Settings** and click **Scan IP** to find the best IPs.

#### Using GSA

Go to the **Dashboard** and follow these steps in order:

1. Enable **Proxy**.
2. Enable **System Proxy**.
3. Enable **GSA Toggle**.

Now you can browse any site — even **Telegram Web** works perfectly.

> **Note:** Desktop apps like Telegram for Windows currently cannot use GSA directly from the OS, but all sites work fine in the browser.

---

## Prerequisites

- Google account (for Apps Script)
- Cloudflare account (for Worker)

---

## Acknowledgments

The **GSA** section of this project is based on the initial version of [mhr-cfw-go](https://github.com/denuitt1/mhr-cfw-go). This project was used as a starting point for the Google Apps Script relay core, but has since been significantly upgraded with many new features.

Thanks to [denuitt1](https://github.com/denuitt1) for providing this project.

The frontend (UI) of this project is taken from the [SniShaper](https://github.com/SniShaper/SniShaper) project. Note that **SniShaper** is designed to bypass China's internet restrictions, and the MITM and GSA cores of Nova have no codebase relationship or dependency on that project. NovaProxy is specifically developed to bypass internet restrictions in Iran.

Thanks to [SniShaper](https://github.com/SniShaper) for providing this frontend.

### SniShaper vs NovaProxy Comparison

| Metric | SniShaper | Nova-Proxy-App |
|--------|-----------|----------------|
| **Language** | Go 87%, TypeScript | Go, TypeScript (Wails v3) |
| **TUN Mode** | No | Yes |
| **Google Apps Script** | No | Yes (GSA Relay) |
| **Main Bypass Technique** | ClientHello manipulation | MITM + Domain Fronting (GSA) |

### Key Differences (What Makes Nova Unique)

Nova is not just a simple copy — it has advanced features not found in SniShaper:

- **GSA Engine (Google Apps Script):** The most important difference — relays traffic through Google's servers. SniShaper does not have this capability.
- **Custom Optimization:** Nova is specifically optimized for bypassing Iran's internet restrictions, with Cloudflare IP Pool and WARP Masque support.
- **TUN Mode:** Nova's TUN mode allows managing all OS traffic without manual configuration, unlike SniShaper.

---

## Disclaimer

This software is provided for educational, research, and testing purposes only.

- The software is provided "AS IS" without any warranty
- The developers are not liable for any damages
- Compliance with local, national, and international laws is the user's responsibility
- Compliance with Google and Cloudflare terms of service is the user's responsibility

---

## Stargazers over time

[![Stargazers over time](https://starchart.cc/IRNova/Nova-Proxy-App.svg?variant=adaptive)](https://starchart.cc/IRNova/Nova-Proxy-App)
