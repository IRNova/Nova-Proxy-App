<div dir="rtl">

# نوواپراکسی (NovaProxy) - Cloudflare IP Shaper

<p align="center">
  <img src="https://github.com/IRNova/Nova-Proxy-App/blob/main/logo.svg" alt="NovaProxy Logo" width="128"/>
</p>

<p align="center">
  <strong>پروکسی هوشمند با پشتیبانی از MITM، Domain Fronting، TUN و ECH</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.25-blue" />
  <img src="https://img.shields.io/badge/Platform-Windows-lightblue" />
  <img src="https://img.shields.io/badge/UI-Wails_v3-purple" />
  <img src="https://img.shields.io/badge/License-MIT-green" />
</p>

---

## فهرست مطالب

1. [معرفی پروژه](#معرفی-پروژه)
2. [معماری کلی سیستم](#معماری-کلی-سیستم)
3. [هسته‌های اصلی](#هسته‌های-اصلی)
   - [Proxy Core](#proxy-core)
   - [GSA Core (Google Scripts Apps Domain Fronting)](#gsa-core)
   - [Core Runtime (فرآیند پشتیبان)](#core-runtime)
   - [Auto Router](#auto-router)
   - [Rule Manager & Config](#rule-manager--config)
   - [DNS Resolver (DoH Failover)](#dns-resolver)
   - [TUN Mode (Mihomo)](#tun-mode)
   - [Certificate Manager](#certificate-manager)
   - [utls (TLS Fingerprinting)](#utls)
   - [Frontend (UI)](#frontend)
4. [نقشه راه GSA](#نقشه-راه-gsa)
5. [نقشه راه کلی پروژه](#نقشه-راه-کلی-پروژه)
6. [نحوه نصب و اجرا](#نحوه-نصب-و-اجرا)
7. [ساختار دایرکتوری‌ها](#ساختار-دایرکتوری‌ها)
8. [تکنولوژی‌های استفاده شده](#تکنولوژی‌های-استفاده-شده)

---

## معرفی پروژه

**NovaProxy** یک پروکسی پیشرفته و دسکتاپی است که با زبان **Go** و فریمورک **Wails v3** ساخته شده است. این ابزار برای کاربرانی طراحی شده که نیاز به عبور هوشمند از محدودیت‌های اینترنتی دارند و از تکنیک‌های متنوعی مانند:

- **MITM Proxy** با گواهی‌های داینامیک
- **Domain Fronting** از طریق Google Apps Script (GSA)
- **TLS Fragmentation (TLS-RF)** برای دور زدن Deep Packet Inspection
- **TUN Mode** با هسته‌ی Mihomo (Clash.Meta)
- **ECH (Encrypted Client Hello)** با پشتیبانی از Cloudflare
- **Cloudflare IP Pool** با Health Check خودکار
- **DNS-over-HTTPS** با Failover
- **Auto Routing** مبتنی بر GFWList
- **SOCKS5 Proxy**
</div>

---

## معماری کلی سیستم

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Wails v3 Desktop App                        │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────────────┐  │
│  │   Frontend   │  │  System Tray │  │       Main Window         │  │
│  │  (Svelte/TS) │  │  (Tray Icon) │  │  (Dashboard / Settings)   │  │
│  └──────┬──────┘  └──────┬───────┘  └─────────────┬─────────────┘  │
│         └────────────────┼────────────────────────┘                │
│                          ▼                                         │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                    App (Service Layer)                        │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────────┐  │  │
│  │  │ProxyServer│  │GSAManager│  │RuleManager│  │CertManager  │  │  │
│  │  └────┬─────┘  └────┬─────┘  └────┬─────┘  └──────┬──────┘  │  │
│  └───────┼──────────────┼─────────────┼────────────────┼─────────┘  │
│          │              │             │                │            │
│          ▼              ▼             ▼                ▼            │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                  Core Client (RPC over TCP)                   │  │
│  │              ┌─────────────────────────────────────┐         │  │
│  │              │     127.0.0.1:18933 (TCP RPC)       │         │  │
│  │              └─────────────────────────────────────┘         │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    Core Runtime (Separate Process)                   │
│  ┌──────────┐  ┌──────────┐  ┌─────────────┐  ┌────────────────┐  │
│  │ProxyServer│  │RuleManager│  │CertManager   │  │External Mihomo │  │
│  │ (MITM/..) │  │          │  │              │  │ (TUN Mode)    │  │
│  └────┬─────┘  └──────────┘  └──────────────┘  └────────┬───────┘  │
│       │                                                  │         │
│       ▼                                                  ▼         │
│  ┌──────────┐                                    ┌──────────────┐  │
│  │ GSA Relay│                                    │ Mihomo Core  │  │
│  │ (Domain  │                                    │ (Clash.Meta) │  │
│  │Fronting) │                                    │ TUN + Route  │  │
│  └──────────┘                                    └──────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

این پروژه دارای **معماری دو-فرآیندی (Dual-Process Architecture)** است:

1. **Desktop Process**: رابط کاربری Wails v3 (سرویس اصلی، منوی سیستمی، پنجره)
2. **Core Process**: فرآیند پشتیبان با دسترسی ادمین (برای TUN و مدیریت پروکسی)

ارتباط بین این دو از طریق **RPC روی TCP (پورت 18933)** انجام می‌شود.

---

## هسته‌های اصلی

### Proxy Core

**فایل‌ها:** `proxy/proxy.go`, `proxy/tls_fragment.go`, `proxy/tun_flow.go`

هسته‌ی مرکزی پروکسی که ترافیک HTTP/HTTPS را مدیریت می‌کند.

#### حالت‌های عملیاتی:
| حالت | توضیحات |
|------|---------|
| `mitm` | Man-in-the-Middle: گواهی داینامیک، رمزگشایی و بازرسی ترافیک |
| `transparent` | عبور شفاف TCP بدون رمزگشایی TLS |
| `tls-rf` | تکه‌تکه کردن ClientHello TLS برای دور زدن DPI |
| `quic` | پروکسی QUIC/HTTP3 با پشتیبانی از ECH |
| `direct` | اتصال مستقیم بدون تغییر |
| `server` | مسیریابی از طریق Worker/SRV |
| `gsa` | ارسال ترافیک به GSA Proxy محلی |

#### قابلیت‌های کلیدی:
- **تولید گواهی dynamic** برای MITM با کش
- **انتخاب هوشمند SNI** با پالیسی‌های `original`, `fake`, `upstream`, `none`
- **پشتیبانی از Upstream** با رزولوشن متغیر (`$1`, `$backend_ip`)
- **Cloudflare IP Pool** با health check، fail/report و latency sorting
- **uTLS fingerprinting** برای شبیه‌سازی مرورگر (Chrome, Firefox)
- **ECH (Encrypted Client Hello)** با auto-refresh
- **Sequential/Parallel dial** با fallback
- **SOCKS5** با تونل‌زنی از طریق GSA

---

### GSA Core

**فایل‌ها:** `proxy/gsa.go`, `proxy/gsa_relay.go`, `proxy/gsa_lan.go`, `proxy/gsa_constants.go`

هسته‌ی **Domain Fronting** از طریق Google Apps Script. قلب تپنده‌ی پروژه برای عبور از محدودیت‌ها.

#### اجزای داخلی:

```
GSA Manager (gsa.go)
├── GSARelay (gsa_relay.go)
│   ├── HTTP/2 Transport (multiplexed)
│   ├── HTTP/1.1 Pool (keep-alive connections)
│   ├── Batch Request Coalescing
│   ├── Response Cache (LRU, 50MB max)
│   ├── Request Coalescing (de-dup)
│   ├── Heartbeat Monitor (30s interval)
│   └── Auto-Failover Logic
├── GSA Proxy Server (gsa_relay.go)
│   ├── HTTP Proxy Handler
│   ├── CONNECT Tunnel Handler
│   ├── MITM TLS Termination
│   ├── CORS Injection
│   ├── Direct Connect Bypass (Google services)
│   └── SNI Rewrite (YouTube, DoubleClick, etc.)
├── GSAMITMManager (gsa_relay.go)
│   ├── Internal CA or Nova's CA
│   ├── Per-host Cert Cache
│   └── Dynamic Certificate Generation
└── Google IP Scanner (gsa.go)
    ├── Static Candidate IPs (26 IPs)
    ├── DNS-Based Discovery (google domains)
    └── TCP+TLS Latency Probing
```

#### معماری GSA Relay:

```
Client (Browser) ──> GSA Proxy Server (:8085)
                         │
                         ▼
                    GSA Relay
                         │
                    ┌────┴────┐
                    │         │
                    ▼         ▼
              HTTP/2 (h2)  HTTP/1.1 (Pool)
                    │         │
                    └────┬────┘
                         │
                         ▼
              Google IP:443 (e.g. 216.239.38.120)
                         │
                         ▼
              Google Apps Script (Script ID)
                         │
                         ▼
              Target Website (یوتیوب، گوگل، ...)
```

#### تنظیمات GSA:

| کلید | پیش‌فرض | توضیحات |
|------|---------|---------|
| `script_id` | `changeme` | شناسه اسکریپت Google Apps |
| `auth_key` | `changeme` | کلید احراز هویت رله |
| `google_ip` | `216.239.38.120` | آی‌پی گوگل برای اتصال |
| `front_domain` | `www.google.com` | دامنه Fronting (SNI) |
| `listen_port` | `8085` | پورت پروکسی محلی |
| `auto_failover_enabled` | `true` | تغییر خودکار آی‌پی در صورت خطا |
| `rotate_front_domain` | `false` | چرخش خودکار دامنه Fronting |
| `exclude_google_services` | `false` | عدم هدایت سرویس‌های حساس گوگل |

#### لیست Candidate IPs گوگل (26 آی‌پی):
`216.239.32.120`, `216.239.34.120`, `216.239.36.120`, `216.239.38.120`, `142.250.80.142`, و ...

#### سرویس‌های مستثنی شده از GSA:
- `gemini.google.com`, `aistudio.google.com`, `mail.google.com`
- `drive.google.com`, `docs.google.com`, `accounts.google.com`
- `meet.google.com`, `photos.google.com`, `play.google.com`
- و ...

#### قابلیت‌های ویژه:
- **Auto-Failover**: در صورت 3 بار خطای متوالی، به‌صورت خودکار آی‌پی گوگل را اسکن می‌کند
- **Front Domain Rotation**: چرخش دوره‌ای دامنه Fronting برای جلوگیری از شناسایی
- **Batch Processing**: گروه‌بندی درخواست‌ها (حداکثر 50 تا) برای کاهش Latency
- **Request Coalescing**: پاسخ‌های همزمان به چند درخواست یکسان
- **Response Cache**: کش هوشمند تا 50 مگابایت با TTL پویا
- **SNI Rewrite**: بازنویسی SNI برای یوتیوب، دابل‌کلیک، گوگل آنالیتیکس
- **CORS Injection**: تزریق هدرهای CORS برای پشتیبانی از درخواست‌های مرورگر
- **GZIP/Brotli/Zstd Decoding**: پشتیبانی از انواع فشرده‌سازی
- **Heartbeat**: مانیتورینگ سلامت اتصال هر 30 ثانیه
- **Speed Test**: تست سرعت واقعی از طریق تونل GSA
- **Split Tunnel**: امکان انتخاب برنامه‌های خاص برای عبور از GSA

---

### Core Runtime

**فایل‌ها:** `core_api.go`, `core_runtime.go`, `core_client.go`, `core_markers.go`

فرآیند پشتیبان که با پرچم `--core` اجرا می‌شود و به‌صورت RPC با فرآیند اصلی ارتباط دارد.

#### سرویس‌های RPC:
| متد | توضیحات |
|-----|---------|
| `Core.Ping` | بررسی سلامت هسته |
| `Core.GetInfo` | دریافت PID، مسیر اجرایی، وضعیت Elevation |
| `Core.ReloadConfig` | بارگذاری مجدد تنظیمات |
| `Core.ReloadCertificate` | بارگذاری مجدد گواهی |
| `Core.StartProxy` | شروع پروکسی |
| `Core.StopProxy` | توقف پروکسی |
| `Core.IsProxyRunning` | وضعیت پروکسی |
| `Core.GetStats` | آمار ترافیک (down/up) |
| `Core.StartTUN` | شروع TUN با دسترسی ادمین |
| `Core.StopTUN` | توقف TUN |
| `Core.GetTUNStatus` | وضعیت TUN |
| `Core.SetGSADialAddr` | تنظیم آدرس GSA برای پروکسی |
| `Core.SetProxyMode` | تغییر حالت پروکسی |

#### ویژگی‌های معماری:
- **قابلیت Elevation**: در صورت نیاز به TUN، فرآیند با دسترسی ادمین ری‌استارت می‌شود
- **بازیابی هوشمند**: پس از ری‌استارت، تنظیمات قبلی (Proxy, LogCapture) بازیابی می‌شوند
- **تشابه فایل اجرایی**: بررسی می‌کند که فایل اجرایی یکسان است

---

### Auto Router

**فایل‌ها:** `proxy/auto_routing.go`, `proxy/gfwlist.go`

مسیریاب خودکار برای دامنه‌هایی که قانون دستی ندارند.

#### حالت‌های مسیریابی:
| حالت | توضیحات |
|------|---------|
| `""` (Off) | بدون مسیریابی خودکار |
| `default` | ECH + TLS-RF + Direct (بر اساس GFWList) |
| `server` | مانند default + Fallback به Worker/SRV |
| `gsa` | همه ترافیک از طریق GSA |

#### منطق تصمیم‌گیری:
```
درخواست → در GFWList است؟
    ├── خیر → Direct
    └── بله → Cloudflare است؟
        ├── بله → MITM + ECH + Cloudflare Pool
        └── خیر → TLS-RF (+ Fallback در حالت server)
```

#### GFWList:
- منبع پیش‌فرض: `Loyalsoldier/v2ray-rules-dat`
- کش محلی در فایل `gfwlist_cache.txt`
- تطابق دقیق و سافیکس (پیمایش سلسله‌مراتب دامنه)

---

### Rule Manager & Config

**فایل‌ها:** `proxy/proxy.go`, `proxy/config.go`

مدیریت قوانین مسیریابی، سایت‌گروپ‌ها، آپستریم‌ها و پروفایل‌های ECH.

#### ساختار داده‌ها:
- **SiteGroup**: گروه دامنه با حالت اختصاصی (MITM, Direct, ...)
- **Upstream**: سرورهای بالادستی
- **DNSNode**: گره‌های DNS-over-HTTPS
- **ECHProfile**: پروفایل‌های Encrypted Client Hello

#### تطابق دامنه:
- **Exact Match**: `google.com` → اولویت 1000+
- **Suffix Match**: `*.google.com` → اولویت بر اساس طول
- **Regex Match**: `~pattern` → اولویت 900+
- **Wildcard Pattern**: `base.*` → تطابق با هر TLD
- **Wildcard**: `*` → اولویت 1

---

### DNS Resolver

**فایل‌ها:** `proxy/doh.go`

سیستم DNS با Failover بین چندین گره DoH.

#### معماری:
```
درخواست DNS → گره اول (با اولویت بالا)
    ├── موفق → پاسخ
    └── ناموفق → Race بین سایر گره‌ها
        ├── موفق → پاسخ (سایر گره‌ها کنسل می‌شوند)
        └── همه ناموفق → Fallback به System DNS
```

#### قابلیت‌ها:
- **Parallel Race**: ارسال همزمان درخواست به چند گره
- **ECH Refresh خودکار**: در صورت خطای TLS، ECH را از Safe Source به‌روز می‌کند
- **Safe Resolver**: پرس‌وجو فقط از گره‌های غیر-ECH (برای شکستن circular dependency)
- **ResolveECHSafe**: دریافت ECH config از طریق گره‌های امن

---

### TUN Mode

**فایل‌ها:** `proxy/tun_flow.go`, `external_mihomo.go`

حالت TUN با استفاده از هسته‌ی **Mihomo (Clash.Meta)** به‌عنوان زیرمجموعه.

#### ویژگی‌ها:
- **TUN Flow Planner**: تحلیل مسیر ترافیک قبل از ارسال
- **Mihomo Config Generator**: تولید پویای کانفیگ
- **PID-based Process Management**: مدیریت فرآیند خارجی
- **Ready Detection**: تشخیص آمادگی از طریق لاگ‌ها
- **Automatic Restart**: در صورت تغییر تنظیمات

#### کانفیگ Mihomo:
- Mixed Port: 7890
- Stack: gvisor
- Fake-IP Range: 198.18.0.1/16
- DNS-over-FakeIP با Enhanced Mode

---

### Certificate Manager

**فایل‌ها:** `cert/` (دایرکتوری جدا)

مدیریت گواهی‌های CA برای MITM.

#### قابلیت‌ها:
- **تولید Root CA**: با OpenSSL یا Go crypto
- **نصب خودکار در فروشگاه گواهی ویندوز**
- **Fallback CA**: برای مهاجرت از نسخه‌های قدیمی
- **Export/Import گواهی**
- **Installed Certificates**: لیست گواهی‌های نصب شده
- **Uninstall**: حذف گواهی از طریق thumbprint

---

### utls (TLS Fingerprinting)

**فایل‌ها:** `utls/` (فورک از refraction-networking/utls)

کتابخانه‌ای برای شبیه‌سازی اثرانگشت TLS مرورگرهای مختلف.

#### پشتیبانی از:
- **Chrome 120** (پیش‌فرض)
- **Firefox 120**
- **Custom ClientHello** با ALPN Rewrite
- **ECH (Encrypted Client Hello)** با پشتیبانی کامل
- **QUIC Transport Parameters**
- **Session Ticket** با کنترل دستی
- **PRNG** با seed مشخص برای تکرارپذیری

---

### Frontend

**مسیر:** `frontend/`

رابط کاربری دسکتاپ با **Wails v3** و **Vite + TypeScript**.

#### تکنولوژی‌ها:
- **Vite** برای build
- **TypeScript** برای type safety
- **Tailwind CSS** برای استایل
- **Wails v3 Bindings** برای ارتباط با Go backend

#### صفحات:
- **Dashboard**: نمایش وضعیت پروکسی، ترافیک، سخت‌افزار
- **Settings**: تنظیمات پورت، پروکسی سیستمی، SOCKS5
- **Rules**: مدیریت قوانین مسیریابی
- **GSA**: مدیریت GSA Domain Fronting
- **DNS**: مدیریت گره‌های DNS
- **Cloudflare**: مدیریت IP Pool
- **Certificates**: مدیریت گواهی‌ها
- **Logs**: مشاهده لاگ‌های بلادرنگ
- **TUN**: مدیریت TUN Mode

---

## نقشه راه GSA

### فاز ۱: پایه (پیاده‌سازی شده) ✓
- [x] رله‌ی HTTP/1.1 با Connection Pool (حداکثر ۵۰ اتصال)
- [x] رله‌ی HTTP/2 با اتصال Multiplexed
- [x] Batch Request Coalescing (پنجره ۵ میلی‌ثانیه، حداکثر ۵۰ تا)
- [x] Request Coalescing (پاسخ واحد به درخواست‌های همزمان یکسان)
- [x] مکانسیم Heartbeat (هر ۳۰ ثانیه)
- [x] Google IP Scanner (Candidate IPs + DNS Discovery)
- [x] MITM TLS Termination با CA اختصاصی
- [x] SNI Rewrite برای یوتیوب و سرویس‌های گوگل
- [x] Direct Connect Bypass برای سرویس‌های حساس گوگل
- [x] CORS Injection

### فاز ۲: بهینه‌سازی (پیاده‌سازی شده) ✓
- [x] Response Cache (LRU، ۵۰ مگابایت، TTL پویا)
- [x] Content Decoding (Gzip, Brotli, Zstd, Deflate)
- [x] Auto-Failover (تغییر خودکار آی‌پی گوگل پس از ۳ خطا)
- [x] Front Domain Rotation چرخه‌ای
- [x] Speed Test & Connection Test
- [x] LAN Sharing (قابلیت اشتراک در شبکه محلی)
- [x] Split Tunnel (انتخاب برنامه‌های خاص)

### فاز ۳: پیشرفته (در حال توسعه)
- [ ] **Warp Integration** - مسیریابی ترافیک از طریق Cloudflare Warp
- [ ] **Multi-Script Load Balancing** - توزیع بار بین چندین Apps Script
- [ ] **QUIC به جای TCP** - کاهش Latency با QUIC به Google
- [ ] **Machine Learning IP Selection** - انتخاب هوشمند آی‌پی گوگل با ML
- [ ] **IPv6 Support** - پشتیبانی کامل از IPv6 برای اتصال به گوگل
- [ ] **WebSocket over GSA** - پشتیبانی از WebSocket از طریق رله

### فاز ۴: آتی
- [ ] **Redis-based Distributed Cache** - کش توزیع شده برای چند نمونه
- [ ] **gRPC Relay** - جایگزینی HTTP/2 با gRPC برای کارایی بیشتر
- [ ] **Obfs4 Integration** - لایه‌ی obfuscation اضافی
- [ ] **Multi-User Support** - پشتیبانی از چند کاربر
- [ ] **GUI Dashboard Real-time** - مانیتورینگ بلادرنگ با نمودار

---

## نقشه راه کلی پروژه

### هسته Proxy

- [x] MITM Proxy با گواهی داینامیک
- [x] Transparent TCP Tunnel
- [x] TLS Fragmentation (TLS-RF)
- [x] QUIC/HTTP3 Transport
- [x] Cloudflare IP Pool با Health Check
- [x] SOCKS5 Proxy
- [x] ECH (Encrypted Client Hello)
- [x] uTLS Fingerprinting
- [x] Cert Bypass Map
- [ ] **HTTP/3 Server-Side** - پشتیبانی از ورودی QUIC
- [ ] **Multi-Protocol on Single Port** - تشخیص خودکار پروتکل
- [ ] **Load-balanced Upstream** - توزیع بار بین آپستریم‌ها
- [ ] **Geo-aware Routing** - مسیریابی مبتنی بر موقعیت مکانی

### هسته Auto Router

- [x] GFWList Integration
- [x] Cloudflare Detection (DoH-based)
- [x] Routing Modes (default, server, gsa)
- [x] Domain Scoring System
- [ ] **Real-time GFWList Update** - به‌روزرسانی خودکار لیست
- [ ] **User-defined Custom Rules Format** - فرمت سفارشی برای قوانین
- [ ] **Historical Routing Analytics** - تحلیل الگوی مسیریابی

### هسته DNS Resolver

- [x] DoH Failover
- [x] Parallel Race
- [x] ECH Refresh خودکار
- [x] Safe Resolver برای circular dependency
- [ ] **DNS-over-QUIC** - پشتیبانی از DoQ
- [ ] **DNS-over-TLS** - پشتیبانی از DoT
- [ ] **DNSSEC Validation** - اعتبارسنجی DNSSEC
- [ ] **Local DNS Cache** - کش DNS محلی با TTL

### هسته TUN

- [x] External Mihomo (Clash.Meta) Integration
- [x] TUN Flow Planning
- [x] Config Template System
- [ ] **Built-in TUN** - TUN داخلی بدون نیاز به Mihomo
- [ ] **Cross-platform TUN** - پشتیبانی از لینوکس و مک
- [ ] **Per-Process Routing** - مسیریابی بر اساس پردازش
- [ ] **TUN Traffic Visualization** - نمایش گرافیکی ترافیک TUN

### هسته Core Runtime

- [x] Dual-Process Architecture (RPC)
- [x] Process Elevation (Admin)
- [x] Config Hot-Reload
- [x] Certificate Hot-Reload
- [x] Route Event Streaming
- [ ] **gRPC instead of net/rpc** - جایگزینی با gRPC برای کارایی
- [ ] **Health Dashboard** - مانیتورینگ سلامت هسته
- [ ] **Auto-Recovery** - بازیابی خودکار در صورت Crash

### Frontend

- [x] Wails v3 Desktop UI
- [x] System Tray Integration
- [x] Real-time Traffic Display
- [x] Rule Management
- [x] DNS Node Management
- [x] GSA Configuration Panel
- [x] Log Viewer
- [x] Certificate Management
- [ ] **PWA/Mobile Support** - پشتیبانی از موبایل
- [ ] **Plugin System** - سیستم افزونه
- [ ] **Advanced Statistics Dashboard** - داشبورد آماری پیشرفته
- [ ] **Dark/Light Theme** - تم تیره و روشن
- [ ] **Multi-language UI** - رابط کاربری چندزبانه

---

## نحوه نصب و اجرا

### پیش‌نیازها

- **Go** 1.25 یا بالاتر
- **Node.js** برای فرانت‌اند
- **Wails v3** (محلی در مسیر `go\src\wails\v3`)
- **Windows 10/11** (برای TUN نیاز به Administrator)

### مراحل Build

```powershell
# نصب وابستگی‌های فرانت‌اند
cd frontend
npm install

# Build فرانت‌اند
npm run build

# Build برنامه
cd ..
go build -o NovaProxy.exe
```

### اجرا

```powershell
# اجرای عادی
.\NovaProxy.exe

# اجرا با هسته (Core Mode - خودکار)
.\NovaProxy.exe --core

# اجرا در Startup
.\NovaProxy.exe --startup
```

---

## ساختار دایرکتوری‌ها

```
Nova/
├── main.go                    # نقطه‌ی ورودی
├── app.go                     # سرویس اصلی برنامه
├── app_admin_windows.go       # توابع مخصوص ویندوز (Elevation)
├── app_admin_other.go         # توابع برای سایر OS
├── core_api.go                # پیاده‌سازی RPC سرویس Core
├── core_runtime.go            # اجرای زمان اجرای Core
├── core_client.go             # کلاینت RPC برای ارتباط با Core
├── core_markers.go            # مارکرهای دیسک (غیرفعال)
├── external_mihomo.go         # مدیریت Mihomo خارجی
├── log_writer.go              # رایت‌کننده‌های لاگ
├── single_instance_recovery_*.go  # بازیابی نمونه تکی
├── autostart_*.go             # مدیریت اجرا در Startup
├── go.mod / go.sum            # وابستگی‌های Go
├── wails.json                 # تنظیمات Wails
│
├── proxy/                     # پکیج هسته پروکسی
│   ├── proxy.go               # سرور پروکسی اصلی
│   ├── gsa.go                 # مدیریت GSA Domain Fronting
│   ├── gsa_relay.go           # رله GSA (شامل proxy server, relay, MITM)
│   ├── gsa_lan.go             # تشخیص آی‌پی‌های LAN
│   ├── gsa_constants.go       # ثابت‌های GSA (IPs, domains, etc.)
│   ├── config.go              # ایمپورت/اکسپورت تنظیمات
│   ├── auto_routing.go        # مسیریاب خودکار
│   ├── gfwlist.go             # لیست GFW
│   ├── doh.go                 # DNS-over-HTTPS Failover Resolver
│   ├── cf_pool.go             # Cloudflare IP Pool
│   ├── tls_fragment.go        # TLS Fragmentation
│   ├── tun_flow.go            # برنامه‌ریزی جریان TUN
│   ├── port_manager.go        # مدیریت پورت
│   ├── procmon.go             # مانیتورینگ پردازش‌ها
│   ├── procmon_windows.go     # TCP Table fetcher
│   ├── procmon_stub.go        # Stub برای لینوکس
│   ├── cert_verify.go         # اعتبارسنجی گواهی
│   └── error_page.go          # صفحات خطا
│
├── cert/                      # مدیریت گواهی‌های CA
├── sysproxy/                  # تنظیمات پروکسی سیستمی
├── sni-server/                # سرور SNI
├── utls/                      # فورک TLS Fingerprinting
├── frontend/                  # رابط کاربری (Vite + TS)
│   ├── src/                   # کد منبع فرانت‌اند
│   ├── dist/                  # خروجی build
│   ├── vite.config.ts         # تنظیمات Vite
│   └── package.json           # وابستگی‌ها
├── build/                     # فایل‌های Build
├── scripts/                   # اسکریپت‌های Build
├── winres/                    # منابع ویندوز
└── .github/workflows/         # CI/CD
```

---

## تکنولوژی‌های استفاده شده

| تکنولوژی | کاربرد |
|-----------|--------|
| **Go 1.25** | زبان اصلی برنامه |
| **Wails v3** | فریمورک دسکتاپ UI |
| **quic-go** | پروتکل QUIC/HTTP3 |
| **uTLS** | شبیه‌سازی اثرانگشت TLS |
| **miekg/dns** | پرس‌وجوی DNS |
| **golang.org/x/net** | HTTP/2, IPv6, etc. |
| **golang.org/x/sys** | توابع سیستمی ویندوز |
| **Vite + TypeScript** | فرانت‌اند |
| **Tailwind CSS** | استایل‌دهی |
| **Mihomo (Clash.Meta)** | TUN Mode |
| **Brotli, Zstd** | فشرده‌سازی محتوا |

---

<p align="center">
  <strong>NovaProxy</strong> — ساخته شده با ❤️ توسط <a href="https://github.com/gamelatest">gamelatest</a>
</p>
</div>
