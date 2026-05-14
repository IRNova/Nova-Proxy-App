<div dir="rtl" style="font-family: 'Vazirmatn', sans-serif;">

<div align="center">

<p align="center">
  <img src="https://raw.githubusercontent.com/IRNova/Nova-Proxy-App/main/logo.svg" width="140" height="140" alt="NovaProxy Logo">
</p>

<h1 style="color: #2c3e50; margin-top: 10px;">
  نوواپراکسی
</h1>

<p style="font-size: 16px; color: #7f8c8d;">
  <strong>NovaProxy</strong> — پل هوشمند به اینترنت آزاد
</p>

<hr style="width: 60px; border: 2px solid #e74c3c; border-radius: 4px;">

</div>

---

## معماری کلّی

در این پروژه دو مسیر اصلی برای دسترسی به اینترنت آزاد وجود دارد:

---

### مسیر GSA (Google Apps Script + Cloudflare Worker)

```
┌──────────┐    ┌───────────────┐    ┌──────────────────┐    ┌──────────────────┐
│          │    │               │    │                  │    │                  │
│  کلاینت   │───>│ GSA Proxy     │───>│ Google Apps      │───>│ Cloudflare       │
│ (مرورگر) │    │ (پورت 8085)   │    │ Script (Code.gs) │    │ Worker (worker)  │
│          │<───│               │<───│                  │<───│                  │
└──────────┘    └───────────────┘    └──────────────────┘    └──────────────────┘
                                                     │
                                                     ▼
                                              ┌──────────────┐
                                              │              │
                                              │ اینترنت آزاد  │
                                              │              │
                                              └──────────────┘
```

**نحوه کار:**

1. **کلاینت** درخواست HTTP خود را به **GSA Proxy Server** (محلی روی پورت ۸۰۸۵) می‌فرستد
2. **GSA Proxy** درخواست را به JSON تبدیل کرده و با کلید احراز به **Google Apps Script** ارسال می‌کند  
3. **Google Apps Script** (`server/Code.gs`) پکیج را به **Cloudflare Worker** فوروارد می‌کند
4. **Cloudflare Worker** (`server/worker.js`) درخواست نهایی را به مقصد می‌زند:
   - دریافت پاسخ (status, headers, body به صورت base64)
   - پشتیبانی از **Upstream Forwarder** زنجیره‌ای
   - شناسایی حلقه با هدر `x-relay-hop`
   - مسدودسازی Self-Fetch
   - تبدیل پاسخ به فرمت JSON
5. پاسخ از همان مسیر برمی‌گردد: **Worker → Apps Script → GSA Proxy → کلاینت**

> **نکته:** GSA یک پروکسی محلی ساده نیست — همه دیتا از طریق زیرساخت Google Apps Script و Cloudflare Worker ارسال و دریافت می‌شود.

---

### مسیر MITM (Google IP Direct)

```
┌──────────┐    ┌──────────────────────┐    ┌───────────────────────┐
│          │    │                      │    │                       │
│  کلاینت   │───>│  آی‌پی‌های سفید گوگل │───>│  سایت‌های گوگل        │
│ (مرورگر) │    │  216.239.38.120     │    │  یوتیوب، جستجو، جیمیل  │
│          │    │  www.google.com     │    │  گوگل‌درایو، مپس و... │
└──────────┘    └──────────────────────┘    └───────────────────────┘
```

**نحوه کار:**

- کلاینت به **آی‌پی‌های سفید گوگل** (لیست ۲۶ آی‌پی ثابت) متصل می‌شود
- SNI به `www.google.com` تنظیم می‌شود (یا دامنه‌های مشابه)
- MITM Proxy ترافیک TLS را رمزگشایی و بازرسی می‌کند
- همه سایت‌های زیرمجموعه گوگل بدون فیلتر در دسترس هستند

---

## هسته‌های پروژه

### ۱. GSA Core
ارسال و دریافت دیتا از طریق **Google Apps Script** و **Cloudflare Worker**:
- رله HTTP/2 و HTTP/1.1 با Connection Pool
- Batch Request (ارسال گروهی تا ۵۰ درخواست)
- Response Cache (کش هوشمند ۵۰ مگابایت)
- Auto-Failover بین آی‌پی‌های گوگل
- Heartbeat (بررسی سلامت هر ۳۰ ثانیه)
- Front Domain Rotation
- Google IP Scanner (۲۶ آی‌پی ثابت + DNS)
- SNI Rewrite (یوتیوب، دابل‌کلیک، گوگل آنالیتیکس)
- CORS Injection
- MITM داخلی با CA اختصاصی (یا CA نووا)
- Split Tunnel (برنامه‌های خاص)

### ۲. Google Apps Script (`server/Code.gs`)
- دریافت درخواست‌های JSON از GSA Proxy
- اعتبارسنجی با کلید احراز (`AUTH_KEY`)
- ارسال به Cloudflare Worker (`WORKER_URL`)
- پشتیبانی از Batch (پردازش گروهی)
- فیلتر هدرهای Hop-by-Hop

### ۳. Cloudflare Worker (`server/worker.js`)
- دریافت از Google Apps Script
- درخواست HTTP واقعی به مقصد نهایی
- پشتیبانی از **Upstream Forwarder** زنجیره‌ای
- شناسایی حلقه (Loop Detection)
- مسدودسازی Self-Fetch
- تبدیل بدنه به base64 با تکه‌تکه کردن (جلوگیری از Stack Overflow)
- Fallback به Direct در صورت خطای Upstream

### ۴. Proxy Core
پروکسی HTTP/HTTPS با قابلیت‌های:
- **حالت‌ها:** mitm, transparent, tls-rf, quic, direct, server
- Cloudflare IP Pool با Health Check
- uTLS Fingerprinting (Chrome, Firefox)
- ECH (Encrypted Client Hello) با Auto-Refresh
- SOCKS5 Proxy
- TLS Fragmentation
- Certificate Cache

### ۵. Core Runtime
فرآیند پشتیبان مجزا با RPC روی پورت ۱۸۹۳۳:
- مدیریت پروکسی و TUN
- بارگذاری مجدد تنظیمات و گواهی
- دسترسی ادمین برای TUN

### ۶. Auto Router
مسیریاب خودکار بر اساس GFW List:
- تشخیص کلودفلر از طریق DoH
- **حالت‌ها:** default, server (با Fallback), gsa

### ۷. DNS Resolver (DoH Failover)
DNS-over-HTTPS با Failover و Parallel Race:
- ECH Refresh خودکار
- Safe Resolver برای Circular Dependency

### ۸. TUN Mode
TUN از طریق Mihomo (Clash.Meta):
- مسیریابی سطح سیستم
- Fake-IP + DNS Hijack

### ۹. Certificate Manager
مدیریت گواهی CA برای MITM

### ۱۰. uTLS
فورک refraction-networking/utls برای شبیه‌سازی اثرانگشت TLS

### ۱۱. Frontend
رابط کاربری با Wails v3 + Vite + TypeScript + Tailwind CSS

---

## Stargazers over time

[![Stargazers over time](https://starchart.cc/IRNova/Nova-Proxy-App.svg?variant=adaptive)](https://starchart.cc/IRNova/Nova-Proxy-App)

---

<div align="center" style="margin-top: 40px;">

<hr style="width: 40px; border: 1px solid #e74c3c;">

<h4>نواپراکسی — <span style="color: #e74c3c;">♥</span></h4>
<p>📡 <a href="https://t.me/irnova_proxy" style="color: #229ED9; text-decoration: none;">@irnova_proxy</a></p>
</div>
</div>
