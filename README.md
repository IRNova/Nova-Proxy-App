<div dir="rtl">

# نوواپراکسی (NovaProxy)

<p align="center">
  <img src="https://github.com/IRNova/Nova-Proxy-App/blob/main/logo.svg" alt="NovaProxy Logo" width="128"/>
</p>

<p align="center">پروکسی هوشمند مبتنی بر Google Apps Script و Cloudflare Worker</p>

---

## معماری کلی

### مسیر GSA (Google Scripts Apps)

```
┌──────────┐       ┌──────────────────┐       ┌─────────────────┐       ┌──────────────┐
│ کلاینت    │ ────> │ Google Apps Script│ ────> │ Cloudflare Worker│ ────> │ اینترنت آزاد │
│ (مرورگر)  │ <──── │ (GSA Relay)      │ <──── │ (Server Worker)  │ <──── │              │
└──────────┘       └──────────────────┘       └─────────────────┘       └──────────────┘
       │                     ▲                        ▲
       │                     │                        │
       │              ┌──────┴──────┐          ┌──────┴──────┐
       │              │ Auth Key    │          │ Script ID   │
       │              │ Front Domain│          │ Worker URL  │
       │              │ Google IP   │          │              │
       │              └─────────────┘          └─────────────┘
       │
       │
       │  ارسال درخواست HTTP → رله از طریق Google Apps Script
       │  دریافت پاسخ → از طریق Cloudflare Worker به کلاینت
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│  GSA Proxy Server (روی پورت 8085)                               │
│  • دریافت درخواست از کلاینت                                     │
│  • تبدیل به JSON و ارسال به Google Apps Script                   │
│  • دریافت پاسخ و بازگرداندن به کلاینت                            │
│  • MITM داخلی برای رمزگشایی TLS                                 │
└─────────────────────────────────────────────────────────────────┘
```

**توضیح:** کلاینت ابتدا به GSA Proxy Server متصل می‌شود. این سرور درخواست را به فرمت JSON تبدیل کرده و از طریق **Google Apps Script** به **Cloudflare Worker** ارسال می‌کند. Worker درخواست را به مقصد نهایی می‌زند و پاسخ را برمی‌گرداند. تمام ترافیک رمزگذاری شده و از طریق زیرساخت گوگل و کلودفلر عبور می‌کند.

---

### مسیر MITM (Google IP Direct)

```
┌──────────┐       ┌────────────────────┐       ┌─────────────────┐
│ کلاینت    │ ────> │ آی‌پی‌های سفید گوگل │ ────> │ سایت‌های گوگل   │
│ (مرورگر)  │ <──── │ (216.239.38.120 و ...)│ <──── │ (یوتیوب، جستجو، │
└──────────┘       └────────────────────┘       │ جیمیل، و...)   │
                                                └─────────────────┘
       │
       │  اتصال مستقیم به آی‌پی گوگل با SNI جعلی
       │  همه سایت‌های زیرمجموعه گوگل باز می‌شود
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│  MITM Proxy (روی پورت 8080)                                    │
│  • رمزگشایی TLS با گواهی داخلی                                 │
│  • تغییر SNI برای عبور از فیلتر                                 │
│  • health check خودکار آی‌پی‌های گوگل                           │
│  • ECH (Encrypted Client Hello) برای کلودفلر                    │
└─────────────────────────────────────────────────────────────────┘
```

**توضیح:** کلاینت به **آی‌پی‌های سفید گوگل** (مانند `216.239.38.120`) متصل می‌شود ولی SNI را به آدرس گوگل (مثلاً `www.google.com`) تنظیم می‌کند. این باعث می‌شود همه سایت‌های گوگل (یوتیوب، جستجو، جیمیل، گوگل‌درایو و ...) بدون فیلتر باز شوند.

---

### مسیر Auto Routing

```
┌──────────┐       ┌──────────────┐       ┌───────────────────────┐
│ کلاینت    │ ────> │ GFW List     │ ────> │  دامنه فیلتر شده؟     │
│ (مرورگر)  │       └──────────────┘       └───────────┬───────────┘
                                                    │
                                       ┌────────────┴────────────┐
                                       │                         │
                                       ▼                         ▼
                               ┌──────────────┐        ┌────────────────┐
                               │ کلودفلر است؟  │        │ TLS Fragmentation│
                               └──────┬───────┘        │ (TLS-RF)       │
                                      │                └────────────────┘
                              ┌───────┴───────┐
                              │               │
                              ▼               ▼
                      ┌──────────────┐ ┌──────────────────┐
                      │ MITM + ECH   │ │ TLS-RF + Fallback│
                      │ + Cloudflare  │ │ به Server Worker │
                      │ IP Pool      │ └──────────────────┘
                      └──────────────┘
```

---

## هسته‌های پروژه

### GSA Core
ارسال و دریافت دیتا از طریق **Google Apps Script** و **Cloudflare Worker**. شامل:
- رله HTTP/2 و HTTP/1.1 با Connection Pool
- Batch Request (ارسال گروهی درخواست‌ها)
- Response Cache (کش هوشمند پاسخ‌ها)
- Auto-Failover بین آی‌پی‌های گوگل
- Heartbeat (بررسی سلامت اتصال هر ۳۰ ثانیه)
- Front Domain Rotation (چرخش دامنه Fronting)
- SNI Rewrite (بازنویسی SNI برای یوتیوب و ...)
- CORS Injection
- Google IP Scanner (اسکن ۲۶ آی‌پی ثابت + DNS)
- MITM داخلی با CA اختصاصی (یا CA نووا)
- Split Tunnel (انتخاب برنامه‌های خاص برای GSA)

### Proxy Core
پروکسی HTTP/HTTPS با قابلیت MITM:
- **حالت‌ها:** mitm, transparent, tls-rf, quic, direct, server
- Cloudflare IP Pool با Health Check
- uTLS Fingerprinting (شبیه‌سازی Chrome/Firefox)
- ECH (Encrypted Client Hello) با Auto-Refresh
- SOCKS5 Proxy
- TLS Fragmentation (تکه‌تکه کردن ClientHello)
- Certificate Cache

### Core Runtime
فرآیند پشتیبان مجزا که از طریق **RPC روی پورت 18933** با برنامه اصلی ارتباط دارد. مدیریت:
- پروکسی اصلی
- TUN Mode
- بارگذاری مجدد تنظیمات و گواهی
- دسترسی ادمین برای TUN

### Auto Router
مسیریاب خودکار برای دامنه‌های بدون قانون دستی:
- GFW List (منبع: Loyalsoldier/v2ray-rules-dat)
- تشخیص کلودفلر از طریق DoH
- **حالت‌ها:** default (ECH+TLS-RF), server (با Fallback), gsa (همه از GSA)

### DNS Resolver (DoH Failover)
DNS-over-HTTPS با Failover:
- ارسال همزمان به چند گره DNS (Parallel Race)
- ECH Refresh خودکار در صورت خطا
- Safe Resolver برای شکستن Circular Dependency

### TUN Mode
TUN از طریق هسته **Mihomo (Clash.Meta)**:
- مسیریابی سطح سیستم
- Fake-IP + DNS Hijack
- فقط ویندوز

### Certificate Manager
مدیریت گواهی CA برای MITM:
- تولید Root CA
- نصب در فروشگاه گواهی ویندوز
- Fallback CA برای مهاجرت از نسخه‌های قدیمی

### utls
فورک **refraction-networking/utls** برای شبیه‌سازی اثرانگشت TLS مرورگرها (Chrome, Firefox) با پشتیبانی از ECH, QUIC, Session Ticket

### Frontend
رابط کاربری دسکتاپ با **Wails v3** و **Vite + TypeScript + Tailwind CSS**

---

## تکنولوژی‌ها

| تکنولوژی | کاربرد |
|----------|--------|
| Go 1.25 | زبان اصلی |
| Wails v3 | فریمورک دسکتاپ |
| quic-go | QUIC/HTTP3 |
| uTLS | TLS Fingerprinting |
| miekg/dns | DNS |
| Mihomo | TUN Mode |
| Vite + TypeScript | فرانت‌اند |

</div>
