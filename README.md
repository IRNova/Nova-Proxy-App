markdown
<div dir="rtl" align="right">

<p align="center">
  <img src="https://raw.githubusercontent.com/IRNova/Nova-Proxy-App/main/logo.svg" width="140" height="140" alt="لوگوی نوواپراکسی">
</p>

<h1 align="center">نوواپراکسی</h1>

<p align="center">
  <strong>NovaProxy</strong> — پل هوشمند به اینترنت آزاد
  <br>
  <a href="https://t.me/irnova_proxy">📡 @irnova_proxy</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="مجوز MIT">
  <img src="https://img.shields.io/github/stars/IRNova/Nova-Proxy-App?style=social" alt="ستاره‌ها">
</p>

<hr>

## معماری کلی

دو مسیر اصلی برای دسترسی به اینترنت آزاد در نوواپراکسی طراحی شده است:

### ۱. مسیر GSA (Google Apps Script + Cloudflare Worker)
┌──────────┐ ┌───────────────┐ ┌──────────────────┐ ┌──────────────────┐
│ کلاینت │───>│ GSA Proxy │───>│ Google Apps │───>│ Cloudflare │
│ (مرورگر) │ │ (پورت 8085) │ │ Script (Code.gs) │ │ Worker (worker) │
└──────────┘ └───────────────┘ └──────────────────┘ └──────────────────┘
│
▼
┌──────────────┐
│ اینترنت آزاد │
└──────────────┘

text

**نحوه کار:**  
کلاینت درخواست HTTP خود را به GSA Proxy محلی (پورت ۸۰۸۵) می‌فرستد. این پروکسی درخواست را به JSON تبدیل کرده و با کلید احراز به Google Apps Script ارسال می‌کند. سپس Apps Script درخواست را به Cloudflare Worker فوروارد می‌کند و Worker درخواست نهایی را به مقصد می‌زند. پاسخ از همان مسیر بازمی‌گردد.

### ۲. مسیر MITM (Google IP Direct)
┌──────────┐ ┌──────────────────────┐ ┌───────────────────────┐
│ کلاینت │───>│ آی‌پی‌های سفید گوگل │───>│ سایت‌های گوگل │
│ (مرورگر) │ │ 216.239.38.120 │ │ یوتیوب، جستجو، جیمیل │
└──────────┘ │ www.google.com │ │ گوگل‌درایو، مپس و... │
└──────────────────────┘ └───────────────────────┘

text

در این مسیر، کلاینت مستقیماً به آی‌پی‌های سفید گوگل (لیست ۲۶ آی‌پی ثابت) متصل می‌شود. MITM Proxy ترافیک TLS را رمزگشایی کرده و همه سرویس‌های گوگل بدون فیلتر در دسترس خواهند بود.

<hr>

## هسته‌های پروژه

| هسته | قابلیت‌ها |
|------|------------|
| **GSA Core** | رله HTTP/2 و HTTP/1.1، Batch Request (تا ۵۰ درخواست)، کش هوشمند ۵۰ مگابایت، Auto-Failover، Heartbeat، SNI Rewrite، MITM داخلی، Split Tunnel |
| **Google Apps Script** (`server/Code.gs`) | اعتبارسنجی با AUTH_KEY، ارسال به Cloudflare Worker، پشتیبانی از Batch، فیلتر هدرهای Hop-by-Hop |
| **Cloudflare Worker** (`server/worker.js`) | Upstream Forwarder زنجیره‌ای، تشخیص حلقه، مسدودسازی Self-Fetch، تبدیل base64 تکه‌تکه، Fallback به Direct |
| **Proxy Core** | حالت‌های mitm/transparent/tls-rf/quic/direct/server، Cloudflare IP Pool، uTLS Fingerprinting، ECH، SOCKS5، TLS Fragmentation |
| **Core Runtime** | فرآیند پشتیبان مجزا با RPC روی پورت ۱۸۹۳۳، مدیریت TUN، بارگذاری مجدد تنظیمات و گواهی |
| **Auto Router** | مسیریاب خودکار بر اساس GFW List، تشخیص کلودفلر از طریق DoH، حالت‌های default/server/gsa |
| **DNS Resolver** | DNS-over-HTTPS با Failover و Parallel Race، ECH Refresh خودکار، Safe Resolver |
| **TUN Mode** | یکپارچه با Mihomo (Clash.Meta)، مسیریابی سطح سیستم، Fake-IP + DNS Hijack |
| **Certificate Manager** | مدیریت گواهی CA برای MITM |
| **uTLS** | فورک refraction-networking/utls برای شبیه‌سازی اثرانگشت TLS |
| **Frontend** | رابط کاربری با Wails v3 + Vite + TypeScript + Tailwind CSS |

<hr>

## نصب و استفاده

برای دانلود آخرین نسخه، به صفحه [Releases](https://github.com/IRNova/Nova-Proxy-App/releases) مراجعه کنید.

### پیش‌نیازها
- سیستم‌عامل‌های ویندوز، لینوکس، macOS
- دسترسی به اینترنت برای برقراری ارتباط با سرورهای گوگل

### راهنمای سریع
1. فایل مناسب سیستم‌عامل خود را دانلود کنید.
2. برنامه را اجرا کنید. (ممکن است نیاز به اجرا به عنوان مدیر/root باشد)
3. پروکسی روی `127.0.0.1:8085` یا پورت دیگر در دسترس خواهد بود.
4. مرورگر یا سیستم خود را روی این پروکسی تنظیم کنید.

> برای تنظیمات پیشرفته (TUN، Split Tunnel و ...) از رابط کاربری یا فایل کانفیگ استفاده کنید.

<hr>

## مشارکت در توسعه

ما از مشارکت شما استقبال می‌کنیم! لطفاً مراحل زیر را دنبال کنید:
- فورک (Fork) مخزن
- ایجاد شاخه (branch) برای تغییرات
- ارسال درخواست Pull Request
- رعایت اصول کدنویسی موجود

<hr>

## ستاره‌ها در طول زمان

[![Stargazers over time](https://starchart.cc/IRNova/Nova-Proxy-App.svg?variant=adaptive)](https://starchart.cc/IRNova/Nova-Proxy-App)

<hr>

<p align="center">
  ♥ نواپراکسی — پلی به اینترنت آزاد و امن<br>
  <a href="https://t.me/irnova_proxy">کانال تلگرام</a>
</p>

</div>
