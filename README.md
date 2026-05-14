<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
  <title>نواپراکسی | NovaProxy — پل هوشمند به اینترنت آزاد</title>
  <!-- Vazirmatn Font + Fallback -->
  <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
  <!-- Font Awesome 6 (Free Icons) -->
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    body {
      background: linear-gradient(145deg, #f8fafc 0%, #eff3f8 100%);
      font-family: 'Vazirmatn', system-ui, 'Segoe UI', Tahoma, sans-serif;
      color: #1e293b;
      line-height: 1.55;
      padding: 2rem 1.5rem;
    }

    .container {
      max-width: 1300px;
      margin: 0 auto;
      background: rgba(255,255,255,0.6);
      backdrop-filter: blur(2px);
      border-radius: 2.5rem;
      box-shadow: 0 25px 45px -12px rgba(0,0,0,0.2);
      padding: 2rem 1.8rem;
      transition: all 0.2s;
    }

    /* HEADER SECTION */
    .hero {
      text-align: center;
      margin-bottom: 2.5rem;
    }
    .logo-wrapper {
      display: inline-block;
      margin-bottom: 1rem;
      perspective: 400px;
    }
    .animated-logo {
      width: 130px;
      height: 130px;
      transition: all 0.3s ease;
      animation: floatGlow 3s infinite ease-in-out;
      filter: drop-shadow(0 10px 12px rgba(231, 76, 60, 0.25));
    }
    @keyframes floatGlow {
      0% { transform: translateY(0px) rotate(0deg); }
      50% { transform: translateY(-6px) rotate(2deg); filter: drop-shadow(0 18px 20px rgba(231,76,60,0.35));}
      100% { transform: translateY(0px) rotate(0deg); }
    }
    .animated-logo:hover {
      animation: softSpin 0.8s ease-out;
      filter: drop-shadow(0 0 12px #e74c3c);
    }
    @keyframes softSpin {
      0% { transform: rotate(0deg) scale(1); }
      100% { transform: rotate(8deg) scale(1.02); }
    }
    h1 {
      font-size: 2.5rem;
      font-weight: 800;
      background: linear-gradient(135deg, #2c3e50, #c0392b);
      -webkit-background-clip: text;
      background-clip: text;
      color: transparent;
      margin: 0.5rem 0 0.2rem;
      letter-spacing: -0.5px;
    }
    .tagline {
      font-size: 1.1rem;
      color: #4b5563;
      border-bottom: 2px solid #e74c3c;
      display: inline-block;
      padding-bottom: 6px;
      margin-bottom: 0.5rem;
      font-weight: 500;
    }
    .divider-heart {
      width: 70px;
      height: 3px;
      background: #e74c3c;
      margin: 1rem auto;
      border-radius: 4px;
    }

    /* Cards style */
    .section-title {
      font-size: 1.8rem;
      font-weight: 700;
      margin: 2rem 0 1rem 0;
      padding-right: 0.5rem;
      border-right: 6px solid #e74c3c;
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .section-title i {
      color: #e74c3c;
      font-size: 1.7rem;
    }
    .grid-2cols {
      display: flex;
      flex-wrap: wrap;
      gap: 1.8rem;
      margin: 1.5rem 0;
    }
    .route-card {
      flex: 1;
      min-width: 280px;
      background: #ffffffdd;
      backdrop-filter: blur(4px);
      background: white;
      border-radius: 1.5rem;
      padding: 1.5rem;
      box-shadow: 0 8px 20px rgba(0,0,0,0.05);
      transition: all 0.25s;
      border: 1px solid rgba(231,76,60,0.15);
    }
    .route-card:hover {
      transform: translateY(-6px);
      box-shadow: 0 20px 30px -12px rgba(0,0,0,0.15);
      border-color: #e74c3c40;
    }
    .route-title {
      font-size: 1.5rem;
      font-weight: 700;
      margin-bottom: 1rem;
      display: flex;
      align-items: center;
      gap: 12px;
      color: #1f2a3e;
    }
    .diagram-pre {
      background: #0f172a;
      color: #e2e8f0;
      padding: 1rem;
      border-radius: 1rem;
      overflow-x: auto;
      font-family: 'SF Mono', 'Fira Code', monospace;
      font-size: 0.75rem;
      line-height: 1.4;
      direction: ltr;
      text-align: left;
      margin: 1rem 0;
    }
    .desc-text {
      margin: 0.8rem 0;
      color: #2d3e50;
    }
    .badge {
      background: #eef2ff;
      padding: 4px 12px;
      border-radius: 30px;
      font-size: 0.8rem;
      display: inline-block;
      font-weight: 500;
    }

    /* core grid */
    .core-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
      gap: 1.5rem;
      margin: 1.5rem 0;
    }
    .core-card {
      background: white;
      border-radius: 1.25rem;
      padding: 1.2rem 1.4rem;
      transition: all 0.2s;
      box-shadow: 0 4px 12px rgba(0,0,0,0.03);
      border: 1px solid #f1f1f1;
    }
    .core-card:hover {
      border-color: #e74c3c60;
      box-shadow: 0 12px 18px -10px rgba(0,0,0,0.1);
    }
    .core-header {
      display: flex;
      align-items: center;
      gap: 12px;
      font-weight: 700;
      font-size: 1.25rem;
      margin-bottom: 12px;
      color: #0f172a;
    }
    .core-header i {
      color: #e74c3c;
      font-size: 1.5rem;
    }
    .core-list {
      padding-right: 1.8rem;
      list-style-type: circle;
      color: #2c3e50;
      font-size: 0.9rem;
    }
    .core-list li {
      margin: 6px 0;
    }

    /* Stargazers & footer */
    .stargazer-section {
      background: linear-gradient(120deg, #1e293b, #0f172a);
      border-radius: 1.5rem;
      padding: 1.5rem;
      margin: 2rem 0;
      text-align: center;
    }
    .stargazer-section h3 {
      color: white;
      font-weight: 600;
    }
    .footer {
      text-align: center;
      margin-top: 2rem;
      padding-top: 1rem;
      border-top: 1px solid #e2e8f0;
      font-size: 0.9rem;
    }
    a {
      color: #c0392b;
      text-decoration: none;
      font-weight: 500;
    }
    a:hover {
      text-decoration: underline;
    }
    hr {
      margin: 1rem 0;
    }
    @media (max-width: 720px) {
      body { padding: 1rem; }
      .container { padding: 1.2rem; }
      h1 { font-size: 1.9rem; }
      .section-title { font-size: 1.5rem; }
    }
  </style>
</head>
<body>
<div class="container">
  <!-- Header with animated logo -->
  <div class="hero">
    <div class="logo-wrapper">
      <img src="https://raw.githubusercontent.com/IRNova/Nova-Proxy-App/main/logo.svg" 
           alt="NovaProxy Logo" 
           class="animated-logo"
           onerror="this.src='https://placehold.co/140x140?text=Nova'">
    </div>
    <h1>نوواپراکسی</h1>
    <p class="tagline"><strong>NovaProxy</strong> — پل هوشمند به اینترنت آزاد</p>
    <div class="divider-heart"></div>
  </div>

  <!-- معماری کلی (دو مسیر اصلی) -->
  <div class="section-title">
    <i class="fas fa-project-diagram"></i>
    <span>معماری کلّی &nbsp; | &nbsp; دو مسیر هوشمند</span>
  </div>
  <div class="grid-2cols">
    <!-- مسیر GSA -->
    <div class="route-card">
      <div class="route-title">
        <i class="fas fa-cloud-upload-alt" style="color:#e74c3c;"></i>
        <span>مسیر GSA (Google Apps Script + Cloudflare Worker)</span>
      </div>
      <div class="diagram-pre">
┌──────────┐    ┌───────────────┐    ┌──────────────────┐    ┌──────────────────┐
│  کلاینت   │───>│ GSA Proxy     │───>│ Google Apps      │───>│ Cloudflare       │
│ (مرورگر) │    │ (پورت 8085)   │    │ Script (Code.gs) │    │ Worker (worker)  │
└──────────┘    └───────────────┘    └──────────────────┘    └──────────────────┘
                                                     │
                                                     ▼
                                              ┌──────────────┐
                                              │ اینترنت آزاد  │
                                              └──────────────┘
      </div>
      <p class="desc-text">
        <i class="fas fa-arrow-right"></i> <strong>نحوه کار:</strong> کلاینت → GSA Proxy محلی (پورت 8085) تبدیل درخواست به JSON، احراز با کلید ارسال به Apps Script، سپس فوروارد به Cloudflare Worker و دریافت پاسخ نهایی. پشتیبانی از Batch، کش هوشمند، Auto-Failover و SNI Rewrite.
      </p>
      <div class="badge"><i class="fas fa-shield-alt"></i> رمزنگاری لایه‌ای</div>
    </div>
    <!-- مسیر MITM (Google IP Direct) -->
    <div class="route-card">
      <div class="route-title">
        <i class="fas fa-shield-virus"></i>
        <span>مسیر MITM (Google IP Direct)</span>
      </div>
      <div class="diagram-pre">
┌──────────┐    ┌──────────────────────┐    ┌───────────────────────┐
│  کلاینت   │───>│  آی‌پی‌های سفید گوگل │───>│  سایت‌های گوگل        │
│ (مرورگر) │    │  216.239.38.120     │    │  یوتیوب، جستجو، جیمیل  │
└──────────┘    │  www.google.com     │    │  گوگل‌درایو، مپس و... │
                └──────────────────────┘    └───────────────────────┘
      </div>
      <p class="desc-text">
        <i class="fas fa-chart-line"></i> اتصال مستقیم به آی‌پی‌های سفید گوگل (لیست ۲۶ آی‌پی ثابت) با SNI تنظیم شده روی دامنه‌های گوگل. MITM Proxy ترافیک TLS را رمزگشایی می‌کند و تمام سرویس‌های گوگل بدون فیلتر در دسترس هستند.
      </p>
      <div class="badge"><i class="fas fa-tachometer-alt"></i> دسترسی پایدار و سریع</div>
    </div>
  </div>

  <!-- هسته‌های پروژه (Core Components) -->
  <div class="section-title">
    <i class="fas fa-microchip"></i>
    <span>هسته‌های قدرتمند پروژه</span>
  </div>
  <div class="core-grid">
    <!-- ۱. GSA Core -->
    <div class="core-card">
      <div class="core-header"><i class="fas fa-exchange-alt"></i> GSA Core</div>
      <ul class="core-list">
        <li>رله HTTP/2 و HTTP/1.1 با Connection Pool</li>
        <li>Batch Request (گروهی تا ۵۰ درخواست)</li>
        <li>Response Cache هوشمند (۵۰ مگابایت)</li>
        <li>Auto-Failover بین آی‌پی‌های گوگل & Heartbeat هر ۳۰ ثانیه</li>
        <li>Front Domain Rotation & Google IP Scanner</li>
        <li>SNI Rewrite (یوتیوب، دابل‌کلیک، گوگل آنالیتیکس)</li>
        <li>MITM داخلی با CA اختصاصی + Split Tunnel</li>
      </ul>
    </div>
    <!-- ۲. Google Apps Script -->
    <div class="core-card">
      <div class="core-header"><i class="fab fa-google"></i> Google Apps Script</div>
      <ul class="core-list">
        <li>دریافت درخواست JSON از GSA Proxy</li>
        <li>اعتبارسنجی با AUTH_KEY</li>
        <li>ارسال به Cloudflare Worker</li>
        <li>پشتیبانی از Batch پردازش گروهی</li>
        <li>فیلتر هدرهای Hop-by-Hop</li>
      </ul>
    </div>
    <!-- ۳. Cloudflare Worker -->
    <div class="core-card">
      <div class="core-header"><i class="fab fa-cloudflare"></i> Cloudflare Worker</div>
      <ul class="core-list">
        <li>دریافت از Apps Script و درخواست واقعی به مقصد</li>
        <li>Upstream Forwarder زنجیره‌ای & Loop Detection</li>
        <li>مسدودسازی Self-Fetch & تبدیل بدنه base64 تکه‌تکه</li>
        <li>Fallback به Direct در صورت خطای Upstream</li>
      </ul>
    </div>
    <!-- ۴. Proxy Core -->
    <div class="core-card">
      <div class="core-header"><i class="fas fa-network-wired"></i> Proxy Core</div>
      <ul class="core-list">
        <li>حالت‌ها: mitm, transparent, tls-rf, quic, direct, server</li>
        <li>Cloudflare IP Pool + Health Check</li>
        <li>uTLS Fingerprinting (Chrome, Firefox)</li>
        <li>ECH (Encrypted Client Hello) با Auto-Refresh</li>
        <li>SOCKS5 Proxy & TLS Fragmentation & Certificate Cache</li>
      </ul>
    </div>
    <!-- ۵. Core Runtime -->
    <div class="core-card">
      <div class="core-header"><i class="fas fa-cogs"></i> Core Runtime</div>
      <ul class="core-list">
        <li>فرآیند پشتیبان مجزا با RPC روی پورت ۱۸۹۳۳</li>
        <li>مدیریت پروکسی و TUN، بارگذاری مجدد تنظیمات</li>
        <li>دسترسی ادمین برای TUN & گواهی‌ها</li>
      </ul>
    </div>
    <!-- ۶. Auto Router -->
    <div class="core-card">
      <div class="core-header"><i class="fas fa-route"></i> Auto Router</div>
      <ul class="core-list">
        <li>مسیریاب خودکار براساس GFW List</li>
        <li>تشخیص کلودفلر از طریق DoH</li>
        <li>حالت‌ها: default, server (با Fallback), gsa</li>
      </ul>
    </div>
    <!-- ۷. DNS Resolver -->
    <div class="core-card">
      <div class="core-header"><i class="fas fa-dns"></i> DNS Resolver (DoH)</div>
      <ul class="core-list">
        <li>DNS-over-HTTPS با Failover و Parallel Race</li>
        <li>ECH Refresh خودکار و Safe Resolver برای Circular Dependency</li>
      </ul>
    </div>
    <!-- ۸. TUN Mode -->
    <div class="core-card">
      <div class="core-header"><i class="fas fa-tunnel"></i> TUN Mode</div>
      <ul class="core-list">
        <li>یکپارچه با Mihomo (Clash.Meta)</li>
        <li>مسیریابی سطح سیستم + Fake-IP و DNS Hijack</li>
      </ul>
    </div>
    <!-- ۹. Certificate Manager -->
    <div class="core-card">
      <div class="core-header"><i class="fas fa-lock"></i> Certificate Manager</div>
      <ul class="core-list"><li>مدیریت کامل گواهی CA برای MITM و امضای گواهی dynamically</li></ul>
    </div>
    <!-- ۱۰. uTLS -->
    <div class="core-card">
      <div class="core-header"><i class="fas fa-fingerprint"></i> uTLS</div>
      <ul class="core-list"><li>فورک refraction-networking/utls برای شبیه‌سازی اثرانگشت TLS مرورگرهای مدرن</li></ul>
    </div>
    <!-- ۱۱. Frontend -->
    <div class="core-card">
      <div class="core-header"><i class="fas fa-desktop"></i> Frontend</div>
      <ul class="core-list"><li>رابط کاربری با Wails v3 + Vite + TypeScript + Tailwind CSS — تجربه کاربری جذاب</li></ul>
    </div>
  </div>

  <!-- جزئیات پیشرفته اضافی: GSA دقیق و MITM دقیق (خلاصه‌ای) -->
  <div class="section-title">
    <i class="fas fa-charging-station"></i>
    <span>نقاط قوت فنی &nbsp;|&nbsp; نوآوری‌ها</span>
  </div>
  <div style="display: flex; flex-wrap: wrap; gap: 1.2rem; justify-content: space-between; margin-bottom: 2rem;">
    <div style="flex:1; background:#fff0ed; border-radius: 1rem; padding: 1rem;">
      <i class="fas fa-sync-alt" style="color:#e74c3c;"></i>
      <strong style="margin-right: 6px;">Upstream Forwarder زنجیره‌ای</strong>
      <p style="font-size: 0.85rem;">Cloudflare Worker قابلیت ارسال درخواست به upstream بعدی، تشخیص حلقه با x-relay-hop</p>
    </div>
    <div style="flex:1; background:#eef2ff; border-radius: 1rem; padding: 1rem;">
      <i class="fas fa-chart-bar" style="color:#e74c3c;"></i>
      <strong style="margin-right: 6px;">Batch Request + Cache</strong>
      <p style="font-size: 0.85rem;">بهبود سرعت و کاهش مصرف منابع با کش ۵۰ مگابایت و ارسال گروهی درخواست‌ها</p>
    </div>
    <div style="flex:1; background:#fef9e3; border-radius: 1rem; padding: 1rem;">
      <i class="fas fa-road" style="color:#e74c3c;"></i>
      <strong style="margin-right: 6px;">Split Tunnel & TUN</strong>
      <p style="font-size: 0.85rem;">مسیریابی انتخابی برنامه‌ها به همراه TUN فراگیر با Clash.Meta</p>
    </div>
  </div>

  <!-- توضیحات دقیق تر از مسیر GSA و سرورها -->
  <div style="background: linear-gradient(110deg, #f1f5f9, #ffffff); border-radius: 1.2rem; padding: 1rem 1.5rem; margin: 1rem 0;">
    <p><i class="fas fa-info-circle" style="color:#e74c3c;"></i> <strong>نکته مهم:</strong> GSA Proxy صرفاً یک پروکسی محلی ساده نیست. تمامی داده‌ها از زیرساخت Google Apps Script و Cloudflare Worker عبور می‌کند. پشتیبانی از <strong>ECH، uTLS، MITM داخلی با CA اختصاصی</strong> و <strong>Auto-Failover</strong> برای حداکثر پایداری.</p>
    <p class="desc-text"><i class="fas fa-chart-simple"></i> همچنین در مسیر مستقیم Google IP، ۲۶ آی‌پی ثابت + اسکنر DNS پویا و SNI Rewrite برای دسترسی به تمام سرویس‌های گوگل (YouTube, Gmail, Drive, Maps و ...) استفاده می‌شود.</p>
  </div>

  <!-- Stargazers over time (نمودار ستاره‌ها) -->
  <div class="stargazer-section">
    <h3><i class="fas fa-star" style="color: #FFD966;"></i> Stargazers over time <i class="fas fa-chart-line"></i></h3>
    <img src="https://starchart.cc/IRNova/Nova-Proxy-App.svg?variant=adaptive" alt="Stargazers Chart" style="max-width:100%; border-radius: 20px; margin-top: 12px; background: #0f172a; padding: 5px;">
    <p style="color:#cbd5e1; margin-top: 10px; font-size:0.8rem;">جامعه رو به رشد نوواپراکسی — مشارکت شما ارزشمند است ⭐</p>
  </div>

  <!-- فوتر با کانال تلگرام و قلب -->
  <div class="footer">
    <hr style="width: 60px; border: 1px solid #e74c3c; margin: 0 auto 1rem auto;">
    <p style="font-size: 1rem;">
      <i class="fas fa-heart" style="color: #e74c3c;"></i> نواپراکسی — پلی به سوی اینترنت آزاد و امن
    </p>
    <p>
      📡 <a href="https://t.me/irnova_proxy" target="_blank"><i class="fab fa-telegram"></i> @irnova_proxy</a> &nbsp;|&nbsp; 
      <i class="fas fa-globe"></i> نوواپراکسی: هوشمند، سریع، متن‌باز
    </p>
    <p style="font-size: 0.75rem; color:#6c757d; margin-top: 12px;">
      Core Runtime | TUN Mode | Auto Router | Cloudflare Worker Integration — توسعه‌یافته با معماری پیشرفته
    </p>
  </div>
</div>
</body>
</html>
