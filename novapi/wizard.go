package novapi

const adminHTML = `<!DOCTYPE html>
<html lang="en" dir="ltr" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"/>
<title>NovaProxy — Command Center</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=Vazirmatn:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;700&family=Noto+Sans+SC:wght@400;500;700&family=Noto+Sans+JP:wght@400;500;700&display=swap" rel="stylesheet">
<style>
:root {
  --bg: #05060a;
  --bg-alt: #090b12;
  --card: rgba(255,255,255,.04);
  --card2: rgba(255,255,255,.06);
  --card-hover: rgba(255,255,255,.08);
  --line: rgba(255,255,255,.09);
  --line2: rgba(255,255,255,.16);
  --tx: #eef1f7;
  --tx2: #c8cedb;
  --mu: #9aa4b8;
  --mu2: #6b7a93;
  --cyan: #22d3ee;
  --violet: #a855f7;
  --indigo: #818cf8;
  --grad: linear-gradient(120deg,#22d3ee 0%,#818cf8 50%,#a855f7 100%);
  --ok: #34d399;
  --bad: #f87171;
  --warn: #f59e0b;
  --blue: #3b82f6;
  --r: 16px;
  --r-sm: 10px;
  --r-lg: 24px;
  --code: #0b0e16;
  --nav: rgba(5,6,10,.7);
  --shadow: 0 10px 40px -12px rgba(99,102,241,.5);
  --font: 'Inter',system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
  --font-fa: 'Vazirmatn','Inter',system-ui,Tahoma,Arial,sans-serif;
  --font-mono: 'JetBrains Mono','SF Mono',monospace;
  --font-zh: 'Noto Sans SC','Inter',sans-serif;
  --font-ru: 'Inter',system-ui,sans-serif;
  --glow-cyan: 0 0 20px rgba(34,211,238,.3);
  --glow-violet: 0 0 20px rgba(168,85,247,.3);
}
:root[data-theme='light'] {
  --bg: #f0f2f8;
  --bg-alt: #e4e7f0;
  --card: rgba(15,23,42,.04);
  --card2: rgba(15,23,42,.07);
  --card-hover: rgba(15,23,42,.1);
  --line: rgba(15,23,42,.12);
  --line2: rgba(15,23,42,.22);
  --tx: #0d1117;
  --tx2: #1e293b;
  --mu: #51607a;
  --mu2: #6b7a93;
  --cyan: #0891b2;
  --violet: #9333ea;
  --indigo: #6366f1;
  --code: #e8ecf4;
  --nav: rgba(240,242,248,.8);
  --shadow: 0 10px 40px -12px rgba(99,102,241,.2);
  --glow-cyan: 0 0 12px rgba(8,145,178,.15);
  --glow-violet: 0 0 12px rgba(147,51,234,.15);
}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent;margin:0;padding:0}
html{scroll-behavior:smooth}
html,body{margin:0;padding:0;height:100%;overflow:hidden}
body{
  background:var(--bg);
  color:var(--tx);
  font-family:var(--font);
  line-height:1.6;
  height:100vh;
  overflow:hidden;
  -webkit-font-smoothing:antialiased;
  background-image:
    radial-gradient(ellipse at 20% 50%, rgba(34,211,238,.06) 0%, transparent 50%),
    radial-gradient(ellipse at 80% 20%, rgba(168,85,247,.06) 0%, transparent 50%),
    radial-gradient(ellipse at 50% 80%, rgba(129,140,248,.04) 0%, transparent 50%);
}
.fa body,html[lang='fa'] body{font-family:var(--font-fa);line-height:1.8}
.zh body,html[lang='zh'] body{font-family:var(--font-zh)}
.ru body,html[lang='ru'] body{font-family:var(--font-ru)}
a{color:var(--cyan);text-decoration:none}
/* ─── SIDEBAR LAYOUT ─── */
.app{display:flex;height:100vh;overflow:hidden}
.sidebar{
  position:fixed;left:0;top:0;bottom:0;z-index:100;
  width:220px;display:flex;flex-direction:column;
  background:var(--bg-alt);border-right:1px solid var(--line);
  backdrop-filter:blur(20px) saturate(1.4);
  -webkit-backdrop-filter:blur(20px) saturate(1.4);
  overflow:hidden;
}
html[dir='rtl'] .sidebar{left:auto;right:0;border-right:none;border-left:1px solid var(--line)}
.sidebar-logo{
  display:flex;align-items:center;gap:10px;
  padding:16px 18px;font-weight:800;font-size:1.1rem;
  border-bottom:1px solid var(--line);flex-shrink:0;
}
.sidebar-logo .mk{
  width:30px;height:30px;border-radius:8px;
  background:var(--grad);
  display:flex;align-items:center;justify-content:center;
  font-weight:900;color:#05060a;font-size:15px;
  box-shadow:var(--glow-cyan);flex-shrink:0;
}
.sidebar-nav{flex:1;padding:8px 10px;display:flex;flex-direction:column;gap:2px;overflow-y:auto}
.sidebar-nav::-webkit-scrollbar{width:3px}
.sidebar-nav::-webkit-scrollbar-thumb{background:var(--line);border-radius:3px}
.nav-item{
  display:flex;align-items:center;gap:10px;
  padding:10px 12px;border-radius:var(--r-sm);
  font-size:.85rem;font-weight:600;
  color:var(--mu);cursor:pointer;white-space:nowrap;
  transition:all .2s;border:none;background:transparent;font-family:inherit;width:100%
}
html[dir='ltr'] .nav-item{text-align:left}
html[dir='rtl'] .nav-item{text-align:right}
.nav-item:hover{color:var(--tx);background:var(--card)}
.nav-item.on{color:#05060a;background:var(--grad);font-weight:700}
.nav-item .ni-icon{font-size:1.15rem;width:22px;text-align:center;flex-shrink:0}
.sidebar-footer{
  padding:12px 14px;border-top:1px solid var(--line);
  display:flex;flex-direction:column;gap:8px;flex-shrink:0;
}
.sidebar-footer .langs{
  display:flex;padding:3px;border-radius:999px;border:1px solid var(--line2);
  background:var(--card2);gap:2px
}
.sidebar-footer .langs button{
  border:0;cursor:pointer;font:inherit;font-size:.7rem;font-weight:600;
  flex:1;padding:4px 6px;border-radius:999px;
  color:var(--mu);background:transparent;transition:all .2s;min-width:0
}
.sidebar-footer .langs button.on{color:#05060a;background:var(--grad);font-weight:700}
.sidebar-footer .theme{
  display:flex;align-items:center;justify-content:center;gap:6px;
  width:100%;padding:8px;border-radius:999px;
  border:1px solid var(--line2);background:var(--card2);
  color:var(--tx);cursor:pointer;font-size:.8rem;font-weight:600;
  transition:all .2s;font-family:inherit
}
.sidebar-footer .theme:hover{background:var(--card-hover)}
/* ─── CONTENT ─── */
.content{margin-left:220px;flex:1;padding:0;width:calc(100% - 220px);height:100vh;overflow-y:auto}
html[dir='rtl'] .content{margin-left:0;margin-right:220px}
.wrap{max-width:960px;margin:0 auto;padding:16px 20px 20px}
/* ─── CARDS ─── */
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:20px;margin:14px 0}
.card-title{font-size:1.05rem;font-weight:700;margin-bottom:12px;display:flex;align-items:center;gap:8px}
.card-title .g{background:var(--grad);-webkit-background-clip:text;background-clip:text;color:transparent}
/* ─── GRID ─── */
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;margin-bottom:14px}
.stat-card{
  background:var(--card);border:1px solid var(--line);
  border-radius:var(--r);padding:18px;position:relative;overflow:hidden;
  transition:all .3s
}
.stat-card:hover{border-color:var(--line2);transform:translateY(-2px);box-shadow:var(--shadow)}
.stat-card .label{font-size:.8rem;color:var(--mu);font-weight:500;margin-bottom:4px;text-transform:uppercase;letter-spacing:.03em}
.stat-card .val{font-size:1.5rem;font-weight:800}
.stat-card .sub{font-size:.8rem;color:var(--mu2);margin-top:2px}
.stat-card .glow{
  position:absolute;top:-50%;right:-50%;width:100%;height:100%;
  background:radial-gradient(circle,var(--cyan) 0%,transparent 70%);
  opacity:0;transition:opacity .4s;pointer-events:none
}
.stat-card:hover .glow{opacity:.06}
/* ─── BUTTONS ─── */
.btn{
  display:inline-flex;align-items:center;justify-content:center;gap:8px;
  background:var(--grad);color:#05060a;font-weight:700;font-size:.9rem;
  padding:11px 22px;border-radius:var(--r-sm);
  border:none;cursor:pointer;font-family:inherit;
  transition:all .15s;white-space:nowrap
}
.btn:active{transform:scale(.97)}
.btn[disabled]{opacity:.5;cursor:not-allowed}
.btn-sm{padding:7px 14px;font-size:.8rem}
.btn-ghost{
  background:var(--card2);border:1px solid var(--line2);
  color:var(--tx);font-weight:600;box-shadow:none
}
.btn-ghost:hover{background:var(--card-hover)}
.btn-outline{
  background:transparent;border:1px solid var(--cyan);
  color:var(--cyan);box-shadow:none
}
.btn-outline:hover{background:rgba(34,211,238,.1)}
.btn-bad{background:var(--bad);color:#fff;box-shadow:none}
.btn-group{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}
/* ─── INPUTS ─── */
input,select,textarea{
  width:100%;background:var(--code);border:1px solid var(--line);
  border-radius:var(--r-sm);color:var(--tx);
  font-size:.9rem;padding:11px 14px;font-family:inherit;transition:border-color .2s
}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--cyan);box-shadow:0 0 0 3px rgba(34,211,238,.15)}
textarea{min-height:80px;resize:vertical;font-family:var(--font-mono);font-size:.8rem}
select{cursor:pointer}
label{display:block;font-weight:600;font-size:.82rem;margin:0 0 5px;color:var(--tx2)}
.form-group{margin-bottom:14px}
.form-hint{color:var(--mu);font-size:.75rem;margin-top:3px}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
@media(max-width:560px){.form-row{grid-template-columns:1fr}}
/* ─── LAYER LIST ─── */
.layers{display:flex;flex-direction:column;gap:6px}
.layer{
  display:flex;align-items:center;justify-content:space-between;
  padding:10px 14px;background:var(--bg);border-radius:var(--r-sm);
  border:1px solid var(--line);transition:all .2s
}
.layer:hover{border-color:var(--line2)}
.layer .name{font-size:.85rem;font-weight:500;font-family:var(--font-mono)}
.layer .status{font-size:.75rem;padding:3px 10px;border-radius:999px;font-weight:600}
.status-up{background:rgba(52,211,153,.15);color:var(--ok)}
.status-down{background:rgba(248,113,113,.15);color:var(--bad)}
.status-active{background:rgba(34,211,238,.15);color:var(--cyan)}
.status-warn{background:rgba(245,158,11,.15);color:var(--warn)}
/* ─── LOGS ─── */
.logs{
  background:var(--code);border:1px solid var(--line);
  border-radius:var(--r-sm);padding:14px;
  font-family:var(--font-mono);font-size:.75rem;line-height:1.7;
  max-height:300px;overflow-y:auto;white-space:pre-wrap;
  color:var(--mu2)
}
/* ─── STEPS / WIZARD ─── */
.gstep{padding:0 0 18px;margin-bottom:18px;border-bottom:1px solid var(--line)}
.gstep:last-child{border-bottom:none;margin-bottom:0;padding-bottom:0}
.gstep-head{display:flex;align-items:center;gap:11px;margin-bottom:7px}
.gnum{
  flex:0 0 28px;width:28px;height:28px;border-radius:50%;
  display:inline-flex;align-items:center;justify-content:center;
  font-weight:800;font-size:.9rem;color:#05060a;background:var(--grad)
}
.gtitle{font-weight:700;font-size:1rem}
.gtext{margin:0 0 10px;color:var(--mu);font-size:.88rem;padding-inline-start:39px}
.steps-mini{margin:8px 0 0;padding:0;list-style:none}
.steps-mini li{display:flex;gap:10px;padding:5px 0;color:var(--mu);font-size:.82rem;align-items:flex-start}
.steps-mini .n{
  flex:0 0 20px;height:20px;border-radius:50%;
  background:var(--card2);border:1px solid var(--line);
  display:flex;align-items:center;justify-content:center;
  font-weight:700;color:var(--cyan);font-size:.7rem
}
.progress{margin:14px 0 0}
.prow{display:flex;align-items:center;gap:11px;padding:8px 0;font-size:.85rem;color:var(--mu)}
.prow .dot{
  flex:0 0 18px;height:18px;border-radius:50%;
  border:2px solid var(--line);
  display:flex;align-items:center;justify-content:center;font-size:.7rem
}
.prow.done{color:var(--tx)}.prow.done .dot{border-color:transparent;background:var(--grad);color:#05060a}
.prow.run .dot{border-color:var(--cyan);border-top-color:transparent;animation:spin .8s linear infinite}
.prow.err{color:var(--bad)}.prow.err .dot{border-color:var(--bad);color:var(--bad)}
@keyframes spin{to{transform:rotate(360deg)}}
/* ─── RESULT ─── */
.result{
  background:linear-gradient(180deg,rgba(34,211,238,.1),var(--card));
  border:1px solid rgba(34,211,238,.4);border-radius:var(--r);padding:18px;margin:14px 0
}
.result h3{margin:0 0 10px;font-size:1.05rem;color:var(--cyan)}
.kv{display:flex;justify-content:space-between;gap:10px;padding:8px 0;border-top:1px solid var(--line);font-size:.85rem;flex-wrap:wrap}
.kv:first-of-type{border-top:none}
.kv .k{color:var(--mu)}.kv .v{font-weight:700;word-break:break-all;direction:ltr;text-align:right}
.err-box{background:rgba(248,113,113,.08);border:1px solid rgba(248,113,113,.35);border-radius:var(--r-sm);padding:12px 14px;margin:12px 0;font-size:.85rem;color:#fecaca}
/* ─── CALLOUT ─── */
.callout{display:flex;gap:11px;border-radius:var(--r-sm);padding:12px 14px;margin:10px 0;font-size:.82rem;border:1px solid}
.callout.iran{background:rgba(168,85,247,.08);border-color:rgba(168,85,247,.3)}
.callout.iran b{color:#c89bf5}
.callout.info{background:rgba(34,211,238,.07);border-color:rgba(34,211,238,.25)}
.callout.warn{background:rgba(245,158,11,.08);border-color:rgba(245,158,11,.3)}
.callout.ok{background:rgba(52,211,153,.08);border-color:rgba(52,211,153,.3)}
.callout .ic{flex:0 0 18px;font-size:1rem}
/* ─── SECTION DISPLAY ─── */
.section-group{margin-bottom:24px}
.section-group h3{
  font-size:.9rem;font-weight:700;color:var(--cyan);
  text-transform:uppercase;letter-spacing:.05em;
  margin-bottom:12px;padding-bottom:8px;
  border-bottom:1px solid var(--line)
}
.setting-item{
  display:flex;justify-content:space-between;align-items:center;
  padding:10px 0;border-top:1px solid var(--line);gap:12px
}
.setting-item:first-child{border-top:none}
.setting-label{flex:1}
.setting-label .name{font-weight:600;font-size:.85rem}
.setting-label .desc{color:var(--mu);font-size:.75rem;margin-top:2px}
.setting-input{max-width:220px}
/* ─── COCKPIT HUD ─── */
.hud{
  position:relative;padding:24px;overflow:hidden;
  border-radius:var(--r-lg);
  background:linear-gradient(135deg,rgba(34,211,238,.05),rgba(168,85,247,.05));
  border:1px solid rgba(34,211,238,.2);
}
.hud::before{
  content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:var(--grad);opacity:.6
}
.hud-grid{
  display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
  gap:16px;margin-top:16px
}
.hud-item{
  text-align:center;padding:14px;
  background:var(--card);border-radius:var(--r-sm);
  border:1px solid var(--line);
}
.hud-item .hud-label{font-size:.7rem;color:var(--mu2);text-transform:uppercase;letter-spacing:.06em;font-weight:600}
.hud-item .hud-val{font-size:1.8rem;font-weight:900;font-family:var(--font-mono);margin-top:4px}
.hud-item .hud-val.cyan{color:var(--cyan)}.hud-item .hud-val.violet{color:var(--violet)}
.hud-item .hud-val.ok{color:var(--ok)}.hud-item .hud-val.bad{color:var(--bad)}
/* ─── MISC ─── */
.hidden{display:none!important}
.tab-content{display:none}
.tab-content.on{display:block}
code{
  background:var(--card2);border:1px solid var(--line);
  border-radius:6px;padding:1px 6px;font-size:.75rem;
  font-family:var(--font-mono);direction:ltr;display:inline-block
}
.badge{display:inline-flex;padding:3px 12px;border-radius:999px;font-size:.75rem;font-weight:600}
.badge-on{background:rgba(34,197,94,.15);color:var(--ok)}
.badge-off{background:rgba(239,68,68,.15);color:var(--bad)}
/* ─── ANIMATIONS ─── */
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
.pulse{animation:pulse 2s ease-in-out infinite}
@keyframes fadeIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
.fade-in{animation:fadeIn .3s ease-out}
@keyframes glow{0%,100%{box-shadow:0 0 5px rgba(34,211,238,.2)}50%{box-shadow:0 0 20px rgba(34,211,238,.4)}}
.glow-border{animation:glow 3s ease-in-out infinite}
/* ─── RESPONSIVE ─── */
@media(max-width:600px){
  .bar{padding:8px 12px}
  .tabs{padding:6px 12px;gap:2px}
  .tab{padding:6px 10px;font-size:.78rem;gap:4px}
  .wrap{padding:12px}
  .grid{grid-template-columns:1fr}
  .stat-card .val{font-size:1.2rem}
  .langs button{min-width:28px;padding:3px 7px;font-size:.68rem}
}
/* ─── PAC MODE TOGGLE ─── */
.toggle{position:relative;width:44px;height:24px;flex-shrink:0}
.toggle input{opacity:0;width:0;height:0}
.toggle .slider{
  position:absolute;cursor:pointer;inset:0;
  background:var(--card2);border-radius:999px;border:1px solid var(--line);
  transition:.3s
}
.toggle .slider::before{
  content:'';position:absolute;height:18px;width:18px;
  left:2px;bottom:2px;background:var(--mu);
  border-radius:50%;transition:.3s
}
.toggle input:checked+.slider{background:var(--grad);border-color:var(--cyan)}
.toggle input:checked+.slider::before{transform:translateX(20px);background:#05060a}
/* ─── DEPLOY PREVIEW ─── */
.deploy-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px}
.deploy-card{
  display:flex;flex-direction:column;align-items:center;gap:8px;
  padding:16px 10px;background:var(--card);border:1px solid var(--line);
  border-radius:var(--r-sm);cursor:pointer;transition:all .2s;
  text-align:center
}
.deploy-card:hover{border-color:var(--cyan);background:var(--card-hover);transform:translateY(-2px)}
.deploy-card .dc-icon{font-size:1.8rem}
.deploy-card .dc-name{font-size:.8rem;font-weight:600}
/* ─── FOOTER ─── */
.foot{text-align:center;color:var(--mu);font-size:.75rem;margin-top:30px;border-top:1px solid var(--line);padding-top:20px}
</style>
</head>
<body>
<div class="app">
<aside class="sidebar">
  <div class="sidebar-logo"><img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAGk0lEQVR4nM1XXWwcVxX+7p3ZzXp/nDROmtox/aM0pqBKDaWCUHigSaWK0lZCrlArJCp4yAsPiaryEFLbvCEhIqFIFQoC1KggYkFTCdpGaSuaNqRSTCiUkCghDklsN3YSe3e93p2de8896NxZO/Zm7dgPlTjS0ezcO3POd77zc2cVWgmz7h2EwhIyCKB33u9lydNwgGL8P4laeKksetx3sLhHZ7KfdlFNEGu/55xsQWIAaxgo7s6yXhchOHqRTDYFRYvEJlaVDhWVRl+4sKvnNPr6NAYGxBLCJjBiIgS5J8J86m6nUnMQZ53LVRAZC6xbDUxVgTDLCMIlyGWGTmlEI1d+DuA00A9gAM0A5oDExpapRORqFUGpPSxW0FCeJDFoLSGTTmFs3ACWEQEItILzTHEzt6yClKJ6nZqdha0AO6JAkQuInJIUcByDxi+hcvUyYksIOrrRffcdoJhRNoCKSqhfvYAZClHovAthKu1BzGFgZqUCBSa1LACwzquyBOgQXCmjeOIw7ssb3POpLpRXhZiMVuOa6UAURdDnh2CGj2LrlodwKi5gWm1AqNgTN5c/RYC1N7jSLRkQGonAVtRCO4vytSt4btsXsf9H38NrOx7DVwoRzl2uoo3rmBo5i4d7NuDgj5/BM5vXoDxdQyBOyS3UFqJbM9BwTuRfZLJQYESxBTmJTOHrd63B+MQ1pMEga1HIZeEYyKZ0EqmTd5t0uQzAp6DhfPbqnAchhSaJ3LJpPXoKdVSrka9SIoJW4nc24nmO3QoBMNmEAUOAETacnwPKtwDwl+MnkW9L49nN7ZguFT0g5fu0kW+yN0YvuuwUmHlF6BkggJ2vDZE/vfU+JoslfOert+O2dAVkkhQ1ECQRL1BJiU1sLQeAMwQXE8iIOlDsACM0JwDOfzyJX712BB2FDJ74XA5cnkagG6ac8+lwXm1Dk7UbE4DWAIwhxMb6qzEWzgO4vl9J34p9B4/4Xt/+6CYoqsA25rCsSVFa6/ywSnT2fuka4FkCYMn4QpQasI1CFPobTxTW34kzw5N4+69/x73dHXj4/k6UKjONt6UGqKkOJJ0xlKvapRlwMvlAqMclGa8wjj0IMSa5bEjQthoo3I69r7zp73/w7Ueh54qw0QEC2CsxmBWbOnFxspw81L8IgMHknqPaRX+0Ca9y6jS6YJYBYo10Vw/eGhrG6XMX8c2tX8KXH+hpGFRNvU9QrMAmnjLDx8b9QwP9vHQbVqY+Qmx9G7KxyUCSCBtRMjFW5W/FjF6Lva+87g+l735rm9/z3bBgBshY1eA4Olc9/eoVYWP+uakXeD6ZxGhG/nWMKlMOjoK5QeIzxIlaBiHA2u4eDB7+G8avTqF7w1o4ln23sPXIsowujorHZMTNstwawICSs1RNvb77Q5opn1QyaA0RSz0QY337KmitkNIMZyyyazZioqzx8h8PJ8aU7Cl/flw/AyhwtTLslVN/nh/k4ikY9GtVNzX6W3ZKyVFsTYhbNvbg1EgRQ2cmcG6shoxyIKSQ3fh5/PrNf+Kj/4zh7KWrmChGCCVbAsJaUjoDrhZPlA7tPurplyDniWpRAX6trfuRrvy2F44HmcJtM5UqP3hnRo+MXsZoSaGtLY8w1I2vJIO4VoRyBkGYhkq3QwXpWVukUrkguvTBc6VDz/8GfaybAegbAShGH1Rt5J1Rc/nfP1FOqzTI3ZLLIMIa5LN5pOSsl+omqXCNTHYd0rlO6FUdUAignOwZ0kE2sKWR90uHnv99K+eLAGjUQh/r4hs7f1H5+MzhQmF1GNfrdqpc9QeVsZSM1oYaE8NaAxKVNWOd5UDHtVKlevbtnYCqoX9h7pcGIDIgX7I6mn533/auzPT5iVoY1oyxdXKoEzXpvDVrOGZw7KBmRk7sqH247zj6nIZSKwQAxS/uJo3S+8N3VN579r8XxsbaMrmQKbae4lZKxo9SpcKAxv+xq/7ei79ELwetqJ/zgptJ74EAg08TPtP7UP6zT+3XmY57uV4myEdy8o3cEGdVkAnZEblrp344c2TXz9DLGoPyMbhEmFiG9PYeCAYFxPoH7slt3r4nyHU+zmQAks9sGWxKq3RBuah4kcaHdtaG9vzBR34T5ysT+TeTAM7ntvTvKDz28lj7kwe5/clXufCN31H2kb37010PbkoQHwjwyQirWePpzi/05L7205fyW196I33/9x+XJQ9Q2u0Tl745JwImc30tGWIrkRW/cF1YycDyP6XHF2mzm8n/AAJQSvURomU4AAAAAElFTkSuQmCC" style="width:30px;height:30px;border-radius:8px;flex-shrink:0" alt="NovaProxy"/><span id="brand-name">NovaProxy</span></div>
  <nav class="sidebar-nav">
    <!-- Original items -->
    <button class="nav-item on" data-tab="connection"><span class="ni-icon">▦</span><span data-i18n="connection">اتصال</span></button>
    <button class="nav-item" data-tab="proxy"><span class="ni-icon">◈</span><span data-i18n="proxy_sidebar">پروکسی</span></button>
    <button class="nav-item" data-tab="tunnel"><span class="ni-icon">⬟</span><span data-i18n="tunnel">تانل</span></button>
    <button class="nav-item" data-tab="mitm"><span class="ni-icon">🔒</span><span data-i18n="mitm">میتم</span></button>
    <button class="nav-item" data-tab="pac"><span class="ni-icon">⇥</span><span data-i18n="pac">پک</span></button>
    <button class="nav-item" data-tab="config"><span class="ni-icon">⚡</span><span data-i18n="config_sidebar">کانفیگ</span></button>
    <button class="nav-item" data-tab="settings"><span class="ni-icon">⚙</span><span data-i18n="settings">تنظیمات</span></button>
    <button class="nav-item" data-tab="about"><span class="ni-icon">ⓘ</span><span data-i18n="about">درباره</span></button>
    <!-- Separator -->
    <div style="height:1px;background:var(--line);margin:6px 8px"></div>
    <!-- New items -->
    <button class="nav-item" data-tab="dns"><span class="ni-icon">🌐</span><span data-i18n="dns">DNS</span></button>
    <button class="nav-item" data-tab="wizard"><span class="ni-icon">✦</span><span data-i18n="wizard">نصب‌کار</span></button>
    <button class="nav-item" data-tab="panel"><span class="ni-icon">⬡</span><span data-i18n="panel">پنل</span></button>
  </nav>
  <div class="sidebar-footer">
    <div class="langs">
      <button id="lang-en" class="on" onclick="setLang('en')">EN</button>
      <button id="lang-fa" onclick="setLang('fa')">FA</button>
      <button id="lang-zh" onclick="setLang('zh')">中文</button>
      <button id="lang-ru" onclick="setLang('ru')">RU</button>
    </div>
    <button class="theme" id="themeBtn" onclick="toggleTheme()" aria-label="Theme">☾ Toggle Theme</button>
  </div>
</aside>
<main class="content">
<div class="wrap">

<!-- ═══ CONNECTION ═══ -->
<div id="tab-connection" class="tab-content on">
  <div class="hud fade-in">
    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px">
      <div>
        <div style="font-size:.75rem;color:var(--mu2);text-transform:uppercase;letter-spacing:.06em;font-weight:600" data-i18n="status">STATUS</div>
        <div style="font-size:1.4rem;font-weight:900" id="hud-status">⏹ <span data-i18n="stopped">Stopped</span></div>
      </div>
      <div class="btn-group" style="margin:0">
        <button class="btn btn-sm" id="hud-start" onclick="startProxy()"><span data-i18n="start">Start</span></button>
        <button class="btn btn-sm btn-bad" id="hud-stop" onclick="stopProxy()"><span data-i18n="stop">Stop</span></button>
        <button class="btn btn-sm btn-ghost" onclick="refreshDashboard()">↻</button>
      </div>
    </div>
    <div class="hud-grid">
      <div class="hud-item"><div class="hud-label" data-i18n="mode">MODE</div><div class="hud-val cyan" id="hud-mode">--</div></div>
      <div class="hud-item"><div class="hud-label" data-i18n="active_layer">ACTIVE LAYER</div><div class="hud-val violet" id="hud-layer">--</div></div>
      <div class="hud-item"><div class="hud-label" data-i18n="proxy_addr">PROXY ADDR</div><div class="hud-val" id="hud-addr">--</div></div>
      <div class="hud-item"><div class="hud-label" data-i18n="tunnel_status">TUNNEL</div><div class="hud-val" id="hud-tunnel">⏹</div></div>
    </div>
  </div>

  <div class="card">
    <div class="card-title"><span class="g" data-i18n="logs">📋 Logs</span></div>
    <div class="btn-group" style="margin:0 0 10px">
      <button class="btn btn-ghost btn-sm" onclick="clearLogs()" data-i18n="clear_logs">Clear Logs</button>
    </div>
    <div id="logs" class="logs" data-i18n="loading">Loading...</div>
  </div>
</div>

<!-- ═══ PROXY ═══ -->
<div id="tab-proxy" class="tab-content">
  <div class="card">
    <div class="card-title"><span class="g" data-i18n="methods">🌐 Proxy Methods (Layers)</span></div>
    <p style="color:var(--mu);font-size:.9rem;margin-bottom:16px" data-i18n="proxy_desc">Select and manage your active proxy connection layers. Each layer provides a different method of bypassing censorship.</p>
    <div id="layers" class="layers"><span style="color:var(--mu);font-size:.85rem" data-i18n="loading">Loading...</span></div>
  </div>
  <div class="card">
    <div class="card-title"><span class="g" data-i18n="mode_switch">🎯 Quick Mode Switch</span></div>
    <div class="btn-group">
      <button class="btn btn-outline btn-sm" onclick="switchMode('rule')" style="font-family:var(--font-mono)">Rule</button>
      <button class="btn btn-outline btn-sm" onclick="switchMode('direct')" style="font-family:var(--font-mono)">Direct</button>
      <button class="btn btn-outline btn-sm" onclick="switchMode('gas')" style="font-family:var(--font-mono)">GAS</button>
      <button class="btn btn-outline btn-sm" onclick="switchMode('v2ray')" style="font-family:var(--font-mono)">V2Ray</button>
      <button class="btn btn-outline btn-sm" onclick="switchMode('pac')" style="font-family:var(--font-mono)">PAC</button>
      <button class="btn btn-outline btn-sm" onclick="switchMode('mitm')" style="font-family:var(--font-mono)">MITM</button>
    </div>
  </div>
</div>

<!-- ═══ WIZARD ═══ -->
<div id="tab-wizard" class="tab-content">
  <div class="hero" style="text-align:center;padding:14px 0;margin-bottom:8px">
    <h1 style="font-size:clamp(1.4rem,5vw,1.8rem);font-weight:800;margin:6px 0 8px">
      <span data-i18n="wizard_title">Install <span class="grad">Nova</span> Worker</span>
    </h1>
    <p style="color:var(--mu);font-size:.9rem;max-width:480px;margin:0 auto" data-i18n="wizard_desc">Paste one Cloudflare token and we'll build your panel on your account — the worker and database, fully set up.</p>
  </div>

  <div class="card" id="wizard-form">
    <div class="gstep">
      <div class="gstep-head"><span class="gnum">1</span><span class="gtitle" data-i18n="wiz_step1">Have a free Cloudflare account?</span></div>
      <p class="gtext" data-i18n="wiz_step1_desc">If not, make one free (takes 1 min).</p>
      <a class="btn btn-ghost gbtn" href="https://dash.cloudflare.com/sign-up" target="_blank" rel="noopener"><span data-i18n="create_account">Create a free account</span></a>
    </div>
    <div class="gstep">
      <div class="gstep-head"><span class="gnum">2</span><span class="gtitle" data-i18n="wiz_step2">Get your token</span></div>
      <p class="gtext" data-i18n="wiz_step2_desc">Tap the button — a Cloudflare page opens, already filled in.</p>
      <button class="btn gbtn" onclick="window.open('https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=%5B%7B%22key%22%3A%22workers_scripts%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22workers_kv_storage%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22d1%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22account_settings%22%2C%22type%22%3A%22read%22%7D%5D&accountId=*&zoneId=all&name=Nova%20Installer','_blank','noopener')"><span data-i18n="get_token">🔑 Get my token</span></button>
      <ol class="steps-mini">
        <li><span class="n">a</span><span data-i18n="wiz_st1">Scroll <b>all the way down</b> → tap <b>Continue to summary</b>.</span></li>
        <li><span class="n">b</span><span data-i18n="wiz_st2">Tap <b>Create Token</b>, then <b>Copy</b> the code.</span></li>
      </ol>
      <div class="callout warn" style="margin-top:8px"><span class="ic">⚠️</span><div><span data-i18n="wiz_warn"><b>Copy the whole code</b> — it's shown only once.</span></div></div>
    </div>
    <div class="gstep">
      <div class="gstep-head"><span class="gnum">3</span><span class="gtitle" data-i18n="wiz_step3">Paste it here</span></div>
      <div style="display:flex;gap:8px">
        <input id="wiz-token" type="text" placeholder="Your Cloudflare token" autocomplete="off" spellcheck="false" style="flex:1"/>
        <button class="btn-ghost" onclick="pasteWizToken()" style="flex:0 0 auto;width:auto;margin-top:0;padding:0 18px;font-size:.85rem;font-weight:700;border-radius:var(--r-sm)" data-i18n="paste">Paste</button>
      </div>
    </div>
    <div class="gstep" style="border-bottom:none;margin-bottom:0;padding-bottom:0">
      <div class="gstep-head"><span class="gnum">4</span><span class="gtitle" data-i18n="wiz_step4">Deploy your Nova</span></div>
      <button class="btn go-big" id="wiz-go" onclick="deployWizard()" style="width:100%;font-size:1.1rem;padding:16px"><span data-i18n="deploy_now">🚀 Deploy Now</span></button>
    </div>
  </div>

  <div class="card hidden" id="wizard-progress">
    <div class="progress" id="wiz-progress"></div>
    <div class="err-box hidden" id="wiz-err"></div>
  </div>
  <div class="result hidden" id="wiz-result"></div>
</div>

<!-- ═══ PANEL ═══ -->
<div id="tab-panel" class="tab-content">
  <div class="card">
    <div class="card-title"><span class="g" data-i18n="panel_deploy">⬡ Panel Deployment</span></div>
    <p style="color:var(--mu);font-size:.9rem;margin-bottom:16px" data-i18n="panel_desc">Deploy proxy panels on your server via SSH. Choose your panel type and enter your server details.</p>

    <div class="form-group">
      <label data-i18n="panel_type">Panel Type</label>
      <div class="deploy-grid" id="panel-types">
        <div class="deploy-card" data-panel="panai" onclick="selectPanel('panai')">
          <div class="dc-icon">📦</div>
          <div class="dc-name">Panai</div>
        </div>
        <div class="deploy-card" data-panel="x-ui" onclick="selectPanel('x-ui')">
          <div class="dc-icon">📊</div>
          <div class="dc-name">X-UI</div>
        </div>
        <div class="deploy-card" data-panel="3ui" onclick="selectPanel('3ui')">
          <div class="dc-icon">📈</div>
          <div class="dc-name">3X-UI</div>
        </div>
        <div class="deploy-card" data-panel="hiddify" onclick="selectPanel('hiddify')">
          <div class="dc-icon">🛡️</div>
          <div class="dc-name">Hiddify</div>
        </div>
        <div class="deploy-card" data-panel="marzban" onclick="selectPanel('marzban')">
          <div class="dc-icon">⚡</div>
          <div class="dc-name">Marzban</div>
        </div>
        <div class="deploy-card" data-panel="freedom" onclick="selectPanel('freedom')">
          <div class="dc-icon">🕊️</div>
          <div class="dc-name">Freedom</div>
        </div>
      </div>
    </div>

    <div id="ssh-form" class="hidden">
      <div class="form-row">
        <div class="form-group">
          <label data-i18n="ssh_host">SSH Host</label>
          <input id="ssh-host" placeholder="192.168.1.1"/>
        </div>
        <div class="form-group">
          <label data-i18n="ssh_port">SSH Port</label>
          <input id="ssh-port" value="22" placeholder="22"/>
        </div>
      </div>
      <div class="form-row">
        <div class="form-group">
          <label data-i18n="ssh_user">SSH User</label>
          <input id="ssh-user" value="root" placeholder="root"/>
        </div>
        <div class="form-group">
          <label data-i18n="ssh_key">SSH Key Path</label>
          <input id="ssh-key" placeholder="C:\Users\me\.ssh\id_rsa"/>
        </div>
      </div>
      <button class="btn" id="ssh-deploy-btn" onclick="deployPanel()"><span data-i18n="deploy">🚀 Deploy Panel</span></button>
      <div id="ssh-result" class="hidden" style="margin-top:12px">
        <div class="callout info"><span class="ic">ℹ️</span><div id="ssh-output" style="font-family:var(--font-mono);font-size:.8rem;white-space:pre-wrap"></div></div>
      </div>
    </div>
  </div>
</div>

<!-- ═══ PAC ═══ -->
<div id="tab-pac" class="tab-content">
  <div class="card">
    <div class="card-title"><span class="g" data-i18n="pac">⇥ PAC Mode</span></div>
    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:16px">
      <div>
        <div style="font-weight:700;font-size:1rem" data-i18n="pac_status">PAC Mode Status</div>
        <div style="color:var(--mu);font-size:.85rem"><span id="pac-status" data-i18n="disabled">Disabled</span></div>
      </div>
      <label class="toggle">
        <input type="checkbox" id="pac-toggle" onchange="togglePAC()"/>
        <span class="slider"></span>
      </label>
    </div>
  </div>

  <div class="card">
    <div class="card-title"><span class="g">PAC Settings</span></div>
    <div class="form-group">
      <label data-i18n="pac_mode">PAC Mode</label>
      <select id="pac-mode">
        <option value="gfwlist" data-i18n="gfwlist">GFW List</option>
        <option value="custom" data-i18n="custom">Custom Rules</option>
        <option value="auto" data-i18n="auto">Auto (Smart)</option>
      </select>
    </div>
    <div class="form-group hidden" id="pac-rules-group">
      <label data-i18n="custom_rules">Custom Rules (one domain per line)</label>
      <textarea id="pac-rules" rows="8" placeholder="google.com&#10;youtube.com&#10;twitter.com"></textarea>
    </div>
    <div class="form-group">
      <label data-i18n="proxy_addr">Proxy Address</label>
      <input id="pac-proxy-addr" value="127.0.0.1:8080"/>
    </div>
    <div class="btn-group">
      <button class="btn" onclick="generatePAC()" data-i18n="generate">⚡ Generate PAC</button>
      <button class="btn btn-ghost" onclick="downloadPAC()" data-i18n="download">⬇ Download .pac</button>
      <button class="btn btn-ghost" onclick="copyPACUrl()" data-i18n="copy_url">📋 Copy PAC URL</button>
    </div>
  </div>

</div>

<!-- ═══ TUNNEL ═══ -->
<div id="tab-tunnel" class="tab-content">
  <div class="card">
    <div class="card-title"><span class="g" data-i18n="tunnel">⬟ TUN/Tunnel Mode</span></div>
    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px">
      <div>
        <div style="font-weight:700;font-size:1rem" data-i18n="tunnel_status">Tunnel Status</div>
        <div style="color:var(--mu);font-size:.85rem"><span id="tun-status-text" data-i18n="disabled">Disabled</span></div>
      </div>
      <label class="toggle">
        <input type="checkbox" id="tun-toggle" onchange="toggleTUN()"/>
        <span class="slider"></span>
      </label>
    </div>
  </div>
  <div class="card">
    <div class="card-title"><span class="g" data-i18n="tunnel_config">Tunnel Configuration</span></div>
    <div class="form-row">
      <div class="form-group">
        <label data-i18n="device_name">Device Name</label>
        <input id="tun-device" value="nova-tun"/>
      </div>
      <div class="form-group">
        <label data-i18n="mtu">MTU</label>
        <input id="tun-mtu" value="1500" type="number"/>
      </div>
    </div>
    <div class="form-group">
      <label>DNS</label>
      <input id="tun-dns" value="1.1.1.1, 8.8.8.8"/>
    </div>
    <button class="btn" onclick="applyTUNConfig()" data-i18n="apply">✓ Apply</button>
  </div>
</div>

<!-- ═══ MITM ═══ -->
<div id="tab-mitm" class="tab-content">
  <div class="card">
    <div class="card-title"><span class="g" data-i18n="mitm_config">🔒 MITM Configuration</span></div>
    <p style="color:var(--mu);font-size:.9rem;margin-bottom:16px" data-i18n="mitm_desc">MITM (Man-in-the-Middle) proxy for inspecting and routing TLS traffic through your proxy chain.</p>
    <div class="form-row">
      <div class="form-group">
        <label data-i18n="mitm_ip">MITM IP</label>
        <input id="mitm-ip" value="127.0.0.1" placeholder="127.0.0.1"/>
      </div>
      <div class="form-group">
        <label data-i18n="mitm_port">MITM Port</label>
        <input id="mitm-port" value="8080" placeholder="8080"/>
      </div>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label data-i18n="sni_fake">SNI Spoof</label>
        <input id="mitm-sni" value="www.google.com" placeholder="www.google.com"/>
      </div>
      <div class="form-group">
        <label data-i18n="mitm_cert">CA Certificate</label>
        <select id="mitm-cert">
          <option value="auto">Auto-generate</option>
          <option value="custom">Custom CA</option>
        </select>
      </div>
    </div>
    <div class="btn-group">
      <button class="btn" onclick="applyMITMConfig()" data-i18n="apply">✓ Apply MITM</button>
      <button class="btn btn-ghost" onclick="generateMITMCert()" data-i18n="gen_cert">📜 Generate Cert</button>
    </div>
    <div id="mitm-result" class="hidden" style="margin-top:12px">
      <div class="callout info"><span class="ic">ℹ️</span><div id="mitm-output" style="font-family:var(--font-mono);font-size:.8rem;white-space:pre-wrap"></div></div>
    </div>
  </div>
  <div class="card">
    <div class="card-title"><span class="g" data-i18n="mitm_services">🌐 Blocked Services</span></div>
    <p style="color:var(--mu);font-size:.85rem;margin-bottom:10px" data-i18n="mitm_services_desc">Services accessible via MITM bypass:</p>
    <div id="mitm-services" style="display:flex;flex-wrap:wrap;gap:8px"></div>
  </div>
</div>

<!-- ═══ CONFIG ═══ -->
<div id="tab-config" class="tab-content">
  <div class="card">
    <div class="card-title"><span class="g" data-i18n="client">◈ Client Configuration</span></div>
    <p style="color:var(--mu);font-size:.9rem;margin-bottom:16px" data-i18n="client_desc">Generate merged configs for your client apps — Clash, Clash Meta, V2Ray, Sing-Box, NekoRay — all in one place.</p>
    <div class="form-row">
      <div class="form-group">
        <label data-i18n="config_format">Config Format</label>
        <select id="cfg-format">
          <option value="clash">Clash</option>
          <option value="clash-meta">Clash Meta</option>
          <option value="v2ray">V2Ray</option>
          <option value="sing-box">Sing-Box</option>
          <option value="nekoray">NekoRay</option>
        </select>
      </div>
      <div class="form-group">
        <label data-i18n="remark">Remark</label>
        <input id="cfg-remark" value="NovaProxy" placeholder="NovaProxy"/>
      </div>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label data-i18n="proxy_addr">Proxy Address</label>
        <input id="cfg-proxy-addr" value="127.0.0.1:8080" placeholder="127.0.0.1:8080"/>
      </div>
      <div class="form-group">
        <label data-i18n="socks_addr">SOCKS5 Address</label>
        <input id="cfg-socks-addr" value="127.0.0.1:1080" placeholder="127.0.0.1:1080"/>
      </div>
    </div>
    <button class="btn" onclick="generateClientConfig()"><span data-i18n="generate">⚡ Generate Config</span></button>
    <div id="cfg-result" class="hidden" style="margin-top:16px">
      <div class="form-group">
        <label data-i18n="config">Config</label>
        <textarea id="cfg-output" rows="12" style="font-size:.75rem" readonly></textarea>
      </div>
      <button class="btn btn-ghost btn-sm" onclick="copyConfig()" data-i18n="copy">📋 Copy</button>
      <a class="btn btn-ghost btn-sm" id="cfg-download" download data-i18n="download">⬇ Download</a>
    </div>
  </div>
  <div class="card">
    <div class="card-title"><span class="g" data-i18n="subscription">🔗 Subscription</span></div>
    <div class="form-group">
      <label data-i18n="subscription_url">Subscription URL</label>
      <input id="sub-url" placeholder="https://your-worker.workers.dev/sub/password"/>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label data-i18n="config_format">Format</label>
        <select id="sub-format">
          <option value="">Plain</option>
          <option value="clash">Clash</option>
          <option value="sing-box">Sing-Box</option>
        </select>
      </div>
    </div>
    <button class="btn btn-ghost btn-sm" onclick="openSubscription()"><span data-i18n="open">🔗 Open in Browser</span></button>
  </div>
</div>

<!-- ═══ DNS ═══ -->
<div id="tab-dns" class="tab-content">
  <div class="card">
    <div class="card-title"><span class="g" data-i18n="dns">🌐 DNS Configuration</span></div>
    <p style="color:var(--mu);font-size:.9rem;margin-bottom:16px" data-i18n="dns_desc">Configure DNS servers and routing for DNS-over-HTTPS, DNS-over-TLS, and smart DNS resolution.</p>
    <div class="form-row">
      <div class="form-group">
        <label data-i18n="dns_primary">Primary DNS</label>
        <input id="dns-primary" value="1.1.1.1" placeholder="1.1.1.1"/>
      </div>
      <div class="form-group">
        <label data-i18n="dns_secondary">Secondary DNS</label>
        <input id="dns-secondary" value="8.8.8.8" placeholder="8.8.8.8"/>
      </div>
    </div>
    <div class="form-group">
      <label data-i18n="dns_doh">DNS-over-HTTPS</label>
      <select id="dns-doh">
        <option value="cloudflare">Cloudflare (1.1.1.1)</option>
        <option value="google">Google (8.8.8.8)</option>
        <option value="quad9">Quad9</option>
        <option value="custom">Custom</option>
      </select>
    </div>
    <div class="form-group hidden" id="dns-doh-custom-group">
      <label data-i18n="doh_url">DoH URL</label>
      <input id="dns-doh-url" placeholder="https://dns.example.com/dns-query"/>
    </div>
    <button class="btn" onclick="applyDNSConfig()" data-i18n="apply">✓ Apply DNS</button>
  </div>
  <div class="card">
    <div class="card-title"><span class="g" data-i18n="dns_cache">📦 DNS Cache</span></div>
    <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">
      <div>
        <div style="color:var(--mu);font-size:.85rem" data-i18n="dns_cache_size">Cached entries: <span id="dns-cache-count">0</span></div>
      </div>
      <button class="btn btn-ghost btn-sm" onclick="clearDNSCache()" data-i18n="clear_cache">🗑 Clear Cache</button>
    </div>
  </div>
</div>

<!-- ═══ SETTINGS ═══ -->
<div id="tab-settings" class="tab-content">
  <div class="card">
    <div class="card-title"><span class="g" data-i18n="settings">⚙ Settings</span></div>
    <p style="color:var(--mu);font-size:.9rem;margin-bottom:12px" data-i18n="settings_desc">All settings organized by section.</p>
    <div id="settings-groups"></div>
  </div>
</div>

<!-- ═══ ABOUT ═══ -->
<div id="tab-about" class="tab-content">
  <div class="card" style="text-align:center;padding:30px">
    <div style="font-size:3rem;margin-bottom:10px"><span class="mk" style="display:inline-flex;width:50px;height:50px;border-radius:12px;background:var(--grad);align-items:center;justify-content:center;font-weight:900;color:#05060a;font-size:1.5rem">N</span></div>
    <h2 style="font-size:1.5rem;font-weight:800;margin-bottom:4px">NovaProxy</h2>
    <p style="color:var(--mu);font-size:.9rem" id="about-version">v1.0.0</p>
    <div style="margin-top:16px;color:var(--mu2);font-size:.85rem;max-width:400px;margin-left:auto;margin-right:auto" data-i18n="about_desc">
      Anti-censorship proxy toolbox. 10+ methods, unified engine, smart routing.
    </div>
    <div class="btn-group" style="justify-content:center;margin-top:16px">
      <a class="btn btn-ghost btn-sm" href="https://novaproxy.online" target="_blank" rel="noopener">🌐 <span data-i18n="website">Website</span></a>
      <a class="btn btn-ghost btn-sm" href="https://github.com/IRNova/Nova-Proxy-App" target="_blank" rel="noopener">🐙 GitHub</a>
    </div>
    <div style="margin-top:20px;padding-top:16px;border-top:1px solid var(--line);color:var(--mu2);font-size:.75rem">
      <span data-i18n="methods">10+ Proxy Methods</span> · <span data-i18n="languages">4 Languages</span> · <span>2 Themes</span>
    </div>
  </div>
</div>
</main>
</div>

<div class="foot">
  <span data-i18n="foot">NovaProxy · Anti-censorship · Open source</span>
</div>
</div>

<script>
/* ═══════════════════════════════════════════════════════════════════════
   I18N — 4 languages (en, fa, zh, ru)
   ═══════════════════════════════════════════════════════════════════════ */
const I18N = {
  en:{
    connection:'Connection',proxy_sidebar:'Proxy',tunnel:'Tunnel',mitm:'MITM',config_sidebar:'Config',dns:'DNS',
    dashboard:'Dashboard',client:'Client',wizard:'Wizard',panel:'Panel',pac:'PAC',tun:'TUN',
    settings:'Settings',about:'About',
    status:'Status',running:'Running',stopped:'Stopped',start:'Start',stop:'Stop',refresh:'Refresh',
    save:'Save',cancel:'Cancel',delete:'Delete',edit:'Edit',create:'Create',deploy:'Deploy',
    install:'Install',configure:'Configure',download:'Download',copy:'Copy',paste:'Paste',
    generating:'Generating...',connecting:'Connecting...',connected:'Connected',disconnected:'Disconnected',
    error:'Error',success:'Success',warning:'Warning',info:'Info',
    active:'Active',inactive:'Inactive',enabled:'Enabled',disabled:'Disabled',
    mode:'Mode',address:'Address',port:'Port',proxy_addr:'Proxy Address',socks_addr:'SOCKS5 Address',
    active_layer:'Active Layer',tunnel_status:'Tunnel Status',
    log:'Log',logs:'Logs',clear_logs:'Clear Logs',loading:'Loading...',
    auto:'Auto',direct:'Direct',rule:'Rule',gas:'GAS',v2ray:'V2Ray',
    bepass:'Bepass',paqet:'Paqet',sni_spoof:'SNI-Spoof',cf_panel:'CF Panel',
    mhr:'MHR',conduit:'Conduit',dns_tunnel:'DNS Tunnel',
    clash:'Clash',clash_meta:'Clash Meta',sing_box:'Sing-Box',nekoray:'NekoRay',
    config_format:'Config Format',subscription:'Subscription',
    token:'Token',account_id:'Account ID',worker_name:'Worker Name',
    panel_type:'Panel Type',ssh_host:'SSH Host',ssh_user:'SSH User',ssh_key:'SSH Key',ssh_port:'SSH Port',
    cf_api_token:'Cloudflare API Token',cf_account_id:'Cloudflare Account ID',
    language:'Language',theme:'Theme',dark:'Dark',light:'Light',
    english:'English',persian:'Persian',chinese:'Chinese',russian:'Russian',
    general:'General',network:'Network',security:'Security',advanced:'Advanced',
    version:'Version',website:'Website',languages:'Languages',methods:'Methods',
    client_desc:'Generate merged configs for your client apps — all in one place.',
    config:'Config',subscription_url:'Subscription URL',open:'Open in Browser',
    generate:'Generate',apply:'Apply',
    wizard_title:'Install <span class="grad">Nova</span> Worker',
    wizard_desc:'Paste one Cloudflare token and build your panel automatically.',
    wiz_step1:'Have a free Cloudflare account?',
    wiz_step1_desc:'If not, make one free (takes 1 min).',
    create_account:'Create a free account',
    wiz_step2:'Get your token',
    wiz_step2_desc:'Tap the button — a Cloudflare page opens, already filled in.',
    get_token:'🔑 Get my token',
    wiz_st1:'Scroll <b>all the way down</b> → tap <b>Continue to summary</b>.',
    wiz_st2:'Tap <b>Create Token</b>, then <b>Copy</b> the code.',
    wiz_warn:'<b>Copy the whole code</b> — it\'s shown only once.',
    wiz_step3:'Paste it here',wiz_step4:'Deploy your Nova',deploy_now:'🚀 Deploy Now',
    panel_deploy:'⬡ Panel Deployment',
    panel_desc:'Deploy proxy panels on your server via SSH.',
    pac_status:'PAC Mode Status',pac_mode:'PAC Mode',
    custom_rules:'Custom Rules (one per line)',gfwlist:'GFW List',custom:'Custom',
    copy_url:'Copy PAC URL',mode_switch:'Quick Mode Switch',
    tun_status:'TUN Status',tun_config:'TUN Configuration',
    device_name:'Device Name',mtu:'MTU',settings_desc:'All settings organized by section.',
    about_desc:'Anti-censorship proxy toolbox. 10+ methods, unified engine, smart routing.',
    foot:'NovaProxy · Anti-censorship · Open source',
    apply_config:'✓ Apply Config',deploying:'Deploying...',close:'Close',
    mitm_config:'MITM Configuration',mitm_desc:'MITM (Man-in-the-Middle) proxy for inspecting and routing TLS traffic through your proxy chain.',
    mitm_ip:'MITM IP',mitm_port:'MITM Port',sni_fake:'SNI Spoof',mitm_cert:'CA Certificate',
    gen_cert:'Generate Cert',mitm_services:'Blocked Services',mitm_services_desc:'Services accessible via MITM bypass:',
    tunnel:'Tunnel',tunnel_status:'Tunnel Status',tunnel_config:'Tunnel Configuration',
    dns_desc:'Configure DNS servers and routing for DNS-over-HTTPS, DNS-over-TLS, and smart DNS resolution.',
    dns_primary:'Primary DNS',dns_secondary:'Secondary DNS',dns_doh:'DNS-over-HTTPS',
    doh_url:'DoH URL',dns_cache:'DNS Cache',dns_cache_size:'Cached entries:',clear_cache:'Clear Cache',
  },
  fa:{
    connection:'اتصال',proxy_sidebar:'پروکسی',tunnel:'تانل',mitm:'میتم',config_sidebar:'کانفیگ',dns:'DNS',
    dashboard:'داشبورد',client:'کلاینت',wizard:'نصب‌کار',panel:'پنل',pac:'پک',tun:'تون',
    settings:'تنظیمات',about:'درباره',
    status:'وضعیت',running:'فعال',stopped:'متوقف',start:'شروع',stop:'توقف',refresh:'بروزرسانی',
    save:'ذخیره',cancel:'لغو',delete:'حذف',edit:'ویرایش',create:'ساخت',deploy:'استقرار',
    install:'نصب',configure:'تنظیم',download:'دانلود',copy:'کپی',paste:'چسباندن',
    generating:'در حال تولید...',connecting:'در حال اتصال...',connected:'متصل',disconnected:'قطع',
    error:'خطا',success:'موفق',warning:'هشدار',info:'اطلاعات',
    active:'فعال',inactive:'غیرفعال',enabled:'روشن',disabled:'خاموش',
    mode:'حالت',address:'آدرس',port:'پورت',proxy_addr:'آدرس پروکسی',socks_addr:'آدرس سوکس',
    active_layer:'لایه فعال',tunnel_status:'وضعیت تونل',
    log:'لاگ',logs:'لاگ‌ها',clear_logs:'پاک کردن لاگ',loading:'در حال بارگیری...',
    auto:'خودکار',direct:'مستقیم',rule:'قانونی',gas:'گاز',v2ray:'وی‌تری',
    bepass:'بای‌پس',paqet:'پاکت',sni_spoof:'اس‌ان‌آی',cf_panel:'پنل کلاودفلر',
    mhr:'ام‌اچ‌آر',conduit:'کاندویت',dns_tunnel:'تونل دی‌ان‌اس',
    clash:'کلش',clash_meta:'کلش متا',sing_box:'سینگ‌باکس',nekoray:'نکوری',
    config_format:'فرمت کانفیگ',subscription:'اشتراک',
    token:'توکن',account_id:'شناسه حساب',worker_name:'نام ورکر',
    panel_type:'نوع پنل',ssh_host:'هاست اس‌اس‌اچ',ssh_user:'کاربر اس‌اس‌اچ',
    ssh_key:'کلید اس‌اس‌اچ',ssh_port:'پورت اس‌اس‌اچ',
    cf_api_token:'توکن ای‌پی‌آی کلاودفلر',cf_account_id:'شناسه حساب کلاودفلر',
    language:'زبان',theme:'پوسته',dark:'تاریک',light:'روشن',
    english:'انگلیسی',persian:'فارسی',chinese:'چینی',russian:'روسی',
    general:'عمومی',network:'شبکه',security:'امنیت',advanced:'پیشرفته',
    version:'نسخه',website:'وبسایت',languages:'زبان‌ها',methods:'روش‌ها',
    client_desc:'کانفیگ‌های کلاینت را با هم در یکجا تولید کن.',
    config:'کانفیگ',subscription_url:'لینک اشتراک',open:'باز در مرورگر',
    generate:'تولید',apply:'اعمال',
    wizard_title:'نصب <span class="grad">نوا</span> ورکر',
    wizard_desc:'یک توکن کلاودفلر بچسبان تا پنل به صورت خودکار ساخته شود.',
    wiz_step1:'حساب رایگان کلاودفلر داری؟',
    wiz_step1_desc:'اگر نه، یکی بساز (۱ دقیقه).',
    create_account:'ساخت حساب رایگان',
    wiz_step2:'توکنت را بگیر',
    wiz_step2_desc:'دکمه را بزن — یک صفحه کلاودفلر باز می‌شود.',
    get_token:'🔑 گرفتن توکن',
    wiz_st1:'<b>تا ته پایین</b> برو → <b>Continue to summary</b> را بزن.',
    wiz_st2:'<b>Create Token</b> را بزن، بعد <b>Copy</b> کن.',
    wiz_warn:'<b>کل کد را کپی کن</b> — فقط یکبار نشان داده می‌شود.',
    wiz_step3:'اینجا بچسبان',wiz_step4:'نوایت را بساز',deploy_now:'🚀 ساختن نوا',
    panel_deploy:'⬡ استقرار پنل',
    panel_desc:'پنل‌های پروکسی را روی سرور با اس‌اس‌اچ نصب کن.',
    pac_status:'وضعیت پک',pac_mode:'حالت پک',
    custom_rules:'قوانین سفارشی (یک دامنه در هر خط)',gfwlist:'لیست جی‌اف‌دبلیو',custom:'سفارشی',
    copy_url:'کپی لینک پک',mode_switch:'تغییر سریع حالت',
    tun_status:'وضعیت تون',tun_config:'تنظیمات تون',
    device_name:'نام دستگاه',mtu:'ام‌تی‌یو',
    settings_desc:'همه تنظیمات دسته‌بندی شده.',
    about_desc:'جعبه ابزار ضدسانسور. ۱۰+ روش، موتور یکپارچه، مسیریابی هوشمند.',
    foot:'نواپروکسی · ضدسانسور · متن‌باز',
    apply_config:'✓ اعمال کانفیگ',deploying:'در حال استقرار...',close:'بستن',
    mitm_config:'تنظیمات میتم',mitm_desc:'پروکسی میتم برای بازرسی و مسیریابی ترافیک TLS از طریق زنجیره پروکسی شما.',
    mitm_ip:'آی‌پی میتم',mitm_port:'پورت میتم',sni_fake:'جعل SNI',mitm_cert:'گواهی CA',
    gen_cert:'ساخت گواهی',mitm_services:'سرویس‌های مسدود',mitm_services_desc:'سرویس‌های قابل دسترسی از طریق میتم:',
    tunnel:'تونل',tunnel_status:'وضعیت تونل',tunnel_config:'تنظیمات تونل',
    dns_desc:'تنظیم سرورهای DNS و مسیریابی برای DNS-over-HTTPS، DNS-over-TLS و تفکیک هوشمند DNS.',
    dns_primary:'DNS اصلی',dns_secondary:'DNS ثانویه',dns_doh:'DNS از طریق HTTPS',
    doh_url:'آدرس DoH',dns_cache:'حافظه DNS',dns_cache_size:'تعداد ورودی‌ها:',clear_cache:'پاک کردن حافظه',
  },
  zh:{
    connection:'连接',proxy_sidebar:'代理',tunnel:'隧道',mitm:'MITM',config_sidebar:'配置',dns:'DNS',
    dashboard:'仪表盘',client:'客户端',wizard:'向导',panel:'面板',pac:'PAC',tun:'TUN',
    settings:'设置',about:'关于',
    status:'状态',running:'运行中',stopped:'已停止',start:'开始',stop:'停止',refresh:'刷新',
    save:'保存',cancel:'取消',deploy:'部署',install:'安装',download:'下载',copy:'复制',paste:'粘贴',
    generating:'生成中...',connecting:'连接中...',connected:'已连接',disconnected:'已断开',
    error:'错误',success:'成功',warning:'警告',info:'信息',
    active:'活跃',inactive:'非活跃',enabled:'启用',disabled:'禁用',
    mode:'模式',address:'地址',port:'端口',proxy_addr:'代理地址',socks_addr:'SOCKS5地址',
    active_layer:'活跃层',tunnel_status:'隧道状态',
    log:'日志',logs:'日志',clear_logs:'清除日志',loading:'加载中...',
    auto:'自动',direct:'直连',rule:'规则',v2ray:'V2Ray',bepass:'Bepass',
    general:'通用',network:'网络',security:'安全',advanced:'高级',
    language:'语言',theme:'主题',dark:'深色',light:'浅色',
    english:'英语',persian:'波斯语',chinese:'中文',russian:'俄语',
    version:'版本',website:'网站',
    deploy_now:'🚀 立即部署',generate:'生成',apply:'应用',
    about_desc:'反审查代理工具箱。10+方法，统一引擎，智能路由。',
    foot:'NovaProxy · 反审查 · 开源',
    mitm_config:'MITM配置',mitm_desc:'MITM代理用于检查和路由TLS流量',
    mitm_ip:'MITM IP',mitm_port:'MITM端口',sni_fake:'SNI伪装',mitm_cert:'CA证书',
    gen_cert:'生成证书',mitm_services:'被屏蔽服务',mitm_services_desc:'可通过MITM访问的服务:',
    tunnel:'隧道',tunnel_status:'隧道状态',tunnel_config:'隧道配置',
    dns_desc:'配置DNS服务器和路由',
    dns_primary:'主DNS',dns_secondary:'次DNS',dns_doh:'DNS-over-HTTPS',
    doh_url:'DoH网址',dns_cache:'DNS缓存',dns_cache_size:'缓存条目:',clear_cache:'清除缓存',
  },
  ru:{
    connection:'Подключение',proxy_sidebar:'Прокси',tunnel:'Туннель',mitm:'MITM',config_sidebar:'Конфиг',dns:'DNS',
    dashboard:'Панель',client:'Клиент',wizard:'Мастер',panel:'Панель',pac:'PAC',tun:'TUN',
    settings:'Настройки',about:'О программе',
    status:'Статус',running:'Работает',stopped:'Остановлен',start:'Старт',stop:'Стоп',refresh:'Обновить',
    save:'Сохранить',cancel:'Отмена',deploy:'Развернуть',install:'Установить',download:'Скачать',copy:'Копировать',paste:'Вставить',
    generating:'Генерация...',connecting:'Подключение...',connected:'Подключено',disconnected:'Отключено',
    error:'Ошибка',success:'Успех',warning:'Внимание',info:'Информация',
    enabled:'Вкл',disabled:'Выкл',mode:'Режим',
    proxy_addr:'Адрес прокси',socks_addr:'SOCKS5 адрес',active_layer:'Активный слой',
    log:'Лог',logs:'Логи',loading:'Загрузка...',
    auto:'Авто',direct:'Прямо',rule:'Правило',
    general:'Общие',network:'Сеть',security:'Безопасность',advanced:'Расширенные',
    language:'Язык',theme:'Тема',dark:'Тёмная',light:'Светлая',
    english:'Английский',persian:'Персидский',chinese:'Китайский',russian:'Русский',
    version:'Версия',website:'Сайт',
    deploy_now:'🚀 Развернуть',generate:'Сгенерировать',apply:'Применить',
    about_desc:'Антицензурный прокси-инструментарий. 10+ методов, единый движок, умная маршрутизация.',
    foot:'NovaProxy · Антицензура · Открытый код',
    mitm_config:'Настройка MITM',mitm_desc:'MITM прокси для проверки и маршрутизации TLS трафика',
    mitm_ip:'MITM IP',mitm_port:'MITM порт',sni_fake:'SNI подмена',mitm_cert:'CA сертификат',
    gen_cert:'Создать сертификат',mitm_services:'Заблокированные сервисы',mitm_services_desc:'Сервисы доступные через MITM:',
    tunnel:'Туннель',tunnel_status:'Статус туннеля',tunnel_config:'Настройки туннеля',
    dns_desc:'Настройка DNS серверов и маршрутизации',
    dns_primary:'Основной DNS',dns_secondary:'Вторичный DNS',dns_doh:'DNS-over-HTTPS',
    doh_url:'URL DoH',dns_cache:'Кэш DNS',dns_cache_size:'Записей в кэше:',clear_cache:'Очистить кэш',
  }
};

let L = 'en';
function T(k) { return (I18N[L]||I18N.en)[k] || k; }

function applyI18N() {
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    const text = T(key);
    if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') {
      el.setAttribute('placeholder', text);
    } else {
      // preserve inner HTML for keys that contain HTML (like wizard_title)
      if (text.indexOf('<') >= 0) el.innerHTML = text;
      else el.textContent = text;
    }
  });
}

function setLang(l) {
  L = l;
  const fa = l === 'fa';
  document.documentElement.lang = l;
  document.documentElement.dir = fa ? 'rtl' : 'ltr';
  document.querySelectorAll('.langs button').forEach(b => b.classList.toggle('on', b.id === 'lang-'+l));
  applyI18N();
  // Update sidebar nav text
  document.querySelectorAll('.nav-item').forEach(item => {
    const span = item.querySelector('[data-i18n]');
    if (span) {
      const key = span.getAttribute('data-i18n');
      span.textContent = T(key);
    }
  });
  try { localStorage.setItem('nova-lang', l); } catch(e) {}
}

function toggleTheme() {
  const d = document.documentElement;
  const next = d.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
  d.setAttribute('data-theme', next);
  document.getElementById('themeBtn').textContent = next === 'light' ? '☀' : '☾';
  try { localStorage.setItem('nova-theme', next); } catch(e) {}
}

// Restore saved preferences
try {
  const th = localStorage.getItem('nova-theme');
  if (th) { document.documentElement.setAttribute('data-theme', th); document.getElementById('themeBtn').textContent = th === 'light' ? '☀' : '☾'; }
  const sv = localStorage.getItem('nova-lang');
  if (sv) setLang(sv);
  else if ((navigator.language||'').toLowerCase().startsWith('fa')) setLang('fa');
  else if ((navigator.language||'').toLowerCase().startsWith('zh')) setLang('zh');
  else if ((navigator.language||'').toLowerCase().startsWith('ru')) setLang('ru');
} catch(e) {}


/* ═══════════════════════════════════════════════════════════════════════
   SIDEBAR NAVIGATION
   ═══════════════════════════════════════════════════════════════════════ */
document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', () => {
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('on'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('on'));
    item.classList.add('on');
    document.getElementById('tab-'+item.dataset.tab).classList.add('on');
  });
});


/* ═══════════════════════════════════════════════════════════════════════
   API HELPERS
   ═══════════════════════════════════════════════════════════════════════ */
async function api(path, opts) {
  const r = await fetch(path, opts || {});
  return r.json();
}
async function apiText(path) {
  const r = await fetch(path);
  return r.text();
}


/* ═══════════════════════════════════════════════════════════════════════
   DASHBOARD
   ═══════════════════════════════════════════════════════════════════════ */
async function refreshDashboard() {
  try {
    const s = await api('/__nova/api/status');
    const hudStatus = document.getElementById('hud-status');
    const badge = document.querySelector('.badge');
    if (s.running) {
      hudStatus.innerHTML = '▶ ' + T('running');
      hudStatus.style.color = 'var(--ok)';
    } else {
      hudStatus.innerHTML = '⏹ ' + T('stopped');
      hudStatus.style.color = 'var(--mu)';
    }
    document.getElementById('hud-mode').textContent = s.mode || '--';
    document.getElementById('hud-addr').textContent = s.addr || '--';
  } catch(e) {}

  try {
    const l = await api('/__nova/api/layers');
    document.getElementById('hud-layer').textContent = l.active || '--';
    const layersEl = document.getElementById('layers');
    if (layersEl) {
      if (l.layers && l.layers.length) {
        layersEl.innerHTML = l.layers.map(x => {
          const isActive = x.layer === l.active;
          const cls = isActive ? 'status-active' : x.available ? 'status-up' : 'status-down';
          const label = isActive ? T('active') : x.available ? T('connected') : T('disconnected');
          return '<div class="layer"><span class="name">'+x.layer+'</span><span class="status '+cls+'">'+label+(x.latency>0 ? ' '+x.latency+'ms' : '')+'</span></div>';
        }).join('');
      } else {
        layersEl.innerHTML = '<span style="color:var(--mu);font-size:.85rem">No layers</span>';
      }
    }
  } catch(e) {}

  try {
    const t = await api('/__nova/api/tunnel');
    const el = document.getElementById('hud-tunnel');
    if (t.state === 'connected') { el.textContent = '▶'; el.style.color = 'var(--ok)'; }
    else if (t.state === 'connecting' || t.state === 'reconnecting') { el.textContent = '⟳'; el.style.color = 'var(--cyan)'; }
    else if (t.state === 'error') { el.textContent = '⚠'; el.style.color = 'var(--bad)'; }
    else { el.textContent = '⏹'; el.style.color = 'var(--mu)'; }
  } catch(e) {}

  // Logs
  try {
    const logs = await apiText('/__nova/api/logs?limit=50');
    document.getElementById('logs').textContent = logs || '(empty)';
  } catch(e) {}
}

async function startProxy() { await api('/__nova/api/start'); refreshDashboard(); }
async function stopProxy()  { await api('/__nova/api/stop');  refreshDashboard(); }
async function clearLogs()  { await api('/__nova/api/logs-clear'); refreshDashboard(); }

refreshDashboard();
setInterval(refreshDashboard, 4000);


/* ═══════════════════════════════════════════════════════════════════════
   CLIENT CONFIG GENERATOR
   ═══════════════════════════════════════════════════════════════════════ */
async function generateClientConfig() {
  const btn = document.querySelector('#tab-config .btn:not(.btn-ghost)');
  btn.disabled = true;
  btn.textContent = T('generating');
  try {
    const resp = await api('/__nova/api/client-config', {
      method: 'POST',
      body: JSON.stringify({
        format: document.getElementById('cfg-format').value,
        proxy_addr: document.getElementById('cfg-proxy-addr').value || '127.0.0.1:8080',
        socks_addr: document.getElementById('cfg-socks-addr').value || '127.0.0.1:1080',
        remark: document.getElementById('cfg-remark').value || 'NovaProxy',
      })
    });
    if (resp.error) { alert('Error: ' + resp.error); return; }
    document.getElementById('cfg-output').value = resp.content;
    document.getElementById('cfg-download').href = 'data:text/plain;charset=utf-8,' + encodeURIComponent(resp.content);
    document.getElementById('cfg-download').setAttribute('download', resp.filename || 'novaproxy-config.txt');
    document.getElementById('cfg-result').classList.remove('hidden');
  } catch(e) { alert('Error: ' + e.message); }
  btn.disabled = false;
  btn.textContent = T('generate');
}

function copyConfig() {
  const ta = document.getElementById('cfg-output');
  ta.select(); try { document.execCommand('copy'); } catch(e) { navigator.clipboard.writeText(ta.value); }
}

function openSubscription() {
  const url = document.getElementById('sub-url').value.trim();
  const fmt = document.getElementById('sub-format').value;
  if (!url) { return; }
  window.open(fmt ? url + '?format=' + fmt : url, '_blank');
}


/* ═══════════════════════════════════════════════════════════════════════
   WIZARD — CLOUDFLARE WORKER DEPLOY
   ═══════════════════════════════════════════════════════════════════════ */
async function pasteWizToken() {
  const inp = document.getElementById('wiz-token');
  try {
    if (navigator.clipboard && navigator.clipboard.readText) {
      const txt = await navigator.clipboard.readText();
      if (txt) { inp.value = txt.trim(); inp.focus(); return; }
    }
  } catch(e) {}
  inp.focus(); inp.select(); try { document.execCommand('paste'); } catch(e) {}
}

const WIZ_STEPS = ['verify','account','sub','db','kv','deploy'];
function renderWizProgress() {
  const el = document.getElementById('wiz-progress');
  const labels = {
    verify: T('connecting'), account: T('account_id'), sub: T('address'),
    db: 'Database', kv: 'Storage', deploy: T('deploy')
  };
  el.innerHTML = WIZ_STEPS.map(s =>
    '<div class="prow" id="pw-'+s+'"><span class="dot"></span><span>'+labels[s]+'</span></div>'
  ).join('');
}
function setWizStep(s, state) {
  const d = document.getElementById('pw-'+s); if (!d) return;
  d.className = 'prow ' + state;
  const dot = d.querySelector('.dot');
  if (state === 'done') dot.textContent = '✓';
  else if (state === 'err') dot.textContent = '!';
  else dot.textContent = '';
}

async function deployWizard() {
  const token = (document.getElementById('wiz-token').value || '').trim();
  if (!token) { document.getElementById('wiz-token').focus(); return; }
  document.getElementById('wiz-go').disabled = true;
  document.getElementById('wizard-form').classList.add('hidden');
  document.getElementById('wizard-progress').classList.remove('hidden');
  renderWizProgress();

  try {
    setWizStep('verify','run');
    const v = await api('/__nova/api/deploy/cf-worker', {
      method:'POST',
      body: JSON.stringify({token: token})
    });
    if (!v.success) {
      setWizStep('verify','err');
      document.getElementById('wiz-err').classList.remove('hidden');
      document.getElementById('wiz-err').textContent = v.message || 'Deploy failed';
      return;
    }
    setWizStep('verify','done');
    ['account','sub','db','kv'].forEach(s => setWizStep(s,'done'));
    setWizStep('deploy','run');
    setWizStep('deploy','done');

    // Show result
    const resultEl = document.getElementById('wiz-result');
    resultEl.classList.remove('hidden');
    resultEl.innerHTML = '<h3>🎉 ' + T('success') + '!</h3>' +
      '<div class="kv"><span class="k">URL</span><span class="v">' + (v.url || 'https://nova-worker.example.workers.dev') + '</span></div>' +
      '<p style="margin-top:12px;font-size:.85rem;color:var(--mu)">' + T('wizard_desc') + '</p>';
  } catch(e) {
    document.getElementById('wiz-err').classList.remove('hidden');
    document.getElementById('wiz-err').textContent = e.message;
  }
}


/* ═══════════════════════════════════════════════════════════════════════
   PANEL — SSH DEPLOY
   ═══════════════════════════════════════════════════════════════════════ */
let selectedPanel = '';

function selectPanel(type) {
  selectedPanel = type;
  document.querySelectorAll('.deploy-card').forEach(c => {
    c.style.borderColor = c.dataset.panel === type ? 'var(--cyan)' : 'var(--line)';
    c.style.background = c.dataset.panel === type ? 'var(--card-hover)' : '';
  });
  document.getElementById('ssh-form').classList.remove('hidden');
}

async function deployPanel() {
  const btn = document.getElementById('ssh-deploy-btn');
  btn.disabled = true; btn.textContent = T('deploying');
  try {
    const resp = await api('/__nova/api/deploy/ssh-panel', {
      method: 'POST',
      body: JSON.stringify({
        host: document.getElementById('ssh-host').value,
        user: document.getElementById('ssh-user').value,
        port: document.getElementById('ssh-port').value || '22',
        key_path: document.getElementById('ssh-key').value,
        panel_type: selectedPanel
      })
    });
    const result = document.getElementById('ssh-result');
    result.classList.remove('hidden');
    document.getElementById('ssh-output').textContent = resp.message || JSON.stringify(resp);
  } catch(e) {
    document.getElementById('ssh-result').classList.remove('hidden');
    document.getElementById('ssh-output').textContent = 'Error: ' + e.message;
  }
  btn.disabled = false; btn.textContent = T('deploy');
}


/* ═══════════════════════════════════════════════════════════════════════
   PAC
   ═══════════════════════════════════════════════════════════════════════ */
document.getElementById('pac-mode').addEventListener('change', function() {
  document.getElementById('pac-rules-group').classList.toggle('hidden', this.value !== 'custom');
});

async function togglePAC() {
  const enabled = document.getElementById('pac-toggle').checked;
  document.getElementById('pac-status').textContent = enabled ? T('enabled') : T('disabled');
  if (enabled) await switchMode('pac');
  else await switchMode('rule');
}

async function generatePAC() {
  const mode = document.getElementById('pac-mode').value;
  const rules = document.getElementById('pac-rules').value;
  const proxy = document.getElementById('pac-proxy-addr').value || '127.0.0.1:8080';
  let url = '/__nova/api/pac?mode=' + mode + '&proxy=' + encodeURIComponent(proxy);
  if (mode === 'custom' && rules) url += '&rules=' + encodeURIComponent(rules);
  const pac = await apiText(url);
  // Show in a new window
  const w = window.open('', '_blank');
  w.document.write('<pre>' + pac + '</pre>');
}

function downloadPAC() {
  const mode = document.getElementById('pac-mode').value;
  const rules = document.getElementById('pac-rules').value;
  const proxy = document.getElementById('pac-proxy-addr').value || '127.0.0.1:8080';
  let url = '/__nova/api/pac?mode=' + mode + '&proxy=' + encodeURIComponent(proxy);
  if (mode === 'custom' && rules) url += '&rules=' + encodeURIComponent(rules);
  window.open(url, '_blank');
}

function copyPACUrl() {
  const mode = document.getElementById('pac-mode').value;
  const proxy = document.getElementById('pac-proxy-addr').value || '127.0.0.1:8080';
  let url = window.location.origin + '/__nova/api/pac?mode=' + mode + '&proxy=' + encodeURIComponent(proxy);
  navigator.clipboard.writeText(url).catch(() => {});
}

async function switchMode(mode) {
  await api('/__nova/api/mode/switch', {
    method: 'POST',
    body: JSON.stringify({mode: mode})
  });
  refreshDashboard();
}


/* ═══════════════════════════════════════════════════════════════════════
   TUN
   ═══════════════════════════════════════════════════════════════════════ */
async function toggleTUN() {
  const enabled = document.getElementById('tun-toggle').checked;
  document.getElementById('tun-status-text').textContent = enabled ? T('enabled') : T('disabled');
  // TUN start/stop via API
  try {
    if (enabled) await api('/__nova/api/start-tun');
    else await api('/__nova/api/stop-tun');
  } catch(e) {}
}

function applyTUNConfig() {
  document.querySelector('#tab-tunnel .btn').textContent = T('apply_config');
}


/* ═══════════════════════════════════════════════════════════════════════
   SETTINGS
   ═══════════════════════════════════════════════════════════════════════ */
async function loadSettings() {
  try {
    const groups = await api('/__nova/api/settings/get');
    const container = document.getElementById('settings-groups');
    container.innerHTML = '';
    const sectionOrder = ['general','proxy','tunnel','client','pac','cloudflare','ssh','advanced'];
    const sectionLabels = {
      general: T('general'), proxy: T('network'), client: T('client'),
      tunnel: T('tunnel_status'), pac: 'PAC', cloudflare: 'Cloudflare',
      ssh: 'SSH', advanced: T('advanced')
    };
    sectionOrder.forEach(section => {
      if (!groups[section] || !groups[section].length) return;
      const div = document.createElement('div');
      div.className = 'section-group';
      div.innerHTML = '<h3>' + (sectionLabels[section] || section) + '</h3>';
      groups[section].forEach(setting => {
        const item = document.createElement('div');
        item.className = 'setting-item';
        let input = '';
        if (setting.type === 'bool') {
          input = '<label class="toggle"><input type="checkbox" ' + (setting.value === true ? 'checked' : '') +
            ' onchange="setSetting(\''+setting.key+'\',this.checked)"/><span class="slider"></span></label>';
        } else if (setting.type === 'select' && setting.options) {
          input = '<select onchange="setSetting(\''+setting.key+'\',this.value)">' +
            setting.options.map(o => '<option value="'+o+'"'+(setting.value===o||setting.value==='"'+o+'"'?' selected':'')+'>'+o+'</option>').join('') +
            '</select>';
        } else if (setting.type === 'password') {
          input = '<input type="password" value="' + (typeof setting.value === 'string' ? setting.value : '') +
            '" placeholder="••••••••" onchange="setSetting(\''+setting.key+'\',this.value)"/>';
        } else {
          input = '<input value="' + (typeof setting.value === 'string' ? setting.value.replace(/"/g,'') : '') +
            '" onchange="setSetting(\''+setting.key+'\',this.value)"/>';
        }
        item.innerHTML = '<div class="setting-label"><div class="name">' + (T(setting.label) || setting.label) + '</div>' +
          (setting.description ? '<div class="desc">' + setting.description + '</div>' : '') + '</div>' +
          '<div class="setting-input">' + input + '</div>';
        div.appendChild(item);
      });
      container.appendChild(div);
    });
  } catch(e) {}
}

async function setSetting(key, value) {
  const val = typeof value === 'boolean' ? value : value;
  await api('/__nova/api/settings/set', {
    method: 'POST',
    body: JSON.stringify({key: key, value: val})
  });
}

loadSettings();


/* ═══════════════════════════════════════════════════════════════════════
   MITM
   ═══════════════════════════════════════════════════════════════════════ */
async function applyMITMConfig() {
  const ip = document.getElementById('mitm-ip').value || '127.0.0.1';
  const port = document.getElementById('mitm-port').value || '8080';
  const sni = document.getElementById('mitm-sni').value || 'www.google.com';
  try {
    const r = await api('/__nova/api/mitm/config', {
      method: 'POST',
      body: JSON.stringify({ip, port, sni})
    });
    document.getElementById('mitm-result').classList.remove('hidden');
    document.getElementById('mitm-output').textContent = r.message || 'MITM configured';
  } catch(e) {
    document.getElementById('mitm-result').classList.remove('hidden');
    document.getElementById('mitm-output').textContent = 'Error: ' + e.message;
  }
}

async function generateMITMCert() {
  try {
    const r = await api('/__nova/api/mitm/cert', {method: 'POST'});
    document.getElementById('mitm-result').classList.remove('hidden');
    document.getElementById('mitm-output').textContent = r.message || r.cert || 'Certificate generated';
  } catch(e) {
    document.getElementById('mitm-result').classList.remove('hidden');
    document.getElementById('mitm-output').textContent = 'Error: ' + e.message;
  }
}

async function loadMITMServices() {
  try {
    const r = await api('/__nova/api/mitm/services');
    if (r.services && r.services.length) {
      document.getElementById('mitm-services').innerHTML = r.services.map(s =>
        '<span style="background:var(--card);border:1px solid var(--line);border-radius:999px;padding:4px 12px;font-size:.8rem">'+s+'</span>'
      ).join('');
    }
  } catch(e) {}
}
loadMITMServices();


/* ═══════════════════════════════════════════════════════════════════════
   DNS
   ═══════════════════════════════════════════════════════════════════════ */
document.getElementById('dns-doh').addEventListener('change', function() {
  document.getElementById('dns-doh-custom-group').classList.toggle('hidden', this.value !== 'custom');
});

async function applyDNSConfig() {
  const primary = document.getElementById('dns-primary').value || '1.1.1.1';
  const secondary = document.getElementById('dns-secondary').value || '8.8.8.8';
  const doh = document.getElementById('dns-doh').value;
  const dohUrl = document.getElementById('dns-doh-url').value || '';
  await api('/__nova/api/dns/config', {
    method: 'POST',
    body: JSON.stringify({primary, secondary, doh, doh_url: dohUrl})
  });
}

async function clearDNSCache() {
  await api('/__nova/api/dns/clear-cache', {method: 'POST'});
  document.getElementById('dns-cache-count').textContent = '0';
}


/* ═══════════════════════════════════════════════════════════════════════
   TUNNEL STATUS POLL
   ═══════════════════════════════════════════════════════════════════════ */
setInterval(async () => {
  try {
    const t = await api('/__nova/api/tunnel');
    const el = document.getElementById('hud-tunnel');
    if (t.state === 'connected') { el.textContent = '▶'; el.style.color = 'var(--ok)'; }
    else if (t.state === 'connecting' || t.state === 'reconnecting') { el.textContent = '⟳'; el.style.color = 'var(--cyan)'; }
    else if (t.state === 'error') { el.textContent = '⚠'; el.style.color = 'var(--bad)'; }
    else { el.textContent = '⏹'; el.style.color = 'var(--mu)'; }
  } catch(e) {}
}, 3000);
</script>
</body>
</html>`
