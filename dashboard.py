"""
╔══════════════════════════════════════════════════════════════╗
║       ANTI-PHISHING DASHBOARD — Flask Web App               ║
║       Built by: Sivamuthu Selvadurai M                      ║
╚══════════════════════════════════════════════════════════════╝

Run:
    pip install flask python-whois requests colorama
    python dashboard.py
Then open: http://127.0.0.1:5000
"""

from flask import Flask, render_template_string, request, jsonify
import re, ssl, socket, whois, requests as req
import datetime, urllib.parse, sys, io, time

app = Flask(__name__)

VIRUSTOTAL_API_KEY = ""

scan_history = []  # stores last 10 scans

SUSPICIOUS_KEYWORDS = [
    "login","verify","update","secure","account","banking","confirm",
    "password","signin","paypal","amazon","apple","microsoft","support",
    "urgent","suspend","click","free","winner","prize","alert","limited",
    "offer","ebay","netflix"
]
SUSPICIOUS_TLDS = [".tk",".ml",".ga",".cf",".gq",".xyz",".top",".click",".link"]
IP_IN_URL_PATTERN = re.compile(r"(https?://)?(\d{1,3}\.){3}\d{1,3}")
HOMOGRAPH_CHARS = {'а':'a','е':'e','о':'o','р':'p','с':'c','х':'x','у':'y','і':'i'}

# ── HTML TEMPLATE ─────────────────────────────────────────────
HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>PhishGuard — URL Threat Analyzer</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&family=Exo+2:wght@300;400;700;900&display=swap" rel="stylesheet"/>
<style>
  :root {
    --bg:        #030b14;
    --panel:     #071525;
    --border:    #0d2a45;
    --accent:    #00d4ff;
    --accent2:   #00ff9d;
    --danger:    #ff3c5a;
    --warn:      #ffaa00;
    --safe:      #00ff9d;
    --text:      #c8e6f5;
    --muted:     #4a7a9b;
    --font-mono: 'Share Tech Mono', monospace;
    --font-ui:   'Rajdhani', sans-serif;
    --font-hero: 'Exo 2', sans-serif;
  }

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--font-ui);
    min-height: 100vh;
    overflow-x: hidden;
  }

  /* animated grid background */
  body::before {
    content: '';
    position: fixed; inset: 0;
    background-image:
      linear-gradient(rgba(0,212,255,0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,212,255,0.03) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none;
    z-index: 0;
  }

  .wrap { position: relative; z-index: 1; max-width: 1100px; margin: 0 auto; padding: 0 24px 60px; }

  /* ── HEADER ── */
  header {
    padding: 36px 0 28px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 36px;
    display: flex;
    align-items: center;
    gap: 18px;
  }
  .logo-icon {
    width: 48px; height: 48px;
    background: linear-gradient(135deg, var(--accent), var(--accent2));
    border-radius: 12px;
    display: grid; place-items: center;
    font-size: 24px;
    box-shadow: 0 0 24px rgba(0,212,255,0.4);
    flex-shrink: 0;
  }
  header h1 {
    font-family: var(--font-hero);
    font-size: 2rem;
    font-weight: 900;
    letter-spacing: 2px;
    color: #fff;
  }
  header h1 span { color: var(--accent); }
  header p {
    font-size: 0.85rem;
    color: var(--muted);
    font-family: var(--font-mono);
    letter-spacing: 1px;
    margin-top: 2px;
  }
  .badge {
    margin-left: auto;
    background: rgba(0,212,255,0.08);
    border: 1px solid rgba(0,212,255,0.2);
    border-radius: 20px;
    padding: 6px 14px;
    font-size: 0.75rem;
    font-family: var(--font-mono);
    color: var(--accent);
    white-space: nowrap;
  }

  /* ── SCAN INPUT ── */
  .scan-box {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 28px 32px;
    margin-bottom: 28px;
    position: relative;
    overflow: hidden;
  }
  .scan-box::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, transparent, var(--accent), transparent);
  }
  .scan-box label {
    display: block;
    font-size: 0.75rem;
    font-family: var(--font-mono);
    color: var(--accent);
    letter-spacing: 2px;
    margin-bottom: 12px;
  }
  .input-row {
    display: flex;
    gap: 12px;
  }
  .url-input {
    flex: 1;
    background: rgba(0,212,255,0.04);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 14px 18px;
    color: #fff;
    font-family: var(--font-mono);
    font-size: 0.95rem;
    outline: none;
    transition: border-color 0.2s, box-shadow 0.2s;
  }
  .url-input:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px rgba(0,212,255,0.12);
  }
  .url-input::placeholder { color: var(--muted); }
  .scan-btn {
    background: linear-gradient(135deg, var(--accent), #0090cc);
    color: #000;
    border: none;
    border-radius: 10px;
    padding: 14px 32px;
    font-family: var(--font-hero);
    font-weight: 700;
    font-size: 1rem;
    letter-spacing: 1px;
    cursor: pointer;
    transition: transform 0.15s, box-shadow 0.15s;
    white-space: nowrap;
  }
  .scan-btn:hover { transform: translateY(-1px); box-shadow: 0 6px 20px rgba(0,212,255,0.35); }
  .scan-btn:active { transform: translateY(0); }
  .scan-btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }

  /* ── LOADING ── */
  #loading {
    display: none;
    text-align: center;
    padding: 20px;
    font-family: var(--font-mono);
    color: var(--accent);
    font-size: 0.9rem;
    letter-spacing: 2px;
    animation: pulse 1.2s ease-in-out infinite;
  }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }

  /* ── RESULTS GRID ── */
  #results { display: none; }
  .results-grid {
    display: grid;
    grid-template-columns: 300px 1fr;
    gap: 20px;
    margin-bottom: 20px;
  }

  /* ── VERDICT BANNER ── */
  .verdict-card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 28px 24px;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 16px;
    position: relative;
    overflow: hidden;
  }
  .verdict-card.critical { border-color: var(--danger); box-shadow: 0 0 30px rgba(255,60,90,0.15); }
  .verdict-card.high     { border-color: #ff6b35;       box-shadow: 0 0 30px rgba(255,107,53,0.15); }
  .verdict-card.moderate { border-color: var(--warn);   box-shadow: 0 0 30px rgba(255,170,0,0.15); }
  .verdict-card.low      { border-color: #88cc00;       box-shadow: 0 0 30px rgba(136,204,0,0.1); }
  .verdict-card.safe     { border-color: var(--safe);   box-shadow: 0 0 30px rgba(0,255,157,0.15); }

  .verdict-emoji { font-size: 3rem; line-height: 1; }
  .verdict-label {
    font-family: var(--font-hero);
    font-weight: 900;
    font-size: 1.1rem;
    letter-spacing: 2px;
    text-align: center;
  }
  .verdict-card.critical .verdict-label { color: var(--danger); }
  .verdict-card.high     .verdict-label { color: #ff6b35; }
  .verdict-card.moderate .verdict-label { color: var(--warn); }
  .verdict-card.low      .verdict-label { color: #88cc00; }
  .verdict-card.safe     .verdict-label { color: var(--safe); }

  /* ── GAUGE ── */
  .gauge-wrap { position: relative; width: 160px; height: 90px; }
  .gauge-wrap svg { width: 160px; height: 90px; }
  .gauge-score {
    position: absolute;
    bottom: 2px; left: 50%;
    transform: translateX(-50%);
    font-family: var(--font-hero);
    font-weight: 900;
    font-size: 1.8rem;
    color: #fff;
    text-align: center;
    white-space: nowrap;
  }
  .gauge-score span {
    font-size: 0.75rem;
    color: var(--muted);
    display: block;
    font-weight: 400;
    letter-spacing: 1px;
    font-family: var(--font-mono);
    margin-top: -4px;
  }

  /* ── CHECK PANELS ── */
  .checks-panel {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 24px;
  }
  .checks-panel h3 {
    font-family: var(--font-mono);
    font-size: 0.75rem;
    color: var(--accent);
    letter-spacing: 2px;
    margin-bottom: 16px;
    padding-bottom: 10px;
    border-bottom: 1px solid var(--border);
  }
  .check-group { margin-bottom: 16px; }
  .check-group-title {
    font-size: 0.8rem;
    font-family: var(--font-mono);
    color: var(--muted);
    letter-spacing: 1px;
    margin-bottom: 8px;
  }
  .check-item {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 8px 12px;
    border-radius: 8px;
    margin-bottom: 4px;
    font-size: 0.88rem;
    line-height: 1.4;
    font-family: var(--font-ui);
  }
  .check-item.ok     { background: rgba(0,255,157,0.05);  color: #a8f0d8; }
  .check-item.warn   { background: rgba(255,170,0,0.07);  color: #ffd580; }
  .check-item.danger { background: rgba(255,60,90,0.08);  color: #ff8fa0; }
  .check-icon { font-size: 0.9rem; flex-shrink: 0; margin-top: 1px; }

  /* ── DOMAIN META ── */
  .meta-row {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
    margin-bottom: 20px;
  }
  .meta-card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 16px;
  }
  .meta-card .meta-label {
    font-size: 0.7rem;
    font-family: var(--font-mono);
    color: var(--muted);
    letter-spacing: 1px;
    margin-bottom: 6px;
  }
  .meta-card .meta-value {
    font-size: 0.95rem;
    font-weight: 600;
    color: #fff;
    word-break: break-all;
  }

  /* ── HISTORY TABLE ── */
  .history-panel {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 24px;
  }
  .history-panel h3 {
    font-family: var(--font-mono);
    font-size: 0.75rem;
    color: var(--accent);
    letter-spacing: 2px;
    margin-bottom: 16px;
    padding-bottom: 10px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .history-count {
    background: rgba(0,212,255,0.1);
    border-radius: 10px;
    padding: 2px 10px;
    font-size: 0.7rem;
    color: var(--accent);
  }
  table { width: 100%; border-collapse: collapse; }
  thead th {
    text-align: left;
    font-size: 0.72rem;
    font-family: var(--font-mono);
    color: var(--muted);
    letter-spacing: 1px;
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
  }
  tbody tr {
    border-bottom: 1px solid rgba(13,42,69,0.5);
    transition: background 0.15s;
    cursor: pointer;
  }
  tbody tr:hover { background: rgba(0,212,255,0.04); }
  tbody td {
    padding: 11px 12px;
    font-size: 0.85rem;
    font-family: var(--font-mono);
    color: var(--text);
  }
  .pill {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 0.5px;
    font-family: var(--font-ui);
  }
  .pill.critical { background: rgba(255,60,90,0.15);  color: var(--danger); }
  .pill.high     { background: rgba(255,107,53,0.15); color: #ff6b35; }
  .pill.moderate { background: rgba(255,170,0,0.15);  color: var(--warn); }
  .pill.low      { background: rgba(136,204,0,0.15);  color: #88cc00; }
  .pill.safe     { background: rgba(0,255,157,0.12);  color: var(--safe); }

  .score-bar-bg {
    width: 80px; height: 6px;
    background: var(--border);
    border-radius: 3px;
    overflow: hidden;
    display: inline-block;
    vertical-align: middle;
    margin-right: 6px;
  }
  .score-bar-fill {
    height: 100%;
    border-radius: 3px;
    transition: width 0.4s ease;
  }

  .empty-history {
    text-align: center;
    padding: 30px;
    color: var(--muted);
    font-family: var(--font-mono);
    font-size: 0.8rem;
    letter-spacing: 1px;
  }

  /* ── SCAN LINE ANIM ── */
  @keyframes scanline {
    0%   { transform: translateY(-100%); opacity: 0; }
    10%  { opacity: 0.6; }
    90%  { opacity: 0.6; }
    100% { transform: translateY(2000%); opacity: 0; }
  }
</style>
</head>
<body>
<div class="wrap">

  <!-- HEADER -->
  <header>
    <div class="logo-icon">🛡️</div>
    <div>
      <h1>PHISH<span>GUARD</span></h1>
      <p>// URL THREAT INTELLIGENCE ANALYZER v2.0</p>
    </div>
    <div class="badge">🟢 SYSTEM ONLINE</div>
  </header>

  <!-- SCAN INPUT -->
  <div class="scan-box">
    <label>// TARGET URL — ENTER DOMAIN OR FULL URL FOR THREAT ANALYSIS</label>
    <div class="input-row">
      <input class="url-input" id="urlInput" type="text"
             placeholder="https://example.com  or  suspicious-site.xyz/login"
             autocomplete="off" spellcheck="false"/>
      <button class="scan-btn" id="scanBtn" onclick="runScan()">⚡ SCAN NOW</button>
    </div>
  </div>

  <!-- LOADING -->
  <div id="loading">⟳ &nbsp; RUNNING THREAT ANALYSIS... PLEASE WAIT</div>

  <!-- RESULTS -->
  <div id="results">

    <!-- META ROW -->
    <div class="meta-row" id="metaRow"></div>

    <!-- VERDICT + GAUGE | CHECKS -->
    <div class="results-grid">
      <div class="verdict-card" id="verdictCard">
        <div class="gauge-wrap">
          <svg viewBox="0 0 160 90">
            <!-- track -->
            <path d="M20,80 A60,60 0 0,1 140,80" fill="none" stroke="#0d2a45" stroke-width="12" stroke-linecap="round"/>
            <!-- fill -->
            <path id="gaugeFill" d="M20,80 A60,60 0 0,1 140,80" fill="none" stroke="#00d4ff" stroke-width="12"
                  stroke-linecap="round" stroke-dasharray="188.5" stroke-dashoffset="188.5"
                  style="transition: stroke-dashoffset 1s ease, stroke 0.5s ease;"/>
          </svg>
          <div class="gauge-score" id="gaugeScore">0<span>/ 100</span></div>
        </div>
        <div class="verdict-emoji" id="verdictEmoji">🔍</div>
        <div class="verdict-label" id="verdictLabel">ANALYZING...</div>
      </div>

      <div class="checks-panel">
        <h3>// DETAILED CHECK RESULTS</h3>
        <div id="checkResults"></div>
      </div>
    </div>

    <!-- HISTORY -->
    <div class="history-panel">
      <h3>
        // SCAN HISTORY
        <span class="history-count" id="historyCount">0 scans</span>
      </h3>
      <div id="historyTableWrap"></div>
    </div>

  </div><!-- /results -->
</div><!-- /wrap -->

<script>
  const urlInput = document.getElementById('urlInput');
  urlInput.addEventListener('keydown', e => { if(e.key === 'Enter') runScan(); });

  function runScan() {
    const url = urlInput.value.trim();
    if (!url) { urlInput.focus(); return; }

    document.getElementById('loading').style.display = 'block';
    document.getElementById('results').style.display = 'none';
    document.getElementById('scanBtn').disabled = true;

    fetch('/scan', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({url})
    })
    .then(r => r.json())
    .then(data => {
      document.getElementById('loading').style.display = 'none';
      document.getElementById('scanBtn').disabled = false;
      renderResults(data);
      renderHistory(data.history);
      document.getElementById('results').style.display = 'block';
    })
    .catch(() => {
      document.getElementById('loading').style.display = 'none';
      document.getElementById('scanBtn').disabled = false;
      alert('Scan failed. Is the Flask server running?');
    });
  }

  function renderResults(d) {
    // META ROW
    const metaRow = document.getElementById('metaRow');
    const scoreColor = getScoreColor(d.score);
    metaRow.innerHTML = `
      <div class="meta-card"><div class="meta-label">// DOMAIN</div><div class="meta-value">${d.domain}</div></div>
      <div class="meta-card"><div class="meta-label">// DOMAIN AGE</div><div class="meta-value">${d.domain_age || 'N/A'}</div></div>
      <div class="meta-card"><div class="meta-label">// SSL ISSUER</div><div class="meta-value">${d.ssl_issuer || 'N/A'}</div></div>
      <div class="meta-card"><div class="meta-label">// VT MALICIOUS</div><div class="meta-value" style="color:${d.vt_malicious > 0 ? 'var(--danger)' : 'var(--safe)'}">
        ${d.vt_malicious} engines</div></div>
    `;

    // GAUGE
    const score = Math.min(d.score, 100);
    const circumference = 188.5;
    const offset = circumference - (score / 100) * circumference;
    const fill = document.getElementById('gaugeFill');
    fill.style.strokeDashoffset = offset;
    fill.style.stroke = scoreColor;
    document.getElementById('gaugeScore').innerHTML = `${score}<span>/ 100</span>`;

    // VERDICT CARD
    const card = document.getElementById('verdictCard');
    const level = d.level.toLowerCase();
    card.className = `verdict-card ${level}`;
    const emojis = {critical:'🚨', high:'⚠️', moderate:'🔍', low:'🔎', safe:'✅'};
    const labels = {
      critical:'CRITICAL — PHISHING',
      high:'HIGH RISK',
      moderate:'MODERATE RISK',
      low:'LOW RISK',
      safe:'SAFE URL'
    };
    document.getElementById('verdictEmoji').textContent = emojis[level] || '🔍';
    document.getElementById('verdictLabel').textContent = labels[level] || d.level;

    // CHECKS
    const checksDiv = document.getElementById('checkResults');
    checksDiv.innerHTML = '';
    d.checks.forEach(group => {
      const g = document.createElement('div');
      g.className = 'check-group';
      g.innerHTML = `<div class="check-group-title">// ${group.title}</div>`;
      group.items.forEach(item => {
        const cls = item.type === 'ok' ? 'ok' : item.type === 'warn' ? 'warn' : 'danger';
        const icon = item.type === 'ok' ? '✅' : item.type === 'warn' ? '⚠️' : '🚨';
        g.innerHTML += `<div class="check-item ${cls}"><span class="check-icon">${icon}</span>${item.text}</div>`;
      });
      checksDiv.appendChild(g);
    });
  }

  function renderHistory(history) {
    const wrap = document.getElementById('historyTableWrap');
    document.getElementById('historyCount').textContent = `${history.length} scan${history.length !== 1 ? 's' : ''}`;
    if (!history.length) {
      wrap.innerHTML = '<div class="empty-history">NO SCAN HISTORY YET</div>';
      return;
    }
    let rows = history.slice().reverse().map(h => {
      const lvl = h.level.toLowerCase();
      const scoreColor = getScoreColor(h.score);
      const fillW = Math.min(h.score, 100);
      return `<tr>
        <td style="max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${h.url}</td>
        <td>${h.domain}</td>
        <td>
          <span class="score-bar-bg"><span class="score-bar-fill" style="width:${fillW}%;background:${scoreColor}"></span></span>
          <span style="color:${scoreColor};font-weight:700">${h.score}</span>
        </td>
        <td><span class="pill ${lvl}">${h.level}</span></td>
        <td style="color:var(--muted)">${h.time}</td>
      </tr>`;
    }).join('');
    wrap.innerHTML = `
      <table>
        <thead><tr>
          <th>URL</th><th>DOMAIN</th><th>SCORE</th><th>VERDICT</th><th>TIME</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
  }

  function getScoreColor(score) {
    if (score >= 70) return '#ff3c5a';
    if (score >= 45) return '#ff6b35';
    if (score >= 25) return '#ffaa00';
    if (score >= 10) return '#88cc00';
    return '#00ff9d';
  }
</script>
</body>
</html>
"""

# ── HELPER FUNCTIONS ───────────────────────────────────────────

def extract_domain(url):
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc or parsed.path
        return domain.replace("www.", "").split("/")[0]
    except:
        return None

def check_whois(domain):
    checks = []
    score  = 0
    domain_age = None
    try:
        old_stderr = sys.stderr
        sys.stderr  = io.StringIO()
        w = whois.whois(domain)
        sys.stderr = old_stderr

        creation = w.creation_date
        expiry   = w.expiration_date
        if isinstance(creation, list): creation = creation[0]
        if isinstance(expiry,   list): expiry   = expiry[0]

        if creation:
            if hasattr(creation,'tzinfo') and creation.tzinfo:
                creation = creation.replace(tzinfo=None)
            age_days   = (datetime.datetime.now() - creation).days
            age_months = age_days // 30
            domain_age = f"{age_months}mo ({age_days}d)"

            if age_days < 30:
                score += 50
                checks.append({"type":"danger","text":f"Domain only {age_days} days old — CRITICAL RISK (+50)"})
            elif age_days < 90:
                score += 35
                checks.append({"type":"danger","text":f"Domain {age_months} months old — HIGH RISK (+35)"})
            elif age_days < 180:
                score += 20
                checks.append({"type":"warn","text":f"Domain {age_months} months old — MODERATE RISK (+20)"})
            elif age_days < 365:
                score += 10
                checks.append({"type":"warn","text":f"Domain {age_months} months old — LOW RISK (+10)"})
            elif age_days < 730:
                score += 5
                checks.append({"type":"warn","text":f"Domain {age_months} months old — MINOR RISK (+5)"})
            else:
                checks.append({"type":"ok","text":f"Established domain — {age_months} months old"})
        else:
            score += 30
            checks.append({"type":"danger","text":"Creation date not found — SUSPICIOUS (+30)"})

        if expiry:
            checks.append({"type":"ok","text":f"Expires: {expiry.strftime('%Y-%m-%d')}"})
        if w.registrar:
            checks.append({"type":"ok","text":f"Registrar: {w.registrar}"})
    except Exception as e:
        score += 25
        checks.append({"type":"warn","text":f"WHOIS lookup failed ({str(e)[:40]}) (+25)"})
    return score, checks, domain_age

def check_ssl(domain):
    checks = []
    score  = 0
    issuer_name = None
    try:
        ctx  = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=domain)
        conn.settimeout(5)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        conn.close()

        issuer  = dict(x[0] for x in cert.get("issuer",  []))
        subject = dict(x[0] for x in cert.get("subject", []))
        not_after = cert.get("notAfter","")
        issuer_name = issuer.get("organizationName","Unknown")

        checks.append({"type":"ok","text":f"Issuer: {issuer_name}"})
        checks.append({"type":"ok","text":f"Subject: {subject.get('commonName','Unknown')}"})

        if not_after:
            expiry_dt = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry_dt - datetime.datetime.now()).days
            if days_left < 0:
                score += 40
                checks.append({"type":"danger","text":"Certificate EXPIRED — HIGH RISK (+40)"})
            elif days_left < 30:
                score += 15
                checks.append({"type":"warn","text":f"Expires in {days_left} days — MODERATE RISK (+15)"})
            else:
                checks.append({"type":"ok","text":f"Valid for {days_left} more days"})

        if issuer.get("organizationName","").lower() in ["","unknown"] or issuer == subject:
            score += 20
            checks.append({"type":"danger","text":"Possibly self-signed certificate (+20)"})
        else:
            checks.append({"type":"ok","text":"Issued by trusted certificate authority"})
    except ssl.SSLCertVerificationError:
        score += 40
        checks.append({"type":"danger","text":"SSL verification FAILED (+40)"})
    except ConnectionRefusedError:
        score += 30
        checks.append({"type":"danger","text":"No HTTPS on port 443 (+30)"})
    except Exception as e:
        score += 10
        checks.append({"type":"warn","text":f"SSL check error: {str(e)[:50]} (+10)"})
    return score, checks, issuer_name

def check_virustotal(url):
    checks = []
    score  = 0
    malicious = 0
    if VIRUSTOTAL_API_KEY == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        checks.append({"type":"warn","text":"VirusTotal API key not set — skipped"})
        return 0, checks, 0
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        resp = req.post("https://www.virustotal.com/api/v3/urls",
                        headers=headers, data={"url":url}, timeout=10)
        if resp.status_code == 200:
            analysis_id = resp.json()["data"]["id"]
            stats = {}
            for _ in range(6):
                r = req.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                            headers=headers, timeout=15)
                rj = r.json()
                if rj.get("data",{}).get("attributes",{}).get("status") == "completed":
                    stats = rj["data"]["attributes"].get("stats",{})
                    break
                time.sleep(5)
            malicious  = stats.get("malicious",  0)
            suspicious = stats.get("suspicious", 0)
            harmless   = stats.get("harmless",   0)
            undetected = stats.get("undetected", 0)
            checks.append({"type":"ok" if malicious==0 else "danger",
                           "text":f"Malicious: {malicious} | Suspicious: {suspicious} | Harmless: {harmless} | Undetected: {undetected}"})
            if malicious > 5:
                score += 50
                checks.append({"type":"danger","text":f"{malicious} engines flagged MALICIOUS (+50)"})
            elif malicious > 0 or suspicious > 3:
                score += 25
                checks.append({"type":"warn","text":"Some engines flagged suspicious (+25)"})
            else:
                checks.append({"type":"ok","text":"No threats detected by VirusTotal"})
    except Exception as e:
        checks.append({"type":"warn","text":f"VirusTotal error: {str(e)[:50]}"})
    return score, checks, malicious

def check_url_structure(url, domain):
    checks = []
    score  = 0
    url_lower = url.lower()

    if IP_IN_URL_PATTERN.match(url):
        score += 30; checks.append({"type":"danger","text":"IP address used instead of domain (+30)"})
    else:
        checks.append({"type":"ok","text":"Domain name used (not raw IP)"})

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 20; checks.append({"type":"danger","text":f"Suspicious TLD: {tld} (+20)"}); break
    else:
        checks.append({"type":"ok","text":"TLD appears normal"})

    if len(url) > 100:
        score += 10; checks.append({"type":"warn","text":f"URL very long ({len(url)} chars) (+10)"})
    else:
        checks.append({"type":"ok","text":f"URL length normal ({len(url)} chars)"})

    found_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    if found_kw:
        score += min(len(found_kw)*5, 25)
        checks.append({"type":"warn","text":f"Suspicious keywords: {', '.join(found_kw[:5])}"})
    else:
        checks.append({"type":"ok","text":"No suspicious keywords in URL"})

    if domain.count(".") > 3:
        score += 15; checks.append({"type":"danger","text":f"Excessive subdomains ({domain.count('.')}) (+15)"})
    else:
        checks.append({"type":"ok","text":f"Subdomain count normal ({domain.count('.')})"})

    for char in url:
        if char in HOMOGRAPH_CHARS:
            score += 30; checks.append({"type":"danger","text":"Homograph/Unicode spoofing detected (+30)"}); break
    else:
        checks.append({"type":"ok","text":"No homograph spoofing detected"})

    if "@" in url:
        score += 20; checks.append({"type":"danger","text":"'@' symbol in URL — phishing trick (+20)"})
    if url.count("//") > 1:
        score += 15; checks.append({"type":"warn","text":"Double '//' redirect trick (+15)"})
    if url.startswith("http://"):
        score += 15; checks.append({"type":"warn","text":"HTTP (not HTTPS) — insecure (+15)"})
    else:
        checks.append({"type":"ok","text":"URL uses HTTPS"})

    return score, checks

def get_verdict(score):
    if score >= 70: return "CRITICAL"
    if score >= 45: return "HIGH"
    if score >= 25: return "MODERATE"
    if score >= 10: return "LOW"
    return "SAFE"

# ── ROUTES ────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(HTML)

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    url  = data.get("url","").strip()
    if not url.startswith("http"):
        url = "https://" + url

    domain = extract_domain(url)
    if not domain:
        return jsonify({"error":"Invalid URL"}), 400

    total = 0
    all_checks = []

    s1, c1, domain_age = check_whois(domain)
    total += s1
    all_checks.append({"title":"WHOIS DOMAIN AGE", "items": c1})

    s2, c2, ssl_issuer = check_ssl(domain)
    total += s2
    all_checks.append({"title":"SSL / TLS CERTIFICATE", "items": c2})

    s3, c3, vt_malicious = check_virustotal(url)
    total += s3
    all_checks.append({"title":"VIRUSTOTAL REPUTATION", "items": c3})

    s4, c4 = check_url_structure(url, domain)
    total += s4
    all_checks.append({"title":"URL STRUCTURE ANALYSIS", "items": c4})

    level = get_verdict(total)
    now   = datetime.datetime.now().strftime("%H:%M:%S")

    entry = {
        "url": url, "domain": domain,
        "score": min(total, 100), "level": level,
        "time": now, "domain_age": domain_age,
        "ssl_issuer": ssl_issuer, "vt_malicious": vt_malicious
    }
    scan_history.append(entry)
    if len(scan_history) > 10:
        scan_history.pop(0)

    return jsonify({
        **entry,
        "checks": all_checks,
        "history": scan_history
    })

if __name__ == "__main__":
    print("\n🛡️  PhishGuard Dashboard starting...")
    print("   Open your browser at: http://127.0.0.1:5000\n")
    app.run(debug=True, port=5000)
