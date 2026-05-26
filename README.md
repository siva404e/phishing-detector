# PhishGuard — URL Threat Intelligence Analyzer

A phishing detection and threat intelligence dashboard built with **Flask** and **Python**. Analyzes suspicious URLs using multi-layer detection: SSL/TLS validation, WHOIS domain age analysis, VirusTotal API integration, homograph spoofing detection, and risk-based scoring — all surfaced through an interactive web dashboard.

> **SOC Context:** Designed to replicate the URL triage workflow a SOC L1/L2 analyst performs during phishing incident response — enriching a suspicious link against multiple threat intelligence sources in seconds, reducing manual lookup time.

---

## Dashboard Preview

```
URL: http://paypa1-secure-login.tk/verify
┌─────────────────────────────────────────────┐
│  VERDICT: 🚨 CRITICAL  │  SCORE: 87 / 100  │
├─────────────────────────────────────────────┤
│  WHOIS     │ Domain 3 days old (+50)        │
│  SSL       │ Self-signed certificate (+20)  │
│  VirusTotal│ 12 engines flagged (+50)       │
│  Structure │ Suspicious TLD (.tk) (+20)     │
│            │ Homograph char detected (+30)  │
└─────────────────────────────────────────────┘
```

---

## Features

- **WHOIS Domain Age Analysis** — flags newly registered domains, a key phishing indicator
- **SSL/TLS Certificate Inspection** — validates issuer, expiry, and detects self-signed certificates
- **VirusTotal API Integration** — cross-references URLs against 70+ security engines
- **URL Structure Analysis** — detects IP-based URLs, suspicious TLDs (.tk, .ml, .xyz), excessive subdomains, and redirect tricks
- **Homograph / Unicode Spoofing Detection** — catches lookalike characters (е vs e, о vs o) used in domain impersonation
- **Keyword Analysis** — flags phishing-associated terms in the URL path
- **Risk Scoring Engine** — weighted scoring system producing SAFE / LOW / MODERATE / HIGH / CRITICAL verdicts
- **Scan History Dashboard** — tracks and displays last 50 scans with score bars and timestamps
- **CSV Export** — exports scan results for documentation and incident reporting

---

## MITRE ATT&CK Coverage

| Detection Technique         | MITRE ID   | Tactic              |
|-----------------------------|------------|---------------------|
| Suspicious URL analysis     | T1566.002  | Initial Access      |
| Homograph domain spoofing   | T1036.003  | Defense Evasion     |
| Newly registered domain     | T1583.001  | Resource Development|
| Invalid/self-signed SSL     | T1566.002  | Initial Access      |
| IP address in URL           | T1036      | Defense Evasion     |

---

## Tech Stack

| Component        | Technology                        |
|------------------|-----------------------------------|
| Backend          | Python 3.x, Flask                 |
| Threat Intel     | VirusTotal API v3                 |
| Domain Analysis  | python-whois                      |
| SSL Inspection   | Python ssl, socket (stdlib)       |
| Frontend         | HTML/CSS/JS (inline Flask template)|
| Config           | python-dotenv (.env)              |

---

## Setup & Installation

### 1. Clone the repository

```bash
git clone https://github.com/siva404e/phishing-detector.git
cd phishing-detector
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure API keys

```bash
cp .env.example .env
```

Edit `.env` and add your VirusTotal API key:

```
VIRUSTOTAL_API_KEY=your_api_key_here
```

Get a free API key at [virustotal.com](https://www.virustotal.com) — the free tier allows 4 requests/minute.

> **Note:** The tool runs without a VirusTotal key — that check will be skipped and all other analysis layers remain active.

### 4. Run the dashboard

```bash
python dashboard.py
```

Open your browser at **http://127.0.0.1:5000**

---

## Project Structure

```
phishing-detector/
├── dashboard.py        # Flask app — routes, analysis logic, HTML template
├── utils.py            # Helper classes: URLValidator, RiskScorer, DomainAnalyzer, PatternDetector
├── config.py           # Environment variable loading (API keys)
├── requirements.txt    # Python dependencies
├── .env.example        # Environment variable template
├── .gitignore          # Excludes .env and sensitive files
└── LICENSE
```

---

## How the Risk Scoring Works

Each detection layer contributes a weighted score. Scores are capped at 100.

| Score Range | Verdict      | Typical Indicators                              |
|-------------|--------------|--------------------------------------------------|
| 70 – 100    | 🚨 CRITICAL  | Brand new domain + flagged by VirusTotal + no SSL|
| 45 – 69     | ⚠️ HIGH      | Suspicious TLD + homograph + multiple keywords   |
| 25 – 44     | 🔍 MODERATE  | Young domain or expired cert                     |
| 10 – 24     | 🔎 LOW       | Minor URL anomalies                              |
| 0 – 9       | ✅ SAFE      | Passes all checks                                |

---

## Usage Examples

**Scan a known phishing pattern:**
```
Input:  http://paypa1-secure-login.tk/verify/account
Result: CRITICAL (score: 87) — suspicious TLD, homograph 'l→1', HTTP only, 3-day-old domain
```

**Scan a legitimate site:**
```
Input:  https://github.com
Result: SAFE (score: 2) — established domain, valid SSL, no threat indicators
```

---

## Limitations & Known Gaps

- VirusTotal free tier is rate-limited to 4 requests/minute; scans may take 15–30 seconds
- WHOIS data can be incomplete or unavailable for some TLDs
- Scan history resets on server restart (file-based persistence planned)
- Not a substitute for full sandbox analysis (e.g., ANY.RUN, Hybrid Analysis)

---

## Future Improvements

- [ ] Persistent scan history (JSON / SQLite)
- [ ] Bulk URL scanning from CSV input
- [ ] WHOIS registrant abuse contact lookup
- [ ] Integration with AbuseIPDB for IP reputation
- [ ] Dockerised deployment

---

## Author

**Sivamuthu Selvadurai M**  
Cybersecurity enthusiast focused on SOC operations, threat intelligence, and blue team tooling.

---

## License

MIT License — see [LICENSE](LICENSE) for details.
