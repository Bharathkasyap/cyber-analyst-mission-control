# Cyber Analyst Mission Control

**Cyber Analyst Mission Control** is a centralized, browser-based toolkit for security analysts, SOC teams, and cybersecurity professionals.  
It brings together calculators, runbooks, cheat sheets, curated links, and threat intelligence lookups into one unified interface — saving time during investigations and incident response.

 **[Check here for Webpage]("https://github.com/Bharathkasyap/CCNA_Notes_Bharath/blob/main/CCNA_CLI_Commands.md")**   
 **[Check here for Webpage]("https://bharathkasyap.github.io/cyber-analyst-mission-control/)**


---

## Features

### 🛠 Tools & Calculators
- **Networking**: CIDR, wildcard mask, hex ↔ decimal, IP range calculations  
- **Crypto & Encoding**: Base64 encode/decode, hash generator, JWT decoder  
- **Risk & Governance**: ALE/SLE/ARO, CVSS scoring, RPO/RTO planners  
- **SIEM & Detection**: KQL & SPL cheat sheets, regex tester, lookup builders  
- **Triage & Artifacts**: Email header parser, URL analyzer, user-agent parser  

### 📂 Runbooks
- Step-by-step response guides for:
  - Ransomware
  - Unauthorized access
  - Phishing
  - Data exfiltration
  - Insider threats
  - Lost/stolen device
- Each runbook has **Quick Actions** and a **Full Checklist** view

### 🌐 Threat Intelligence Lookup
- Unified enrichment for IPs, domains, URLs, hashes, emails, and CVEs
- Works with:
  - **Keyless sources**: ThreatMiner, Shodan InternetDB, NVD API
  - **Optional keyed sources**: AlienVault OTX, AbuseIPDB, Pulsedive, GreyNoise, VirusTotal, urlscan.io

### 📚 Gold Links
- One-click access to essential cybersecurity references:
  - Microsoft Sentinel & KQL docs
  - MITRE ATT&CK
  - CISA KEV catalog
  - NVD CVE search
  - Splunk Search Reference
  - Palo Alto Networks tech docs

### 🧪 Samples Lab
- Downloadable sample logs for common threat hunting scenarios
- Ready-to-use KQL and SPL queries

---

## Getting Started

### 1. Open the Project
This is a **static HTML/CSS/JS project** — no installation required.  
Simply open `index.html` in a browser, or deploy via GitHub Pages.

### 2. API Keys (Optional)
Some threat intel sources require a free API key.  
To enable them:
1. Copy `config.sample.js` → `config.js`
2. Paste your keys in `config.js`
3. Set `DEMO_MODE` to `false`
4. Keep `config.js` **out of Git** (already in `.gitignore`)

Without keys, the app still works with keyless APIs and demo data.

---

## Deployment
To publish on **GitHub Pages**:
1. Go to **Settings → Pages**
2. Set **Source** to `main` branch, root folder
3. Save and wait for the deployment URL

---

## Security Notes
- All tools run **entirely in the browser**  
- API keys (if added in `config.js`) are visible to anyone using your deployed page — for production use, route through a serverless proxy  
- No sensitive data is stored; preferences are saved locally in the browser

---

## Roadmap
- [ ] CIDR calculator with IPv4/IPv6 support
- [ ] Org Planner: subnet planning + SIEM sizing
- [ ] More runbooks with industry mappings
- [ ] Offline-ready PWA version
- [ ] Serverless proxy for secure API key handling

---

## License
MIT License — free to use and adapt with attribution.
