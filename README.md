# 🌐 WebScan — Modular Web Vulnerability Scanner

WebScan is a **modular, cross-platform web reconnaissance and vulnerability scanning tool** written in **Python**.  
It performs **passive and safe active analysis** on a target website and generates **professional HTML + JSON reports**.

The project focuses on **OSINT-based detection**, **real-world security tooling concepts**, and **clean modular architecture**, making it suitable for **academic evaluation, learning cybersecurity fundamentals, and portfolio use**.

---

## ✨ Key Features

### 🔍 Reconnaissance
- DNS resolution (A / AAAA records)
- WHOIS lookup
- ASN lookup using **ipwhois**
  - ISP / Organization
  - ASN number
  - Registry
  - Country
- CDN detection (Cloudflare, Akamai, Fastly, etc.)

### 🧠 Technology & CMS Detection
- Web server fingerprinting
- Backend technology detection
- CMS detection:
  - WordPress
  - Joomla
  - Drupal

### 🛡️ Security Analysis
- HTTP security header analysis
- SSL/TLS certificate inspection
- Passive WAF detection (header, cookie & body-based)
- Safe directory enumeration
- Optional async deep directory scanning

### 🐞 Vulnerability Detection
- Server & application CVE lookup (NVD-based)
- CMS-specific CVE detection (even without server version)
- Risk scoring engine (LOW / MEDIUM / HIGH)

### 📸 Visual Intelligence
- Website screenshot capture (Playwright-based)
- Screenshot embedded in HTML report via dropdown

### 📊 Reporting
- Automatically generated:
  - **HTML report** (interactive, collapsible sections)
  - **JSON report** (machine-readable)
- Clean, professional UI suitable for reports & submissions

---

## 🧩 Project Architecture

webscanner/
├── webscan.py # Main scan pipeline
├── modules/
│ ├── resolve.py # DNS, WHOIS, CDN detection
│ ├── asn_lookup.py # ASN lookup (ipwhois)
│ ├── tech_detect.py # Technology fingerprinting
│ ├── cms_detect.py # CMS detection
│ ├── cms_cve.py # CMS-based CVE lookup
│ ├── cve_lookup.py # NVD CVE search
│ ├── headers.py # Security header checks
│ ├── ssl_checker.py # SSL/TLS inspection
│ ├── waf_detector.py # WAF fingerprinting
│ ├── subdomains.py # Subdomain enumeration
│ ├── portscan.py # Nmap integration (safe mode)
│ ├── nikto_scan.py # Nikto integration (safe mode)
│ ├── dirscan_async.py # Async directory scanner
│ ├── risk_engine.py # Risk scoring logic
│ ├── screenshot.py # Website screenshots
│ └── reporter.py # HTML & JSON report generator
│
├── reports/ # Generated scan reports
├── requirements.txt
└── README.md

yaml
Copy code

---

## 🛠️ Installation

### 1️⃣ Clone the repository
```bash
git clone https://github.com/yourusername/webscanner.git
cd webscanner
2️⃣ Install dependencies
bash
Copy code
pip install -r requirements.txt
⚠️ Optional tools:

Nmap and Nikto give full results on Linux/Kali

On Windows, they run in safe/limited mode

▶️ Usage
bash
Copy code
python webscan.py https://example.com
Example Output
text
Copy code
[+] Resolving domain
[+] Performing ASN lookup
[+] Running Nmap (safe mode)
[+] Detecting technologies
[+] Detecting CMS
[+] Running CVE scans
[+] Capturing screenshot
[+] Calculating risk score
[✓] Report generated
📄 Generated Reports
HTML Report
Interactive dropdown sections

Color-coded CVE severity

Screenshot preview

Clean professional layout

JSON Report
Complete structured scan data

Suitable for automation or further analysis

Reports are saved in:

bash
Copy code
/reports/
⚠️ Safety & Ethics
Designed for educational and defensive security use

Uses passive detection and safe requests

Avoids exploit attempts

Does not bypass authentication or WAFs

Scan only assets you own or have permission to test

📚 Learning Outcomes
This project demonstrates:

Real-world web security tooling design

OSINT-based vulnerability analysis

Modular Python architecture

Async scanning concepts

Professional report generation

Defensive security best practices

🚀 Future Enhancements
JavaScript framework CVEs (React / Angular / Vue)

Shodan / Censys / VirusTotal integration

Authenticated scanning

Web UI dashboard

Export to PDF

📜 License
MIT License — free to use, modify, and learn from.

👤 Author
Ambar
Cybersecurity | Python | Web Security

⭐ Star the repository if you found it useful.

markdown
Copy code

---

If you want next, I can:
- Rewrite this for **college project submission**
- Add **system design / workflow diagram**
- Write a **viva explanation script**
- Create a **resume bullet version**
- Make a **PDF report template**

Just say the word.
