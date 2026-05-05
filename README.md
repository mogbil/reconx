# ReconX — Web Server Reconnaissance Tool

<p align="center">
  <img src="https://reconx.wondtech.com/reconx.png" alt="ReconX" width="400" />
</p>

**ReconX v1.0**

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0-cyan?style=for-the-badge" />
  <img src="https://img.shields.io/badge/python-3.8+-blue?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=for-the-badge" />
</p>

> **ReconX** is an advanced passive reconnaissance tool for web servers. It performs deep analysis across control panel detection, SSL/TLS, HTTP headers, DNS enumeration, WAF/CDN fingerprinting, port scanning, endpoint discovery, technology fingerprinting, and more — all in a single run.

---

## Features

| Module | Description |
|--------|-------------|
| **Control Panel Detection** | Detects cPanel, CWP, Plesk, DirectAdmin, CyberPanel, Webmin, HestiaCP, ISPmanager, Ajenti |
| **Vulnerability Check** | Known CVEs for each control panel |
| **CMS Detection** | Identifies WordPress, Joomla, Drupal, Magento, PrestaShop, OpenCart, WooCommerce |
| **SSL/TLS Analysis** | Protocol version, cipher strength, expiry, SAN, self-signed check, and A+ to F grading |
| **HTTP Headers Audit** | Security headers audit (HSTS, CSP, X-Frame-Options…), server fingerprinting |
| **WAF / CDN Detection** | Identifies Cloudflare, Sucuri, Akamai, Incapsula, Imunify360, and more |
| **Cloudflare Real IP** | Bypasses Cloudflare to discover origin server IP |
| **DNS & Subdomain Enum** | Resolves A, MX, NS records — enumerates common subdomains |
| **DNS Zone Transfer Check** | Detects if DNS zone transfer is vulnerable |
| **Certificate Transparency** | Discovers subdomains via crt.sh logs |
| **Port Scanning** | Scans 14 critical ports including FTP, SSH, MySQL, cPanel, and more |
| **Endpoint Discovery** | Probes sensitive paths like `/.env`, `/.git/HEAD`, `/phpinfo.php` |
| **Technology Fingerprint** | Identifies backend (Nginx, Apache, IIS), frontend (React, Vue, Angular), frameworks (Laravel, Django, Express), languages, and CDN |
| **Hosting / Geolocation** | IP location, country, city, hosting provider, and ASN |
| **Page Speed Metrics** | TTFB (Time To First Byte), page size, redirect count |
| **S3 Bucket Enumeration** | Detects exposed AWS S3 buckets |
| **OpenAPI / Swagger Detection** | Finds API documentation endpoints |
| **Risk Scoring** | Weighted 0–100 risk score with CRITICAL / HIGH / MEDIUM / LOW levels |

---

## Installation

```bash
cd client
pip install -r requirements.txt
```

### Requirements

**Python:** 3.8 or higher

```
requests>=2.28.0
aiohttp>=0.99.0 (optional, for async mode)
```

---

## Usage

```bash
# Interactive mode (prompts for target)
python reconx.py

# With target as argument
python reconx.py example.com

# JSON output (for scripting)
python reconx.py example.com -j

# Save to file
python reconx.py example.com -o results.json

# Quiet mode (for scripts/CI)
python reconx.py example.com -q

# Custom API endpoint
python reconx.py example.com --url https://custom-domain.com

# Retry on failure
python reconx.py example.com -r 5

# Force sync mode (no aiohttp)
python reconx.py example.com --sync
```

### Options

| Option | Description |
|--------|-------------|
| `-j, --json` | Output raw JSON response |
| `-q, --quiet` | Suppress banner and progress |
| `-o, --output FILE` | Save output to file |
| `--url URL` | Override base URL |
| `-r, --retry N` | Number of retry attempts (default: 3) |
| `--sync` | Force sync mode (no aiohttp) |

---

## Sample Output

```
──────────────────────────────────────────────────────
  TARGET
──────────────────────────────────────────────────────
  URL                   https://example.com
  Host                  example.com
  Duration              3.2s

──────────────────────────────────────────────────────
  RISK ASSESSMENT
──────────────────────────────────────────────────────

  Score: 55/100  [HIGH]
  [██████████░░░░░░░░░░░]

     +20  No WAF/CDN protection
       +5  AWS hosting - check for S3 buckets
       +5  cPanel detected
     +10  WordPress: CVE-2024-3144 [critical]

──────────────────────────────────────────────────────
  SSL / TLS
──────────────────────────────────────────────────────
  Grade                 A
  Issuer                Let's Encrypt
  Subject               example.com
  Days Until Exp.       45

──────────────────────────────────────────────────────
  WAF / CDN
──────────────────────────────────────────────────────
  ✘ No WAF/CDN Detected

──────────────────────────────────────────────────────
  CONTROL PANEL
──────────────────────────────────────────────────────
  Type                  cPanel
  [header_cpsrvd]       cpsrvd/11.122.2

  Vulnerabilities:
  ⚠ CVE-2022-44823 [high]
  ⚠ CVE-2022-44824 [high]

──────────────────────────────────────────────────────
  DNS ZONE TRANSFER
──────────────────────────────────────────────────────
  Status                Secure (blocked)

──────────────────────────────────────────────────────
  OPEN PORTS
──────────────────────────────────────────────────────
  HTTP      :80
  HTTPS     :443
  SSH       :22
  cPanel    :2082
  cPanel SSL:2083

──────────────────────────────────────────────────────
  CMS DETECTION
──────────────────────────────────────────────────────
  CMS                  WordPress
  Version              6.4.3

  Vulnerabilities:
  ⚠ CVE-2024-3144 [critical]

──────────────────────────────────────────────────────
  TECHNOLOGY STACK
──────────────────────────────────────────────────────
  Backend              Nginx
  Frontend              React

  Frameworks:
  • Laravel

  Languages:
  • PHP
  • JavaScript

  CDN:
  ✔ Cloudflare
  ✔ CloudFront

──────────────────────────────────────────────────────
  HOSTING / GEOLOCATION
──────────────────────────────────────────────────────
  IP                   192.168.1.1
  Country              US
  City                 Ashburn
  Provider             AWS
  ASN                  AS12345

──────────────────────────────────────────────────────
  PERFORMANCE
──────────────────────────────────────────────────────
  TTFB                 145.32 ms
  Page Size            45,231 bytes
  Redirects            0

════════════════════════════════════════════════════════════
```

---

## Supported Control Panels

| Panel | Ports | Vulnerabilities |
|-------|-------|----------------|
| cPanel | 2082, 2083, 2086, 2087, 2095, 2096 | CVE-2022-44823, CVE-2022-44824, CVE-2023-32487 |
| CWP | 2030, 2031, 2408 | CVE-2023-31327, CVE-2023-31328, CVE-2024-25817 |
| Plesk | 8443, 8447, 8880 | CVE-2022-42868, CVE-2023-28403, CVE-2024-23757 |
| DirectAdmin | 2222 | CVE-2023-2637, CVE-2023-2638 |
| CyberPanel | 8090, 8091 | CVE-2023-23498, CVE-2023-23499, CVE-2024-23169 |
| Webmin | 10000, 20000 | CVE-2022-43945, CVE-2023-25179, CVE-2024-36401 |
| ISPmanager | 1500, 1501 | CVE-2023-32788, CVE-2023-32789 |
| HestiaCP | 8083 | CVE-2024-25818 |
| Ajenti | 8000, 8002 | CVE-2022-26695, CVE-2023-26132 |

---

## Supported CMS

| CMS | Key Files | Vulnerabilities |
|-----|-----------|----------------|
| WordPress | /wp-login.php, /wp-admin/ | CVE-2024-3144, CVE-2024-3145 |
| Joomla | /administrator/, /configuration.php | CVE-2024-21780, CVE-2023-23752 |
| Drupal | /user/login, /sites/default/ | CVE-2024-1596, CVE-2023-28252 |
| Magento | /admin/, /downloader/ | CVE-2024-34102, CVE-2023-22247 |
| PrestaShop | /admin/, /modules/ | CVE-2023-39517, CVE-2022-0190 |
| OpenCart | /admin/, /catalog/view/ | CVE-2023-36325 |
| WooCommerce | /checkout/, /cart/ | CVE-2023-28154 |

---

## Technology Detection

| Category | Detected Technologies |
|----------|------------------------|
| **Backend** | Nginx, Apache, IIS, LiteSpeed, OpenResty, Node.js |
| **Frontend** | React, Vue.js, Angular, Next.js, Nuxt, Svelte, jQuery |
| **Frameworks** | Laravel, Django, Flask, FastAPI, Express, Symfony, CodeIgniter |
| **Languages** | PHP, Python, Node.js, Ruby, Java, ASP.NET |
| **CDN** | Cloudflare, Akamai, Fastly, CloudFront, Azure CDN, Google Cloud CDN |

---

## Legal Disclaimer

> ! **WARNING:** ReconX must only be used on systems you own, manage, or have explicit written authorization to test.

> **ReconX** is designed for **authorized security auditing and reconnaissance only**.
> Do not use this tool against systems you do not own or have explicit written permission to test.
> The author is not responsible for any misuse or damage caused by this tool.
> Always comply with applicable laws and regulations.

### ! International Legal Considerations

**Country-Specific Restrictions:**

| Country | Key Law | Notes |
|---------|---------|-------|
| USA | CFAA (Computer Fraud and Abuse Act) | Unauthorized scanning is a federal crime |
| EU | NIS2 Directive | Reconnaissance tools may be restricted |
| Saudi Arabia | Anti-Cybercrime Law | Requires official authorization |
| UAE | Federal Law No. 5/2012 | Similar restrictions apply |
| UK | Computer Misuse Act 1990 | Unauthorized access is prohibited |

### What is Allowed
- Scanning servers you **own or manage**
- **Authorized penetration testing** with written consent
- Academic research on networks you have legal access to

### What is Prohibited
- Scanning servers **without authorization**
- Scanning **government domains** (.gov, gov.x, .mil, .edu.x, etc.) — strictly prohibited
- Attempting to bypass security measures (WAF/CDN bypass)
- Using scan results for **malicious purposes**

---

## License

MIT License

---

## Author

Mogbil Sourketti | info@wondtech.com
