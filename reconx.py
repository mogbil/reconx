#!/usr/bin/env python3
"""
ReconX - Web Server Reconnaissance Tool
Client Edition (Async)
"""
import os
import sys
import time
import json
import asyncio
import argparse

if sys.platform == "win32":
    os.system("") 

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    import requests

BASE_URL = "https://reconx.wondtech.com"

class C:
    _force_color = sys.platform == "win32" and os.environ.get("FORCE_COLOR")

    @staticmethod
    def _get_color(code):
        if sys.platform == "win32" and not C._force_color:
            if hasattr(sys.stdout, "reconfigure"):
                try:
                    sys.stdout.reconfigure()
                except Exception:
                    pass
            if not hasattr(sys.stdout, "reconfigure") and "ANSICON" not in os.environ:
                return ""
        return f"\033[{code}m"

    RED    = _get_color("91")
    GREEN  = _get_color("92")
    YELLOW = _get_color("93")
    BLUE   = _get_color("94")
    CYAN   = _get_color("96")
    BOLD   = _get_color("1")
    DIM    = _get_color("2")
    RESET  = _get_color("0")

def spinner(msg: str, stop: bool = False):
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    if stop:
        print(f"\r{C.DIM}{' '*60}{C.RESET}\r", end="")
        sys.stdout.flush()
    else:
        for f in frames:
            print(f"\r{C.CYAN}{f}{C.RESET} {msg} …", end="", flush=True)
            time.sleep(0.1)

def section(title: str):
    print(f"\n{C.CYAN}{C.BOLD}{'─'*54}")
    print(f"  {title}")
    print(f"{'─'*54}{C.RESET}")

def item(label: str, value: str, color: str = C.RESET):
    print(f"  {C.DIM}{label:<22}{C.RESET}{color}{value}{C.RESET}")

def display(data: dict):
    section("TARGET")
    item("URL",      data.get("target", "N/A"))
    item("Host",     data.get("host",   "N/A"))
    item("Duration", f"{data.get('duration_sec','?')}s")

    section("RISK ASSESSMENT")
    risk = data.get("risk", {})
    score = risk.get("score", 0)
    level = risk.get("level", "N/A")
    bar_len = score // 5
    bar = "█" * bar_len + "░" * (20 - bar_len)
    r_color = C.RED if level in ("CRITICAL","HIGH") else (C.YELLOW if level == "MEDIUM" else C.GREEN)
    print(f"\n  {r_color}{C.BOLD}Score: {score}/100  [{level}]{C.RESET}")
    print(f"  {r_color}[{bar}]{C.RESET}\n")
    for desc, delta, sev in risk.get("detail", []):
        sev_color = {"critical": C.RED, "high": C.RED, "medium": C.YELLOW, "good": C.GREEN, "info": C.CYAN}.get(sev, C.DIM)
        arrow = f"+{delta}" if delta > 0 else "  "
        print(f"  {sev_color}  {arrow:>4}  {desc}{C.RESET}")

    section("SSL / TLS")
    tls = data.get("tls", {})
    grade = tls.get("grade", "N/A")
    grade_color = C.GREEN if grade in ("A+","A") else (C.YELLOW if grade == "B" else C.RED)
    item("Grade", grade, grade_color)
    item("Issuer", tls.get("issuer", "N/A"))
    item("Subject", tls.get("subject", "N/A"))
    days = tls.get("days_left")
    if days is not None:
        color = C.GREEN if days > 60 else (C.YELLOW if days > 0 else C.RED)
        item("Days Until Exp.", str(days), color)
    if tls.get("self_signed"):
        print(f"  {C.YELLOW}  ⚠ Self-Signed Certificate{C.RESET}")
    if tls.get("expired"):
        print(f"  {C.RED}  ⚠ Certificate Expired!{C.RESET}")
    san = tls.get("san", [])
    if san:
        item("SANs", ", ".join(san[:5]))

    section("WAF / CDN")
    waf = data.get("waf", [])
    if waf:
        item("Protection", ", ".join(waf), C.GREEN)
        real_ip = data.get("real_ip", {})
        if real_ip and real_ip.get("found"):
            print(f"\n  {C.RED}{C.BOLD}! Real IP Found:{C.RESET}")
            item("Real IP", real_ip.get("real_ip", "Unknown"), C.RED)
            item("Method", real_ip.get("method", "Unknown"), C.YELLOW)
    else:
        print(f"  {C.RED}  ✘ No WAF/CDN Detected{C.RESET}")

    section("CONTROL PANEL")
    panel = data.get("panel", {})
    panel_type = panel.get("panel_type")
    if panel_type:
        panel_colors = {
            "cPanel": C.RED, "CWP": C.YELLOW, "Plesk": C.BLUE,
            "DirectAdmin": C.GREEN, "CyberPanel": C.RED, "Webmin": C.YELLOW,
            "ISPmanager": C.CYAN, "HestiaCP": C.GREEN, "Ajenti": C.BLUE,
        }
        color = panel_colors.get(panel_type, C.RED)
        item("Type", panel_type, color)
        for src, val in panel.get("signatures", {}).items():
            if str(src).startswith("port_"):
                item(f"  Port", str(src).replace("port_", ":") + " (open)", C.GREEN)
            else:
                item(f"  [{src}]", str(val))
        vulns = panel.get("vulnerabilities", [])
        if vulns:
            print(f"\n  {C.RED}{C.BOLD}Vulnerabilities:{C.RESET}")
            for v in vulns:
                sev_color = C.RED if v.get("severity") == "critical" else (C.YELLOW if v.get("severity") == "high" else C.DIM)
                print(f"  {sev_color}  ⚠ {v.get('cve')} [{v.get('severity')}]{C.RESET}")
    else:
        item("Type", "None detected", C.GREEN)

    section("DNS ZONE TRANSFER")
    dns_transfer = data.get("dns_transfer", {})
    if dns_transfer.get("vulnerable"):
        print(f"  {C.RED}{C.BOLD}  ⚠ ZONE TRANSFER IS OPEN!{C.RESET}")
        print(f"  {C.DIM}    Found {len(dns_transfer.get('records', []))} records{C.RESET}")
        for rec in dns_transfer.get("records", [])[:10]:
            print(f"  {C.YELLOW}  [{rec.get('type')}] {rec.get('name')} → {rec.get('target')}{C.RESET}")
    else:
        item("Status", "Secure (blocked)", C.GREEN)

    section("OPEN PORTS")
    for p in data.get("ports", []):
        risky = p["port"] in [21, 3306, 5432, 2086]
        color = C.RED if risky else C.GREEN
        print(f"  {color}  {p['name']:<22} :{p['port']}{C.RESET}")

    cms = data.get("cms", {})
    if cms and cms.get("cms"):
        section("CMS DETECTION")
        item("CMS", cms.get("cms", "Unknown"), C.CYAN)
        if cms.get("version"):
            item("Version", cms.get("version"), C.YELLOW)
        if cms.get("vulnerabilities"):
            print(f"\n  {C.RED}{C.BOLD}Vulnerabilities:{C.RESET}")
            for v in cms.get("vulnerabilities", []):
                sev_color = C.RED if v.get("severity") == "critical" else (C.YELLOW if v.get("severity") == "high" else C.DIM)
                print(f"  {sev_color}  ⚠ {v.get('cve')} [{v.get('severity')}]{C.RESET}")

    section("HTTP HEADERS")
    hdrs = data.get("headers", {})
    item("Server", hdrs.get("server", "Unknown"))
    if hdrs.get("powered_by"):
        item("Powered By", hdrs.get("powered_by"))
    print(f"\n  {C.BOLD}Security Headers:{C.RESET}")
    for h in hdrs.get("present", []):
        print(f"  {C.GREEN}  ✔ {h['label']:<18}{C.DIM} {h['header']}{C.RESET}")
    for h in hdrs.get("missing", []):
        sev_color = C.RED if h["severity"] == "critical" else (C.YELLOW if h["severity"] == "high" else C.DIM)
        print(f"  {sev_color}  ✘ {h['label']:<18} [{h['severity']}]{C.RESET}")

    section("DNS RECORDS")
    dns = data.get("dns", {})
    for rtype, vals in dns.get("records", {}).items():
        if vals:
            item(rtype, ", ".join(str(v) for v in vals[:3]))
    item("Mail Provider", dns.get("mail_provider") or "Unknown / Self-hosted")

    ct = data.get("cert_transparency", {})
    if ct.get("subdomains"):
        section("CERTIFICATE TRANSPARENCY")
        print(f"  {C.DIM}  {ct.get('count', 0)} subdomains found via crt.sh{C.RESET}")
        for sub in ct.get("subdomains", [])[:20]:
            print(f"  {C.CYAN}  • {sub}{C.RESET}")

    tech = data.get("technology", {})
    if tech and (tech.get("backend") or tech.get("frontend") or tech.get("framework")):
        section("TECHNOLOGY STACK")
        if tech.get("backend"):
            item("Backend", tech.get("backend", "N/A"), C.YELLOW)
        if tech.get("frontend"):
            item("Frontend", tech.get("frontend", "N/A"), C.CYAN)
        frameworks = tech.get("framework", [])
        if frameworks:
            print(f"\n  {C.DIM}Frameworks:{C.RESET}")
            for f in frameworks:
                print(f"  {C.CYAN}  • {f}{C.RESET}")
        languages = tech.get("languages", [])
        if languages:
            print(f"\n  {C.DIM}Languages:{C.RESET}")
            for l in languages:
                print(f"  {C.GREEN}  • {l}{C.RESET}")
        cdn_list = tech.get("cdn", [])
        if cdn_list:
            print(f"\n  {C.DIM}CDN:{C.RESET}")
            for c in cdn_list:
                print(f"  {C.GREEN}  ✔ {c}{C.RESET}")

    hosting = data.get("hosting", {})
    if hosting and hosting.get("ip"):
        section("HOSTING / GEOLOCATION")
        item("IP", hosting.get("ip", "N/A"), C.CYAN)
        if hosting.get("hostname"):
            item("Hostname", hosting.get("hostname", "N/A"))
        if hosting.get("country"):
            item("Country", hosting.get("country", "N/A"))
        if hosting.get("city"):
            item("City", hosting.get("city", "N/A"))
        if hosting.get("provider"):
            item("Provider", hosting.get("provider", "N/A"), C.YELLOW)
        if hosting.get("asn"):
            item("ASN", hosting.get("asn", "N/A"))

    perf = data.get("performance", {})
    if perf and perf.get("ttfb_ms"):
        section("PERFORMANCE")
        ttfb = perf.get("ttfb_ms", 0)
        ttfb_color = C.GREEN if ttfb < 200 else (C.YELLOW if ttfb < 500 else C.RED)
        item("TTFB", f"{ttfb:.2f} ms", ttfb_color)
        if perf.get("page_size_bytes"):
            item("Page Size", f"{perf.get('page_size_bytes', 0):,} bytes")
        if perf.get("redirects"):
            item("Redirects", str(perf.get("redirects", 0)))

    s3 = data.get("s3", {})
    if s3 and s3.get("buckets"):
        section("S3 BUCKETS")
        if s3.get("vulnerable"):
            print(f"  {C.RED}{C.BOLD}  ⚠ Accessible buckets found!{C.RESET}")
        for bucket in s3.get("buckets", []):
            status_color = C.RED if bucket.get("status") == "accessible" else C.YELLOW
            print(f"  {status_color}  {bucket.get('name', 'N/A')} [{bucket.get('status', 'unknown')}]{C.RESET}")

    openapi = data.get("openapi", {})
    if openapi and openapi.get("found"):
        section("API DOCUMENTATION")
        print(f"  {C.GREEN}  ✔ OpenAPI/Swagger detected{C.RESET}")
        for ep in openapi.get("endpoints", []):
            item("Endpoint", ep)

    endpoints = data.get("endpoints", [])
    if endpoints:
        section("ENDPOINT DISCOVERY")
        for e in endpoints:
            code_color = C.GREEN if e["status"] == 200 else (C.YELLOW if e["status"] in [301,302] else C.RED)
            flag = " !" if e.get("sensitive") else ""
            print(f"  {code_color}  [{e['status']}] {e['path']}{flag}{C.RESET}")

    print(f"\n{C.DIM}{'═'*56}{C.RESET}\n")

def parse_args():
    p = argparse.ArgumentParser(description="ReconX - Web Server Reconnaissance Tool", formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("target", nargs="?", help="Target URL (e.g., example.com)")
    p.add_argument("-j", "--json", action="store_true", help="Output raw JSON response")
    p.add_argument("-q", "--quiet", action="store_true", help="Suppress banner and progress")
    p.add_argument("-o", "--output", metavar="FILE", help="Save output to file")
    p.add_argument("--url", metavar="URL", help="Override base URL (default: https://reconx.wondtech.com)")
    p.add_argument("-r", "--retry", type=int, default=3, metavar="N", help="Number of retry attempts (default: 3)")
    p.add_argument("--sync", action="store_true", help="Force sync mode (no aiohttp)")
    return p.parse_args()

def run_sync(args):
    """Fallback synchronous mode using requests"""
    import requests
    requests.packages.urllib3.disable_warnings()
    _session = requests.Session()

    base_url = args.url or BASE_URL
    scan_url = base_url + "/scan.php"

    if not args.quiet:
        banner_url = base_url + "/banner.php"
        try:
            r = _session.get(banner_url, timeout=5)
            if r.status_code == 200:
                print(r.text)
        except Exception:
            print(f"{C.CYAN}{C.BOLD}ReconX{C.RESET}")
    else:
        print(f"{C.CYAN}{C.BOLD}ReconX{C.RESET}")

    target = args.target
    if not target:
        target = input(f"{C.CYAN}  Target (example.com): {C.RESET}").strip()

    if not target:
        print(f"  {C.RED}[!] No target provided.{C.RESET}")
        sys.exit(1)

    print(f"\n  {C.DIM}[ReconX] Sending request to server …{C.RESET}\n")
    print(f"[ReconX] Scanning {target}…")

    for attempt in range(1, args.retry + 1):
        try:
            r = _session.post(scan_url, json={"target": target}, timeout=60)
            break
        except requests.exceptions.ConnectionError:
            if attempt == args.retry:
                print(f"  {C.RED}[!] Connection failed after {args.retry} attempts.{C.RESET}")
                sys.exit(1)
            print(f"{C.YELLOW}[!] Connection failed (attempt {attempt}/{args.retry}), retrying…{C.RESET}")
            time.sleep(min(2 ** attempt, 8))

    if r.status_code == 403:
        data = r.json()
        print(f"\n{C.RED}{C.BOLD}  ╔══════════════════════════════════════════════════════╗")
        print(f"  ║              ⛔  ACCESS DENIED                       ║")
        print(f"  ╚══════════════════════════════════════════════════════╝{C.RESET}")
        print(f"  {C.RED}Reason : {data.get('reason','')}{C.RESET}")
        sys.exit(1)

    if r.status_code == 429:
        print(f"  {C.YELLOW}[!] Rate limit exceeded.{C.RESET}\n")
        sys.exit(1)

    if r.status_code != 200:
        print(f"  {C.RED}[!] Server error: HTTP {r.status_code}{C.RESET}\n")
        sys.exit(1)

    data = r.json()

    if args.json:
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        display(data)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"\n  {C.GREEN}[✓] Results saved to {args.output}{C.RESET}")

async def run_async(args):
    """Async mode with aiohttp - faster connection pooling"""
    import ssl
    base_url = args.url or BASE_URL
    scan_url = base_url + "/scan.php"

    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    connector = aiohttp.TCPConnector(limit=10, ttl_dns_cache=300, ssl=ssl_context)
    async with aiohttp.ClientSession(connector=connector) as session:
        if not args.quiet:
            try:
                async with session.get(base_url + "/banner.php", timeout=aiohttp.ClientTimeout(total=5)) as r:
                    if r.status == 200:
                        print(await r.text())
            except Exception:
                print(f"{C.CYAN}{C.BOLD}ReconX{C.RESET}")
        else:
            print(f"{C.CYAN}{C.BOLD}ReconX{C.RESET}")

        target = args.target
        if not target:
            target = input(f"{C.CYAN}  Target (example.com): {C.RESET}").strip()

        if not target:
            print(f"  {C.RED}[!] No target provided.{C.RESET}")
            sys.exit(1)

        print(f"\n  {C.DIM}[ReconX] Sending request to server …{C.RESET}\n")
        print(f"[ReconX] Scanning {target}…")

        for attempt in range(1, args.retry + 1):
            try:
                async with session.post(scan_url, json={"target": target}, timeout=aiohttp.ClientTimeout(total=60)) as r:
                    data = await r.json()
                    break
            except (aiohttp.ClientError, asyncio.TimeoutError, ConnectionError):
                if attempt == args.retry:
                    print(f"  {C.RED}[!] Connection failed after {args.retry} attempts.{C.RESET}")
                    sys.exit(1)
                print(f"{C.YELLOW}[!] Connection failed (attempt {attempt}/{args.retry}), retrying…{C.RESET}")
                await asyncio.sleep(min(2 ** attempt, 8))

        if r.status == 403:
            print(f"\n{C.RED}{C.BOLD}  ╔══════════════════════════════════════════════════════╗")
            print(f"  ║              ⛔  ACCESS DENIED                       ║")
            print(f"  ╚══════════════════════════════════════════════════════╝{C.RESET}")
            print(f"  {C.RED}Reason : {data.get('reason','')}{C.RESET}")
            sys.exit(1)

        if r.status == 429:
            print(f"  {C.YELLOW}[!] Rate limit exceeded.{C.RESET}\n")
            sys.exit(1)

        if r.status != 200:
            print(f"  {C.RED}[!] Server error: HTTP {r.status}{C.RESET}\n")
            sys.exit(1)

        if args.json:
            print(json.dumps(data, indent=2, ensure_ascii=False))
        else:
            display(data)

        if args.output:
            with open(args.output, "w") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            print(f"\n  {C.GREEN}[✓] Results saved to {args.output}{C.RESET}")

def main():
    args = parse_args()

    if args.sync or not AIOHTTP_AVAILABLE:
        if not args.sync and not AIOHTTP_AVAILABLE:
            print(f"{C.YELLOW}[!] aiohttp not installed, using sync mode. Install with: pip install aiohttp{C.RESET}")
        run_sync(args)
    else:
        try:
            asyncio.run(run_async(args))
        except KeyboardInterrupt:
            print(f"\n{C.YELLOW}[!] Interrupted{C.RESET}")
            sys.exit(1)

if __name__ == "__main__":
    main()
