#!/usr/bin/env python3
"""
ReconX - Web Server Reconnaissance Tool
Client Edition
"""

import argparse
import json
import sys
import time

import requests

# ─────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────
BASE_URL = "https://reconx.wondtech.com"

requests.packages.urllib3.disable_warnings()

# ─────────────────────────────────────────────
#  COLOR OUTPUT
# ─────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def spinner(msg: str, stop: bool = False):
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    if stop:
        print(f"\r{C.DIM}{' '*60}{C.RESET}\r", end="")
    else:
        for f in frames:
            print(f"\r{C.CYAN}{f}{C.RESET} {msg} …", end="", flush=True)
            time.sleep(0.1)

def fetch_banner(base_url: str):
    banner_url = base_url + "/banner.php"
    try:
        r = requests.get(banner_url, timeout=10, verify=True)
        if r.status_code == 200:
            return r.text
    except Exception:
        pass
    return None

# ─────────────────────────────────────────────
#  DISPLAY HELPERS
# ─────────────────────────────────────────────
def section(title: str):
    print(f"\n{C.CYAN}{C.BOLD}{'─'*54}")
    print(f"  {title}")
    print(f"{'─'*54}{C.RESET}")

def item(label: str, value: str, color: str = C.RESET):
    print(f"  {C.DIM}{label:<22}{C.RESET}{color}{value}{C.RESET}")

# ─────────────────────────────────────────────
#  DISPLAY RESULTS
# ─────────────────────────────────────────────
def display(data: dict):

    section("TARGET")
    item("URL",      data.get("target", "N/A"))
    item("Host",     data.get("host",   "N/A"))
    item("Scan ID",  data.get("scan_id","N/A"))
    item("Duration", f"{data.get('duration_sec','?')}s")

    # ── Panel ──
    section("CONTROL PANEL")
    panel = data.get("panel", {})
    panel_type = panel.get("panel_type")

    if panel_type:
        # Different colors for different panels
        panel_colors = {
            "cPanel": C.RED,
            "CWP": C.YELLOW,
            "Plesk": C.BLUE,
            "DirectAdmin": C.GREEN,
            "CyberPanel": C.RED,
            "Webmin": C.YELLOW,
            "ISPmanager": C.CYAN,
            "HestiaCP": C.GREEN,
            "Ajenti": C.BLUE,
        }
        color = panel_colors.get(panel_type, C.RED)
        item("Type",        panel_type, color)

        # Show signatures
        for src, val in panel.get("signatures", {}).items():
            if str(src).startswith("port_"):
                item(f"  Port", str(src).replace("port_", ":") + " (open)", C.GREEN)
            else:
                item(f"  [{src}]", str(val))

        # Vulnerabilities
        vulns = panel.get("vulnerabilities", [])
        if vulns:
            print(f"\n  {C.RED}{C.BOLD}Vulnerabilities:{C.RESET}")
            for v in vulns:
                sev_color = C.RED if v.get("severity") == "critical" else (C.YELLOW if v.get("severity") == "high" else C.DIM)
                print(f"  {sev_color}  ⚠ {v.get('cve')} [{v.get('severity')}]{C.RESET}")
    else:
        item("Type", "None detected", C.GREEN)

    # ── Protection Status ──
    section("PROTECTION STATUS")
    waf = data.get("waf", [])
    if waf:
        item("Protection", ", ".join(waf), C.GREEN)
    else:
        item("Protection", "NONE !", C.RED)

    # Cloudflare Real IP
    real_ip = data.get("real_ip", {})
    if real_ip and real_ip.get("found"):
        print(f"\n  {C.RED}{C.BOLD}! Real IP Found:{C.RESET}")
        item("Real IP", real_ip.get("real_ip", "Unknown"), C.RED)
        item("Method", real_ip.get("method", "Unknown"), C.YELLOW)
    else:
        item("IP Protection", "Not exposed", C.GREEN)

    # ── TLS ──
    section("SSL / TLS")
    tls = data.get("tls", {})
    grade = tls.get("grade", "N/A")
    grade_color = C.GREEN if grade in ("A+","A") else (C.YELLOW if grade == "B" else C.RED)
    item("Grade",        grade,                       grade_color)
    item("Issuer",       tls.get("issuer",  "N/A"))
    item("Subject",      tls.get("subject", "N/A"))
    days = tls.get("days_left")
    if days is not None:
        color = C.GREEN if days > 60 else (C.YELLOW if days > 0 else C.RED)
        item("Days Until Exp.", str(days), color)
    item("Self-Signed",  str(tls.get("self_signed", False)))
    san = tls.get("san", [])
    if san:
        item("SANs", ", ".join(san[:5]))

    # ── Headers ──
    section("HTTP HEADERS")
    hdrs = data.get("headers", {})
    item("Server",     hdrs.get("server",     "Unknown"))
    item("Powered By", hdrs.get("powered_by") or "Not disclosed")
    print(f"\n  {C.BOLD}Security Headers:{C.RESET}")
    for h in hdrs.get("present", []):
        print(f"  {C.GREEN}  ✔ {h['label']:<18}{C.DIM} {h['header']}{C.RESET}")
    for h in hdrs.get("missing", []):
        sev_color = C.RED if h["severity"] == "critical" else \
                   (C.YELLOW if h["severity"] == "high" else C.DIM)
        print(f"  {sev_color}  ✘ {h['label']:<18} [{h['severity']}]{C.RESET}")
    if hdrs.get("interesting"):
        print(f"\n  {C.YELLOW}Interesting Headers:{C.RESET}")
        for h, v in hdrs["interesting"].items():
            print(f"  {C.YELLOW}  → {h}: {v}{C.RESET}")

    # ── DNS ──
    section("DNS ANALYSIS")
    dns = data.get("dns", {})

    # Show main DNS records
    for rtype, vals in dns.get("records", {}).items():
        if vals:
            item(rtype, ", ".join(str(v) for v in vals[:3]))
    item("Mail Provider", dns.get("mail_provider") or "Unknown / Self-hosted")

    # Show subdomains
    dns_subs = dns.get("subdomains", [])
    ct_subs = data.get("cert_transparency", {}).get("subdomains", [])
    all_subs = list(dict.fromkeys(dns_subs + ct_subs))  # Remove duplicates

    if all_subs:
        print(f"\n  {C.BOLD}Discovered Subdomains ({len(all_subs)}):{C.RESET}")
        for s in all_subs[:30]:
            marker = "🔍" if s in ct_subs else "•"
            print(f"  {C.CYAN}  {marker} {s}{C.RESET}")
        if len(all_subs) > 30:
            print(f"  {C.DIM}  ... and {len(all_subs) - 30} more{C.RESET}")

    # ── Ports ──
    section("OPEN PORTS")
    for p in data.get("ports", []):
        risky = p["port"] in [21, 3306, 5432, 2086]
        color = C.RED if risky else C.GREEN
        print(f"  {color}  {p['name']:<22} :{p['port']}{C.RESET}")

    # ── Endpoints ──
    section("ENDPOINT DISCOVERY")
    for e in data.get("endpoints", []):
        code_color = C.GREEN if e["status"] == 200 else \
                    (C.YELLOW if e["status"] in [301,302] else C.RED)
        flag = " !" if e.get("sensitive") else ""
        print(f"  {code_color}  [{e['status']}] {e['path']}{flag}{C.RESET}")

    # ── CMS ──
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
                if v.get("desc"):
                    print(f"  {C.DIM}    {v.get('desc')}{C.RESET}")

    # ── DNS Zone Transfer ──
    dns_transfer = data.get("dns_transfer", {})
    if dns_transfer:
        section("DNS ZONE TRANSFER")
        if dns_transfer.get("vulnerable"):
            print(f"  {C.RED}  ! ZONE TRANSFER IS OPEN!{C.RESET}")
            print(f"  {C.DIM}    Found {len(dns_transfer.get('records', []))} records{C.RESET}")
            for rec in dns_transfer.get("records", [])[:10]:
                print(f"  {C.YELLOW}  [{rec.get('type')}] {rec.get('name')} → {rec.get('target')}{C.RESET}")
        else:
            item("Status", "Not vulnerable", C.GREEN)

    # ── Certificate Transparency ──
    ct = data.get("cert_transparency", {})
    if ct and ct.get("count", 0) > 0:
        item("SSL Issuer", ct.get("issuer", "Unknown"), C.DIM)

    # ── Risk ──
    section("RISK ASSESSMENT")
    risk = data.get("risk", {})
    score = risk.get("score", 0)
    level = risk.get("level", "N/A")
    bar_len = score // 5
    bar = "█" * bar_len + "░" * (20 - bar_len)
    r_color = C.RED if level in ("CRITICAL","HIGH") else \
             (C.YELLOW if level == "MEDIUM" else C.GREEN)
    print(f"\n  {r_color}{C.BOLD}Score: {score}/100  [{level}]{C.RESET}")
    print(f"  {r_color}[{bar}]{C.RESET}\n")
    for desc, delta, sev in risk.get("detail", []):
        sev_color = {"critical": C.RED, "high": C.RED, "medium": C.YELLOW,
                     "good": C.GREEN, "info": C.CYAN}.get(sev, C.DIM)
        arrow = f"+{delta}" if delta > 0 else "  "
        print(f"  {sev_color}  {arrow:>4}  {desc}{C.RESET}")

    print(f"\n{C.DIM}{'═'*56}{C.RESET}\n")

def parse_args():
    p = argparse.ArgumentParser(
        description="ReconX - Web Server Reconnaissance Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("target", nargs="?", help="Target URL (e.g., example.com)")
    p.add_argument("-j", "--json", action="store_true", help="Output raw JSON response")
    p.add_argument("-q", "--quiet", action="store_true", help="Suppress banner and progress")
    p.add_argument("-o", "--output", metavar="FILE", help="Save output to file")
    p.add_argument("--url", metavar="URL", help="Override base URL (default: https://reconx.wondtech.com)")
    p.add_argument("-r", "--retry", type=int, default=3, metavar="N",
                   help="Number of retry attempts (default: 3)")
    return p.parse_args()

def send_request(url: str, target: str, retries: int):
    for attempt in range(1, retries + 1):
        try:
            r = requests.post(
                url,
                json={"target": target},
                timeout=120,
                verify=True
            )
            return r
        except requests.exceptions.ConnectionError:
            if attempt == retries:
                raise
            print(f"{C.YELLOW}[!] Connection failed (attempt {attempt}/{retries}), retrying…{C.RESET}")
            time.sleep(2 ** attempt)

# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────
def run():
    args = parse_args()

    base_url = args.url or BASE_URL
    scan_url = base_url + "/scan.php"

    if not args.quiet:
        banner = fetch_banner(base_url)
        if banner:
            print(banner)
        else:
            print(f"{C.CYAN}{C.BOLD}ReconX{C.RESET}")

    target = args.target
    if not target:
        target = input(f"{C.CYAN}  Target (example.com): {C.RESET}").strip()

    if not target:
        print(f"  {C.RED}[!] No target provided.{C.RESET}")
        sys.exit(1)

    if not args.quiet:
        print(f"\n  {C.DIM}[ReconX] Sending request to server …{C.RESET}\n")

    if not sys.stdout.isatty() or args.quiet:
        print(f"[ReconX] Scanning {target}…")

    try:
        if not args.quiet:
            spinner("Scanning")
            r = send_request(scan_url, target, args.retry)
            spinner("", stop=True)
        else:
            r = send_request(scan_url, target, args.retry)

        if r.status_code == 403:
            data = r.json()
            print(f"\n{C.RED}{C.BOLD}")
            print(f"  ╔══════════════════════════════════════════════════════╗")
            print(f"  ║              ⛔  ACCESS DENIED                       ║")
            print(f"  ╚══════════════════════════════════════════════════════╝{C.RESET}")
            print(f"  {C.RED}Reason : {data.get('reason','')}{C.RESET}")
            print(f"  {C.DIM}{data.get('message','')}{C.RESET}\n")
            sys.exit(1)

        if r.status_code == 429:
            print(f"  {C.YELLOW}[!] Rate limit exceeded. Please wait and try again.{C.RESET}\n")
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

    except Exception as e:
        print(f"  {C.RED}[!] Error: {e}{C.RESET}\n")
        sys.exit(1)

if __name__ == "__main__":
    run()
