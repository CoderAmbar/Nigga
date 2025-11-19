import sys
import urllib.parse

from modules.nikto_scan import run_nikto
from modules.resolve import resolve_domain
from modules.portscan import run_nmap
from modules.tech_detect import run_whatweb
from modules.ssl_checker import ssl_basic_check, run_sslscan
from modules.headers import check_security_headers
from modules.subdomains import brute_subdomains
from modules.cve_lookup import search_cve
from modules.reporter import save_report


def normalize_target(url):
    """Ensure URL has https:// scheme."""
    if not url.startswith("http"):
        url = "https://" + url
    return url


def extract_domain(url):
    """Extract domain from a URL."""
    parsed = urllib.parse.urlparse(url)
    return parsed.netloc


def main():
    if len(sys.argv) < 2:
        print("Usage: python webscan.py <https://target.com>")
        sys.exit(1)

    url = normalize_target(sys.argv[1])
    domain = extract_domain(url)

    print(f"\n[+] Target: {url}")
    print(f"[+] Domain: {domain}")

    # -------------------------------------
    # 1. DNS Resolution
    # -------------------------------------
    print("\n[+] Resolving domain...")
    dns = resolve_domain(domain)
    print("    DNS:", dns)

    # -------------------------------------
    # 2. Nmap Scan (Windows will skip)
    # -------------------------------------
    print("\n[+] Running Nmap (safe mode)...")
    nmap_output = run_nmap(domain)
    print("    Done.")

    # -------------------------------------
    # 3. Nikto Scan (Windows will skip)
    # -------------------------------------
    print("\n[+] Running Nikto (safe mode)...")
    nikto_output = run_nikto(url)
    print("    Done.")

    # -------------------------------------
    # 4. Technology Detection (WhatWeb mode)
    # -------------------------------------
    print("\n[+] Detecting technologies...")
    tech = run_whatweb(url)
    print("    Done.")

    # -------------------------------------
    # 5. SSL Certificate Info
    # -------------------------------------
    print("\n[+] Checking SSL certificate...")
    ssl_info = ssl_basic_check(domain)
    print("    Done.")

    # -------------------------------------
    # 6. Security Headers
    # -------------------------------------
    print("\n[+] Checking security headers...")
    headers = check_security_headers(url)
    print("    Done.")

    # -------------------------------------
    # 7. Subdomain Enumeration
    # -------------------------------------
    print("\n[+] Enumerating subdomains (safe brute)...")
    subs = brute_subdomains(domain)
    print(f"    Found: {len(subs)} subdomains")
    print("    Done.")

    # -------------------------------------
    # 8. CVE Lookup (Based on tech fingerprint)
    # -------------------------------------
    print("\n[+] Running CVE lookup...")

    cves = []
    if isinstance(tech, dict):
        server = tech.get("server")  # e.g. "Apache/2.4.49"
        if server:
            parts = server.split("/")
            if len(parts) >= 2:
                cves = search_cve(parts[0], parts[1])
            else:
                cves = search_cve(parts[0])

    print(f"    CVEs Found: {len(cves)}")
    print("    Done.")

    # -------------------------------------
    # 9. Generate Reports
    # -------------------------------------
    print("\n[+] Generating final reports (HTML + JSON)...")

    paths = save_report(
        domain,
        dns,
        {
            "nmap": nmap_output,
            "nikto": nikto_output
        },
        tech,
        ssl_info,
        headers,
        subs,
        cves
    )

    print("\n[✓] Scan complete!")
    print(f"\nReport Files:")
    print(f" → JSON: {paths['json']}")
    print(f" → HTML: {paths['html']}\n")


if __name__ == "__main__":
    main()
