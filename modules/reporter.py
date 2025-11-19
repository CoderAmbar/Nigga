import json
import os
from datetime import datetime
from jinja2 import Template

REPORT_DIR = "reports"

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>WebScan Report - {{ target }}</title>
    <style>
        body { font-family: Arial, sans-serif; padding: 20px; background: #f8f8f8; }
        h1 { background: #2c3e50; color: white; padding: 12px; }
        h2 { color: #2c3e50; border-bottom: 2px solid #2c3e50; padding-bottom: 5px; }
        pre { background: #fff; padding: 12px; border: 1px solid #ddd; overflow-x: auto; }
        .section { background: #fff; padding: 15px; margin-bottom: 25px; border-radius: 4px; border: 1px solid #ddd; }
        .kv { font-weight: bold; }
    </style>
</head>
<body>

<h1>WebScan Report</h1>
<p><b>Target:</b> {{ target }}</p>
<p><b>Generated:</b> {{ timestamp }}</p>

<!-- DNS -->
<div class="section">
    <h2>DNS Resolution</h2>
    <pre>{{ dns | tojson(indent=2) }}</pre>
</div>

<!-- PORT SCANS -->
<div class="section">
    <h2>Port Scanning</h2>
    <h3>Nmap Output</h3>
    <pre>{{ nmap.nmap }}</pre>
    <h3>Nikto Output</h3>
    <pre>{{ nmap.nikto }}</pre>
</div>

<!-- TECHNOLOGY -->
<div class="section">
    <h2>Technology Fingerprint</h2>
    <pre>{{ tech | tojson(indent=2) }}</pre>
</div>

<!-- SSL -->
<div class="section">
    <h2>SSL/TLS Information</h2>
    <pre>{{ ssl | tojson(indent=2) }}</pre>
</div>

<!-- SECURITY HEADERS -->
<div class="section">
    <h2>Security Headers</h2>
    <h3>Present Headers</h3>
    <pre>{{ headers.present | tojson(indent=2) }}</pre>

    <h3>Missing Headers</h3>
    <pre>{{ headers.missing | tojson(indent=2) }}</pre>
</div>

<!-- SUBDOMAINS -->
<div class="section">
    <h2>Subdomains</h2>
    <pre>{{ subs | tojson(indent=2) }}</pre>
</div>

<!-- CVEs -->
<div class="section">
    <h2>Known Vulnerabilities (CVE)</h2>
    <pre>{{ cves | tojson(indent=2) }}</pre>
</div>

</body>
</html>
"""


def save_report(target, dns, nmap_results, tech, ssl, headers, subs, cves):
    """
    Save JSON and HTML report files.
    nmap_results = { "nmap": "...", "nikto": "..." }
    """

    if not os.path.exists(REPORT_DIR):
        os.mkdir(REPORT_DIR)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    # ------------------
    # JSON REPORT
    # ------------------
    json_path = f"{REPORT_DIR}/{target}_{timestamp}.json"

    data = {
        "target": target,
        "timestamp": timestamp,
        "dns": dns,
        "port_scans": nmap_results,     # contains both nmap + nikto
        "tech": tech,
        "ssl": ssl,
        "headers": headers,
        "subdomains": subs,
        "cves": cves
    }

    with open(json_path, "w") as f:
        json.dump(data, f, indent=4)

    # ------------------
    # HTML REPORT
    # ------------------
    html_path = f"{REPORT_DIR}/{target}_{timestamp}.html"
    template = Template(HTML_TEMPLATE)

    html_output = template.render(
        target=target,
        timestamp=timestamp,
        dns=dns,
        nmap=nmap_results,
        tech=tech,
        ssl=ssl,
        headers=headers,
        subs=subs,
        cves=cves
    )

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_output)

    return {"json": json_path, "html": html_path}
