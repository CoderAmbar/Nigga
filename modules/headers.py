import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS is missing",
    "Content-Security-Policy": "CSP is missing",
    "X-Frame-Options": "Clickjacking protection missing",
    "X-Content-Type-Options": "MIME sniffing protection missing",
    "Referrer-Policy": "Referrer policy missing",
    "Permissions-Policy": "Feature control policy missing",
    "X-XSS-Protection": "Legacy XSS header missing"
}

def check_security_headers(url):
    """Check standard security headers."""
    try:
        r = requests.get(url, timeout=5)
        headers = r.headers
    except Exception as e:
        return {"error": str(e)}

    result = {
        "present": {},
        "missing": []
    }

    for h, msg in SECURITY_HEADERS.items():
        if h in headers:
            result["present"][h] = headers[h]
        else:
            result["missing"].append(msg)

    return result
