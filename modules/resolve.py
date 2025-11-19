import socket
import dns.resolver
import whois
from modules import IS_WINDOWS, IS_LINUX

def resolve_domain(domain):
    """Resolve A and AAAA records cross-platform."""
    ips = []
    try:
        answers = dns.resolver.resolve(domain, 'A')
        for r in answers:
            ips.append(r.to_text())
    except:
        pass

    try:
        answers = dns.resolver.resolve(domain, 'AAAA')
        for r in answers:
            ips.append(r.to_text())
    except:
        pass

    return list(set(ips))

def detect_cdn(domain):
    """
    Detect CDN using CNAME analysis.
    Works on both Windows and Linux.
    """
    try:
        answers = dns.resolver.resolve(domain, 'CNAME')
        for r in answers:
            cname = r.to_text().lower()
            cdn_keywords = ["cloudflare", "akamai", "cloudfront", "fastly", "cdn"]
            if any(k in cname for k in cdn_keywords):
                return True, cname
    except:
        pass
    return False, None

def whois_info(domain):
    """Windows + Linux supported (python-whois)."""
    try:
        w = whois.whois(domain)
        return {
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers,
        }
    except Exception as e:
        return {"error": str(e)}
