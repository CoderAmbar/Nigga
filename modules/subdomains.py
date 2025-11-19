import dns.resolver

def brute_subdomains(domain, wordlist_path="data/subdomains.txt"):
    """Simple and safe subdomain brute-forcing."""
    found = []

    try:
        with open(wordlist_path, "r") as f:
            words = [line.strip() for line in f if line.strip()]
    except:
        return {"error": "Subdomain wordlist missing"}

    for sub in words:
        subdomain = f"{sub}.{domain}"

        try:
            answers = dns.resolver.resolve(subdomain, "A")
            ips = [ans.address for ans in answers]
            found.append({"subdomain": subdomain, "ip": ips})
        except dns.resolver.NXDOMAIN:
            continue
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.LifetimeTimeout:
            continue
        except Exception:
            continue

    return found
