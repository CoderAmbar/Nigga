import ssl
import socket
from datetime import datetime
import subprocess
from modules import IS_WINDOWS, IS_LINUX

def ssl_basic_check(host):
    """Perform a simple SSL cert check (cross-platform)."""
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM),
            server_hostname=host
        )
        conn.settimeout(5)
        conn.connect((host, 443))

        cert = conn.getpeercert()

        out = {
            "issuer": cert.get("issuer"),
            "subject": cert.get("subject"),
            "notBefore": cert.get("notBefore"),
            "notAfter": cert.get("notAfter"),
            "valid": None
        }

        # Check expiry
        exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        out["valid"] = exp > datetime.utcnow()

        return out
    except Exception as e:
        return {"error": str(e)}


def run_sslscan(host):
    """Full SSL check using sslscan (Kali only)."""
    if IS_WINDOWS:
        return {"error": "sslscan not available on Windows"}

    try:
        cmd = ["sslscan", "--no-colour", host]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
        return out.decode("utf-8", errors="ignore")
    except Exception as e:
        return {"error": str(e)}
