import subprocess
import requests
from modules import IS_WINDOWS, IS_LINUX

def run_whatweb(target):
    """Runs WhatWeb on Linux, fallback to Python detection on Windows."""

    if IS_WINDOWS:
        return python_fingerprint(target)

    # Linux/Kali: full WhatWeb scan
    try:
        cmd = ["whatweb", "--color=never", "--log-json=-", target]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
        return out.decode("utf-8", errors="ignore")
    except:
        return python_fingerprint(target)


def python_fingerprint(url):
    """Lightweight fingerprinting for Windows."""
    out = {
        "server": None,
        "x_powered_by": None,
        "tech_guesses": [],
    }

    try:
        r = requests.get(url, timeout=5)
        headers = r.headers

        out["server"] = headers.get("Server")
        out["x_powered_by"] = headers.get("X-Powered-By")

        # Guess framework / CMS via content
        body = r.text.lower()

        if "wp-content" in body or "wordpress" in body:
            out["tech_guesses"].append("WordPress")

        if "django" in body:
            out["tech_guesses"].append("Django")

        if "laravel" in body:
            out["tech_guesses"].append("Laravel")

        if "react" in body:
            out["tech_guesses"].append("React.js")

        if "vue" in body:
            out["tech_guesses"].append("Vue.js")

        if "next.js" in body:
            out["tech_guesses"].append("Next.js")

        return out

    except Exception as e:
        return {"error": str(e)}
