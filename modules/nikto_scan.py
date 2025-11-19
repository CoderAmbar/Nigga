import subprocess
from modules import IS_WINDOWS, IS_LINUX

def run_nikto(target):
    """
    Run Nikto web vulnerability scanner safely.
    Windows: returns a skip message.
    Linux/Kali: runs Nikto with safe tuning (1,2,3).
    """
    if IS_WINDOWS:
        return "<error>Nikto is not available on Windows. Run on Kali Linux for full scan.</error>"

    cmd = [
        "nikto",
        "-h", target,
        "-Tuning", "1 2 3",   # INFORMATION GATHERING ONLY — NO EXPLOITS
        "-nointeractive",
    ]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        out, err = proc.communicate()
        return out if out else err
    except Exception as e:
        return f"<error>{e}</error>"
