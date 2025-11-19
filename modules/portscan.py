import subprocess
import xmltodict
from modules import IS_WINDOWS, IS_LINUX

# Correct path (based on your system)
WINDOWS_NMAP_PATH = r"C:\Program Files (x86)\Nmap\nmap.exe"


def safe_run(cmd_list):
    """
    Safe subprocess wrapper for Windows + Linux.
    Uses shell=False and properly quoted executable path.
    """
    try:
        # If Windows → wrap nmap path in quotes
        if IS_WINDOWS:
            cmd_list = [f'"{cmd_list[0]}"'] + cmd_list[1:]

        proc = subprocess.Popen(
            cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False   # important: avoids Access Denied
        )

        out, err = proc.communicate()

        return out.decode("utf-8", errors="ignore")

    except Exception as e:
        return f"<error>{e}</error>"


def run_nmap(target, top_ports=100):
    """
    Skip Nmap on Windows (Npcap blocks Python).
    Full Nmap works on Kali Linux.
    """
    if IS_WINDOWS:
        return "<error>Nmap scanning is disabled on Windows. Run this tool on Kali Linux for full scan.</error>"

    # Linux / Kali full scan
    nmap_bin = "nmap"
    cmd = [
        nmap_bin,
        f"--top-ports={top_ports}",
        "-sV",
        "-Pn",
        "--script", "default,safe,discovery",
        "-oX", "-"
    ]
    cmd.append(target)

    return safe_run(cmd)



def parse_nmap_xml(xml_text):
    """Parses Nmap XML safely."""
    try:
        doc = xmltodict.parse(xml_text)
    except:
        return []

    hosts = []
    host_entries = doc.get("nmaprun", {}).get("host", [])

    if isinstance(host_entries, dict):
        host_entries = [host_entries]

    for h in host_entries:
        address = "-"
        addr_data = h.get("address")
        if isinstance(addr_data, list):
            address = addr_data[0].get("@addr", "-")
        elif isinstance(addr_data, dict):
            address = addr_data.get("@addr", "-")

        ports = []
        ports_raw = h.get("ports", {}).get("port", [])
        if isinstance(ports_raw, dict):
            ports_raw = [ports_raw]

        for p in ports_raw:
            service = p.get("service", {}) or {}
            ports.append({
                "port": p.get("@portid"),
                "protocol": p.get("@protocol"),
                "state": p.get("state", {}).get("@state"),
                "service": service.get("@name"),
                "product": service.get("@product"),
                "version": service.get("@version")
            })

        hosts.append({
            "address": address,
            "status": h.get("status", {}).get("@state", "unknown"),
            "ports": ports
        })

    return hosts
