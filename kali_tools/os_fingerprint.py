import subprocess
import re
import socket

# TTL-based OS fingerprinting
# Initial TTL values by OS (observed TTL after routing hops)
TTL_OS_MAP = [
    (range(0,   65),  "Linux / Android / IoT"),
    (range(65,  65),  "Linux / Android"),
    (range(64,  65),  "Linux / macOS / iOS"),
    (range(65, 129),  "Windows"),
    (range(128, 129), "Windows"),
    (range(129, 256), "Cisco / Network Device"),
    (range(255, 256), "Solaris / AIX / Cisco"),
]

# TCP Window Size fingerprinting
WINDOW_OS_MAP = {
    65535: "Windows XP / 2003",
    8192:  "Windows Vista / 7",
    64240: "Windows 10 / 11",
    29200: "Linux 4.x+",
    5840:  "Linux 2.6",
    65535: "macOS / iOS",
    4128:  "Cisco IOS",
    32768: "FreeBSD",
    16384: "OpenBSD",
}

def _ping_ttl(ip, count=3):
    """Get TTL from ping response."""
    try:
        out = subprocess.check_output(
            ["ping", "-c", str(count), "-W", "1", ip],
            stderr=subprocess.DEVNULL, text=True, timeout=10
        )
        m = re.search(r"ttl=(\d+)", out, re.IGNORECASE)
        if m:
            return int(m.group(1))
    except Exception:
        pass
    return None

def _ttl_to_os(ttl):
    """Convert observed TTL to OS guess."""
    if ttl is None:
        return None
    # Normalize to initial TTL (account for up to 30 hops)
    if ttl <= 64:
        return "🐧 Linux / Android / macOS"
    elif ttl <= 128:
        return "🪟 Windows"
    elif ttl <= 255:
        return "🔧 Cisco / Network Device"
    return None

def _tcp_window_probe(ip, port=80, timeout=2):
    """Try to grab TCP window size from SYN-ACK."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        # The connection itself reveals window size via scapy ideally,
        # but we can check via /proc/net/tcp or just return connected
        s.close()
        return True
    except Exception:
        return False

def passive_os_fingerprint(ip, open_ports=None):
    """
    Passive OS fingerprint using TTL analysis.
    Returns dict with os_guess, ttl, confidence, method.
    """
    result = {
        "ip": ip,
        "ttl": None,
        "os_guess": "Unknown",
        "confidence": "Low",
        "method": "none",
        "detail": "",
    }

    # TTL fingerprint via ping
    ttl = _ping_ttl(ip)
    if ttl:
        result["ttl"] = ttl
        os_guess = _ttl_to_os(ttl)
        if os_guess:
            result["os_guess"] = os_guess
            result["confidence"] = "Medium"
            result["method"] = "TTL"
            result["detail"] = f"TTL={ttl} → {os_guess}"

    # Refine with open ports
    if open_ports:
        ports = set(open_ports)
        if 5353 in ports or 62078 in ports:
            result["os_guess"] = "🍎 Apple (macOS / iOS)"
            result["confidence"] = "High"
            result["detail"] += " | mDNS/Apple ports detected"
        elif 445 in ports and 3389 in ports:
            result["os_guess"] = "🪟 Windows (Server/Pro)"
            result["confidence"] = "High"
            result["detail"] += " | SMB+RDP = Windows Server"
        elif 445 in ports:
            result["os_guess"] = "🪟 Windows"
            result["confidence"] = "High"
            result["detail"] += " | SMB port = Windows"
        elif 22 in ports and 80 in ports and 443 in ports:
            result["os_guess"] = "🐧 Linux Server"
            result["confidence"] = "High"
            result["detail"] += " | SSH+HTTP+HTTPS = Linux server"
        elif 554 in ports or 8000 in ports:
            result["os_guess"] = "📷 IP Camera / IoT"
            result["confidence"] = "High"
            result["detail"] += " | RTSP/camera port"
        elif 1883 in ports or 8883 in ports:
            result["os_guess"] = "🧠 IoT Device (MQTT)"
            result["confidence"] = "High"
            result["detail"] += " | MQTT = IoT device"
        elif 9100 in ports:
            result["os_guess"] = "🖨️ Network Printer"
            result["confidence"] = "High"
            result["detail"] += " | Port 9100 = printer"

    return result


def fingerprint_subnet(devices):
    """
    Run passive fingerprinting on all devices.
    Returns list of fingerprint results.
    """
    results = []
    for d in devices:
        ip = d.get("ip", "")
        ports = d.get("ports", [])
        if not ip:
            continue
        fp = passive_os_fingerprint(ip, ports)
        # If nmap already found OS, use that instead
        nmap_os = d.get("os", "")
        if nmap_os and nmap_os not in ("Unknown", "Scanning...", ""):
            fp["os_guess"] = nmap_os
            fp["confidence"] = "High"
            fp["method"] = "nmap"
        results.append(fp)
    return results
