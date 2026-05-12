"""
IPv6 Bypass Scanner
====================
PSPF (Public Secure Packet Forwarding) only blocks IPv4 client-to-client traffic.
IPv6 link-local (fe80::/10) traffic is NOT blocked by most Cisco PSPF configs.

This module:
1. Discovers all devices via IPv6 NDP (Neighbor Discovery Protocol)
2. Maps IPv6 link-local -> MAC -> IPv4 (via ARP correlation)
3. Port scans devices via IPv6 (bypasses client isolation)
4. Derives IPv4 from MAC using EUI-64 reverse calculation
"""

import subprocess
import re
import socket
import threading
from collections import defaultdict

SUDO_PASS = __import__('os').environ.get("CYBERSCOPE_SUDO_PASS", "dogs")


def _sudo(cmd, timeout=60):
    try:
        out = subprocess.check_output(
            f"echo '{SUDO_PASS}' | sudo -S bash -c \"{cmd}\"",
            shell=True, stderr=subprocess.DEVNULL, text=True, timeout=timeout
        )
        return out
    except Exception:
        return ""


def get_ndp_table(iface="wlan0"):
    """Get all IPv6 neighbors from NDP table. Returns {ipv6: mac}."""
    ndp = {}
    try:
        out = subprocess.check_output(
            ["ip", "-6", "neigh", "show", "dev", iface],
            text=True, stderr=subprocess.DEVNULL
        )
        for line in out.splitlines():
            m = re.match(r"(fe80::\S+)\s+lladdr\s+([0-9a-f:]{17})", line)
            if m:
                ndp[m.group(1)] = m.group(2).lower()
    except Exception:
        pass
    return ndp


def get_arp_table():
    """Get IPv4 ARP table. Returns {mac: ipv4}."""
    mac_to_ip = {}
    try:
        out = subprocess.check_output(["arp", "-n"], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3 and ":" in parts[2]:
                mac_to_ip[parts[2].lower()] = parts[0]
    except Exception:
        pass
    return mac_to_ip


def mac_to_ipv6_linklocal(mac):
    """Convert MAC address to IPv6 EUI-64 link-local address."""
    try:
        parts = mac.lower().split(":")
        if len(parts) != 6:
            return None
        # Flip bit 6 of first byte (universal/local bit)
        first = int(parts[0], 16) ^ 0x02
        eui64 = f"{first:02x}{parts[1]}:{parts[2]}ff:fe{parts[3]}:{parts[4]}{parts[5]}"
        return f"fe80::{eui64}"
    except Exception:
        return None


def ipv6_to_mac(ipv6):
    """Reverse EUI-64: extract MAC from IPv6 link-local address."""
    try:
        # Remove fe80:: prefix and expand
        addr = ipv6.lower().replace("fe80::", "").strip()
        # Handle compressed notation
        groups = addr.split(":")
        if len(groups) == 4:
            # Standard EUI-64: xxxx:xxff:fexx:xxxx
            g1, g2, g3, g4 = groups
            # g2 should end in ff, g3 should start with fe
            if g2.endswith("ff") and g3.startswith("fe"):
                b1 = g1[:2]
                b2 = g1[2:]
                b3 = g2[:2]
                b4 = g3[2:]
                b5 = g4[:2]
                b6 = g4[2:]
                # Flip bit 6 back
                first = int(b1, 16) ^ 0x02
                return f"{first:02x}:{b2}:{b3}:{b4}:{b5}:{b6}"
    except Exception:
        pass
    return None


def discover_ipv6_devices(iface="wlan0", timeout=15):
    """
    Discover all IPv6 devices by:
    1. Sending multicast ping6 to ff02::1 (all nodes)
    2. Reading NDP table
    Returns list of {ipv6, mac, ipv4}
    """
    # Trigger NDP discovery via multicast ping
    try:
        subprocess.run(
            ["ping6", "-c", "3", "-I", iface, "ff02::1"],
            capture_output=True, timeout=timeout
        )
    except Exception:
        pass

    ndp = get_ndp_table(iface)
    arp = get_arp_table()

    devices = []
    seen_macs = set()

    for ipv6, mac in ndp.items():
        if mac in seen_macs:
            continue
        seen_macs.add(mac)

        ipv4 = arp.get(mac, "")
        devices.append({
            "ipv6": ipv6,
            "mac": mac,
            "ipv4": ipv4,
            "iface": iface,
        })

    return devices


def ipv6_port_scan(ipv6, iface="wlan0", top_ports=1000):
    """
    Port scan a device via IPv6 link-local.
    Returns list of open ports.
    """
    addr = f"{ipv6}%{iface}"
    open_ports = []
    try:
        out = _sudo(
            f"nmap -6 -sS -T4 --open --top-ports {top_ports} '{addr}' 2>/dev/null",
            timeout=120
        )
        for line in out.splitlines():
            m = re.match(r"(\d+)/tcp\s+open", line)
            if m:
                open_ports.append(int(m.group(1)))
    except Exception:
        pass
    return open_ports


def ipv6_service_scan(ipv6, ports, iface="wlan0"):
    """Service/version detection via IPv6."""
    if not ports:
        return {}
    addr = f"{ipv6}%{iface}"
    ports_str = ",".join(str(p) for p in ports[:20])
    services = {}
    try:
        out = _sudo(
            f"nmap -6 -sV -T4 -p {ports_str} '{addr}' 2>/dev/null",
            timeout=60
        )
        for line in out.splitlines():
            m = re.match(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)", line)
            if m:
                services[int(m.group(1))] = {
                    "name": m.group(2),
                    "product": m.group(3).strip(),
                    "version": "",
                }
    except Exception:
        pass
    return services


def ipv6_os_detect(ipv6, iface="wlan0"):
    """OS detection via IPv6."""
    addr = f"{ipv6}%{iface}"
    try:
        out = _sudo(f"nmap -6 -O --osscan-guess -T4 '{addr}' 2>/dev/null", timeout=60)
        for line in out.splitlines():
            if "OS:" in line or "Running:" in line:
                m = re.search(r"(?:OS:|Running:)\s*(.+)", line)
                if m:
                    return m.group(1).strip()
    except Exception:
        pass
    return "Unknown"


def ipv6_ping(ipv6, iface="wlan0"):
    """Test if device responds to ping6."""
    try:
        result = subprocess.run(
            ["ping6", "-c", "1", "-W", "2", f"{ipv6}%{iface}"],
            capture_output=True, timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False


def scan_all_ipv6(iface="wlan0", max_devices=50):
    """
    Full IPv6 network scan:
    1. Discover all devices via NDP
    2. Port scan each via IPv6
    3. Map back to IPv4 via MAC
    Returns list of enriched device dicts.
    """
    print(f"[IPv6] Discovering devices on {iface}...")
    devices = discover_ipv6_devices(iface)
    print(f"[IPv6] Found {len(devices)} devices in NDP table")

    results = []
    lock = threading.Lock()

    def scan_one(d):
        ipv6 = d["ipv6"]
        mac  = d["mac"]

        # Quick ping check
        if not ipv6_ping(ipv6, iface):
            return

        print(f"[IPv6] Scanning {ipv6} ({mac})...")
        ports = ipv6_port_scan(ipv6, iface, top_ports=500)

        if ports:
            services = ipv6_service_scan(ipv6, ports, iface)
            os_info  = ipv6_os_detect(ipv6, iface)
        else:
            services = {}
            os_info  = "Unknown"

        result = {
            "ipv6":     ipv6,
            "mac":      mac,
            "ipv4":     d.get("ipv4", ""),
            "ports":    ports,
            "services": services,
            "os":       os_info,
            "method":   "IPv6-bypass",
        }
        with lock:
            results.append(result)
            if ports:
                print(f"[IPv6] {ipv6} ({mac}) -> ports={ports} os={os_info}")

    # Scan in parallel threads (max 10 at a time)
    sem = threading.Semaphore(10)
    threads = []

    for d in devices[:max_devices]:
        def worker(dev=d):
            with sem:
                scan_one(dev)
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join(timeout=180)

    return results


def get_ipv6_for_mac(mac, iface="wlan0"):
    """Get IPv6 link-local address for a given MAC."""
    ndp = get_ndp_table(iface)
    mac = mac.lower()
    for ipv6, m in ndp.items():
        if m == mac:
            return ipv6
    # Try EUI-64 calculation
    return mac_to_ipv6_linklocal(mac)
