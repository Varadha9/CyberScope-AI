"""
Smart Network Scanner
======================
Adapts to client isolation automatically:
1. Detects if client isolation is active
2. Scans infrastructure devices (not isolated)
3. Uses passive intel for client devices
4. Uses MITM for deep scanning isolated clients
"""

import subprocess
import re
import socket
import threading
from scapy.all import ARP, Ether, srp, conf, get_if_hwaddr, getmacbyip

import os

SUDO_PASS = os.environ.get("CYBERSCOPE_SUDO_PASS", "dogs")

def _sudo(cmd, timeout=60):
    full = f"echo '{SUDO_PASS}' | sudo -S bash -c \"{cmd}\""
    try:
        out = subprocess.check_output(full, shell=True, stderr=subprocess.DEVNULL,
                                      text=True, timeout=timeout)
        return out
    except Exception:
        return ""

def detect_isolation(test_ip, gateway):
    """Detect if client isolation is active by testing ICMP to another client."""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", test_ip],
            capture_output=True, text=True, timeout=3
        )
        if "1 received" in result.stdout:
            return False  # No isolation
    except Exception:
        pass
    return True  # Isolation active

def get_gateway():
    """Get default gateway IP and MAC."""
    try:
        out = subprocess.check_output(["ip", "route", "show", "default"], text=True)
        m = re.search(r"default via ([\d.]+)", out)
        if m:
            gw_ip = m.group(1)
            # Get MAC from ARP table
            try:
                arp_out = subprocess.check_output(["arp", "-n", gw_ip], text=True)
                mac_m = re.search(r"([0-9a-f:]{17})", arp_out, re.IGNORECASE)
                gw_mac = mac_m.group(1) if mac_m else "unknown"
            except Exception:
                gw_mac = "unknown"
            return gw_ip, gw_mac
    except Exception:
        pass
    return None, None

def get_infrastructure_subnet(gw_ip):
    """
    Infrastructure devices (switches, APs, WLC) are usually in the gateway's /24.
    These are NOT behind client isolation.
    """
    if not gw_ip:
        return None
    parts = gw_ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

def scan_infrastructure(gw_ip):
    """
    Scan infrastructure subnet — these devices respond to port scans.
    Returns list of {ip, mac, ports, services, vendor, device_type}
    """
    infra_subnet = get_infrastructure_subnet(gw_ip)
    if not infra_subnet:
        return []

    devices = []
    try:
        out = _sudo(
            f"nmap -sS -sV -T4 --open --top-ports 50 {infra_subnet} 2>/dev/null",
            timeout=120
        )
        current = {}
        for line in out.splitlines():
            # New host
            ip_m = re.search(r"Nmap scan report for (?:.+ \()?([\d.]+)\)?", line)
            if ip_m:
                if current.get("ip"):
                    devices.append(current)
                current = {"ip": ip_m.group(1), "mac": "", "vendor": "",
                           "ports": [], "services": {}, "device_type": ""}
            # MAC + vendor
            mac_m = re.search(r"MAC Address: ([0-9A-F:]{17}) \((.+?)\)", line, re.IGNORECASE)
            if mac_m and current:
                current["mac"]    = mac_m.group(1).lower()
                current["vendor"] = mac_m.group(2)
                current["device_type"] = _vendor_to_device_type(mac_m.group(2))
            # Open port
            port_m = re.match(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)", line)
            if port_m and current:
                port    = int(port_m.group(1))
                service = port_m.group(2)
                version = port_m.group(3).strip()
                current["ports"].append(port)
                current["services"][port] = {"name": service, "version": version}
        if current.get("ip"):
            devices.append(current)
    except Exception as e:
        print(f"[InfraScan] Error: {e}")

    # Enrich device types
    for d in devices:
        if not d["device_type"]:
            d["device_type"] = _ports_to_device_type(d["ports"], d.get("services", {}))

    return [d for d in devices if d.get("ip") and d["ip"] != gw_ip]

def smart_port_scan(ip, mac, gw_ip, use_mitm=False):
    """
    Smart port scan that adapts to isolation.
    - If not isolated: direct nmap
    - If isolated + MITM: scan after ARP spoof
    - If isolated + no MITM: return empty (use passive intel)
    """
    isolated = detect_isolation(ip, gw_ip)

    if not isolated:
        # Direct scan works
        return _direct_scan(ip)

    if use_mitm:
        # Start MITM, wait for routing to establish, then scan
        return _mitm_scan(ip, gw_ip)

    return []

def _direct_scan(ip):
    """Standard nmap scan."""
    ports = []
    try:
        out = _sudo(f"nmap -sS -T4 --open --top-ports 1000 {ip} 2>/dev/null")
        for line in out.splitlines():
            m = re.match(r"(\d+)/tcp\s+open", line)
            if m:
                ports.append(int(m.group(1)))
    except Exception:
        pass
    return ports

def _mitm_scan(ip, gw_ip):
    """ARP spoof then scan."""
    ports = []
    try:
        # Start spoof
        spoof_proc = subprocess.Popen(
            f"echo '{SUDO_PASS}' | sudo -S arpspoof -i wlan0 -t {ip} {gw_ip}",
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        spoof_proc2 = subprocess.Popen(
            f"echo '{SUDO_PASS}' | sudo -S arpspoof -i wlan0 -t {gw_ip} {ip}",
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        import time
        time.sleep(3)  # Wait for ARP tables to update

        # Scan
        ports = _direct_scan(ip)

        # Stop spoof
        spoof_proc.terminate()
        spoof_proc2.terminate()
    except Exception as e:
        print(f"[MITM Scan] Error: {e}")
    return ports

def _vendor_to_device_type(vendor):
    v = vendor.lower()
    if "cisco" in v:
        if "wireless" in v or "wlc" in v:  return "📡 Cisco WLC (WiFi Controller)"
        if "switch" in v:                   return "🔀 Cisco Switch"
        return "🔧 Cisco Network Device"
    if "aruba" in v:    return "📡 Aruba AP/Controller"
    if "ruckus" in v:   return "📡 Ruckus AP"
    if "ubiquiti" in v: return "📡 Ubiquiti AP"
    if "fortinet" in v: return "🔥 Fortinet Firewall"
    if "palo alto" in v: return "🔥 Palo Alto Firewall"
    if "juniper" in v:  return "🔧 Juniper Device"
    if "hp" in v or "hewlett" in v: return "🖨️ HP Device"
    if "apple" in v:    return "🍎 Apple Device"
    if "intel" in v:    return "💻 Intel WiFi Device"
    return ""

def _ports_to_device_type(ports, services):
    port_set = set(ports)
    svc_str = " ".join(str(s) for s in services.values()).lower()
    if "wireless lan controller" in svc_str or "wlc" in svc_str or "cisco wireless" in svc_str:
        return "📡 Cisco WLC (WiFi Controller)"
    if {22, 23, 80, 443} & port_set and not {3306, 5432} & port_set:
        return "🔧 Network Infrastructure"
    if 161 in port_set:  return "🔧 SNMP Device"
    if 9100 in port_set: return "🖨️ Network Printer"
    if {80, 443} & port_set: return "🌐 Web Server"
    return "📡 Network Device"
