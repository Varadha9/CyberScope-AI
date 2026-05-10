import subprocess
import re
from scapy.all import ARP, Ether, srp

def get_wifi_subnet():
    """Auto-detect WiFi subnet — use /24 around our IP for practical ARP scanning"""
    try:
        out = subprocess.check_output(["ip", "addr", "show", "wlan0"], text=True)
        match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", out)
        if match:
            ip = match.group(1)
            parts = ip.split(".")
            # Always use /24 of our IP — ARP on larger subnets is impractical
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception:
        pass
    return "10.50.99.0/24"

def get_gateway():
    """Get default gateway IP and MAC"""
    try:
        out = subprocess.check_output(["ip", "route", "show", "default"], text=True)
        m = re.search(r"default via ([\d.]+)", out)
        if m:
            gw_ip = m.group(1)
            arp_out = subprocess.check_output(["arp", "-n", gw_ip], text=True)
            mac_m = re.search(r"([0-9a-f:]{17})", arp_out, re.IGNORECASE)
            mac = mac_m.group(1) if mac_m else "00:00:00:00:00:00"
            return [{"ip": gw_ip, "mac": mac}]
    except Exception:
        pass
    return []

def nmap_ping_scan(subnet):
    """Fallback: nmap -sn ping scan when ARP is blocked"""
    devices = []
    try:
        out = subprocess.check_output(
            ["nmap", "-sn", "-T4", subnet],
            stderr=subprocess.DEVNULL, text=True, timeout=60
        )
        current_ip = None
        for line in out.splitlines():
            ip_m = re.search(r"Nmap scan report for ([\d.]+)", line)
            if ip_m:
                current_ip = ip_m.group(1)
            mac_m = re.search(r"MAC Address: ([0-9A-F:]{17})", line, re.IGNORECASE)
            if mac_m and current_ip:
                devices.append({"ip": current_ip, "mac": mac_m.group(1)})
                current_ip = None
    except Exception as e:
        print(f"[Nmap Ping Scan Error] {e}")
    return devices

def scan_network(ip_range, iface="wlan0"):
    """ARP scan on WiFi interface, fallback to nmap ping + gateway if blocked"""
    devices = []
    try:
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        result = srp(ether / arp, timeout=5, verbose=0, iface=iface)[0]
        devices = [{"ip": r.psrc, "mac": r.hwsrc} for _, r in result]
        if devices:
            print(f"[ARP Scan] Found {len(devices)} device(s)")
            return devices
    except PermissionError:
        print(f"[ARP Scan Error] Permission denied - need root")
    except Exception as e:
        print(f"[ARP Scan Error] {e}")

    print("[*] ARP blocked (client isolation). Falling back to nmap ping scan...")
    devices = nmap_ping_scan(ip_range)
    if not devices:
        # Last resort: at least return the gateway
        print("[*] No hosts found via nmap ping. Adding gateway only.")
        devices = get_gateway()
    return devices
