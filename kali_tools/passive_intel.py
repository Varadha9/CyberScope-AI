"""
Passive Intelligence Engine
============================
Harvests device names, OS hints, and activity from broadcast/multicast traffic.
Works on client-isolated networks — no direct device contact needed.

Sources:
  - DHCP requests  → hostname, MAC, device type
  - mDNS           → .local names, service types
  - NetBIOS/NBNS   → Windows computer names
  - SSDP/UPnP      → device model, manufacturer
  - ARP            → IP↔MAC mapping updates
  - ICMPv6/NDP     → IPv6 device discovery
"""

import subprocess
import re
import threading
import time
from collections import defaultdict

# Global intelligence store: mac -> {hostname, os_hint, services, last_seen, ip}
_intel = {}
_lock  = threading.Lock()
_running = False
_thread  = None


def _run_tshark(fields, bpf_filter, count=500, timeout=30):
    cmd = ["tshark", "-i", "wlan0", "-c", str(count),
           "-a", f"duration:{timeout}",
           "-T", "fields"] + fields
    if bpf_filter:
        cmd += ["-f", bpf_filter]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL,
                                      text=True, timeout=timeout + 5)
        return out
    except Exception:
        return ""


def _parse_dhcp(timeout=20):
    """DHCP requests reveal hostname + MAC — most reliable source."""
    out = _run_tshark(
        ["-e", "bootp.hw.mac_addr",
         "-e", "bootp.option.hostname",
         "-e", "bootp.option.vendor_class_id",
         "-e", "bootp.ip.your",
         "-e", "ip.src"],
        "udp port 67 or udp port 68",
        count=300, timeout=timeout
    )
    results = []
    for line in out.splitlines():
        parts = line.strip().split("\t")
        if len(parts) < 2:
            continue
        mac      = parts[0].strip() if parts[0] else ""
        hostname = parts[1].strip() if len(parts) > 1 else ""
        vendor   = parts[2].strip() if len(parts) > 2 else ""
        your_ip  = parts[3].strip() if len(parts) > 3 else ""
        src_ip   = parts[4].strip() if len(parts) > 4 else ""

        if not hostname:
            continue

        # Deduplicate MAC (DHCP packets have it twice sometimes)
        if "," in mac:
            mac = mac.split(",")[0].strip()

        os_hint = _vendor_class_to_os(vendor)
        device_type = _hostname_to_type(hostname)

        results.append({
            "mac": mac.lower(),
            "hostname": hostname,
            "os_hint": os_hint,
            "device_type": device_type,
            "ip": your_ip or src_ip,
            "source": "DHCP",
        })
    return results


def _parse_mdns(timeout=15):
    """mDNS reveals .local hostnames and service types."""
    out = _run_tshark(
        ["-e", "ip.src",
         "-e", "eth.src",
         "-e", "mdns.dns.resp.name",
         "-e", "mdns.dns.qry.name",
         "-e", "dns.srv.name"],
        "udp port 5353",
        count=300, timeout=timeout
    )
    results = []
    seen = set()
    for line in out.splitlines():
        parts = line.strip().split("\t")
        if len(parts) < 2:
            continue
        ip   = parts[0].strip()
        mac  = parts[1].strip().lower() if len(parts) > 1 else ""
        name = ""
        for p in parts[2:]:
            p = p.strip()
            if p and ".local" in p.lower():
                name = p.replace(".local", "").strip(".")
                break
            elif p and p.endswith("."):
                name = p.strip(".")
                break

        if not name or not ip:
            continue
        key = (ip, name)
        if key in seen:
            continue
        seen.add(key)

        # Extract device type from mDNS service names
        device_type = _mdns_service_to_type(name)
        results.append({
            "mac": mac,
            "hostname": name,
            "ip": ip,
            "os_hint": _mdns_os_hint(name),
            "device_type": device_type,
            "source": "mDNS",
        })
    return results


def _parse_nbns(timeout=10):
    """NetBIOS Name Service — Windows computer names."""
    out = _run_tshark(
        ["-e", "ip.src",
         "-e", "eth.src",
         "-e", "nbns.name"],
        "udp port 137",
        count=200, timeout=timeout
    )
    results = []
    for line in out.splitlines():
        parts = line.strip().split("\t")
        if len(parts) < 3:
            continue
        ip   = parts[0].strip()
        mac  = parts[1].strip().lower()
        name = parts[2].strip().rstrip("<00>").strip()
        # Remove NetBIOS type suffixes like <1c>, <20>
        name = re.sub(r"<[0-9a-f]{2}>", "", name, flags=re.IGNORECASE).strip()
        if not name or not ip:
            continue
        results.append({
            "mac": mac,
            "hostname": name,
            "ip": ip,
            "os_hint": "🪟 Windows",
            "device_type": "💻 Windows PC",
            "source": "NetBIOS",
        })
    return results


def _parse_ssdp(timeout=10):
    """SSDP/UPnP — device model and manufacturer."""
    out = _run_tshark(
        ["-e", "ip.src",
         "-e", "eth.src",
         "-e", "http.user_agent",
         "-e", "http.server",
         "-e", "http.location"],
        "udp port 1900",
        count=200, timeout=timeout
    )
    results = []
    for line in out.splitlines():
        parts = line.strip().split("\t")
        if len(parts) < 3:
            continue
        ip         = parts[0].strip()
        mac        = parts[1].strip().lower()
        user_agent = parts[2].strip() if len(parts) > 2 else ""
        server     = parts[3].strip() if len(parts) > 3 else ""
        info       = user_agent or server
        if not info or not ip:
            continue
        # Extract device name from UPnP user-agent
        name = _ssdp_to_name(info)
        results.append({
            "mac": mac,
            "hostname": name or info[:40],
            "ip": ip,
            "os_hint": _ssdp_os_hint(info),
            "device_type": _ssdp_device_type(info),
            "source": "SSDP/UPnP",
        })
    return results


def _parse_arp(timeout=10):
    """ARP — IP to MAC mapping, always works."""
    out = _run_tshark(
        ["-e", "arp.src.hw_mac",
         "-e", "arp.src.proto_ipv4"],
        "arp",
        count=200, timeout=timeout
    )
    results = []
    seen = set()
    for line in out.splitlines():
        parts = line.strip().split("\t")
        if len(parts) < 2:
            continue
        mac = parts[0].strip().lower()
        ip  = parts[1].strip()
        if not mac or not ip or ip == "0.0.0.0":
            continue
        if (mac, ip) in seen:
            continue
        seen.add((mac, ip))
        results.append({"mac": mac, "ip": ip, "source": "ARP"})
    return results


# ── OS / device type helpers ──────────────────────────────────────────────────

def _vendor_class_to_os(vendor):
    if not vendor:
        return ""
    v = vendor.lower()
    if "android" in v:    return "🤖 Android"
    if "iphone" in v or "ipad" in v or "ios" in v: return "🍎 iOS"
    if "windows" in v:    return "🪟 Windows"
    if "linux" in v:      return "🐧 Linux"
    if "macos" in v or "mac os" in v: return "🍎 macOS"
    if "dhcpcd" in v:     return "🐧 Linux"
    if "msft" in v:       return "🪟 Windows"
    return ""

def _hostname_to_type(hostname):
    h = hostname.lower()
    if any(x in h for x in ["iphone", "ipad"]):      return "🍎 iPhone/iPad"
    if any(x in h for x in ["macbook", "imac"]):      return "🍎 MacBook"
    if any(x in h for x in ["laptop", "notebook", "desktop", "pc"]): return "💻 Laptop/PC"
    if any(x in h for x in ["oneplus", "redmi", "xiaomi", "poco"]): return "📱 Android Phone"
    if any(x in h for x in ["samsung", "galaxy"]):    return "📱 Samsung Phone"
    if any(x in h for x in ["vivo", "oppo", "realme", "iqoo"]): return "📱 Android Phone"
    if any(x in h for x in ["huawei", "honor"]):      return "📱 Huawei Phone"
    if any(x in h for x in ["pixel"]):                return "📱 Google Pixel"
    if re.match(r"^[a-z]{1,2}\d{4,6}$", h):          return "📱 Android Phone"  # e.g. V2338, I2127
    if "desktop" in h or h.startswith("desktop-"):    return "🖥️ Windows Desktop"
    if "laptop" in h or h.startswith("laptop-"):      return "💻 Windows Laptop"
    if any(x in h for x in ["router", "ap-", "wifi"]): return "🌐 Router/AP"
    if any(x in h for x in ["cam", "nvr", "dvr"]):    return "📷 Camera"
    if any(x in h for x in ["printer", "hp-", "canon", "epson"]): return "🖨️ Printer"
    return "📡 Device"

def _mdns_service_to_type(name):
    n = name.lower()
    if "_airplay" in n or "_raop" in n:  return "🍎 Apple AirPlay"
    if "_ipp" in n or "_printer" in n:   return "🖨️ Printer"
    if "_smb" in n or "_afpovertcp" in n: return "💻 Mac/Windows Share"
    if "_googlecast" in n:               return "📺 Chromecast"
    if "_spotify" in n:                  return "🎵 Spotify Connect"
    if "_http" in n:                     return "🌐 Web Service"
    if "_ssh" in n:                      return "🐧 SSH Server"
    return "📡 mDNS Device"

def _mdns_os_hint(name):
    n = name.lower()
    if any(x in n for x in ["iphone", "ipad", "macbook", "imac", "apple"]): return "🍎 Apple"
    if "_airplay" in n or "_raop" in n: return "🍎 Apple"
    if "_smb" in n:                     return "🪟 Windows / macOS"
    return ""

def _ssdp_to_name(info):
    # Extract from UPnP strings like "Samsung SmartTV/T-HKMFDEUC-1252.3"
    m = re.search(r"([A-Z][a-zA-Z]+ [A-Z][a-zA-Z]+(?:/[\w.-]+)?)", info)
    return m.group(1) if m else ""

def _ssdp_os_hint(info):
    i = info.lower()
    if "windows" in i: return "🪟 Windows"
    if "linux" in i:   return "🐧 Linux"
    if "android" in i: return "🤖 Android"
    return ""

def _ssdp_device_type(info):
    i = info.lower()
    if "tv" in i or "smarttv" in i:    return "📺 Smart TV"
    if "printer" in i:                  return "🖨️ Printer"
    if "router" in i or "gateway" in i: return "🌐 Router"
    if "camera" in i or "cam" in i:     return "📷 Camera"
    return "📡 UPnP Device"


# ── Main harvest function ─────────────────────────────────────────────────────

def harvest_passive(timeout=30):
    """
    Run all passive harvesting in parallel.
    Returns dict: {mac: {hostname, ip, os_hint, device_type, source}}
    """
    results = defaultdict(dict)
    threads = []
    collected = []
    lock = threading.Lock()

    def run(fn, t):
        data = fn(t)
        with lock:
            collected.extend(data)

    for fn, t in [(_parse_dhcp, timeout), (_parse_mdns, timeout),
                  (_parse_nbns, min(timeout, 10)), (_parse_ssdp, min(timeout, 10)),
                  (_parse_arp, min(timeout, 10))]:
        th = threading.Thread(target=run, args=(fn, t), daemon=True)
        th.start()
        threads.append(th)

    for th in threads:
        th.join(timeout=timeout + 5)

    # Merge: ARP first (IP↔MAC), then enrich with names
    ip_to_mac = {}
    for item in collected:
        if item.get("source") == "ARP" and item.get("mac") and item.get("ip"):
            ip_to_mac[item["ip"]] = item["mac"]

    for item in collected:
        mac = item.get("mac", "")
        ip  = item.get("ip", "")
        # Try to resolve MAC from IP via ARP table
        if not mac and ip:
            mac = ip_to_mac.get(ip, "")
        if not mac:
            continue

        mac = mac.lower()
        if mac not in results:
            results[mac] = {"mac": mac, "ip": ip, "hostname": "",
                            "os_hint": "", "device_type": "", "sources": []}

        # Priority: DHCP > NetBIOS > mDNS > SSDP
        src = item.get("source", "")
        hn  = item.get("hostname", "")
        priority = {"DHCP": 4, "NetBIOS": 3, "mDNS": 2, "SSDP": 1, "ARP": 0}
        cur_priority = max((priority.get(s, 0) for s in results[mac]["sources"]), default=0)

        if hn and priority.get(src, 0) >= cur_priority:
            results[mac]["hostname"] = hn
        if item.get("os_hint") and not results[mac]["os_hint"]:
            results[mac]["os_hint"] = item["os_hint"]
        if item.get("device_type") and not results[mac]["device_type"]:
            results[mac]["device_type"] = item["device_type"]
        if ip and not results[mac]["ip"]:
            results[mac]["ip"] = ip
        if src not in results[mac]["sources"]:
            results[mac]["sources"].append(src)

    # Update global intel store
    with _lock:
        for mac, data in results.items():
            if mac in _intel:
                # Merge — don't overwrite good data with empty
                for k, v in data.items():
                    if v and (not _intel[mac].get(k)):
                        _intel[mac][k] = v
                _intel[mac]["last_seen"] = time.time()
            else:
                data["last_seen"] = time.time()
                _intel[mac] = data

    return dict(results)


def get_intel(mac=None, ip=None):
    """Get stored intelligence for a MAC or IP."""
    with _lock:
        if mac:
            return _intel.get(mac.lower(), {})
        if ip:
            for data in _intel.values():
                if data.get("ip") == ip:
                    return data
        return dict(_intel)


def get_all_intel():
    with _lock:
        return dict(_intel)


def start_continuous_harvest(interval=60):
    """Run passive harvest continuously in background."""
    global _running, _thread
    if _running:
        return
    _running = True

    def loop():
        while _running:
            try:
                harvest_passive(timeout=30)
            except Exception as e:
                print(f"[Passive Intel] Error: {e}")
            time.sleep(interval)

    _thread = threading.Thread(target=loop, daemon=True)
    _thread.start()


def stop_continuous_harvest():
    global _running
    _running = False
