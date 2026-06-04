import subprocess
import re
import socket
from scapy.all import ARP, Ether, srp

# ── Load nmap OUI database (52k entries) ──────────────────────────────────
_OUI_DB = {}
_OUI_DB_PATH = "/usr/share/nmap/nmap-mac-prefixes"

def _load_oui_db():
    global _OUI_DB
    if _OUI_DB:
        return
    try:
        with open(_OUI_DB_PATH) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    _OUI_DB[parts[0].upper()] = parts[1]
    except Exception:
        pass

def mac_vendor(mac):
    """Look up MAC vendor from nmap's 52k-entry OUI database."""
    if not mac:
        return ""
    _load_oui_db()
    oui = mac.replace(":", "").replace("-", "").upper()[:6]
    # Locally administered (randomized) MAC — second nibble 2,6,A,E
    try:
        if int(oui[1], 16) in (2, 6, 0xA, 0xE):
            return "[Randomized MAC]"
    except Exception:
        pass
    return _OUI_DB.get(oui, "")

# ── Friendly device label from vendor string ──────────────────────────────
_VENDOR_LABELS = [
    # Routers / APs
    (["jio", "jiofibr", "reliance"], "JioFiber Router"),
    (["tp-link", "tp link"], "TP-Link Router"),
    (["d-link"], "D-Link Router"),
    (["netgear"], "Netgear Router"),
    (["cisco"], "Cisco Device"),
    (["ubiquiti"], "Ubiquiti AP"),
    (["mikrotik"], "MikroTik Router"),
    # Cameras
    (["hikvision"], "Hikvision Camera"),
    (["dahua"], "Dahua Camera"),
    (["axis"], "Axis Camera"),
    (["hanwha", "samsung techwin"], "Samsung Camera"),
    # Phones
    (["xiaomi", "mi com"], "Xiaomi Phone"),
    (["samsung"], "Samsung Device"),
    (["oneplus"], "OnePlus Phone"),
    (["vivo"], "Vivo Phone"),
    (["oppo"], "OPPO Phone"),
    (["realme"], "Realme Phone"),
    (["huawei"], "Huawei Device"),
    (["motorola"], "Motorola Phone"),
    (["zte"], "ZTE Phone"),
    (["lge", "lg electron"], "LG Phone"),
    # Apple
    (["apple"], "Apple Device"),
    # Laptops / PCs
    (["intel", "intel corp"], "Intel WiFi Adapter"),
    (["dell"], "Dell Laptop/PC"),
    (["lenovo"], "Lenovo Laptop"),
    (["hewlett", "hp "], "HP Laptop/PC"),
    (["acer"], "Acer Laptop"),
    (["asus"], "ASUS Device"),
    (["toshiba"], "Toshiba Laptop"),
    (["msi "], "MSI Laptop"),
    # IoT
    (["espressif"], "ESP32/ESP8266 IoT"),
    (["raspberry"], "Raspberry Pi"),
    (["arduino"], "Arduino IoT"),
    (["tuya"], "Tuya Smart Device"),
    # Cloud/WiFi chips (used in phones/laptops)
    (["azurewave"], "WiFi Device (AzureWave)"),
    (["cloud network technology", "cloud network"], "WiFi Device (Realtek)"),
    (["liteon"], "WiFi Device (Lite-On)"),
    (["mediatek"], "MediaTek Device"),
    (["qualcomm"], "Qualcomm Device"),
    (["broadcom"], "Broadcom WiFi Device"),
    (["murata"], "Murata WiFi Module"),
    (["u-blox"], "u-blox IoT Module"),
    # Printers
    (["brother"], "Brother Printer"),
    (["canon"], "Canon Printer"),
    (["epson"], "Epson Printer"),
    (["xerox"], "Xerox Printer"),
    (["ricoh"], "Ricoh Printer"),
    # Gaming
    (["nintendo"], "Nintendo Console"),
    (["sony interactive", "playstation"], "PlayStation"),
    (["microsoft", "xbox"], "Xbox / Microsoft"),
    (["valve"], "Steam Deck"),
    # Smart TV
    (["tcl"], "TCL Smart TV"),
    (["hisense"], "Hisense TV"),
    (["lg electron"], "LG Smart TV"),
]

def vendor_to_label(vendor):
    """Convert raw vendor string to a friendly device label."""
    if not vendor:
        return ""
    v = vendor.lower()
    for keywords, label in _VENDOR_LABELS:
        if any(k in v for k in keywords):
            return label
    # Return cleaned vendor name (title case, max 30 chars)
    return vendor[:30].strip()


def _nmap_hostname(ip):
    """Use nmap -sn to get hostname AND vendor in one call."""
    try:
        out = subprocess.check_output(
            ["nmap", "-sn", "-R", ip, "-oN", "-"],
            stderr=subprocess.DEVNULL, text=True, timeout=8
        )
        hostname = None
        vendor = None
        for line in out.splitlines():
            # Hostname: "scan report for HOSTNAME (IP)"
            m = re.search(r"scan report for (.+?) \(", line)
            if m:
                hostname = m.group(1).strip()
            # Vendor: "MAC Address: XX:XX:XX:XX:XX:XX (Vendor Name)"
            mv = re.search(r"MAC Address: [0-9A-F:]{17} \((.+?)\)", line, re.IGNORECASE)
            if mv:
                vendor = mv.group(1).strip()
        return hostname, vendor
    except Exception:
        pass
    return None, None

def _netbios_hostname(ip):
    try:
        out = subprocess.check_output(
            ["nmblookup", "-A", ip],
            stderr=subprocess.DEVNULL, text=True, timeout=5
        )
        for line in out.splitlines():
            if "<00>" in line and "GROUP" not in line:
                name = line.strip().split()[0]
                if name and name != "*":
                    return name
    except Exception:
        pass
    return None

def _avahi_hostname(ip):
    try:
        out = subprocess.check_output(
            ["avahi-resolve", "-a", ip],
            stderr=subprocess.DEVNULL, text=True, timeout=5
        )
        parts = out.strip().split()
        if len(parts) >= 2:
            return parts[1]
    except Exception:
        pass
    return None

def resolve_hostname(ip, mac=None):
    """Resolve device name using all available methods."""
    # 1. DNS reverse lookup
    try:
        name = socket.gethostbyaddr(ip)[0]
        if name and name != ip:
            return name
    except Exception:
        pass

    # 2. nmap (gets hostname + vendor in one shot)
    hostname, nmap_vendor = _nmap_hostname(ip)
    if hostname:
        return hostname

    # 3. avahi mDNS
    name = _avahi_hostname(ip)
    if name:
        return name

    # 4. NetBIOS
    name = _netbios_hostname(ip)
    if name:
        return name

    # 5. MAC vendor label (nmap OUI DB)
    if mac:
        vendor = mac_vendor(mac)
        label = vendor_to_label(vendor)
        if label and "Randomized" not in label:
            return label

    return "unknown"


def best_device_name(ip, mac, passive_intel=None):
    """
    Return the best human-readable device name from all available sources.
    Priority: passive intel (DHCP/mDNS/NetBIOS) > DNS > nmap > avahi > NetBIOS > OUI vendor
    Never returns empty string — always returns something.
    """
    # 1. Passive intel (DHCP hostname is most accurate for phones/laptops)
    if passive_intel:
        hn = passive_intel.get("hostname", "")
        if hn and hn not in ("unknown", ""):
            return hn
        dt = passive_intel.get("device_type", "")
        if dt:
            return dt

    # 2. DNS reverse lookup (fast)
    try:
        name = socket.gethostbyaddr(ip)[0]
        if name and name != ip and not name.startswith(ip):
            return name
    except Exception:
        pass

    # 3. avahi mDNS (fast, catches Apple/Linux .local names)
    name = _avahi_hostname(ip)
    if name:
        return name

    # 4. NetBIOS (Windows machines)
    name = _netbios_hostname(ip)
    if name:
        return name

    # 5. OUI vendor label — always available from MAC
    if mac:
        vendor = mac_vendor(mac)
        if vendor == "[Randomized MAC]":
            return "📱 Phone/Laptop"
        label = vendor_to_label(vendor)
        if label:
            return label

    return "Unknown Device"

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
            return [{"ip": gw_ip, "mac": mac, "hostname": resolve_hostname(gw_ip, mac)}]
    except Exception:
        pass
    return []

def nmap_ping_scan(subnet):
    """nmap -sn ping scan — captures IP, MAC, vendor in one pass."""
    devices = []
    try:
        out = subprocess.check_output(
            ["nmap", "-sn", "-T4", "--send-eth", subnet],
            stderr=subprocess.DEVNULL, text=True, timeout=60
        )
        current_ip = None
        for line in out.splitlines():
            ip_m = re.search(r"Nmap scan report for (?:.+ \()?([\d.]+)\)?", line)
            if ip_m:
                current_ip = ip_m.group(1)
                # Also grab hostname if present: "scan report for HOSTNAME (IP)"
                hn_m = re.search(r"scan report for (.+?) \(", line)
                hostname = hn_m.group(1).strip() if hn_m else None
            mac_m = re.search(r"MAC Address: ([0-9A-F:]{17}) \((.+?)\)", line, re.IGNORECASE)
            if mac_m and current_ip:
                mac    = mac_m.group(1)
                vendor = mac_m.group(2).strip()
                label  = hostname or vendor_to_label(vendor) or vendor
                devices.append({"ip": current_ip, "mac": mac,
                                 "hostname": label, "vendor": vendor})
                current_ip = None
    except Exception as e:
        print(f"[Nmap Ping Scan Error] {e}")
    return devices

def scan_network(ip_range, iface="wlan0"):
    """ARP scan, then enrich with nmap vendor data."""
    devices = []
    # Run nmap -sn which gives us MAC + vendor in one shot
    try:
        out = subprocess.check_output(
            ["nmap", "-sn", "-T4", "--send-eth", ip_range],
            stderr=subprocess.DEVNULL, text=True, timeout=60
        )
        current_ip  = None
        hostname    = None
        for line in out.splitlines():
            ip_m = re.search(r"Nmap scan report for (?:.+ \()?([\d.]+)\)?", line)
            if ip_m:
                current_ip = ip_m.group(1)
                hn_m = re.search(r"scan report for (.+?) \(", line)
                hostname = hn_m.group(1).strip() if hn_m else None
            mac_m = re.search(r"MAC Address: ([0-9A-F:]{17}) \((.+?)\)", line, re.IGNORECASE)
            if mac_m and current_ip:
                mac    = mac_m.group(1)
                vendor = mac_m.group(2).strip()
                label  = hostname or vendor_to_label(vendor) or vendor
                devices.append({"ip": current_ip, "mac": mac,
                                 "hostname": label, "vendor": vendor})
                current_ip = None
                hostname   = None
        if devices:
            print(f"[Nmap Scan] Found {len(devices)} device(s)")
            return devices
    except Exception as e:
        print(f"[Nmap Scan Error] {e}")

    # Fallback: Scapy ARP
    try:
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        result = srp(ether / arp, timeout=5, verbose=0, iface=iface)[0]
        for _, r in result:
            vendor = mac_vendor(r.hwsrc)
            label  = vendor_to_label(vendor) or vendor
            devices.append({"ip": r.psrc, "mac": r.hwsrc,
                             "hostname": label or "unknown", "vendor": vendor})
        if devices:
            print(f"[ARP Scan] Found {len(devices)} device(s)")
            return devices
    except Exception as e:
        print(f"[ARP Scan Error] {e}")

    # Last resort: gateway only
    print("[*] No hosts found. Adding gateway only.")
    return get_gateway()
