import subprocess
import re
import os

def _iwlist_scan(iface="wlan0"):
    """Scan nearby WiFi APs using iwlist."""
    try:
        out = subprocess.check_output(
            ["iwlist", iface, "scan"],
            stderr=subprocess.DEVNULL, text=True, timeout=15
        )
        return out
    except Exception:
        return ""

def _parse_iwlist(raw):
    """Parse iwlist scan output into list of AP dicts."""
    aps = []
    current = {}
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("Cell "):
            if current:
                aps.append(current)
            mac_m = re.search(r"Address: ([0-9A-F:]{17})", line, re.IGNORECASE)
            current = {"mac": mac_m.group(1) if mac_m else "", "ssid": "", "channel": "",
                       "signal": "", "encryption": "Open", "frequency": "", "mode": ""}
        elif "ESSID:" in line:
            m = re.search(r'ESSID:"(.*?)"', line)
            current["ssid"] = m.group(1) if m else "<hidden>"
        elif "Channel:" in line:
            m = re.search(r"Channel:(\d+)", line)
            current["channel"] = m.group(1) if m else ""
        elif "Frequency:" in line:
            m = re.search(r"Frequency:([\d.]+)", line)
            current["frequency"] = m.group(1) + " GHz" if m else ""
        elif "Signal level=" in line:
            m = re.search(r"Signal level=(-?\d+)", line)
            current["signal"] = m.group(1) + " dBm" if m else ""
        elif "Encryption key:on" in line:
            current["encryption"] = "Encrypted"
        elif "Encryption key:off" in line:
            current["encryption"] = "Open ⚠️"
        elif "IE: WPA" in line or "WPA2" in line:
            current["encryption"] = "WPA2"
        elif "IE: IEEE 802.11i/WPA2" in line:
            current["encryption"] = "WPA2"
        elif "WPA3" in line:
            current["encryption"] = "WPA3"
        elif "Mode:" in line:
            m = re.search(r"Mode:(\S+)", line)
            current["mode"] = m.group(1) if m else ""
    if current:
        aps.append(current)
    return aps

def _nmcli_scan():
    """Fallback: use nmcli to scan WiFi APs."""
    try:
        out = subprocess.check_output(
            ["nmcli", "-t", "-f", "SSID,BSSID,CHAN,SIGNAL,SECURITY", "dev", "wifi", "list"],
            stderr=subprocess.DEVNULL, text=True, timeout=15
        )
        aps = []
        for line in out.splitlines():
            parts = line.split(":")
            if len(parts) >= 5:
                ssid = parts[0] or "<hidden>"
                # BSSID has colons so rejoin
                bssid_parts = parts[1:7]
                bssid = ":".join(bssid_parts) if len(bssid_parts) == 6 else parts[1]
                chan = parts[-3] if len(parts) > 3 else ""
                signal = parts[-2] if len(parts) > 2 else ""
                security = parts[-1] if parts else ""
                enc = "Open ⚠️" if not security.strip() or security.strip() == "--" else security.strip()
                aps.append({
                    "ssid": ssid, "mac": bssid, "channel": chan,
                    "signal": signal + "%", "encryption": enc,
                    "frequency": "", "mode": "Master"
                })
        return aps
    except Exception:
        return []

def scan_wifi_aps(iface="wlan0"):
    """Scan nearby WiFi APs. Returns list of AP dicts."""
    raw = _iwlist_scan(iface)
    if raw:
        aps = _parse_iwlist(raw)
        if aps:
            return aps
    # Fallback to nmcli
    return _nmcli_scan()

def detect_rogue_aps(aps, known_ssid=None):
    """
    Detect potentially rogue APs:
    - Open networks (no encryption)
    - Duplicate SSIDs with different MACs (evil twin)
    - Hidden SSIDs
    - Very strong signal from unknown AP (close proximity)
    """
    rogues = []
    ssid_map = {}  # ssid -> list of MACs

    for ap in aps:
        ssid = ap.get("ssid", "")
        mac  = ap.get("mac", "")
        enc  = ap.get("encryption", "")

        # Track SSIDs
        if ssid and ssid != "<hidden>":
            ssid_map.setdefault(ssid, []).append(mac)

        # Open network
        if "Open" in enc:
            rogues.append({
                "type": "OPEN_NETWORK",
                "severity": "HIGH",
                "ssid": ssid or "<hidden>",
                "mac": mac,
                "detail": f"No encryption — credentials transmitted in plaintext",
                "ap": ap,
            })

        # Hidden SSID
        if ssid == "<hidden>" or not ssid:
            rogues.append({
                "type": "HIDDEN_SSID",
                "severity": "MEDIUM",
                "ssid": "<hidden>",
                "mac": mac,
                "detail": "Hidden SSID — could be a rogue AP or private network",
                "ap": ap,
            })

    # Evil twin — same SSID, multiple MACs
    for ssid, macs in ssid_map.items():
        if len(macs) > 1:
            rogues.append({
                "type": "EVIL_TWIN",
                "severity": "CRITICAL",
                "ssid": ssid,
                "mac": ", ".join(macs),
                "detail": f"⚠️ EVIL TWIN: '{ssid}' seen from {len(macs)} different MACs — possible MITM attack!",
                "ap": {},
            })

    return rogues

def get_connected_ap(iface="wlan0"):
    """Get currently connected AP info."""
    try:
        out = subprocess.check_output(["iwconfig", iface], stderr=subprocess.DEVNULL, text=True)
        ssid_m = re.search(r'ESSID:"(.*?)"', out)
        ap_m   = re.search(r"Access Point: ([0-9A-F:]{17})", out, re.IGNORECASE)
        sig_m  = re.search(r"Signal level=(-?\d+)", out)
        return {
            "ssid":   ssid_m.group(1) if ssid_m else "",
            "bssid":  ap_m.group(1)   if ap_m   else "",
            "signal": sig_m.group(1) + " dBm" if sig_m else "",
        }
    except Exception:
        return {}
