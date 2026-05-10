import subprocess
import re

def netdiscover_scan(subnet):
    """Passive/active host discovery using netdiscover on wlan0"""
    devices = []
    try:
        cmd = ["netdiscover", "-r", subnet, "-i", "wlan0", "-P", "-N", "-c", "3"]
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=30, text=True)
        for line in out.splitlines():
            # Format:  10.50.x.x   aa:bb:cc:dd:ee:ff   1   60   Vendor
            m = re.match(r"\s*([\d.]+)\s+([0-9a-f:]{17})", line, re.IGNORECASE)
            if m:
                devices.append({"ip": m.group(1), "mac": m.group(2)})
    except subprocess.TimeoutExpired:
        print("[Netdiscover] Timeout")
    except Exception as e:
        print(f"[Netdiscover Error] {e}")
    return devices
