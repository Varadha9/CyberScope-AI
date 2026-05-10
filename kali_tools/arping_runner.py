import subprocess
import re

def arping_discover(subnet_base, count=5):
    """ARP ping a range of IPs to discover live hosts"""
    devices = []
    base = subnet_base.rsplit(".", 1)[0]
    for i in range(1, count + 1):
        ip = f"{base}.{i}"
        try:
            out = subprocess.check_output(
                ["arping", "-c", "1", "-W", "1", ip],
                stderr=subprocess.DEVNULL, timeout=5, text=True
            )
            mac_m = re.search(r"\[([0-9A-Fa-f:]{17})\]", out)
            if "1 response" in out or mac_m:
                mac = mac_m.group(1) if mac_m else "unknown"
                devices.append({"ip": ip, "mac": mac})
        except Exception:
            pass
    return devices
