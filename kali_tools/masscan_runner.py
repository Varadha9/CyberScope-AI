import subprocess
import re

def masscan_quick(subnet, rate=1000):
    """Fast port discovery using masscan on WiFi subnet"""
    results = []
    try:
        cmd = ["masscan", subnet, "-p", "22,23,80,443,445,3389,8080,8443,21,25,110,3306,5432",
               "--rate", str(rate), "--wait", "2", "-e", "wlan0"]
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=60, text=True)
        for line in out.splitlines():
            # Discovered open port 80/tcp on 10.50.x.x
            m = re.search(r"port (\d+)/(\w+) on ([\d.]+)", line)
            if m:
                results.append({"port": int(m.group(1)), "proto": m.group(2), "ip": m.group(3)})
    except subprocess.TimeoutExpired:
        print("[Masscan] Timeout")
    except Exception as e:
        print(f"[Masscan Error] {e}")
    return results
