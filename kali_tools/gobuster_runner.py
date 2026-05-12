import subprocess
import os

WORDLIST = "/usr/share/wordlists/dirb/common.txt"

def gobuster_scan(target, port=80):
    findings = []
    if not os.path.exists(WORDLIST):
        return ["Wordlist not found: " + WORDLIST]
    try:
        url = f"http{'s' if port in (443, 8443) else ''}://{target}:{port}"
        out = subprocess.check_output(
            ["gobuster", "dir", "-u", url, "-w", WORDLIST,
             "-t", "20", "-q", "--no-error", "-o", "/dev/stdout",
             "--timeout", "5s"],
            stderr=subprocess.DEVNULL, timeout=30, text=True
        )
        for line in out.splitlines():
            line = line.strip()
            if line and line.startswith("/"):
                findings.append(line)
    except subprocess.TimeoutExpired:
        print(f"[Gobuster] Timeout on {target}:{port}")
    except Exception as e:
        print(f"[Gobuster Error] {e}")
    return findings[:10]
