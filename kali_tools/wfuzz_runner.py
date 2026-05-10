import subprocess
import os

WORDLIST = "/usr/share/wordlists/dirb/common.txt"

def wfuzz_scan(target, port=80):
    findings = []
    if not os.path.exists(WORDLIST):
        return ["Wordlist not found: " + WORDLIST]
    try:
        url = f"http{'s' if port in (443, 8443) else ''}://{target}:{port}/FUZZ"
        out = subprocess.check_output(
            ["wfuzz", "-w", WORDLIST, "--hc", "404", "-t", "20", "-f", "/dev/stdout,raw", url],
            stderr=subprocess.DEVNULL, timeout=90, text=True
        )
        for line in out.splitlines():
            line = line.strip()
            if line and not line.startswith("*") and "FUZZ" not in line and line:
                findings.append(line)
    except subprocess.TimeoutExpired:
        print(f"[Wfuzz] Timeout on {target}:{port}")
    except Exception as e:
        print(f"[Wfuzz Error] {e}")
    return findings[:10]
