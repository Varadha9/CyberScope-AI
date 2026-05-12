import subprocess

def fierce_scan(target):
    findings = []
    try:
        out = subprocess.check_output(
            ["fierce", "--domain", target],
            stderr=subprocess.DEVNULL, timeout=25, text=True
        )
        for line in out.splitlines():
            line = line.strip()
            if line and any(kw in line for kw in ["Found:", "Nearby:", "IP:", "Subdomain"]):
                findings.append(line)
    except subprocess.TimeoutExpired:
        print(f"[Fierce] Timeout on {target}")
    except Exception as e:
        print(f"[Fierce Error] {e}")
    return findings[:10]
