import subprocess

def sslscan_scan(target, port=443):
    findings = []
    try:
        out = subprocess.check_output(
            ["sslscan", "--no-colour", f"{target}:{port}"],
            stderr=subprocess.DEVNULL, timeout=30, text=True
        )
        for line in out.splitlines():
            line = line.strip()
            if any(kw in line for kw in ["Vulnerable", "enabled", "SSLv", "TLSv", "Heartbleed", "POODLE", "expired", "self-signed"]):
                findings.append(line)
    except subprocess.TimeoutExpired:
        print(f"[SSLScan] Timeout on {target}:{port}")
    except Exception as e:
        print(f"[SSLScan Error] {e}")
    return findings[:10]
