import subprocess

def sqlmap_scan(target, port=80):
    findings = []
    try:
        url = f"http{'s' if port in (443, 8443) else ''}://{target}:{port}"
        out = subprocess.check_output(
            ["sqlmap", "-u", url, "--batch", "--level=1", "--risk=1",
             "--timeout=10", "--retries=1", "--output-dir=/tmp/sqlmap_out"],
            stderr=subprocess.DEVNULL, timeout=120, text=True
        )
        for line in out.splitlines():
            line = line.strip()
            if any(kw in line for kw in ["injectable", "vulnerable", "parameter", "payload", "Type:"]):
                findings.append(line)
    except subprocess.TimeoutExpired:
        print(f"[SQLMap] Timeout on {target}:{port}")
    except Exception as e:
        print(f"[SQLMap Error] {e}")
    return findings[:10]
