import subprocess

def whatweb_scan(target, port=80):
    findings = []
    try:
        url = f"http{'s' if port in (443, 8443) else ''}://{target}:{port}"
        out = subprocess.check_output(
            ["whatweb", "--no-errors", "-a", "1", url],
            stderr=subprocess.DEVNULL, timeout=30, text=True
        )
        for line in out.splitlines():
            line = line.strip()
            if line:
                findings.append(line)
    except subprocess.TimeoutExpired:
        print(f"[WhatWeb] Timeout on {target}:{port}")
    except Exception as e:
        print(f"[WhatWeb Error] {e}")
    return findings[:5]
