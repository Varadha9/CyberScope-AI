import subprocess

def searchsploit_scan(services: dict):
    """Search Exploit-DB for each detected service version"""
    findings = []
    seen = set()
    for port, svc in services.items():
        if not svc or svc in seen:
            continue
        seen.add(svc)
        # Use first 2 words of service string for better matches
        query = " ".join(svc.split()[:2])
        try:
            out = subprocess.check_output(
                ["searchsploit", "--colour", query],
                stderr=subprocess.DEVNULL, timeout=15, text=True
            )
            for line in out.splitlines():
                line = line.strip()
                if line and "|" in line and "Title" not in line and "---" not in line:
                    findings.append(f"[Port {port}] {line}")
        except Exception as e:
            print(f"[SearchSploit Error] {e}")
        if len(findings) >= 10:
            break
    return findings[:10]
