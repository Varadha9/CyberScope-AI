import subprocess

def searchsploit_scan(services: dict):
    """Search Exploit-DB for each detected service version"""
    findings = []
    seen = set()
    for port, svc in services.items():
        if not svc:
            continue
        # svc is a dict: {name, product, version}
        if isinstance(svc, dict):
            parts = [svc.get("product", ""), svc.get("version", "")]
            query = " ".join(p for p in parts if p).strip()
            if not query:
                query = svc.get("name", "").strip()
        else:
            query = " ".join(str(svc).split()[:2])
        if not query or query in seen:
            continue
        seen.add(query)
        try:
            out = subprocess.check_output(
                ["searchsploit", query],
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
