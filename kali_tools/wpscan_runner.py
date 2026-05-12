import subprocess

def wpscan(target, port=80):
    findings = []
    try:
        url = f"http{'s' if port in (443, 8443) else ''}://{target}:{port}"
        out = subprocess.check_output(
            ["wpscan", "--url", url, "--no-update", "--format", "cli",
             "--max-threads", "5"],
            stderr=subprocess.DEVNULL, timeout=40, text=True
        )
        for line in out.splitlines():
            line = line.strip()
            if any(kw in line for kw in ["[!]", "[+]", "vulnerability", "CVE", "outdated"]):
                findings.append(line.lstrip("[!] ").lstrip("[+] ").strip())
    except subprocess.TimeoutExpired:
        print(f"[WPScan] Timeout on {target}:{port}")
    except Exception as e:
        print(f"[WPScan Error] {e}")
    return findings[:10]
