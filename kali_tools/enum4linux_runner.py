import subprocess

def enum4linux_scan(target):
    findings = []
    try:
        out = subprocess.check_output(
            ["enum4linux", "-a", target],
            stderr=subprocess.DEVNULL, timeout=90, text=True
        )
        for line in out.splitlines():
            line = line.strip()
            if any(kw in line for kw in ["[+]", "Share", "user:", "Group", "Domain", "Password Policy"]):
                findings.append(line.lstrip("[+] ").strip())
    except subprocess.TimeoutExpired:
        print(f"[Enum4linux] Timeout on {target}")
    except Exception as e:
        print(f"[Enum4linux Error] {e}")
    return findings[:10]
