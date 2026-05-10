import subprocess

def nikto_scan(target, port=80):
    """Run nikto web vulnerability scan on a target"""
    findings = []
    try:
        ssl_flag = ["-ssl"] if port in (443, 8443) else []
        cmd = ["nikto", "-h", target, "-p", str(port), "-maxtime", "60s",
               "-nointeractive", "-Format", "txt"] + ssl_flag
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=90, text=True)
        for line in out.splitlines():
            if line.startswith("+") and "OSVDB" not in line and "Server:" not in line:
                findings.append(line.strip("+ ").strip())
    except subprocess.TimeoutExpired:
        print(f"[Nikto] Timeout on {target}:{port}")
    except Exception as e:
        print(f"[Nikto Error] {e}")
    return findings[:10]  # cap at 10 findings
