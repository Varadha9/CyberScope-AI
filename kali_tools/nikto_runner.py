import subprocess

def nikto_scan(target, port=80):
    """Run nikto web vulnerability scan on a target"""
    findings = []
    try:
        ssl_flag = ["-ssl"] if port in (443, 8443) else []
        cmd = ["nikto", "-h", target, "-p", str(port), "-maxtime", "30s",
               "-nointeractive", "-Format", "txt", "-output", "/dev/null"] + ssl_flag
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=45, text=True)
        for line in out.splitlines():
            line = line.strip("+ ").strip()
            if not line:
                continue
            # Skip noisy/meta lines
            if any(skip in line for skip in [
                "OSVDB", "Server:", "Start Time:", "End Time:", "Target IP:",
                "Target Hostname:", "Target Port:", "Platform:", "host(s) tested",
                "Scan terminated", "No CGI", "CGI tests skipped"
            ]):
                continue
            if line.startswith("-") or line.startswith("+"):
                findings.append(line.strip("+ -").strip())
            elif "VULNERABLE" in line or "missing" in line or "CVE" in line:
                findings.append(line)
    except subprocess.TimeoutExpired:
        print(f"[Nikto] Timeout on {target}:{port}")
    except Exception as e:
        print(f"[Nikto Error] {e}")
    return findings[:10]  # cap at 10 findings
