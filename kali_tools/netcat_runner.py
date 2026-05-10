import subprocess

def netcat_banner(target, ports):
    banners = {}
    for port in ports[:5]:
        try:
            out = subprocess.check_output(
                ["nc", "-w", "3", "-z", "-v", target, str(port)],
                stderr=subprocess.STDOUT, timeout=10, text=True
            )
            for line in out.splitlines():
                if line.strip():
                    banners[port] = line.strip()
                    break
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass
    return banners
