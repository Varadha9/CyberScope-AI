import subprocess

def tcpdump_capture(iface="wlan0", count=20):
    packets = []
    try:
        out = subprocess.check_output(
            ["tcpdump", "-i", iface, "-c", str(count), "-nn", "-l", "--immediate-mode"],
            stderr=subprocess.DEVNULL, timeout=30, text=True
        )
        for line in out.splitlines():
            line = line.strip()
            if line:
                packets.append(line)
    except subprocess.TimeoutExpired:
        pass
    except Exception as e:
        print(f"[Tcpdump Error] {e}")
    return packets
