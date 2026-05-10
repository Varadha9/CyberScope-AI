import subprocess

def tshark_capture(iface="wlan0", count=20):
    packets = []
    try:
        out = subprocess.check_output(
            ["tshark", "-i", iface, "-c", str(count), "-T", "fields",
             "-e", "frame.time_relative", "-e", "ip.src", "-e", "ip.dst",
             "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "_ws.col.Protocol",
             "-e", "frame.len"],
            stderr=subprocess.DEVNULL, timeout=30, text=True
        )
        for line in out.splitlines():
            parts = line.strip().split("\t")
            if len(parts) >= 4:
                packets.append({
                    "time": parts[0], "src": parts[1], "dst": parts[2],
                    "sport": parts[3], "dport": parts[4] if len(parts) > 4 else "",
                    "proto": parts[5] if len(parts) > 5 else "",
                    "len": parts[6] if len(parts) > 6 else ""
                })
    except subprocess.TimeoutExpired:
        pass
    except Exception as e:
        print(f"[Tshark Error] {e}")
    return packets
