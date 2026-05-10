import nmap

_scanner = nmap.PortScanner()

def scan_ports(target, port_range="--top-ports 1000"):
    """Fast port scan on top 1000 ports"""
    try:
        _scanner.scan(target, arguments=f"-T4 --open {port_range}")
        open_ports = []
        for host in _scanner.all_hosts():
            for proto in _scanner[host].all_protocols():
                for port, data in _scanner[host][proto].items():
                    if data["state"] == "open":
                        open_ports.append(port)
        return open_ports
    except Exception as e:
        print(f"[Port Scan Error] {e}")
        return []
