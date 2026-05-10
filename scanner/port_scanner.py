import nmap

_scanner = nmap.PortScanner()

def scan_ports(target, port_range="1-1000"):
    _scanner.scan(target, port_range)
    open_ports = []
    for host in _scanner.all_hosts():
        for proto in _scanner[host].all_protocols():
            for port, data in _scanner[host][proto].items():
                if data["state"] == "open":
                    open_ports.append(port)
    return open_ports
