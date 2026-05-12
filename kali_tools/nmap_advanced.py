import nmap

_nm = nmap.PortScanner()

def os_detect(target):
    """OS fingerprinting via nmap -O"""
    try:
        _nm.scan(target, arguments="-O --osscan-guess -T4")
        for host in _nm.all_hosts():
            osmatch = _nm[host].get("osmatch", [])
            if osmatch:
                return osmatch[0].get("name", "Unknown")
    except Exception as e:
        print(f"[OS Detect Error] {e}")
    return "Unknown"

def service_scan(target):
    """Service/version detection -sV on known open ports only"""
    services = {}
    try:
        _nm.scan(target, arguments="-sV -T4 --open --top-ports 1000")
        for host in _nm.all_hosts():
            for proto in _nm[host].all_protocols():
                for port, data in _nm[host][proto].items():
                    if data["state"] == "open":
                        services[port] = {
                            "name": data.get("name", ""),
                            "product": data.get("product", ""),
                            "version": data.get("version", ""),
                        }
    except Exception as e:
        print(f"[Service Scan Error] {e}")
    return services

def vuln_scan(target, open_ports):
    """Nmap vuln scripts on open ports"""
    vulns = []
    if not open_ports:
        return vulns
    ports_str = ",".join(str(p) for p in open_ports[:20])  # limit to 20 ports
    try:
        _nm.scan(target, ports_str, arguments="--script vuln -T4")
        for host in _nm.all_hosts():
            for proto in _nm[host].all_protocols():
                for port, data in _nm[host][proto].items():
                    scripts = data.get("script", {})
                    for script_name, output in scripts.items():
                        if "VULNERABLE" in output or "CVE" in output:
                            vulns.append(f"[{port}] {script_name}: {output[:200]}")
    except Exception as e:
        print(f"[Vuln Scan Error] {e}")
    return vulns
