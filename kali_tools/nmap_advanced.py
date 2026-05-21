import nmap

_nm = nmap.PortScanner()

def os_detect(target):
    """OS fingerprinting via nmap -O — returns clean human-readable string."""
    try:
        _nm.scan(target, arguments="-O --osscan-guess -T4")
        for host in _nm.all_hosts():
            osmatch = _nm[host].get("osmatch", [])
            if osmatch:
                name = osmatch[0].get("name", "")
                if name:
                    return _clean_os(name)
    except Exception as e:
        print(f"[OS Detect Error] {e}")
    return "Unknown"

def _clean_os(raw):
    """Convert raw nmap OS string to short readable label."""
    import re
    # Strip SCAN(...) fingerprint blobs entirely
    if raw.startswith("SCAN(") or raw.startswith("OS:"):
        return "Unknown"
    r = raw.lower()
    if "windows 11" in r:  return "Windows 11"
    if "windows 10" in r:  return "Windows 10"
    if "windows server 2022" in r: return "Windows Server 2022"
    if "windows server 2019" in r: return "Windows Server 2019"
    if "windows server 2016" in r: return "Windows Server 2016"
    if "windows server" in r: return "Windows Server"
    if "windows 7" in r:   return "Windows 7"
    if "windows xp" in r:  return "Windows XP"
    if "windows" in r:     return "Windows"
    if "android" in r:     return "Android"
    if "ios" in r:         return "iOS"
    if "macos" in r or "mac os x" in r: return "macOS"
    if "ubuntu" in r:      return "Ubuntu Linux"
    if "debian" in r:      return "Debian Linux"
    if "centos" in r:      return "CentOS Linux"
    if "fedora" in r:      return "Fedora Linux"
    if "linux" in r:       return "Linux"
    if "openwrt" in r:     return "OpenWrt (Router)"
    if "freebsd" in r:     return "FreeBSD"
    if "cisco" in r:       return "Cisco IOS"
    # Return first 40 chars of raw if nothing matched
    return raw[:40].strip()

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
