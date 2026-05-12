import subprocess
import re
from collections import defaultdict

def get_dns_queries(ip, iface="wlan0", count=500, timeout=20):
    """Capture DNS queries from a specific IP. Returns list of {domain, count, app}."""
    try:
        out = subprocess.check_output(
            ["tshark", "-i", iface, "-c", str(count),
             "-f", f"src host {ip} and udp port 53",
             "-T", "fields",
             "-e", "dns.qry.name",
             "-e", "frame.time_epoch",
             "-a", f"duration:{timeout}"],
            stderr=subprocess.DEVNULL, text=True, timeout=timeout + 5
        )
    except Exception:
        return []

    counts = defaultdict(lambda: {"count": 0, "timestamps": []})
    for line in out.splitlines():
        parts = line.strip().split("\t")
        domain = parts[0].strip() if parts else ""
        ts = parts[1].strip() if len(parts) > 1 else ""
        if not domain or domain == "0.0.0.0":
            continue
        counts[domain]["count"] += 1
        if ts:
            try:
                counts[domain]["timestamps"].append(float(ts))
            except ValueError:
                pass

    result = []
    for domain, info in sorted(counts.items(), key=lambda x: -x[1]["count"]):
        result.append({
            "domain": domain,
            "count": info["count"],
            "timestamps": info["timestamps"][:10],
        })
    return result


def get_subnet_dns(iface="wlan0", count=300, timeout=15):
    """Capture DNS queries from all local IPs. Returns {ip: [domains]}."""
    try:
        out = subprocess.check_output(
            ["tshark", "-i", iface, "-c", str(count),
             "-f", "udp port 53",
             "-T", "fields",
             "-e", "ip.src",
             "-e", "dns.qry.name",
             "-a", f"duration:{timeout}"],
            stderr=subprocess.DEVNULL, text=True, timeout=timeout + 5
        )
    except Exception:
        return {}

    result = defaultdict(set)
    for line in out.splitlines():
        parts = line.strip().split("\t")
        if len(parts) < 2:
            continue
        src, domain = parts[0].strip(), parts[1].strip()
        if src.startswith("192.168.") and domain:
            result[src].add(domain)

    return {ip: list(domains) for ip, domains in result.items()}
