import urllib.request
import json
import threading

_cache = {}
_lock = threading.Lock()

# Countries that are commonly associated with C2/exfil — flag these
SUSPICIOUS_COUNTRIES = {
    "CN", "RU", "KP", "IR", "BY", "SY", "CU", "VE", "MM",
}

def lookup(ip):
    """Return geo info dict for an IP. Cached. Returns {} on failure."""
    if ip.startswith(("192.168.", "10.", "172.16.", "172.17.", "172.18.",
                      "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                      "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                      "172.29.", "172.30.", "172.31.", "127.", "0.")):
        return {"country": "Local", "countryCode": "LO", "flag": "🏠", "suspicious": False, "city": ""}

    with _lock:
        if ip in _cache:
            return _cache[ip]

    try:
        url = f"http://ip-api.com/json/{ip}?fields=country,countryCode,city,org,lat,lon"
        with urllib.request.urlopen(url, timeout=3) as r:
            d = json.loads(r.read())
        cc = d.get("countryCode", "")
        name = d.get("country", "")
        flag = "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in cc.upper()) if len(cc) == 2 else "🌐"
        result = {
            "country": name,
            "countryCode": cc,
            "city": d.get("city", ""),
            "org": d.get("org", ""),
            "lat": d.get("lat", 0),
            "lon": d.get("lon", 0),
            "flag": flag,
            "suspicious": cc in SUSPICIOUS_COUNTRIES,
        }
    except Exception:
        result = {"country": "", "countryCode": "", "flag": "🌐", "suspicious": False, "city": ""}

    with _lock:
        _cache[ip] = result
    return result


def enrich_packets(packets):
    """Add geo info to a list of packet dicts (from watch_ip). Modifies in-place."""
    seen = set()
    for p in packets:
        ip = p.get("remote_ip", "")
        if not ip or ip in seen or ip == "DNS":
            continue
        seen.add(ip)
        geo = lookup(ip)
        p["country"] = f"{geo['flag']} {geo['country']}".strip() if geo.get("country") else geo.get("flag", "")
        p["country_code"] = geo.get("countryCode", "")
        p["geo_suspicious"] = geo.get("suspicious", False)
    return packets
