import subprocess
import socket
import re
from collections import defaultdict

# ── Own IPs (filter self-traffic) ──────────────────────────────────────────
def _get_own_ips():
    ips = set()
    try:
        out = subprocess.check_output(["ip", "addr", "show"], text=True)
        for m in re.finditer(r"inet (\d+\.\d+\.\d+\.\d+)", out):
            ips.add(m.group(1))
    except Exception:
        pass
    ips.add("127.0.0.1")
    return ips

OWN_IPS = _get_own_ips()

# ── Port → Service ──────────────────────────────────────────────────────────
PORT_LABELS = {
    80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH", 21: "FTP",
    25: "SMTP", 110: "POP3", 143: "IMAP", 3306: "MySQL",
    5432: "PostgreSQL", 3389: "RDP", 23: "Telnet", 445: "SMB",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 1935: "RTMP",
    554: "RTSP", 5353: "mDNS", 67: "DHCP", 68: "DHCP",
    123: "NTP", 161: "SNMP", 1883: "MQTT", 5228: "FCM/Push",
    5222: "XMPP", 6881: "BitTorrent", 27015: "Steam",
    3074: "Xbox", 8000: "HTTP-Alt", 9010: "Custom",
    4244: "WhatsApp", 5223: "Apple Push", 2195: "Apple Push",
    8883: "MQTT-SSL", 9243: "Elasticsearch",
}

# ── IP prefix → Organization ────────────────────────────────────────────────
IP_ORG_MAP = [
    (["142.250.", "172.217.", "216.58.", "74.125.", "64.233.",
      "66.102.", "173.194.", "209.85.", "35.190.", "35.191.",
      "34.64.",  "34.65.",  "34.66.",  "34.67.",  "34.68.",
      "34.69.",  "34.70.",  "34.71.",  "34.72.",  "34.73.",
      "34.74.",  "34.75.",  "34.76.",  "34.77.",  "34.78.",
      "34.79.",  "34.80.",  "34.81.",  "34.82.",  "34.83.",
      "34.84.",  "34.85.",  "34.86.",  "34.87.",  "34.88.",
      "34.89.",  "34.90.",  "34.91.",  "34.92.",  "34.93.",
      "34.94.",  "34.95.",  "34.96.",  "34.97.",  "34.98.",
      "34.99.",  "34.100.", "34.101.", "34.102.", "34.103.",
      "34.104.", "34.105.", "34.106.", "34.107.", "34.108.",
      "34.109.", "34.110.", "34.111.", "34.112.", "34.113.",
      "34.114.", "34.115.", "34.116.", "34.117.", "34.118.",
      "34.119.", "34.120.", "34.121.", "34.122.", "34.123.",
      "34.124.", "34.125.", "34.126.", "34.127.", "34.128.",
      "34.129.", "34.130.", "34.131.", "34.132.", "34.133.",
      "34.134.", "34.135.", "34.136.", "34.137.", "34.138.",
      "34.139.", "34.140.", "34.141.", "34.142.", "34.143.",
      "34.144.", "34.145.", "34.146.", "34.147.", "34.148.",
      "34.149.", "34.150.", "34.151.", "34.152.", "34.153.",
      "34.154.", "34.155.", "34.156.", "34.157.", "34.158.",
      "34.159.", "34.160."],
     "📺 Google / YouTube"),

    (["157.240.", "31.13.", "179.60.", "185.89.",
      "129.134.", "163.70.", "163.77.", "204.15."],
     "💬 Facebook / Instagram / WhatsApp"),

    (["20.", "40.", "52.1", "52.2", "52.3", "52.4", "52.5",
      "52.6", "52.7", "52.8", "52.9", "13.107.", "13.64.",
      "13.65.", "13.66.", "13.67.", "13.68.", "13.69.", "13.70.",
      "13.71.", "13.72.", "13.73.", "13.74.", "13.75.", "13.76.",
      "13.77.", "13.78.", "13.79.", "13.80.", "13.81.", "13.82.",
      "13.83.", "13.84.", "13.85.", "13.86.", "13.87.", "13.88.",
      "13.89.", "13.90.", "13.91.", "13.92.", "13.93.", "13.94.",
      "13.95.", "13.96.", "13.97.", "13.98.", "13.99.",
      "13.200.", "13.201.", "13.202.", "13.203.", "13.204.",
      "13.205.", "13.206.", "13.207.", "13.208.", "13.209.",
      "13.210.", "13.211.", "13.212.", "13.213.", "13.214.",
      "13.215.", "13.216.", "13.217.", "13.218.", "13.219.",
      "13.220.", "13.221.", "13.222.", "13.223.", "13.224.",
      "13.225.", "13.226.", "13.227.", "13.228.", "13.229.",
      "13.230.", "13.231.", "13.232.", "13.233.", "13.234.",
      "13.235.", "13.236.", "13.237.", "13.238.", "13.239.",
      "13.240.", "13.241.", "13.242.", "13.243.", "13.244.",
      "13.245.", "13.246.", "13.247.", "13.248.", "13.249.",
      "13.250.", "13.251.", "13.252.", "13.253.", "13.254.",
      "13.255."],
     "🪟 Microsoft / Azure"),

    (["54.", "18.", "3.0.", "3.1.", "3.2.", "3.3.", "3.4.",
      "3.5.", "3.6.", "3.7.", "3.8.", "3.9.", "3.10.", "3.11.",
      "3.12.", "3.13.", "3.14.", "3.15.", "3.16.", "3.17.",
      "3.18.", "3.19.", "3.20.", "3.21.", "3.22.", "3.23.",
      "3.24.", "3.25.", "3.26.", "3.27.", "3.28.", "3.29.",
      "3.100.", "3.101.", "3.102.", "3.103.", "3.104.", "3.105.",
      "3.106.", "3.107.", "3.108.", "3.109.", "3.110.", "3.111.",
      "3.112.", "3.113.", "3.114.", "3.115.", "3.116.", "3.117.",
      "3.118.", "3.119.", "3.120.", "3.121.", "3.122.", "3.123.",
      "3.124.", "3.125.", "3.126.", "3.127.", "3.128.", "3.129.",
      "3.130.", "3.131.", "3.132.", "3.133.", "3.134.", "3.135.",
      "3.136.", "3.137.", "3.138.", "3.139.", "3.140.", "3.141.",
      "3.142.", "3.143.", "3.144.", "3.145.", "3.146.", "3.147.",
      "3.148.", "3.149.", "3.150.", "3.151.", "3.152.", "3.153.",
      "3.154.", "3.155.", "3.156.", "3.157.", "3.158.", "3.159.",
      "3.160.", "3.161.", "3.162.", "3.163.", "3.164.", "3.165.",
      "3.166.", "3.167.", "3.168.", "3.169.", "3.170.", "3.171.",
      "3.172.", "3.173.", "3.174.", "3.175.", "3.176.", "3.177.",
      "3.178.", "3.179.", "3.180.", "3.181.", "3.182.", "3.183.",
      "3.184.", "3.185.", "3.186.", "3.187.", "3.188.", "3.189.",
      "3.190.", "3.191.", "3.192.", "3.193.", "3.194.", "3.195.",
      "3.196.", "3.197.", "3.198.", "3.199.", "3.200.", "3.201.",
      "3.202.", "3.203.", "3.204.", "3.205.", "3.206.", "3.207.",
      "3.208.", "3.209.", "3.210.", "3.211.", "3.212.", "3.213.",
      "3.214.", "3.215.", "3.216.", "3.217.", "3.218.", "3.219.",
      "3.220.", "3.221.", "3.222.", "3.223.", "3.224.", "3.225.",
      "3.226.", "3.227.", "3.228.", "3.229.", "3.230.", "3.231.",
      "3.232.", "3.233.", "3.234.", "3.235.", "3.236.", "3.237.",
      "3.238.", "3.239.", "3.240.", "3.241.", "3.242.", "3.243.",
      "3.244.", "3.245.", "3.246.", "3.247.", "3.248.", "3.249.",
      "3.250.", "3.251.", "3.252.", "3.253.", "3.254.", "3.255."],
     "🛒 Amazon / AWS"),

    (["17."],                                    "🍎 Apple / iCloud"),
    (["104.16.", "104.17.", "104.18.", "104.19.",
      "104.20.", "104.21.", "172.64.", "172.65.",
      "172.66.", "172.67.", "172.68.", "172.69.",
      "1.1.1.",  "1.0.0."],                      "☁️ Cloudflare"),
    (["151.101."],                               "📦 Fastly CDN"),
    (["49.44.", "49.45.", "49.46.", "49.47.",
      "1.22.",  "1.23.",  "1.38.",  "1.39.",
      "49.32.", "49.33.", "49.34.", "49.35.",
      "49.36.", "49.37.", "49.38.", "49.39.",
      "49.40.", "49.41.", "49.42.", "49.43.",
      "122.160.", "122.161.", "122.162.", "122.163.",
      "122.164.", "122.165.", "122.166.", "122.167.",
      "122.168.", "122.169.", "122.170.", "122.171.",
      "122.172.", "122.173.", "122.174.", "122.175.",
      "122.176.", "122.177.", "122.178.", "122.179.",
      "122.180.", "122.181.", "122.182.", "122.183.",
      "122.184.", "122.185.", "122.186.", "122.187.",
      "122.188.", "122.189.", "122.190.", "122.191.",
      "122.192.", "122.193.", "122.194.", "122.195.",
      "122.196.", "122.197.", "122.198.", "122.199.",
      "122.200.", "122.201.", "122.202.", "122.203.",
      "122.204.", "122.205.", "122.206.", "122.207.",
      "122.208.", "122.209.", "122.210.", "122.211.",
      "122.212.", "122.213.", "122.214.", "122.215.",
      "122.216.", "122.217.", "122.218.", "122.219.",
      "122.220.", "122.221.", "122.222.", "122.223.",
      "122.224.", "122.225.", "122.226.", "122.227.",
      "122.228.", "122.229.", "122.230.", "122.231.",
      "122.232.", "122.233.", "122.234.", "122.235.",
      "122.236.", "122.237.", "122.238.", "122.239.",
      "122.240.", "122.241.", "122.242.", "122.243.",
      "122.244.", "122.245.", "122.246.", "122.247.",
      "122.248.", "122.249.", "122.250.", "122.251.",
      "122.252.", "122.253.", "122.254.", "122.255."],
     "📡 Jio / Reliance"),
    (["129.227."],                               "📡 Jio Network"),
    (["192.168.", "10.", "172.16.", "172.17.",
      "172.18.", "172.19.", "172.20.", "172.21.",
      "172.22.", "172.23.", "172.24.", "172.25.",
      "172.26.", "172.27.", "172.28.", "172.29.",
      "172.30.", "172.31."],                     "🏠 Local Network"),
]

# ── SNI/hostname → App fingerprint ─────────────────────────────────────────
SNI_APP_MAP = [
    # WhatsApp
    (r"whatsapp|wa\.me|wam\.|w\.net|whatsapp\.net", "💬 WhatsApp"),
    # Instagram
    (r"instagram|cdninstagram|ig-", "📸 Instagram"),
    # Facebook
    (r"facebook|fbcdn|graph\.facebook|fb\.com", "👤 Facebook"),
    # YouTube
    (r"youtube|ytimg|googlevideo|yt3\.|youtu\.be", "▶️ YouTube"),
    # Google services
    (r"googleapis|gstatic|google\.com|gvt1|gvt2|1e100|ggpht", "🔍 Google"),
    # Gmail
    (r"gmail|mail\.google", "📧 Gmail"),
    # Google Play
    (r"play\.google|android\.clients\.google|goog\.gl", "🎮 Google Play"),
    # Chrome / browser
    (r"safebrowsing|update\.googleapis|chrome|chromium", "🌐 Chrome Browser"),
    # Twitter/X
    (r"twitter|twimg|t\.co|abs\.twimg", "🐦 Twitter / X"),
    # Snapchat
    (r"snapchat|sc-cdn|snap\.com", "👻 Snapchat"),
    # TikTok
    (r"tiktok|musical\.ly|bytedance|tiktokcdn|ibytedtos", "🎵 TikTok"),
    # Telegram
    (r"telegram|t\.me|tdesktop|core\.telegram", "✈️ Telegram"),
    # Spotify
    (r"spotify|scdn\.co|audio-sp-", "🎵 Spotify"),
    # Netflix
    (r"netflix|nflx|fast\.com", "🎬 Netflix"),
    # Amazon
    (r"amazon|amazonaws|cloudfront|aws", "🛒 Amazon"),
    # Microsoft
    (r"microsoft|live\.com|outlook|office|xbox|msedge|windows|azure|hotmail", "🪟 Microsoft"),
    # Apple
    (r"apple|icloud|itunes|mzstatic|aaplimg", "🍎 Apple"),
    # Zoom
    (r"zoom\.us|zoomgov", "📹 Zoom"),
    # Jio
    (r"jio|reliance|jiocloud|jiosaavn|jiotv", "📡 Jio"),
    # Hikvision
    (r"hikvision|hik-connect|ezviz", "📷 Hikvision"),
    # GitHub
    (r"github|gitlab|githubusercontent", "💻 GitHub"),
    # Cloudflare
    (r"cloudflare|1\.1\.1\.1|1\.0\.0\.1", "☁️ Cloudflare"),
]

_hostname_cache = {}

def _resolve(ip):
    if ip in _hostname_cache:
        return _hostname_cache[ip]
    try:
        name = socket.gethostbyaddr(ip)[0]
        _hostname_cache[ip] = name
        return name
    except Exception:
        _hostname_cache[ip] = ip
        return ip

def _ip_to_org(ip):
    for prefixes, label in IP_ORG_MAP:
        for prefix in prefixes:
            if ip.startswith(prefix):
                return label
    return None

def _fingerprint(sni, host, remote_ip, dport):
    """Identify the exact app/service from SNI, HTTP host, or IP."""
    combined = (sni or host or "").lower()
    if combined:
        for pattern, label in SNI_APP_MAP:
            if re.search(pattern, combined):
                return label
    # Fall back to IP org
    org = _ip_to_org(remote_ip)
    if org:
        return org
    # Fall back to port
    svc = PORT_LABELS.get(int(dport) if str(dport).isdigit() else 0, "")
    if svc in ("HTTPS", "HTTP", "HTTP-Alt", "HTTPS-Alt"):
        return "🌐 Web Browsing"
    if svc == "DNS":
        return "🔍 DNS Lookup"
    if svc == "RTSP":
        return "📷 Camera Stream"
    if svc == "XMPP":
        return "💬 Chat (XMPP)"
    if svc == "FCM/Push":
        return "🔔 Push Notifications"
    if svc == "NTP":
        return "🕐 Time Sync"
    if svc == "mDNS":
        return "📡 mDNS"
    if svc == "DHCP":
        return "🔧 DHCP"
    return "📦 Other"


def _geo_country(ip):
    """Fast GeoIP lookup using ip-api.com (free, no key needed)."""
    if ip.startswith(("192.168.", "10.", "172.", "127.")):
        return "🏠 Local"
    try:
        import urllib.request, json as _json
        with urllib.request.urlopen(f"http://ip-api.com/json/{ip}?fields=country,countryCode", timeout=2) as r:
            d = _json.loads(r.read())
            cc = d.get("countryCode", "")
            name = d.get("country", "")
            # Flag emoji from country code
            flag = "".join(chr(0x1F1E6 + ord(c) - ord('A')) for c in cc.upper()) if len(cc) == 2 else ""
            return f"{flag} {name}" if name else ""
    except Exception:
        return ""


def detect_beacons(packets, min_repeats=3, max_interval_variance=0.3):
    """Detect C2 beacon patterns — same IP contacted repeatedly at regular intervals."""
    beacons = []
    for p in packets:
        ts = p.get("timestamps", [])
        if len(ts) < min_repeats:
            continue
        ts_sorted = sorted(ts)
        intervals = [ts_sorted[i+1] - ts_sorted[i] for i in range(len(ts_sorted)-1)]
        if not intervals:
            continue
        avg = sum(intervals) / len(intervals)
        if avg < 0.5:  # ignore sub-second bursts (normal TCP)
            continue
        variance = sum(abs(x - avg) for x in intervals) / len(intervals)
        if avg > 0 and (variance / avg) < max_interval_variance:
            beacons.append({
                "ip":       p["remote_ip"],
                "host":     p["remote_host"],
                "app":      p["app"],
                "interval": round(avg, 1),
                "count":    len(ts),
                "country":  p.get("country", ""),
            })
    return beacons


def _detect_activity(remote_host, dport):
    """Detect activity label from hostname and destination port — alias for _fingerprint."""
    return _fingerprint("", remote_host, "", dport)


def _run_tshark(args, timeout):
    """Run tshark with a duration autostop so output is never lost on kill."""
    # Use tshark's built-in duration autostop instead of Python timeout
    # This ensures all captured packets are flushed before process exits
    full_args = ["tshark"] + args + ["-a", f"duration:{timeout}"]
    try:
        out = subprocess.check_output(
            full_args,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout + 5  # safety net only
        )
        return out or ""
    except subprocess.TimeoutExpired:
        return ""
    except Exception:
        return ""


def _get_active_iface():
    """Return the active wireless/ethernet interface."""
    try:
        out = subprocess.check_output(["ip", "route", "show", "default"], text=True)
        import re
        m = re.search(r"dev (\S+)", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return "wlan0"


def watch_ip(ip, iface="wlan0", count=9999, timeout=20):
    seen = {}

    # Auto-detect interface if wlan0 doesn't exist
    import os
    if not os.path.exists(f"/sys/class/net/{iface}"):
        iface = _get_active_iface()

    # Refresh own IPs at call time (app may have started before network was up)
    own_ips = _get_own_ips()

    out = _run_tshark([
        "-i", iface, "-c", str(count),
        "-f", f"host {ip} and not arp",
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "_ws.col.Protocol",
        "-e", "frame.len",
        "-e", "tls.handshake.extensions_server_name",
        "-e", "http.host",
        "-e", "http.request.method",
        "-e", "dns.qry.name",
        "-e", "http.request.uri",
        "-e", "frame.time_epoch",
    ], timeout=timeout)

    for line in out.splitlines():
        parts = line.strip().split("\t")
        if len(parts) < 2:
            continue

        src        = parts[0]
        dst        = parts[1]
        tcp_sp     = parts[2]  if len(parts) > 2  else ""
        tcp_dp     = parts[3]  if len(parts) > 3  else ""
        udp_sp     = parts[4]  if len(parts) > 4  else ""
        udp_dp     = parts[5]  if len(parts) > 5  else ""
        proto      = parts[6]  if len(parts) > 6  else ""
        length     = parts[7]  if len(parts) > 7  else "0"
        sni        = parts[8]  if len(parts) > 8  else ""
        hhost      = parts[9]  if len(parts) > 9  else ""
        hmethod    = parts[10] if len(parts) > 10 else ""
        dns_name   = parts[11] if len(parts) > 11 else ""
        http_uri   = parts[12] if len(parts) > 12 else ""
        frame_time = parts[13] if len(parts) > 13 else ""

        if not src or not dst:
            continue
        if ip not in (src, dst):
            continue

        sport = tcp_sp or udp_sp
        dport = tcp_dp or udp_dp

        # Direction from the target device's perspective
        if src == ip:
            direction   = "OUT"
            remote_ip   = dst
            remote_port = dport
        else:
            direction   = "IN"
            remote_ip   = src
            remote_port = sport

        if not remote_ip or remote_ip == ip:
            continue
        # Skip multicast / broadcast
        if remote_ip.startswith("224.") or remote_ip.startswith("239.") or remote_ip.endswith(".255"):
            continue

        # ── Label our own IP as "This Scanner" instead of dropping it ──
        is_scanner = remote_ip in own_ips

        # DNS query
        if dns_name and src == ip:
            key = ("dns", dns_name)
            if key not in seen:
                app = _fingerprint(dns_name, "", remote_ip, 53)
                seen[key] = {
                    "direction":   "OUT",
                    "remote_ip":   "DNS",
                    "remote_host": dns_name,
                    "remote_port": "53",
                    "service":     "DNS Query",
                    "proto":       "DNS",
                    "app":         app,
                    "bytes":       0,
                    "count":       1,
                    "http_urls":   [],
                    "timestamps":  [],
                    "country":     "",
                }
            else:
                seen[key]["count"] += 1
            continue

        remote_host = "This Scanner" if is_scanner else _resolve(remote_ip)
        display     = sni or hhost or (remote_host if remote_host != remote_ip else "")
        country     = _geo_country(remote_ip) if not is_scanner else ""

        if is_scanner:
            target_port = (tcp_dp or udp_dp) if src in own_ips else (tcp_sp or udp_sp)
            svc_label   = PORT_LABELS.get(int(target_port) if str(target_port).isdigit() else 0, target_port or "?")
            key         = ("scanner", svc_label, proto)
            service     = svc_label
            display_port = svc_label
            app         = "\U0001f52c CyberScope Scanner"
        else:
            target_port  = remote_port
            svc_label    = PORT_LABELS.get(int(remote_port) if str(remote_port).isdigit() else 0, remote_port or "?")
            key          = (remote_ip, remote_port, proto)
            service      = svc_label
            display_port = remote_port
            app          = _fingerprint(sni, hhost, remote_ip, remote_port)

        ts = frame_time[:10] if frame_time else ""
        http_url = ""
        if hmethod and http_uri:
            http_url = f"{hmethod} http://{hhost or remote_ip}{http_uri}"
        elif hmethod and hhost:
            http_url = f"{hmethod} http://{hhost}/"

        if key in seen:
            seen[key]["bytes"] += int(length) if length.isdigit() else 0
            seen[key]["count"] += 1
            if (sni or hhost) and seen[key]["remote_host"] in ("", remote_ip):
                seen[key]["remote_host"] = display
                seen[key]["app"]         = app
            if http_url and http_url not in seen[key]["http_urls"]:
                seen[key]["http_urls"].append(http_url)
            if ts and len(seen[key]["timestamps"]) < 60:
                seen[key]["timestamps"].append(float(frame_time))
        else:
            seen[key] = {
                "direction":   direction,
                "remote_ip":   remote_ip,
                "remote_host": display,
                "remote_port": display_port,
                "service":     service,
                "proto":       proto,
                "app":         app,
                "bytes":       int(length) if length.isdigit() else 0,
                "count":       1,
                "http_urls":   [http_url] if http_url else [],
                "timestamps":  [float(frame_time)] if frame_time else [],
                "country":     country,
            }

    # Sort: outgoing first, then by bytes descending
    packets = sorted(seen.values(),
                     key=lambda x: (0 if x["direction"] == "OUT" else 1, -x["bytes"]))
    return packets[:100]
