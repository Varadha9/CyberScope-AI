"""
RTSP → MJPEG proxy using ffmpeg.
Streams camera footage directly to the browser as multipart/x-mixed-replace.
"""

import subprocess
import threading
import time

# Active stream processes: ip -> {proc, users, lock}
_streams = {}
_lock = threading.Lock()

RTSP_PATHS = [
    "/Streaming/Channels/101",
    "/Streaming/Channels/102",
    "/Streaming/Channels/201",
    "/h264/ch1/main/av_stream",
    "/h264/ch01/main/av_stream",
    "/PSIA/Streaming/channels/1",
    "/cam/realmonitor?channel=1&subtype=0",
]


def _build_rtsp_url(ip, path, user, password):
    if user and password:
        return f"rtsp://{user}:{password}@{ip}:554{path}"
    return f"rtsp://{ip}:554{path}"


def probe_rtsp(ip, user="admin", password=""):
    """Try all RTSP paths and return the first working URL."""
    import socket
    # Quick TCP check on port 554
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, 554))
        s.close()
    except Exception:
        return None

    cred_combos = []
    if user and password:
        cred_combos.append((user, password))
    cred_combos.append((user, ""))  # no auth

    for u, p in cred_combos:
        for path in RTSP_PATHS:
            url = _build_rtsp_url(ip, path, u, p)
            try:
                result = subprocess.run(
                    ["ffprobe", "-v", "quiet", "-rtsp_transport", "tcp",
                     "-i", url, "-show_entries", "stream=codec_type",
                     "-of", "csv=p=0"],
                    capture_output=True, timeout=4
                )
                if result.returncode == 0 and b"video" in result.stdout:
                    return url
            except Exception:
                pass
    return None


def mjpeg_stream(ip, user="admin", password="", path=None):
    """
    Generator that yields MJPEG frames from an RTSP stream via ffmpeg.
    Each yield is a complete multipart chunk.
    """
    if path:
        url = _build_rtsp_url(ip, path, user, password)
    else:
        url = probe_rtsp(ip, user, password)
        if not url:
            # Yield a single error frame
            yield _error_frame(f"Cannot connect to RTSP on {ip}:554")
            return

    cmd = [
        "ffmpeg", "-loglevel", "quiet",
        "-rtsp_transport", "tcp",
        "-i", url,
        "-vf", "scale=1280:-1",
        "-q:v", "5",
        "-f", "mjpeg",
        "-r", "10",          # 10 fps — good balance
        "pipe:1"
    ]

    proc = None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        buf = b""
        while True:
            chunk = proc.stdout.read(4096)
            if not chunk:
                break
            buf += chunk
            # Find JPEG boundaries
            while True:
                start = buf.find(b"\xff\xd8")
                end   = buf.find(b"\xff\xd9", start + 2) if start != -1 else -1
                if start == -1 or end == -1:
                    break
                frame = buf[start:end + 2]
                buf = buf[end + 2:]
                yield (
                    b"--frame\r\n"
                    b"Content-Type: image/jpeg\r\n"
                    b"Content-Length: " + str(len(frame)).encode() + b"\r\n\r\n"
                    + frame + b"\r\n"
                )
    except GeneratorExit:
        pass
    except Exception as e:
        yield _error_frame(str(e))
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()


def _error_frame(msg):
    """Return a minimal MJPEG chunk with a placeholder JPEG."""
    # 1x1 red JPEG (minimal valid JPEG)
    RED_JPEG = (
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        b"\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t"
        b"\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a"
        b"\x1f\x1e\x1d\x1a\x1c\x1c $.' \",#\x1c\x1c(7),01444\x1f'9=82<.342\x1e"
        b"\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00\xff\xc4\x00"
        b"\x1f\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\xff\xc4\x00"
        b"\xb5\x10\x00\x02\x01\x03\x03\x02\x04\x03\x05\x05\x04\x04\x00\x00"
        b"\x01}\x01\x02\x03\x00\x04\x11\x05\x12!1A\x06\x13Qa\x07\"q\x142\x81"
        b"\x91\xa1\x08#B\xb1\xc1\x15R\xd1\xf0$3br\x82\t\n\x16\x17\x18\x19"
        b"\x1a%&'()*456789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz\x83\x84\x85\x86"
        b"\x87\x88\x89\x8a\x92\x93\x94\x95\x96\x97\x98\x99\x9a\xa2\xa3\xa4"
        b"\xa5\xa6\xa7\xa8\xa9\xaa\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xc2"
        b"\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9"
        b"\xda\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xf1\xf2\xf3\xf4\xf5"
        b"\xf6\xf7\xf8\xf9\xfa\xff\xda\x00\x08\x01\x01\x00\x00?\x00\xfb\xd4"
        b"\xff\xd9"
    )
    return (
        b"--frame\r\n"
        b"Content-Type: image/jpeg\r\n"
        b"Content-Length: " + str(len(RED_JPEG)).encode() + b"\r\n\r\n"
        + RED_JPEG + b"\r\n"
    )
