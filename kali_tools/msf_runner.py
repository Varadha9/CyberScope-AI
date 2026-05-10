import subprocess
import tempfile
import os

# Map ports to Metasploit auxiliary scanner modules
PORT_MSF_MAP = {
    21:   "auxiliary/scanner/ftp/anonymous",
    22:   "auxiliary/scanner/ssh/ssh_version",
    23:   "auxiliary/scanner/telnet/telnet_version",
    25:   "auxiliary/scanner/smtp/smtp_version",
    80:   "auxiliary/scanner/http/http_version",
    443:  "auxiliary/scanner/http/http_version",
    445:  "auxiliary/scanner/smb/smb_version",
    3306: "auxiliary/scanner/mysql/mysql_version",
    3389: "auxiliary/scanner/rdp/rdp_scanner",
    5432: "auxiliary/scanner/postgres/postgres_version",
    6667: "auxiliary/scanner/irc/irc_version",
    8080: "auxiliary/scanner/http/http_version",
}

def msf_check(target, open_ports):
    """Run Metasploit auxiliary scanners for detected open ports"""
    findings = []
    modules_to_run = []
    for port in open_ports:
        if port in PORT_MSF_MAP:
            modules_to_run.append((port, PORT_MSF_MAP[port]))

    if not modules_to_run:
        return findings

    # Build msfconsole RC script
    rc_lines = []
    for port, module in modules_to_run[:5]:  # limit to 5 modules per host
        rc_lines += [
            f"use {module}",
            f"set RHOSTS {target}",
            f"set RPORT {port}",
            "set THREADS 1",
            "run -z",
        ]
    rc_lines.append("exit")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rc", delete=False) as f:
        f.write("\n".join(rc_lines))
        rc_path = f.name

    try:
        out = subprocess.check_output(
            ["msfconsole", "-q", "-r", rc_path],
            stderr=subprocess.DEVNULL, timeout=120, text=True
        )
        for line in out.splitlines():
            line = line.strip()
            if any(kw in line for kw in ["[+]", "version", "Banner", "Anonymous"]):
                findings.append(line)
    except subprocess.TimeoutExpired:
        print(f"[MSF] Timeout on {target}")
    except Exception as e:
        print(f"[MSF Error] {e}")
    finally:
        os.unlink(rc_path)

    return findings[:10]
