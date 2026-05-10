import subprocess

def dnsrecon_scan(target):
    findings = []
    try:
        out = subprocess.check_output(
            ["dnsrecon", "-d", target, "-t", "std"],
            stderr=subprocess.DEVNULL, timeout=60, text=True
        )
        for line in out.splitlines():
            line = line.strip()
            if any(kw in line for kw in ["[*]", "[+]", "A ", "MX ", "NS ", "TXT ", "CNAME", "SOA"]):
                findings.append(line.lstrip("[*] ").lstrip("[+] ").strip())
    except subprocess.TimeoutExpired:
        print(f"[DNSRecon] Timeout on {target}")
    except Exception as e:
        print(f"[DNSRecon Error] {e}")
    return findings[:10]
