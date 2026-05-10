SUSPICIOUS_PORTS = {
    21:   "FTP — Unencrypted file transfer",
    23:   "Telnet — Unencrypted remote access",
    445:  "SMB — Common ransomware vector",
    3389: "RDP — Remote Desktop exposed",
    4444: "Metasploit default listener",
    6667: "IRC — Often used by botnets",
}

def detect_threat(port):
    if port in SUSPICIOUS_PORTS:
        return {"risk": "HIGH RISK", "reason": SUSPICIOUS_PORTS[port]}
    return {"risk": "SAFE", "reason": "No known threat"}

def scan_threats(open_ports):
    threats = []
    for port in open_ports:
        result = detect_threat(port)
        if result["risk"] == "HIGH RISK":
            threats.append({"port": port, **result})
    return threats
