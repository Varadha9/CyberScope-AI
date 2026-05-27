SUSPICIOUS_PORTS = {
    21:   ("HIGH",     "FTP — Unencrypted file transfer"),
    22:   ("MEDIUM",   "SSH — Brute-force target"),
    23:   ("CRITICAL", "Telnet — Unencrypted remote access"),
    25:   ("MEDIUM",   "SMTP — Mail relay abuse"),
    53:   ("LOW",      "DNS — Possible open resolver"),
    80:   ("LOW",      "HTTP — Web server exposed"),
    110:  ("MEDIUM",   "POP3 — Unencrypted mail"),
    111:  ("HIGH",     "RPCBind — NFS/RPC exposed"),
    135:  ("HIGH",     "MSRPC — Windows RPC exposed"),
    139:  ("HIGH",     "NetBIOS — Windows file sharing"),
    143:  ("MEDIUM",   "IMAP — Unencrypted mail"),
    161:  ("MEDIUM",   "SNMP — Network info disclosure"),
    389:  ("HIGH",     "LDAP — Directory service exposed"),
    443:  ("LOW",      "HTTPS — Web server exposed"),
    445:  ("CRITICAL", "SMB — Common ransomware vector"),
    554:  ("MEDIUM",   "RTSP — Camera stream exposed"),
    1433: ("HIGH",     "MSSQL — Database exposed"),
    1521: ("HIGH",     "Oracle DB — Database exposed"),
    2049: ("HIGH",     "NFS — Network file share exposed"),
    2375: ("CRITICAL", "Docker API — Unauthenticated container access"),
    3306: ("HIGH",     "MySQL — Database exposed"),
    3389: ("CRITICAL", "RDP — Remote Desktop exposed"),
    4444: ("CRITICAL", "Metasploit default listener"),
    5432: ("HIGH",     "PostgreSQL — Database exposed"),
    5900: ("HIGH",     "VNC — Remote desktop exposed"),
    5984: ("HIGH",     "CouchDB — Unauthenticated DB"),
    6379: ("CRITICAL", "Redis — Unauthenticated cache/DB"),
    6667: ("HIGH",     "IRC — Often used by botnets"),
    7547: ("CRITICAL", "TR-069 — Router remote management"),
    8080: ("LOW",      "HTTP-Alt — Web server exposed"),
    8443: ("LOW",      "HTTPS-Alt — Web server exposed"),
    8888: ("MEDIUM",   "Jupyter Notebook — Possible unauthenticated"),
    9200: ("CRITICAL", "Elasticsearch — Unauthenticated DB"),
    9042: ("HIGH",     "Cassandra — Database exposed"),
    11211:("CRITICAL", "Memcached — Unauthenticated cache"),
    27017:("CRITICAL", "MongoDB — Unauthenticated DB"),
    50070:("HIGH",     "Hadoop NameNode — Big data exposed"),
}

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

def detect_threat(port):
    if port in SUSPICIOUS_PORTS:
        severity, reason = SUSPICIOUS_PORTS[port]
        return {"risk": severity, "reason": reason}
    return {"risk": "SAFE", "reason": "No known threat"}

def scan_threats(open_ports):
    threats = []
    for port in open_ports:
        result = detect_threat(port)
        if result["risk"] != "SAFE":
            threats.append({"port": port, **result})
    threats.sort(key=lambda x: SEVERITY_ORDER.get(x["risk"], 0), reverse=True)
    return threats
