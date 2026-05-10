def generate_comment(activity):
    comments = {
        "malware":          "⚠️ Possible C2/malware beacon detected! Isolate NOW 🚨",
        "critical_target":  "🔴 Critical attack surface — multiple dangerous ports open!",
        "suspicious":       "Bro is definitely up to something 👀",
        "remote_access":    "Remote access ports open — RDP/VNC exposed 🖥️",
        "database_exposed": "Database port exposed to network — data breach risk 🗄️",
        "web_server":       "Web server running — check for vulnerabilities 🌐",
        "streaming":        "Someone is binge watching again 🍿",
        "gaming":           "Gaming traffic detected 🎮",
        "heavy_download":   "Downloading the internet again? 😭",
        "port_scan":        "Someone is knocking on ALL the doors 🚪",
        "stealth":          "Ghost device — no open ports, just lurking 👻",
        "normal":           "All quiet on the network front 😴",
    }
    return comments.get(activity, "Normal activity detected 🔍")
