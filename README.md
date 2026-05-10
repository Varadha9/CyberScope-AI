# 🔭 CyberScope AI

A real-time **WiFi network security scanner** with an AI-powered behavior analysis engine and a live web dashboard. Built for Kali Linux, it discovers devices on your local network, scans for open ports, detects threats, runs deep vulnerability assessments using industry-standard tools, and generates detailed reports — all from a browser.

---

## 📸 Features

- **Live Device Discovery** — ARP scan + Netdiscover to find all devices on your WiFi subnet
- **Fast Port Scanning** — Top 1000 ports scanned per device using Nmap (T4 speed)
- **Threat Detection** — Flags dangerous open ports (SMB, RDP, Telnet, MongoDB, etc.) with severity levels
- **AI Behavior Analysis** — Classifies each device's behavior (malware beacon, database exposed, gaming, stealth, etc.)
- **Deep Scan Engine** (background threads):
  - OS Fingerprinting via `nmap -O`
  - Full service/version detection (`nmap -sV`)
  - Vulnerability scripts (`nmap --script vuln`)
  - Web vulnerability scanning via **Nikto**
  - Metasploit auxiliary scanners via **msfconsole**
- **Masscan Integration** — Ultra-fast port discovery across the subnet
- **Packet Sniffer** — Live packet capture using Scapy on `wlan0`
- **Real-time Dashboard** — WebSocket-powered live updates via Flask-SocketIO
- **Persistent Storage** — SQLite database for devices, alerts, and scan results
- **CSV Report Generation** — Exportable reports with full scan summaries

---

## 🗂️ Project Structure

```
CyberScope-AI/
├── app.py                  # Main Flask app, API routes, scan orchestration
├── run.sh                  # Launch script (handles sudo + port cleanup)
├── requirements.txt        # Python dependencies
│
├── scanner/
│   ├── device_scanner.py   # ARP scan, nmap ping fallback, gateway detection
│   └── port_scanner.py     # Nmap top-1000 port scanner
│
├── threat/
│   └── detector.py         # Port-based threat detection with severity ratings
│
├── ai/
│   ├── behavior_analyzer.py  # Classifies device behavior from open ports
│   └── comment_engine.py     # Human-readable AI comments per behavior type
│
├── kali_tools/
│   ├── nmap_advanced.py    # OS detection, service scan, vuln scripts
│   ├── masscan_runner.py   # Fast subnet port discovery
│   ├── nikto_runner.py     # Web vulnerability scanner
│   ├── msf_runner.py       # Metasploit auxiliary scanner runner
│   └── netdiscover_runner.py # Passive/active host discovery
│
├── sniffer/
│   └── packet_sniffer.py   # Live packet capture (Scapy)
│
├── database/
│   └── models.py           # SQLite ORM — devices, alerts, scan_results
│
├── reports/
│   └── generator.py        # CSV report + JSON summary generator
│
├── static/
│   ├── app.js              # Frontend WebSocket client + UI logic
│   └── style.css           # Dashboard styles
│
├── templates/
│   └── dashboard.html      # Main web dashboard
│
└── logs/
    ├── cyberscope.db       # SQLite database
    └── report_*.csv        # Generated scan reports
```

---

## ⚙️ Requirements

### System (Kali Linux recommended)

| Tool | Purpose |
|------|---------|
| `nmap` | Port scanning, OS detection, vuln scripts |
| `masscan` | Fast subnet port discovery |
| `nikto` | Web vulnerability scanning |
| `metasploit-framework` | Auxiliary service scanners |
| `netdiscover` | Passive/active host discovery |
| `python3` | Runtime |

Install missing tools:
```bash
sudo apt update
sudo apt install nmap masscan nikto metasploit-framework netdiscover -y
```

### Python Dependencies

```
flask
flask-socketio
scapy
python-nmap
```

Install:
```bash
pip install -r requirements.txt
```

---

## 🚀 Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/<your-username>/CyberScope-AI.git
cd CyberScope-AI
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the application

```bash
chmod +x run.sh
./run.sh
```

> **Root is required** — Scapy ARP scanning and Nmap OS detection need raw socket access.

The app will start on `http://0.0.0.0:5000`. Open your browser and go to:

```
http://localhost:5000
```

---

## 🌐 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Live dashboard UI |
| `/api/scan` | GET | Run full network scan (fast + deep) |
| `/api/masscan` | GET | Run masscan on WiFi subnet |
| `/api/sniff` | GET | Capture packets (`?count=N`, default 30) |
| `/api/devices` | GET | List all discovered devices |
| `/api/alerts` | GET | List all security alerts |
| `/api/scan_results` | GET | List all scan results |
| `/api/report` | GET | Generate and download CSV report |

---

## 🔍 How It Works

### Scan Flow

```
1. Auto-detect WiFi subnet (wlan0 → /24)
2. ARP scan + Netdiscover → discover live hosts
3. For each host:
   a. Fast Nmap port scan (top 1000 ports)
   b. Threat detection on open ports
   c. AI behavior classification
   d. Save to DB, emit to dashboard via WebSocket
4. Background deep scan threads (per host):
   a. Service/version detection (nmap -sV, all 65535 ports)
   b. OS fingerprinting (nmap -O)
   c. Vuln scripts (nmap --script vuln)
   d. Nikto (if port 80/443/8080/8443 open)
   e. Metasploit auxiliary scanners
5. All findings saved to SQLite + pushed live to dashboard
6. Background scan repeats every 120 seconds
```

### Threat Severity Levels

| Severity | Example Ports |
|----------|--------------|
| CRITICAL | Telnet (23), SMB (445), RDP (3389), MongoDB (27017), Metasploit (4444) |
| HIGH | FTP (21), MSRPC (135), NetBIOS (139), MySQL (3306), VNC (5900), IRC (6667) |
| MEDIUM | SSH (22), SMTP (25), POP3 (110) |
| LOW | DNS (53), HTTP (80), HTTPS (443) |

### AI Behavior Tags

| Tag | Trigger Condition |
|-----|------------------|
| `malware` | Port 4444 or 6667 open |
| `critical_target` | MongoDB (27017) or SMB+RDP combo |
| `suspicious` | FTP, Telnet, or SMB open |
| `remote_access` | RDP (3389) or VNC (5900) |
| `database_exposed` | MySQL, PostgreSQL, or MSSQL open |
| `web_server` | HTTP/HTTPS ports open |
| `port_scan` | More than 20 open ports |
| `stealth` | No open ports detected |
| `gaming` | Ports 27015 or 3074 open |
| `streaming` | Ports 554 or 1935 open |

---

## 📊 Reports

Reports are auto-saved to the `logs/` directory as CSV files.

Each report includes:
- All discovered devices (IP, MAC, status, last seen)
- Scan results per device (OS, open ports, threat count, vuln count, MSF findings)
- All security alerts with severity and timestamp
- Summary totals

Generate a report via API:
```bash
curl http://localhost:5000/api/report
```

---

## ⚠️ Legal Disclaimer

> This tool is intended for **authorized security testing only**.  
> Only use CyberScope AI on networks you own or have explicit written permission to test.  
> Unauthorized scanning of networks is **illegal** and may violate computer crime laws in your jurisdiction.  
> The author is not responsible for any misuse of this tool.

---

## 🛠️ Built With

- [Flask](https://flask.palletsprojects.com/) — Web framework
- [Flask-SocketIO](https://flask-socketio.readthedocs.io/) — Real-time WebSocket communication
- [Scapy](https://scapy.net/) — Packet crafting and sniffing
- [python-nmap](https://pypi.org/project/python-nmap/) — Nmap Python wrapper
- [Nmap](https://nmap.org/) — Port scanning, OS detection, vuln scripts
- [Masscan](https://github.com/robertdavidgraham/masscan) — High-speed port scanner
- [Nikto](https://cirt.net/Nikto2) — Web server vulnerability scanner
- [Metasploit Framework](https://www.metasploit.com/) — Exploitation and auxiliary scanning
- [Netdiscover](https://github.com/netdiscover-scanner/netdiscover) — ARP-based host discovery
- SQLite — Lightweight persistent storage

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
