# 🔭 CyberScope AI

> **Real-time WiFi Network Security Monitor & Vulnerability Scanner**  
> Built on Kali Linux · Powered by 20+ Security Tools · Live WebSocket Dashboard

![License](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/badge/python-3.x-green)
![Platform](https://img.shields.io/badge/platform-Kali%20Linux-purple)
![Status](https://img.shields.io/badge/status-active-brightgreen)

---

## 🧠 Problem Statement

Most home users, small offices, and college networks have **zero visibility** into what is happening on their own WiFi. They don't know:

- How many devices are connected to their network
- Whether an unauthorized device has joined their WiFi
- Which devices are running dangerous or exposed services
- Whether any device has a known vulnerability that can be exploited
- If someone is running a rogue server, database, or remote access tool on the network

Traditional security tools like Nmap, Nikto, and Metasploit are **powerful but complex** — they require deep command-line knowledge, manual execution, and separate interpretation of results. There is no unified, real-time, beginner-friendly interface that combines all of them.

**CyberScope AI solves this** by automating the entire network security assessment pipeline and presenting everything in a live, real-time browser dashboard — no command-line knowledge required.

---

## 💡 What Is CyberScope AI?

CyberScope AI is an **automated WiFi network security monitoring system** that:

1. Automatically detects your WiFi subnet
2. Discovers every device connected to the network
3. Scans each device for open ports and running services
4. Detects security threats based on exposed ports
5. Runs deep vulnerability assessments using 20+ professional-grade tools
6. Uses an AI behavior engine to classify each device
7. Streams all results live to a browser dashboard via WebSockets
8. Stores all findings in a database and generates exportable reports

It is designed to work **out of the box** — just run one command and open your browser.

---

## ✨ Features

### 🔍 Network Discovery
- **ARP Scanning** via Scapy — sends ARP requests to every IP in the subnet and collects responses
- **ARPing Runner** — alternative ARP-based host discovery using `arping`
- **Netdiscover** — passive/active ARP-based host discovery as a secondary sweep
- **Nmap Ping Scan** — fallback when ARP is blocked (client isolation networks)
- **Gateway Detection** — always includes the router even if ARP is blocked
- **Auto subnet detection** — reads `wlan0` IP and computes `/24` subnet automatically
- **Auto DB reset** — detects when you switch WiFi networks and clears stale data

### ⚡ Fast Port Scanning
- Scans **top 1000 ports** per device using Nmap with `-T4` (aggressive timing)
- Runs in sequence per device, results pushed to dashboard immediately
- Identifies open TCP ports for further analysis

### 🚨 Threat Detection
- Checks every open port against a **threat intelligence database**
- Assigns severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`
- Generates human-readable alert messages per threat
- Saves all alerts to SQLite with deduplication

### 🤖 AI Behavior Analysis
- Analyzes the combination of open ports on each device
- Classifies device behavior into categories (web server, database, malware beacon, stealth, etc.)
- Generates a natural language comment for each device
- Updates in real-time as deep scan results arrive

### 🔬 Deep Scan Engine (Background Threads)
Runs in parallel background threads per device — does not block the UI:
- **Service & Version Detection** — `nmap -sV` identifies exact software and version on each port
- **OS Fingerprinting** — `nmap -O` detects the operating system (Windows 11, Linux, Android, etc.)
- **Vulnerability Scripts** — `nmap --script vuln` checks for known CVEs and exploitable conditions
- **Nikto Web Scanner** — scans HTTP/HTTPS ports for web vulnerabilities, missing headers, CVEs
- **Metasploit Auxiliary Scanners** — runs `msfconsole` auxiliary modules per open port
- **SSLScan** — detects weak SSL/TLS ciphers, expired certificates, POODLE/BEAST/HEARTBLEED
- **WhatWeb** — fingerprints web technologies, CMS, frameworks, and server versions
- **SearchSploit** — searches Exploit-DB for known exploits matching detected services
- **Enum4Linux** — enumerates SMB shares, users, groups, and policies on Windows/Samba hosts
- **DNSRecon** — performs DNS enumeration, zone transfers, and subdomain discovery
- **Fierce** — DNS reconnaissance and network range discovery
- **WPScan** — WordPress vulnerability scanner for themes, plugins, and user enumeration
- **SQLMap** — automated SQL injection detection and exploitation on web endpoints
- **Gobuster** — directory and file brute-forcing on web servers
- **WFuzz** — web application fuzzer for parameter and path discovery
- **Hydra** — online password brute-force for SSH, FTP, HTTP, and other services
- **Netcat** — banner grabbing and raw TCP/UDP service probing
- **TCPDump** — low-level packet capture and traffic analysis per host
- **TShark** — Wireshark CLI for deep packet inspection and protocol dissection

### ⚡ Masscan Integration
- Ultra-fast port discovery across the entire subnet
- Can scan all 65535 ports across the whole `/24` in seconds
- Results pushed live to the dashboard

### 📡 Live Packet Sniffer
- Captures live packets on `wlan0` using Scapy
- Displays source IP, destination IP, ports, and protocol
- Configurable packet count

### 📊 Real-time Dashboard
- **WebSocket-powered** — all scan results stream live to the browser, no page refresh needed
- Device table updates in real-time as each scan phase completes
- Live activity log showing every tool running in the background
- Threat alerts feed with color-coded severity
- Charts for device count and threat levels over time
- Loading spinner during active scans
- Dedicated pages for Alerts, Device Detail, Network Map, and Reports

### 💾 Persistent Storage
- SQLite database stores all devices, alerts, and scan results
- Deduplication on alerts — same alert never stored twice
- Upsert on scan results — always shows latest data per device
- One-click database clear via dashboard button

### 📄 Report Generation
- Exports full scan summary as a **CSV file**
- Includes all devices, open ports, OS, threats, vulns, MSF findings
- JSON summary with totals for devices, alerts, high-risk findings
- Dedicated Reports page in the dashboard UI

---

## 🗂️ Project Structure

```
CyberScope-AI/
├── app.py                    # Flask app, API routes, scan orchestration, WebSocket events
├── run.sh                    # Launch script (kills port 5000, sets PYTHONPATH, runs with sudo)
├── requirements.txt          # Python dependencies
│
├── scanner/
│   ├── device_scanner.py     # ARP scan (Scapy), nmap ping fallback, gateway detection, subnet detection
│   └── port_scanner.py       # Nmap top-1000 TCP port scanner
│
├── threat/
│   └── detector.py           # Port-to-threat mapping with CRITICAL/HIGH/MEDIUM/LOW severity
│
├── ai/
│   ├── behavior_analyzer.py  # Classifies device behavior from open port combinations
│   └── comment_engine.py     # Generates human-readable AI comments per behavior type
│
├── kali_tools/
│   ├── nmap_advanced.py      # OS detection (-O), service scan (-sV), vuln scripts (--script vuln)
│   ├── masscan_runner.py     # Fast full-subnet port discovery via masscan
│   ├── nikto_runner.py       # Web vulnerability scanner — CVEs, missing headers, misconfigs
│   ├── msf_runner.py         # Metasploit auxiliary scanner — msfconsole RC scripts per port
│   ├── netdiscover_runner.py # ARP-based passive/active host discovery
│   ├── arping_runner.py      # ARP ping host discovery using arping
│   ├── sslscan_runner.py     # SSL/TLS cipher and certificate weakness detection
│   ├── whatweb_runner.py     # Web technology and CMS fingerprinting
│   ├── searchsploit_runner.py# Exploit-DB search for known CVEs matching services
│   ├── enum4linux_runner.py  # SMB/Samba enumeration — shares, users, groups
│   ├── dnsrecon_runner.py    # DNS enumeration, zone transfers, subdomain discovery
│   ├── fierce_runner.py      # DNS recon and network range discovery
│   ├── wpscan_runner.py      # WordPress vulnerability scanner
│   ├── sqlmap_runner.py      # SQL injection detection and exploitation
│   ├── gobuster_runner.py    # Web directory and file brute-forcing
│   ├── wfuzz_runner.py       # Web application fuzzer
│   ├── hydra_runner.py       # Online password brute-force (SSH, FTP, HTTP, etc.)
│   ├── netcat_runner.py      # Banner grabbing and raw service probing
│   ├── tcpdump_runner.py     # Low-level packet capture per host
│   └── tshark_runner.py      # Deep packet inspection via TShark/Wireshark CLI
│
├── sniffer/
│   └── packet_sniffer.py     # Live packet capture on wlan0 using Scapy
│
├── database/
│   └── models.py             # SQLite — devices, alerts, scan_results with upsert + dedup logic
│
├── reports/
│   └── generator.py          # CSV report + JSON summary generator
│
├── static/
│   ├── app.js                # WebSocket client, live UI updates, chart rendering, all button logic
│   └── style.css             # Hacker-themed dark dashboard styles
│
├── templates/
│   ├── dashboard.html        # Main web dashboard (single page)
│   ├── alerts.html           # Dedicated alerts view page
│   ├── device.html           # Per-device detail page
│   ├── map.html              # Network topology map page
│   └── reports.html          # Reports and export page
│
└── logs/
    ├── cyberscope.db         # SQLite database (auto-created)
    ├── .last_subnet          # Stores last known subnet for change detection
    └── report_*.csv          # Auto-generated scan reports
```

---

## ⚙️ System Requirements

### Operating System
- **Kali Linux** (recommended — all tools pre-installed)
- Any Debian/Ubuntu-based Linux with root access

### Required Tools

| Tool | Purpose | Install |
|------|---------|---------|
| `nmap` | Port scanning, OS detection, vuln scripts | `sudo apt install nmap` |
| `masscan` | Ultra-fast subnet port discovery | `sudo apt install masscan` |
| `nikto` | Web server vulnerability scanning | `sudo apt install nikto` |
| `metasploit-framework` | Auxiliary service scanners | `sudo apt install metasploit-framework` |
| `netdiscover` | ARP-based host discovery | `sudo apt install netdiscover` |
| `sslscan` | SSL/TLS weakness detection | `sudo apt install sslscan` |
| `whatweb` | Web technology fingerprinting | `sudo apt install whatweb` |
| `exploitdb` | SearchSploit — Exploit-DB search | `sudo apt install exploitdb` |
| `enum4linux` | SMB/Samba enumeration | `sudo apt install enum4linux` |
| `dnsrecon` | DNS enumeration | `sudo apt install dnsrecon` |
| `fierce` | DNS recon and range discovery | `sudo apt install fierce` |
| `wpscan` | WordPress vulnerability scanner | `sudo apt install wpscan` |
| `sqlmap` | SQL injection scanner | `sudo apt install sqlmap` |
| `gobuster` | Web directory brute-forcer | `sudo apt install gobuster` |
| `wfuzz` | Web application fuzzer | `sudo apt install wfuzz` |
| `hydra` | Password brute-force tool | `sudo apt install hydra` |
| `netcat-openbsd` | Banner grabbing / raw probing | `sudo apt install netcat-openbsd` |
| `tcpdump` | Packet capture | `sudo apt install tcpdump` |
| `tshark` | Deep packet inspection | `sudo apt install tshark` |
| `python3` | Runtime | Pre-installed |

Install all at once:
```bash
sudo apt update && sudo apt install nmap masscan nikto metasploit-framework netdiscover \
  sslscan whatweb exploitdb enum4linux dnsrecon fierce wpscan sqlmap gobuster wfuzz \
  hydra netcat-openbsd tcpdump tshark -y
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
git clone https://github.com/varad-comrad/CyberScope-AI.git
cd CyberScope-AI
```

### 2. Install system tools
```bash
sudo apt update && sudo apt install nmap masscan nikto metasploit-framework netdiscover \
  sslscan whatweb exploitdb enum4linux dnsrecon fierce wpscan sqlmap gobuster wfuzz \
  hydra netcat-openbsd tcpdump tshark -y
```

### 3. Install Python dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the application
```bash
sudo bash run.sh
```

> **Root privileges are required** — Scapy ARP scanning and Nmap OS fingerprinting need raw socket access.

### 5. Open the dashboard
```
http://localhost:5000
```

The background scan starts automatically on launch. The dashboard will populate with devices within 30–60 seconds.

---

## 🌐 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Live dashboard UI |
| `/api/scan` | GET | Trigger full network scan (fast + deep) |
| `/api/masscan` | GET | Run masscan across WiFi subnet |
| `/api/sniff` | GET | Capture live packets (`?count=N`, default 30) |
| `/api/devices` | GET | List all discovered devices from DB |
| `/api/alerts` | GET | List all security alerts from DB |
| `/api/scan_results` | GET | List latest scan results per device |
| `/api/report` | GET | Generate and save CSV report |
| `/api/subnet` | GET | Get current detected WiFi subnet |
| `/api/clear_db` | POST | Wipe all devices, alerts, scan results |

---

## 📄 Dashboard Pages

| Page | Route | Description |
|------|-------|-------------|
| **Dashboard** | `/` | Main live scan view — devices, stats, activity log |
| **Alerts** | `/alerts` | Full threat alerts feed with filtering |
| **Device Detail** | `/device/<ip>` | Per-device deep scan results and findings |
| **Network Map** | `/map` | Visual network topology map |
| **Reports** | `/reports` | Export and view generated scan reports |

---

## 🔄 How It Works — Full Scan Flow

```
┌─────────────────────────────────────────────────────────┐
│                    APP STARTUP                          │
│  1. Detect wlan0 IP → compute /24 subnet                │
│  2. Compare with last known subnet                      │
│  3. If subnet changed → clear DB (new network)          │
│  4. Start background scan thread (every 10 minutes)     │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│                  DEVICE DISCOVERY                       │
│  ARP Scan (Scapy) ──► finds devices by MAC+IP           │
│  ARPing Runner ─────► alternative ARP discovery         │
│       │ if blocked                                      │
│  Nmap Ping Scan ────► fallback host discovery           │
│       │ if still empty                                  │
│  Gateway Detection ─► at least return the router        │
│  Netdiscover ───────► secondary ARP sweep               │
│  Filter 0.0.0.0 / 127.0.0.1 / invalid IPs              │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│              FAST SCAN (per device, sequential)         │
│  Nmap top-1000 TCP ports (-T4)                          │
│  Threat detection on open ports                         │
│  AI behavior classification                             │
│  Save to DB → emit to dashboard via WebSocket           │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│           DEEP SCAN (per device, parallel threads)      │
│  ├── nmap -sV         → service & version detection     │
│  ├── nmap -O          → OS fingerprinting               │
│  ├── nmap --script vuln → CVE checks                    │
│  ├── nikto            → web vulnerability scan          │
│  ├── msfconsole       → auxiliary scanners per port     │
│  ├── sslscan          → SSL/TLS weakness detection      │
│  ├── whatweb          → web tech fingerprinting         │
│  ├── searchsploit     → Exploit-DB CVE matching         │
│  ├── enum4linux       → SMB/Samba enumeration           │
│  ├── dnsrecon         → DNS enumeration                 │
│  ├── fierce           → DNS recon                       │
│  ├── wpscan           → WordPress vuln scan             │
│  ├── sqlmap           → SQL injection detection         │
│  ├── gobuster         → web directory brute-force       │
│  ├── wfuzz            → web fuzzing                     │
│  ├── hydra            → password brute-force            │
│  ├── netcat           → banner grabbing                 │
│  ├── tcpdump          → packet capture per host         │
│  └── tshark           → deep packet inspection          │
│  All results → save to DB → push live to dashboard      │
└─────────────────────────────────────────────────────────┘
```

---

## 🚨 Threat Severity Reference

| Severity | Ports | Risk |
|----------|-------|------|
| 🔴 CRITICAL | 23 (Telnet), 445 (SMB), 3389 (RDP), 4444 (Metasploit), 27017 (MongoDB) | Direct exploitation possible, ransomware vector |
| 🟠 HIGH | 21 (FTP), 135 (MSRPC), 139 (NetBIOS), 3306 (MySQL), 5900 (VNC), 6667 (IRC) | Credential theft, lateral movement |
| 🟡 MEDIUM | 22 (SSH), 25 (SMTP), 110 (POP3), 143 (IMAP) | Brute-force risk, mail relay abuse |
| 🟢 LOW | 53 (DNS), 80 (HTTP), 443 (HTTPS), 8080, 8443 | Information disclosure, web attacks |

---

## 🤖 AI Behavior Classification

| Behavior Tag | Trigger Condition | Comment |
|---|---|---|
| `malware` | Port 4444 or 6667 open | Possible C2 beacon or IRC botnet |
| `critical_target` | MongoDB (27017) or SMB+RDP combo | High-value attack target |
| `suspicious` | FTP, Telnet, or SMB open | Legacy protocols — likely vulnerable |
| `remote_access` | RDP (3389) or VNC (5900) | Remote desktop exposed |
| `database_exposed` | MySQL, PostgreSQL, MSSQL open | Database accessible from network |
| `web_server` | HTTP/HTTPS ports open | Web server — check for vulns |
| `port_scan` | 20+ open ports | Unusual — possible honeypot or server |
| `stealth` | No open ports | Ghost device — just lurking |
| `gaming` | Ports 27015 or 3074 | Gaming server or console |
| `streaming` | Ports 554 or 1935 | RTSP/RTMP stream (camera, media server) |

---

## 📊 Dashboard Panels

| Panel | Description |
|-------|-------------|
| **Stats Bar** | Live counts — Devices, Alerts, Open Ports, Threats, Vulns |
| **Connected Devices** | Table with IP, MAC, OS, Open Ports, Threats, Vulns, AI Comment |
| **Background Activity Log** | Real-time terminal showing every tool running |
| **Threat Alerts** | Color-coded feed — CRITICAL (purple), HIGH (red), MEDIUM (yellow), LOW (green) |
| **Live Packets** | Packet sniffer output — src/dst IP, ports, protocol |
| **Device Activity Chart** | Line chart — device count over time |
| **Threat Levels Chart** | Bar chart — threat count over scan cycles |
| **AI Comment** | Current AI assessment of the network |

---

## 🔐 Real-World Findings Example

From a real scan on a home network:

| Device | Finding | Severity |
|--------|---------|----------|
| `192.168.31.246` | HikVision NVR camera — Slowloris DOS vulnerability (CVE-2007-6750) | CRITICAL |
| `192.168.31.104` | Windows 11 PC — SMB port 445 open, ransomware vector | CRITICAL |
| `192.168.31.1` | Router — admin panel on port 8080 exposed, DNS open resolver risk | LOW–HIGH |

---

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Web Framework | Flask (Python) | HTTP server, API routes, template rendering |
| Real-time Comms | Flask-SocketIO | WebSocket — push scan results live to browser |
| Packet Crafting | Scapy | ARP scanning, packet sniffing |
| Port Scanning | Nmap + python-nmap | Fast scan, OS detection, vuln scripts |
| Fast Discovery | Masscan | High-speed full-subnet port scan |
| Web Vuln Scan | Nikto | HTTP/HTTPS vulnerability assessment |
| SSL Analysis | SSLScan | TLS cipher and certificate weakness detection |
| Web Fingerprinting | WhatWeb | CMS and technology identification |
| Exploit Search | SearchSploit | Exploit-DB CVE matching |
| SMB Enumeration | Enum4Linux | Windows/Samba share and user enumeration |
| DNS Recon | DNSRecon + Fierce | DNS enumeration and zone transfer |
| CMS Scanning | WPScan | WordPress vulnerability assessment |
| Injection Testing | SQLMap | Automated SQL injection detection |
| Directory Fuzzing | Gobuster + WFuzz | Web path and parameter discovery |
| Brute Force | Hydra | Online credential brute-forcing |
| Service Probing | Netcat | Raw TCP/UDP banner grabbing |
| Packet Analysis | TCPDump + TShark | Deep traffic capture and inspection |
| Exploitation Framework | Metasploit (msfconsole) | Auxiliary service scanners |
| Host Discovery | Netdiscover + ARPing | ARP-based passive/active discovery |
| Database | SQLite | Persistent storage — devices, alerts, results |
| Frontend | HTML + CSS + JavaScript | Multi-page dashboard UI |
| Charts | Chart.js | Device activity and threat level charts |

---

## ⚠️ Legal Disclaimer

> This tool is intended **strictly for authorized security testing and educational purposes only.**  
> Only use CyberScope AI on networks you **own** or have **explicit written permission** to test.  
> Unauthorized scanning of networks is **illegal** and may violate the Computer Fraud and Abuse Act (CFAA), IT Act, or equivalent laws in your jurisdiction.  
> The authors accept **no responsibility** for any misuse, damage, or legal consequences arising from the use of this tool.

---

## 👨‍💻 Author

**Varad**  
CyberScope AI — Built as a network security monitoring project on Kali Linux.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
