# 🔭 CyberScope AI

> **Real-time WiFi Network Security Monitor & Vulnerability Scanner**  
> Built on Kali Linux · Powered by 20+ Security Tools · Live WebSocket Dashboard · Camera Intelligence

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
- Whether IP cameras on the network are accessible or exploitable

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
9. Detects and streams live footage from IP cameras on the network
10. Performs MITM attacks to intercept and crack camera credentials

---

## ✨ Features

### 🔍 Network Discovery
- **ARP Scanning** via Scapy — sends ARP requests to every IP in the subnet
- **ARPing Runner** — alternative ARP-based host discovery
- **Netdiscover** — passive/active ARP-based host discovery
- **Nmap Ping Scan** — fallback when ARP is blocked
- **Gateway Detection** — always includes the router
- **Auto subnet detection** — reads `wlan0` IP and computes `/24` subnet
- **Auto DB reset** — detects when you switch WiFi networks and clears stale data
- **Passive Intelligence Harvest** — continuous DHCP/mDNS/NetBIOS sniffing for device enrichment
- **IPv6 Bypass Scanner** — bypasses client isolation using IPv6 link-local addresses

### ⚡ Fast Port Scanning
- Scans **top 1000 ports** per device using Nmap with `-T4`
- Smart scanner with IPv6 bypass for client-isolated networks
- Results pushed to dashboard immediately

### 🚨 Threat Detection
- Checks every open port against a **threat intelligence database**
- Assigns severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`
- Generates human-readable alert messages per threat
- Saves all alerts to SQLite with deduplication

### 🤖 AI Behavior Analysis
- Analyzes the combination of open ports on each device
- Classifies device behavior (web server, database, malware beacon, stealth, etc.)
- Generates a natural language comment for each device
- Updates in real-time as deep scan results arrive

### 🔬 Deep Scan Engine (Background Threads)
- **Service & Version Detection** — `nmap -sV`
- **OS Fingerprinting** — `nmap -O` + passive fingerprinting
- **Vulnerability Scripts** — `nmap --script vuln`
- **Nikto Web Scanner** — HTTP/HTTPS vulnerability scanning
- **Metasploit Auxiliary Scanners** — `msfconsole` per open port
- **SSLScan** — weak SSL/TLS cipher and certificate detection
- **WhatWeb** — web technology and CMS fingerprinting
- **SearchSploit** — Exploit-DB CVE matching
- **Enum4Linux** — SMB/Samba enumeration
- **DNSRecon** — DNS enumeration and zone transfers
- **Fierce** — DNS recon and network range discovery
- **WPScan** — WordPress vulnerability scanner
- **SQLMap** — SQL injection detection
- **Gobuster** — web directory brute-forcing
- **WFuzz** — web application fuzzer
- **Hydra** — online password brute-force
- **John the Ripper** — offline hash cracking
- **Netcat** — banner grabbing
- **TCPDump** — packet capture per host
- **TShark** — deep packet inspection
- **NVD CVE Lookup** — real-time CVE scoring via NVD API

### 📷 Camera Intelligence (NEW)
- **Auto-detection** of IP cameras on the network (Hikvision, Dahua, Axis, etc.)
- **Live MJPEG stream** — pulls RTSP feed via ffmpeg and serves it directly in the browser (no plugins needed)
- **RTSP path probe** — automatically discovers working stream URLs across 7 known paths
- **Snapshot capture** — grabs JPEG frames via ISAPI endpoints
- **Credential brute force** — tries 24+ Hikvision default passwords automatically
- **CVE-2021-36260** — unauthenticated RCE check
- **CVE-2017-7921** — authentication bypass check
- **MITM hash intercept** — ARP spoofs the camera, captures Digest auth hash when someone logs in, cracks it with hashcat/john
- **Device info extraction** — model, serial number, firmware version via ISAPI
- **Snapshot gallery** — saves and displays all captured frames with download links

### 📡 Live Traffic Watcher (NEW)
- Per-device traffic monitoring with connection table
- Direction (IN/OUT), remote host, port, protocol, app classification
- Geo-IP enrichment — country flags, suspicious country detection
- Beacon detection — identifies periodic C2-style connections
- HTTP URL capture (requires MITM for HTTPS)
- Traffic timeline and protocol breakdown charts
- CSV export of all captured connections

### 🔓 MITM / ARP Spoofing (NEW)
- One-click ARP spoof per device from the Watch page
- Auto-MITM on persistent ghost devices (no open ports)
- IP forwarding management
- Stop/start controls with live status

### 🌐 Recon Page (NEW)
- WiFi AP scanner — detects all nearby access points
- Evil Twin / rogue AP detection
- DNS subnet logger — captures all DNS queries on the network
- Passive intelligence dashboard

### 🗺️ Network Map (NEW)
- Visual topology map of all discovered devices
- Color-coded by threat level
- Click any device to go to its detail page

### 📊 Real-time Dashboard
- **WebSocket-powered** — all results stream live, no page refresh
- Device table with IP, MAC, OS, Open Ports, Threats, Vulns, AI Comment
- Live activity log showing every tool running
- Threat alerts feed with color-coded severity
- Charts for device count and threat levels
- Stats bar: Devices, Alerts, Open Ports, Threats, Vulns

### 💾 Persistent Storage
- SQLite database — devices, alerts, scan results
- Deduplication on alerts
- Upsert on scan results
- One-click database clear

### 📄 Report Generation
- CSV export with all devices, ports, OS, threats, vulns, MSF findings
- JSON summary with totals
- Dedicated Reports page

---

## 🗂️ Project Structure

```
CyberScope-AI/
├── app.py                        # Flask app, API routes, scan orchestration, WebSocket
├── run.sh                        # Launch script
├── requirements.txt              # Python dependencies
│
├── scanner/
│   ├── device_scanner.py         # ARP scan, nmap ping fallback, subnet detection
│   └── port_scanner.py           # Nmap top-1000 TCP port scanner
│
├── threat/
│   └── detector.py               # Port-to-threat mapping
│
├── ai/
│   ├── behavior_analyzer.py      # Device behavior classification
│   └── comment_engine.py         # AI comment generation
│
├── kali_tools/
│   ├── nmap_advanced.py          # OS detection, service scan, vuln scripts
│   ├── masscan_runner.py         # Fast full-subnet port discovery
│   ├── nikto_runner.py           # Web vulnerability scanner
│   ├── msf_runner.py             # Metasploit auxiliary scanners
│   ├── netdiscover_runner.py     # ARP-based host discovery
│   ├── arping_runner.py          # ARP ping discovery
│   ├── sslscan_runner.py         # SSL/TLS weakness detection
│   ├── whatweb_runner.py         # Web tech fingerprinting
│   ├── searchsploit_runner.py    # Exploit-DB CVE search
│   ├── enum4linux_runner.py      # SMB/Samba enumeration
│   ├── dnsrecon_runner.py        # DNS enumeration
│   ├── fierce_runner.py          # DNS recon
│   ├── wpscan_runner.py          # WordPress scanner
│   ├── sqlmap_runner.py          # SQL injection detection
│   ├── gobuster_runner.py        # Web directory brute-force
│   ├── wfuzz_runner.py           # Web fuzzer
│   ├── hydra_runner.py           # Password brute-force
│   ├── john_runner.py            # Hash cracking
│   ├── netcat_runner.py          # Banner grabbing
│   ├── tcpdump_runner.py         # Packet capture
│   ├── tshark_runner.py          # Deep packet inspection
│   ├── hikvision_scanner.py      # Hikvision camera CVE scanner + brute force
│   ├── rtsp_proxy.py             # RTSP → MJPEG proxy (live browser stream via ffmpeg)
│   ├── cam_interceptor.py        # MITM hash capture + hashcat/john cracking
│   ├── arp_spoof.py              # ARP spoofing engine
│   ├── traffic_watcher.py        # Per-device traffic analysis + beacon detection
│   ├── dns_logger.py             # DNS query capture
│   ├── geo_ip.py                 # Geo-IP enrichment
│   ├── cve_lookup.py             # NVD API CVE lookup
│   ├── wifi_scanner.py           # WiFi AP scanner + evil twin detection
│   ├── os_fingerprint.py         # Passive OS fingerprinting
│   ├── passive_intel.py          # DHCP/mDNS/NetBIOS passive harvest
│   ├── smart_scanner.py          # Client isolation detection + smart scan
│   └── ipv6_scanner.py           # IPv6 device discovery + port scan
│
├── sniffer/
│   └── packet_sniffer.py         # Live packet capture via Scapy
│
├── database/
│   └── models.py                 # SQLite — devices, alerts, scan_results
│
├── reports/
│   └── generator.py              # CSV + JSON report generator
│
├── static/
│   ├── app.js                    # WebSocket client, live UI, charts
│   └── style.css                 # Hacker-themed dark dashboard
│
├── templates/
│   ├── dashboard.html            # Main live scan dashboard
│   ├── alerts.html               # Threat alerts feed
│   ├── device.html               # Per-device deep scan results
│   ├── map.html                  # Network topology map
│   ├── cameras.html              # Camera intelligence + live stream viewer
│   ├── watch.html                # Per-device live traffic watcher
│   ├── recon.html                # WiFi recon + DNS logger
│   ├── activity.html             # Network-wide activity monitor
│   └── reports.html              # Reports and export
│
└── logs/
    ├── cyberscope.db             # SQLite database (auto-created)
    ├── .last_subnet              # Last known subnet for change detection
    └── report_*.csv              # Auto-generated scan reports
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
| `john` | Offline hash cracker | `sudo apt install john` |
| `netcat-openbsd` | Banner grabbing / raw probing | `sudo apt install netcat-openbsd` |
| `tcpdump` | Packet capture | `sudo apt install tcpdump` |
| `tshark` | Deep packet inspection | `sudo apt install tshark` |
| `ffmpeg` | RTSP → MJPEG camera stream proxy | `sudo apt install ffmpeg` |
| `arpspoof` | ARP spoofing for MITM | `sudo apt install dsniff` |
| `hashcat` | GPU hash cracking | `sudo apt install hashcat` |
| `python3` | Runtime | Pre-installed |

Install all at once:
```bash
sudo apt update && sudo apt install nmap masscan nikto metasploit-framework netdiscover \
  sslscan whatweb exploitdb enum4linux dnsrecon fierce wpscan sqlmap gobuster wfuzz \
  hydra john netcat-openbsd tcpdump tshark ffmpeg dsniff hashcat -y
```

### Python Dependencies

```
flask
flask-socketio
scapy
python-nmap
requests
urllib3
```

Install:
```bash
pip install -r requirements.txt
```

---

## 🚀 Getting Started

### 1. Clone the repository
```bash
git clone https://github.com/Varadha9/CyberScope-AI.git
cd CyberScope-AI
```

### 2. Install system tools
```bash
sudo apt update && sudo apt install nmap masscan nikto metasploit-framework netdiscover \
  sslscan whatweb exploitdb enum4linux dnsrecon fierce wpscan sqlmap gobuster wfuzz \
  hydra john netcat-openbsd tcpdump tshark ffmpeg dsniff hashcat -y
```

### 3. Install Python dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the application
```bash
sudo bash run.sh
```

> **Root privileges are required** — Scapy ARP scanning, Nmap OS fingerprinting, and ARP spoofing need raw socket access.

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
| `/api/scan` | GET | Trigger full network scan |
| `/api/masscan` | GET | Run masscan across WiFi subnet |
| `/api/sniff` | GET | Capture live packets (`?count=N`) |
| `/api/devices` | GET | List all discovered devices |
| `/api/alerts` | GET | List all security alerts |
| `/api/scan_results` | GET | Latest scan results per device |
| `/api/report` | GET | Generate CSV report |
| `/api/subnet` | GET | Current detected WiFi subnet |
| `/api/cameras` | GET | List detected IP cameras |
| `/api/camera/stream/<ip>` | GET | Live MJPEG stream from camera (`?user=&pass=`) |
| `/api/camera/snapshot` | GET | Capture JPEG snapshot (`?ip=&user=&pass=`) |
| `/api/camera/probe/<ip>` | GET | Find working RTSP URL (`?user=&pass=`) |
| `/api/camera/brute` | GET | Brute force camera credentials (`?ip=`) |
| `/api/camera/test_creds` | GET | Test camera credentials |
| `/api/camera/intercept/<ip>` | GET | Start MITM hash capture on camera |
| `/api/hikvision/<ip>` | GET | Full Hikvision CVE assessment |
| `/api/watch/<ip>` | GET | Per-device traffic capture |
| `/api/spoof/start/<ip>` | GET | Start ARP spoof on device |
| `/api/spoof/stop/<ip>` | GET | Stop ARP spoof |
| `/api/spoof/status` | GET | List active spoofs |
| `/api/wifi_scan` | GET | Scan WiFi APs + detect evil twins |
| `/api/dns/<ip>` | GET | Capture DNS queries from device |
| `/api/passive_intel/harvest` | GET | Trigger passive intelligence harvest |
| `/api/ipv6_scan` | GET | IPv6 bypass scan |
| `/api/john` | GET | Crack hashes (`?target=IP&ports=22,3306`) |
| `/api/clear_db` | POST | Wipe all data |

---

## 📄 Dashboard Pages

| Page | Route | Description |
|------|-------|-------------|
| **Dashboard** | `/` | Main live scan view |
| **Alerts** | `/alerts` | Full threat alerts feed |
| **Device Detail** | `/device/<ip>` | Per-device deep scan results |
| **Network Map** | `/map` | Visual network topology |
| **Cameras** | `/cameras` | IP camera viewer + live stream |
| **Watch** | `/watch/<ip>` | Per-device live traffic monitor |
| **Recon** | `/recon` | WiFi AP scan + DNS logger |
| **Activity** | `/activity` | Network-wide activity monitor |
| **Reports** | `/reports` | Export and view reports |

---

## 📷 Camera Intelligence — How It Works

```
┌─────────────────────────────────────────────────────────┐
│              CAMERA DETECTION                           │
│  Scan results checked for: Hikvision MAC, ports 554/    │
│  8000/9010, hostname keywords (hik, nvr, cam, dahua)    │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│              CREDENTIAL DISCOVERY                       │
│  ├── Brute force 24+ default passwords (Digest auth)    │
│  ├── CVE-2017-7921 auth bypass check                    │
│  ├── CVE-2021-36260 unauthenticated RCE check           │
│  └── MITM: ARP spoof → capture Digest hash → hashcat   │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│              LIVE STREAM                                │
│  ffprobe probes 7 RTSP paths to find working URL        │
│  ffmpeg pulls RTSP → encodes as MJPEG → Flask streams   │
│  Browser receives multipart/x-mixed-replace             │
│  <img src="/api/camera/stream/IP"> = live video         │
└─────────────────────────────────────────────────────────┘
```

---

## 🔄 Full Scan Flow

```
┌─────────────────────────────────────────────────────────┐
│                    APP STARTUP                          │
│  1. Detect wlan0 IP → compute /24 subnet                │
│  2. Compare with last known subnet                      │
│  3. If subnet changed → clear DB                        │
│  4. Start background scan thread (every 30 minutes)     │
│  5. Start continuous passive harvest (every 45s)        │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│                  DEVICE DISCOVERY                       │
│  ARP Scan (Scapy) + ARPing + Netdiscover                │
│  Nmap Ping Scan fallback                                │
│  Gateway Detection                                      │
│  IPv6 NDP table lookup                                  │
│  Passive Intel (DHCP/mDNS/NetBIOS)                      │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│              FAST SCAN (per device)                     │
│  Smart port scan (IPv6 bypass if client isolation)      │
│  Threat detection → AI behavior classification          │
│  Save to DB → emit to dashboard via WebSocket           │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│           DEEP SCAN (parallel background threads)       │
│  nmap -sV / -O / --script vuln                          │
│  nikto / whatweb / wpscan / sqlmap / gobuster / wfuzz   │
│  sslscan / msf / hydra / john / enum4linux              │
│  searchsploit / netcat / NVD CVE lookup                 │
│  Hikvision CVE scan (if camera ports detected)          │
│  All results → DB → live WebSocket push                 │
└─────────────────────────────────────────────────────────┘
```

---

## 🚨 Threat Severity Reference

| Severity | Ports | Risk |
|----------|-------|------|
| 🔴 CRITICAL | 23 (Telnet), 445 (SMB), 3389 (RDP), 4444 (Metasploit), 27017 (MongoDB) | Direct exploitation possible |
| 🟠 HIGH | 21 (FTP), 135 (MSRPC), 139 (NetBIOS), 3306 (MySQL), 5900 (VNC), 6667 (IRC) | Credential theft, lateral movement |
| 🟡 MEDIUM | 22 (SSH), 25 (SMTP), 110 (POP3), 143 (IMAP) | Brute-force risk |
| 🟢 LOW | 53 (DNS), 80 (HTTP), 443 (HTTPS), 8080, 8443 | Information disclosure |

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

## 🔐 Real-World Findings Example

From a real scan on a home network:

| Device | Finding | Severity |
|--------|---------|----------|
| `192.168.31.246` | HikVision NVR — Slowloris DOS (CVE-2007-6750), RTSP stream on port 554 | CRITICAL |
| `192.168.31.104` | Windows 11 PC — SMB port 445 open, ransomware vector, SMB v3.1.1 detected | CRITICAL |
| `192.168.31.54` | Windows 11 PC — MySQL port 3306 open, empty password confirmed | CRITICAL |
| `192.168.31.1` | JioFiber Router — admin panel on 8080, missing security headers, DNS open resolver | LOW–HIGH |

---

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Web Framework | Flask (Python) | HTTP server, API routes, template rendering |
| Real-time Comms | Flask-SocketIO | WebSocket — push scan results live |
| Packet Crafting | Scapy | ARP scanning, packet sniffing, MITM |
| Port Scanning | Nmap + python-nmap | Fast scan, OS detection, vuln scripts |
| Fast Discovery | Masscan | High-speed full-subnet port scan |
| Web Vuln Scan | Nikto | HTTP/HTTPS vulnerability assessment |
| SSL Analysis | SSLScan | TLS cipher and certificate weakness |
| Web Fingerprinting | WhatWeb | CMS and technology identification |
| Exploit Search | SearchSploit | Exploit-DB CVE matching |
| SMB Enumeration | Enum4Linux | Windows/Samba share and user enumeration |
| DNS Recon | DNSRecon + Fierce | DNS enumeration and zone transfer |
| CMS Scanning | WPScan | WordPress vulnerability assessment |
| Injection Testing | SQLMap | Automated SQL injection detection |
| Directory Fuzzing | Gobuster + WFuzz | Web path and parameter discovery |
| Brute Force | Hydra | Online credential brute-forcing |
| Hash Cracking | John the Ripper + Hashcat | Offline hash cracking |
| Service Probing | Netcat | Raw TCP/UDP banner grabbing |
| Packet Analysis | TCPDump + TShark | Deep traffic capture and inspection |
| Exploitation | Metasploit (msfconsole) | Auxiliary service scanners |
| Host Discovery | Netdiscover + ARPing | ARP-based passive/active discovery |
| Camera Streaming | ffmpeg | RTSP → MJPEG browser-compatible stream |
| Camera CVEs | Custom scanner | CVE-2021-36260, CVE-2017-7921 |
| MITM | arpspoof + TShark | ARP spoof + Digest hash capture |
| Geo-IP | ip-api.com | Country and ASN enrichment |
| CVE Scoring | NVD API | Real-time CVSS scores |
| Database | SQLite | Persistent storage |
| Frontend | HTML + CSS + JavaScript | Multi-page dashboard UI |
| Charts | Chart.js | Device activity and threat charts |

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
GitHub: [Varadha9](https://github.com/Varadha9)

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
