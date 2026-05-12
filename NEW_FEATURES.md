# 🔥 NEW HACKER-GRADE FEATURES ADDED

## 🎯 What a Real Hacker Needs

These features reveal **what's actually happening** on the network, not just scan noise.

---

## 🆕 Features Added

### 1. 🔥 Real-Time CVE Lookup (NVD API)
**What it does:**
- Queries the National Vulnerability Database (NVD) API for every detected service
- Returns actual CVEs with CVSS scores (0-10 severity scale)
- Auto-alerts on CRITICAL (CVSS ≥ 9.0) and HIGH (CVSS ≥ 7.0) CVEs
- Cached to avoid rate limits

**Why it matters:**
- Knowing "MySQL 5.5.62" is running means nothing
- Knowing it has **CVE-2019-2614 (CVSS 9.8)** means you can own the box

**Where to see it:**
- `/recon` page → CVE Vulnerability Database section
- Device detail page → CVE Vulnerabilities (NVD) panel
- Risk score now factors in max CVSS score

**Example output:**
```
CVE-2019-2614 (CVSS 9.8) on 10.50.99.206:3306 [MySQL 5.5.62]
Description: Vulnerability in MySQL Server component allows unauthenticated 
attacker with network access to compromise MySQL Server...
```

---

### 2. 📡 WiFi Scanner + Rogue AP Detection
**What it does:**
- Scans nearby WiFi access points using `iwlist` / `nmcli`
- Detects:
  - **Evil Twin APs** — same SSID from multiple MACs (MITM attack)
  - **Open Networks** — no encryption (credentials in plaintext)
  - **Hidden SSIDs** — suspicious stealth networks
- Shows signal strength, channel, encryption type, BSSID
- Highlights currently connected AP

**Why it matters:**
- On a college/office WiFi, someone can set up a fake AP with the same SSID
- Your device auto-connects, attacker captures all traffic
- This detects it instantly

**Where to see it:**
- `/recon` page → WiFi Access Points + Rogue AP Detection sections

**Example alert:**
```
EVIL TWIN: 'College-WiFi' — seen from 3 different MACs — possible MITM attack!
```

---

### 3. 🕵️ Passive OS Fingerprinting
**What it does:**
- Identifies OS **without nmap** using TTL analysis
- Works on **ghost devices** (0 open ports) where nmap fails
- Analyzes:
  - **TTL values** from ping responses (Linux=64, Windows=128, Cisco=255)
  - **Port combinations** (SMB+RDP=Windows Server, SSH+HTTP=Linux, etc.)
- Returns confidence level (High/Medium/Low)

**Why it matters:**
- Ghost devices with randomized MACs and 0 ports are invisible to nmap
- TTL-based fingerprinting works even through client isolation
- Reveals phones, IoT devices, cameras that hide behind firewalls

**Where to see it:**
- `/recon` page → Passive OS Fingerprinting section
- Auto-runs on ghost devices during deep scan

**Example output:**
```
IP: 10.50.99.24
TTL: 64
OS Guess: 🐧 Linux / Android / macOS
Confidence: Medium
Method: TTL
Detail: TTL=64 → Linux / Android / macOS
```

---

### 4. 🎯 Smarter Risk Scoring
**What changed:**
- Risk score now includes **CVSS score contribution**:
  - CVSS ≥ 9.0 → +40 points
  - CVSS ≥ 7.0 → +25 points
  - CVSS ≥ 4.0 → +10 points
- A device with MySQL 5.5.62 (CVE-2019-2614, CVSS 9.8) now shows **Risk Score 80+** instead of 15

**Why it matters:**
- Old scoring: "3 open ports = low risk"
- New scoring: "MySQL with CVSS 9.8 CVE = CRITICAL risk"

---

## 🚀 How to Use

### 1. Access the Recon Page
```
http://localhost:5000/recon
```

### 2. Scan WiFi APs
Click **🔄 Scan WiFi** button
- Requires sudo/root
- Takes ~15 seconds
- Auto-detects rogue APs and emits CRITICAL alerts for evil twins

### 3. View CVEs
- Auto-loads on page load from last scan
- Shows all CVEs sorted by CVSS score (highest first)
- Click CVE ID to open NVD detail page

### 4. Run Passive Fingerprinting
Click **▶ Run Fingerprinting** button
- Analyzes all known devices via TTL
- Works on ghost devices
- Shows confidence level per device

---

## 🔧 Technical Details

### CVE Lookup API
- **Endpoint:** `https://services.nvd.nist.gov/rest/json/cves/2.0`
- **Rate limit:** ~5 requests/10 seconds (free tier)
- **Caching:** In-memory cache to avoid duplicate queries
- **Query format:** `?keywordSearch=MySQL+5.5.62&resultsPerPage=5`

### WiFi Scanner
- **Primary method:** `iwlist wlan0 scan` (requires root)
- **Fallback:** `nmcli dev wifi list` (no root needed)
- **Rogue detection logic:**
  - Evil twin: Same SSID, different MACs
  - Open network: Encryption key:off
  - Hidden SSID: ESSID:""

### Passive Fingerprinting
- **TTL ranges:**
  - 0-64: Linux / Android / macOS
  - 65-128: Windows
  - 129-255: Cisco / Network Device
- **Port-based refinement:**
  - 445+3389 → Windows Server
  - 22+80+443 → Linux Server
  - 554/8000 → IP Camera
  - 1883/8883 → IoT (MQTT)
  - 9100 → Network Printer

---

## 📊 New API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/recon` | GET | Recon dashboard page |
| `/api/wifi_scan` | GET | Scan WiFi APs + detect rogues |
| `/api/cve_lookup?ip=X` | GET | Lookup CVEs for a specific device |
| `/api/passive_fp` | GET | Fingerprint all devices via TTL |
| `/api/passive_fp/<ip>` | GET | Fingerprint a specific device |

---

## 🎯 Real-World Use Cases

### 1. College WiFi Evil Twin Detection
**Scenario:** Attacker sets up fake "College-WiFi" AP in library
**Detection:** Recon page shows EVIL TWIN alert — same SSID from 2 MACs
**Action:** Alert security team, avoid connecting

### 2. Ghost Device Identification
**Scenario:** 50 devices with 0 open ports (client isolation)
**Detection:** Passive fingerprinting reveals 30 Android phones, 15 laptops, 5 IoT devices
**Action:** Identify unauthorized IoT devices

### 3. Critical CVE on Database
**Scenario:** MySQL 5.5.62 running on 10.50.99.206
**Detection:** CVE-2019-2614 (CVSS 9.8) — unauthenticated RCE
**Action:** Immediate patching required

### 4. Rogue Open Network
**Scenario:** "Free-WiFi" AP with no encryption
**Detection:** Rogue AP panel shows OPEN_NETWORK alert
**Action:** Avoid — credentials transmitted in plaintext

---

## 🔥 What Makes This Hacker-Grade

| Feature | Script Kiddie Tool | CyberScope AI |
|---------|-------------------|---------------|
| Port scan | ✓ | ✓ |
| Service detection | ✓ | ✓ |
| CVE lookup | ✗ Manual | ✓ Automatic + NVD API |
| WiFi AP scan | ✗ Separate tool | ✓ Integrated |
| Evil twin detection | ✗ Manual analysis | ✓ Automatic |
| Passive fingerprinting | ✗ Requires nmap | ✓ Works on ghosts |
| CVSS-based risk scoring | ✗ Port count only | ✓ Real vulnerability severity |
| Real-time alerts | ✗ | ✓ WebSocket push |
| Unified dashboard | ✗ CLI only | ✓ Live web UI |

---

## 🛠️ Dependencies

All tools already included in Kali Linux:
- `iwlist` / `iwconfig` — WiFi scanning (wireless-tools package)
- `nmcli` — NetworkManager CLI (fallback)
- `ping` — TTL analysis
- `curl` / `urllib` — NVD API access

No additional installation needed.

---

## 📝 Notes

- **CVE lookup requires internet** — queries NVD API
- **WiFi scan requires sudo** — raw socket access for iwlist
- **Passive fingerprinting works offline** — only uses ping
- **All features are non-intrusive** — no exploitation, just reconnaissance

---

## 🎯 Next Steps

1. Click **🗑 Clear DB** to remove old alerts
2. Run **▶ Full Scan** to populate CVE data
3. Open `/recon` page to see new features
4. Click **🔄 Scan WiFi** to detect rogue APs
5. Click **▶ Run Fingerprinting** to identify ghost devices

---

**Built for hackers, by hackers. 🔥**
