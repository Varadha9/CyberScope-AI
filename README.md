# CyberScope AI
> AI-powered cybersecurity monitoring and network intelligence platform.

## Features
- Device discovery (ARP scanning)
- Port scanning
- Packet monitoring
- Threat detection
- Real-time dashboard
- AI-generated behavior comments

## Technologies
- Kali Linux
- Python
- Flask + Flask-SocketIO
- Scapy
- Nmap
- SQLite
- Chart.js

## Installation
```bash
pip install -r requirements.txt
```

## Run
```bash
python app.py
```

## Project Structure
```
CyberScopeAI/
├── app.py
├── requirements.txt
├── scanner/
│   ├── device_scanner.py
│   └── port_scanner.py
├── sniffer/
│   └── packet_sniffer.py
├── ai/
│   ├── comment_engine.py
│   └── behavior_analyzer.py
├── threat/
│   └── detector.py
├── database/
│   └── models.py
├── reports/
│   └── generator.py
├── static/
│   ├── style.css
│   └── app.js
├── templates/
│   └── dashboard.html
└── logs/
```

## Disclaimer
This project is built for **educational purposes only** in an isolated lab environment. Do not use on networks you don't own.
