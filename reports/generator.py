import csv
import os
import json
from datetime import datetime
from database.models import get_all_devices, get_all_alerts, get_scan_results

REPORTS_DIR = "logs"

def generate_csv():
    devices = get_all_devices()
    alerts = get_all_alerts()
    scan_results = get_scan_results()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(REPORTS_DIR, f"report_{timestamp}.csv")

    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["=== CYBERSCOPE AI REPORT ===", timestamp])
        writer.writerow([])
        writer.writerow(["DEVICES"])
        writer.writerow(["IP", "MAC", "Status", "Last Seen"])
        for d in devices:
            writer.writerow([d["ip"], d["mac"], d["status"], d["last_seen"]])
        writer.writerow([])
        writer.writerow(["SCAN RESULTS"])
        writer.writerow(["IP", "OS", "Open Ports", "Threats", "Vulns", "MSF Findings"])
        for r in scan_results:
            data = r["data"]
            writer.writerow([
                r["ip"],
                data.get("os", ""),
                ",".join(str(p) for p in data.get("ports", [])),
                len(data.get("threats", [])),
                len(data.get("vulns", [])),
                len(data.get("msf", [])),
            ])
        writer.writerow([])
        writer.writerow(["ALERTS"])
        writer.writerow(["Alert", "Severity", "Timestamp"])
        for a in alerts:
            writer.writerow([a["alert"], a["severity"], a["timestamp"]])
        writer.writerow([])
        writer.writerow([f"Total Devices: {len(devices)}"])
        writer.writerow([f"Total Alerts: {len(alerts)}"])

    return path

def generate_summary():
    devices = get_all_devices()
    alerts = get_all_alerts()
    critical = [a for a in alerts if a["severity"] == "CRITICAL"]
    high     = [a for a in alerts if a["severity"] == "HIGH"]
    return {
        "total_devices": len(devices),
        "total_alerts": len(alerts),
        "critical_alerts": len(critical),
        "high_risk_alerts": len(high),
    }
