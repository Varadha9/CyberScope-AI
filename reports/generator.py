import csv
import os
from datetime import datetime
from database.models import get_all_devices, get_all_alerts

REPORTS_DIR = "logs"

def generate_csv():
    devices = get_all_devices()
    alerts = get_all_alerts()
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
    high = [a for a in alerts if a["severity"] == "HIGH"]
    return {
        "total_devices": len(devices),
        "total_alerts": len(alerts),
        "high_risk_alerts": len(high),
    }
