from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
from scanner.device_scanner import scan_network
from scanner.port_scanner import scan_ports
from threat.detector import scan_threats
from ai.behavior_analyzer import analyze
from database.models import init_db, save_device, save_alert, get_all_devices, get_all_alerts
from reports.generator import generate_csv, generate_summary
import threading
import time

app = Flask(__name__)
app.config["SECRET_KEY"] = "cyberscopeai-secret-key"
socketio = SocketIO(app, cors_allowed_origins="*")

init_db()

IP_RANGE = "192.168.56.0/24"

def run_scan():
    devices = scan_network(IP_RANGE)
    results = []
    for d in devices:
        save_device(d["ip"], d["mac"])
        ports = scan_ports(d["ip"])
        threats = scan_threats(ports)
        comment = analyze(ports)
        for t in threats:
            msg = f"Port {t['port']} open on {d['ip']} — {t['reason']}"
            save_alert(msg, "HIGH")
            socketio.emit("alert", {"message": msg, "severity": "HIGH"})
        results.append({
            "ip": d["ip"], "mac": d["mac"],
            "ports": ports, "threats": threats, "comment": comment
        })
    socketio.emit("scan_complete", {"devices": results})
    return results

@app.route("/")
def dashboard():
    return render_template("dashboard.html")

@app.route("/api/scan")
def api_scan():
    return jsonify(run_scan())

@app.route("/api/devices")
def api_devices():
    return jsonify(get_all_devices())

@app.route("/api/alerts")
def api_alerts():
    return jsonify(get_all_alerts())

@app.route("/api/report")
def api_report():
    path = generate_csv()
    summary = generate_summary()
    summary["report_file"] = path
    return jsonify(summary)

def background_scan():
    while True:
        try:
            run_scan()
        except Exception as e:
            print(f"[Scan Error] {e}")
        time.sleep(30)

if __name__ == "__main__":
    t = threading.Thread(target=background_scan, daemon=True)
    t.start()
    socketio.run(app, debug=True, host="0.0.0.0", port=5000)
