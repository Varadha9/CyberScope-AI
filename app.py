from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO
from scanner.device_scanner import scan_network, get_wifi_subnet
from scanner.port_scanner import scan_ports
from threat.detector import scan_threats
from ai.behavior_analyzer import analyze
from database.models import init_db, save_device, save_alert, get_all_devices, get_all_alerts, save_scan_result, get_scan_results, clear_db
from reports.generator import generate_csv, generate_summary
from kali_tools.nmap_advanced import os_detect, vuln_scan, service_scan
from kali_tools.masscan_runner import masscan_quick
from kali_tools.nikto_runner import nikto_scan
from kali_tools.msf_runner import msf_check
from kali_tools.netdiscover_runner import netdiscover_scan
from sniffer.packet_sniffer import start_sniff
import threading
import time
import os

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "cyberscopeai-secret-key")
socketio = SocketIO(app, cors_allowed_origins="*")

init_db()

# Auto-clear DB if we're on a different subnet than last time
_current_subnet = get_wifi_subnet() or "10.50.99.0/24"
try:
    import os as _os
    _subnet_file = "logs/.last_subnet"
    _last_subnet = open(_subnet_file).read().strip() if _os.path.exists(_subnet_file) else ""
    if _last_subnet != _current_subnet:
        clear_db()
        open(_subnet_file, "w").write(_current_subnet)
except Exception:
    pass

def log(msg, type="info"):
    print(f"[{type.upper()}] {msg}")
    socketio.emit("log", {"msg": msg, "type": type})

def get_target_subnet():
    return get_wifi_subnet() or "10.50.99.0/24"

def deep_scan(ip, ports, result):
    """Run slow tools in background and push updates via socket"""
    try:
        log(f"[{ip}] Starting deep scan ({len(ports)} open ports)", "tool")
        log(f"[{ip}] Running service/version detection...", "tool")
        services = service_scan(ip)
        log(f"[{ip}] Service scan done: {list(services.values())[:3]}", "success")

        log(f"[{ip}] Running OS fingerprinting...", "tool")
        os_info = os_detect(ip)
        log(f"[{ip}] OS detected: {os_info}", "success")

        log(f"[{ip}] Running nmap vuln scripts...", "tool")
        vulns = vuln_scan(ip, ports)
        log(f"[{ip}] Vuln scan done: {len(vulns)} finding(s)", "warn" if vulns else "success")

        nikto_results = []
        for p in ports:
            if p in (80, 443, 8080, 8443):
                log(f"[{ip}] Running Nikto on port {p}...", "tool")
                nikto_results = nikto_scan(ip, p)
                log(f"[{ip}] Nikto done: {len(nikto_results)} finding(s)", "warn" if nikto_results else "success")
                break

        log(f"[{ip}] Running Metasploit auxiliary scanners...", "tool")
        msf_results = msf_check(ip, ports)
        log(f"[{ip}] MSF done: {len(msf_results)} finding(s)", "warn" if msf_results else "success")

        comment = analyze(ports, services)

        for v in vulns:
            save_alert(f"VULN on {ip}: {v}", "CRITICAL")
            socketio.emit("alert", {"message": f"VULN {ip}: {v}", "severity": "CRITICAL"})
        for n in nikto_results:
            save_alert(f"NIKTO {ip}: {n}", "MEDIUM")
            socketio.emit("alert", {"message": f"NIKTO {ip}: {n}", "severity": "MEDIUM"})
        for m in msf_results:
            save_alert(f"MSF {ip}: {m}", "HIGH")
            socketio.emit("alert", {"message": f"MSF {ip}: {m}", "severity": "HIGH"})

        result.update({
            "services": services, "os": os_info,
            "vulns": vulns, "nikto": nikto_results,
            "msf": msf_results, "comment": comment
        })
        save_scan_result(ip, result)
        socketio.emit("device_update", {"ip": ip, "data": result})
        log(f"[{ip}] ✔ Deep scan complete", "success")
    except Exception as e:
        log(f"[{ip}] Deep scan error: {e}", "error")

def run_scan():
    subnet = get_target_subnet()
    log(f"Scanning WiFi subnet: {subnet}", "info")

    log("Running ARP scan + netdiscover...", "tool")
    devices = scan_network(subnet, iface="wlan0")
    nd_devices = netdiscover_scan(subnet)
    known_ips = {d["ip"] for d in devices}
    for d in nd_devices:
        if d["ip"] not in known_ips:
            devices.append(d)
    # Filter out invalid IPs (0.0.0.0, localhost, our own IP)
    own_ip = get_wifi_subnet().rsplit(".", 1)[0] + "." if get_wifi_subnet() else ""
    devices = [d for d in devices if d["ip"] not in ("0.0.0.0", "127.0.0.1") and d["ip"] != ""]
    log(f"Device discovery done: {len(devices)} device(s) found", "success")

    results = []
    for d in devices:
        ip  = d["ip"]
        mac = d["mac"]
        save_device(ip, mac)
        socketio.emit("device_found", {"ip": ip, "mac": mac})
        log(f"Found device: {ip} ({mac})", "info")

        log(f"[{ip}] Running fast port scan (top 1000)...", "tool")
        ports = scan_ports(ip)
        log(f"[{ip}] Port scan done: {len(ports)} open port(s): {ports[:10]}", "success")

        threats = scan_threats(ports)
        comment = analyze(ports, {})
        if threats:
            log(f"[{ip}] {len(threats)} threat(s) detected!", "warn")

        for t in threats:
            msg = f"Port {t['port']} open on {ip} — {t['reason']}"
            save_alert(msg, t["risk"])
            socketio.emit("alert", {"message": msg, "severity": t["risk"]})

        result = {
            "ip": ip, "mac": mac,
            "ports": ports, "services": {},
            "os": "Scanning...", "threats": threats,
            "vulns": [], "nikto": [], "msf": [],
            "comment": comment
        }
        results.append(result)
        save_scan_result(ip, result)

    socketio.emit("scan_complete", {"devices": results, "subnet": subnet})
    log(f"Fast scan complete. Launching deep scan threads for {len(results)} device(s)...", "info")

    for result in results:
        threading.Thread(
            target=deep_scan,
            args=(result["ip"], result["ports"], result),
            daemon=True
        ).start()

    return results

@app.route("/")
def dashboard():
    return render_template("dashboard.html")

@app.route("/api/clear_db", methods=["POST"])
def api_clear_db():
    clear_db()
    return jsonify({"status": "cleared"})

@app.route("/api/subnet")
def api_subnet():
    return jsonify({"subnet": get_target_subnet()})

@app.route("/api/scan")
def api_scan():
    return jsonify(run_scan())

@app.route("/api/masscan")
def api_masscan():
    subnet = get_target_subnet()
    results = masscan_quick(subnet)
    return jsonify(results)

@app.route("/api/sniff")
def api_sniff():
    count = int(request.args.get("count", 30))
    packets = start_sniff(count=count, iface="wlan0")
    return jsonify(packets)

@app.route("/api/devices")
def api_devices():
    return jsonify(get_all_devices())

@app.route("/api/alerts")
def api_alerts():
    return jsonify(get_all_alerts())

@app.route("/api/scan_results")
def api_scan_results():
    return jsonify(get_scan_results())

@app.route("/api/report")
def api_report():
    path = generate_csv()
    summary = generate_summary()
    summary["report_file"] = path
    return jsonify(summary)

def background_scan():
    while True:
        try:
            log("Background scan cycle started", "info")
            run_scan()
        except Exception as e:
            log(f"Background scan error: {e}", "error")
        time.sleep(600)

if __name__ == "__main__":
    t = threading.Thread(target=background_scan, daemon=True)
    t.start()
    socketio.run(app, debug=False, use_reloader=False, host="0.0.0.0", port=5000)
