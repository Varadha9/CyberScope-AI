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
from kali_tools.wpscan_runner import wpscan
from kali_tools.sqlmap_runner import sqlmap_scan
from kali_tools.hydra_runner import hydra_scan
from kali_tools.enum4linux_runner import enum4linux_scan
from kali_tools.gobuster_runner import gobuster_scan
from kali_tools.whatweb_runner import whatweb_scan
from kali_tools.sslscan_runner import sslscan_scan
from kali_tools.wfuzz_runner import wfuzz_scan
from kali_tools.dnsrecon_runner import dnsrecon_scan
from kali_tools.fierce_runner import fierce_scan
from kali_tools.netcat_runner import netcat_banner
from kali_tools.john_runner import john_scan
from kali_tools.searchsploit_runner import searchsploit_scan
from kali_tools.tcpdump_runner import tcpdump_capture
from kali_tools.tshark_runner import tshark_capture
from kali_tools.netdiscover_runner import netdiscover_scan
from sniffer.packet_sniffer import start_sniff
import threading
import time
import os
from datetime import datetime

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

        # WhatWeb
        whatweb_results = []
        for p in ports:
            if p in (80, 443, 8080, 8443):
                log(f"[{ip}] Running WhatWeb on port {p}...", "tool")
                whatweb_results = whatweb_scan(ip, p)
                log(f"[{ip}] WhatWeb done: {len(whatweb_results)} finding(s)", "success")
                break

        # WPScan
        wpscan_results = []
        for p in ports:
            if p in (80, 443, 8080, 8443):
                log(f"[{ip}] Running WPScan on port {p}...", "tool")
                wpscan_results = wpscan(ip, p)
                log(f"[{ip}] WPScan done: {len(wpscan_results)} finding(s)", "warn" if wpscan_results else "success")
                break

        # SQLMap
        sqlmap_results = []
        for p in ports:
            if p in (80, 443, 8080, 8443):
                log(f"[{ip}] Running SQLMap on port {p}...", "tool")
                sqlmap_results = sqlmap_scan(ip, p)
                log(f"[{ip}] SQLMap done: {len(sqlmap_results)} finding(s)", "warn" if sqlmap_results else "success")
                break

        # Gobuster
        gobuster_results = []
        for p in ports:
            if p in (80, 443, 8080, 8443):
                log(f"[{ip}] Running Gobuster on port {p}...", "tool")
                gobuster_results = gobuster_scan(ip, p)
                log(f"[{ip}] Gobuster done: {len(gobuster_results)} path(s)", "success")
                break

        # Wfuzz
        wfuzz_results = []
        for p in ports:
            if p in (80, 443, 8080, 8443):
                log(f"[{ip}] Running Wfuzz on port {p}...", "tool")
                wfuzz_results = wfuzz_scan(ip, p)
                log(f"[{ip}] Wfuzz done: {len(wfuzz_results)} finding(s)", "success")
                break

        # SSLScan
        sslscan_results = []
        for p in ports:
            if p in (443, 8443):
                log(f"[{ip}] Running SSLScan on port {p}...", "tool")
                sslscan_results = sslscan_scan(ip, p)
                log(f"[{ip}] SSLScan done: {len(sslscan_results)} finding(s)", "warn" if sslscan_results else "success")
                break

        # Hydra
        log(f"[{ip}] Running Hydra brute-force check...", "tool")
        hydra_results = hydra_scan(ip, ports)
        log(f"[{ip}] Hydra done: {len(hydra_results)} credential(s) found", "warn" if hydra_results else "success")

        # John the Ripper
        log(f"[{ip}] Running John the Ripper hash cracker...", "tool")
        john_results = john_scan(ip, ports)
        log(f"[{ip}] John done: {len(john_results)} hash(es) cracked", "warn" if john_results else "success")

        # Enum4linux (SMB/Windows)
        enum4linux_results = []
        if any(p in ports for p in (139, 445)):
            log(f"[{ip}] Running Enum4linux...", "tool")
            enum4linux_results = enum4linux_scan(ip)
            log(f"[{ip}] Enum4linux done: {len(enum4linux_results)} finding(s)", "success")

        # SearchSploit
        log(f"[{ip}] Running SearchSploit for CVE matches...", "tool")
        searchsploit_results = searchsploit_scan(services)
        log(f"[{ip}] SearchSploit done: {len(searchsploit_results)} exploit(s) found", "warn" if searchsploit_results else "success")

        # Netcat banner grab
        log(f"[{ip}] Running Netcat banner grab...", "tool")
        nc_banners = netcat_banner(ip, ports)
        log(f"[{ip}] Netcat done: {len(nc_banners)} banner(s)", "success")

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
        for j in john_results:
            save_alert(f"JOHN {ip}: {j}", "CRITICAL")
            socketio.emit("alert", {"message": f"JOHN {ip}: {j}", "severity": "CRITICAL"})

        result.update({
            "services": services, "os": os_info,
            "vulns": vulns, "nikto": nikto_results,
            "msf": msf_results, "comment": comment,
            "whatweb": whatweb_results, "wpscan": wpscan_results,
            "sqlmap": sqlmap_results, "gobuster": gobuster_results,
            "wfuzz": wfuzz_results, "sslscan": sslscan_results,
            "hydra": hydra_results, "john": john_results, "enum4linux": enum4linux_results,
            "searchsploit": searchsploit_results, "nc_banners": nc_banners,
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
            "ip": ip, "mac": mac, "hostname": d.get("hostname", "unknown"),
            "ports": ports, "services": {},
            "os": "Scanning...", "threats": threats,
            "vulns": [], "nikto": [], "msf": [],
            "whatweb": [], "wpscan": [], "sqlmap": [],
            "gobuster": [], "wfuzz": [], "sslscan": [],
            "hydra": [], "john": [], "enum4linux": [], "searchsploit": [],
            "nc_banners": {}, "comment": comment
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

@app.route("/device/<ip>")
def device_detail(ip):
    return render_template("device.html")

@app.route("/alerts")
def alerts_page():
    return render_template("alerts.html")

@app.route("/map")
def map_page():
    return render_template("map.html")

@app.route("/reports")
def reports_page():
    return render_template("reports.html")

@app.route("/api/clear_db", methods=["POST"])
def api_clear_db():
    clear_db()
    return jsonify({"status": "cleared"})

@app.route("/api/subnet")
def api_subnet():
    return jsonify({"subnet": get_target_subnet()})

@app.route("/api/scan")
def api_scan():
    threading.Thread(target=run_scan, daemon=True).start()
    return jsonify({"status": "started"})

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

@app.route("/api/tcpdump")
def api_tcpdump():
    count = int(request.args.get("count", 20))
    return jsonify(tcpdump_capture(iface="wlan0", count=count))

@app.route("/api/tshark")
def api_tshark():
    count = int(request.args.get("count", 20))
    return jsonify(tshark_capture(iface="wlan0", count=count))

@app.route("/api/dnsrecon")
def api_dnsrecon():
    target = request.args.get("target", "")
    if not target:
        return jsonify({"error": "target required"}), 400
    return jsonify(dnsrecon_scan(target))

@app.route("/api/john")
def api_john():
    target = request.args.get("target", "")
    ports  = [int(p) for p in request.args.get("ports", "").split(",") if p.isdigit()]
    if not target:
        return jsonify({"error": "target required"}), 400
    return jsonify(john_scan(target, ports))

@app.route("/api/fierce")
def api_fierce():
    target = request.args.get("target", "")
    if not target:
        return jsonify({"error": "target required"}), 400
    return jsonify(fierce_scan(target))

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

@app.route("/api/reports_list")
def api_reports_list():
    import glob
    files = sorted(glob.glob("logs/report_*.csv"), reverse=True)
    result = []
    for f in files:
        stat = os.stat(f)
        result.append({
            "filename": os.path.basename(f),
            "path": f,
            "size": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
        })
    return jsonify(result)

@app.route("/api/download_report/<filename>")
def api_download_report(filename):
    from flask import send_file
    path = os.path.join("logs", filename)
    if not os.path.exists(path) or not filename.startswith("report_"):
        return jsonify({"error": "not found"}), 404
    return send_file(path, as_attachment=True)

def background_scan():
    time.sleep(15)  # Wait for app to fully start
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
