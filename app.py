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
from kali_tools.traffic_watcher import watch_ip
from kali_tools.traffic_watcher import detect_beacons
from kali_tools.dns_logger import get_dns_queries, get_subnet_dns
from kali_tools.geo_ip import lookup as geo_lookup, enrich_packets
from kali_tools.arp_spoof import start_spoof, stop_spoof, is_spoofing, list_spoofs
from kali_tools.john_runner import john_scan
from kali_tools.searchsploit_runner import searchsploit_scan
from kali_tools.tcpdump_runner import tcpdump_capture
from kali_tools.tshark_runner import tshark_capture
from kali_tools.netdiscover_runner import netdiscover_scan
from kali_tools.cve_lookup import lookup_cves, get_max_cvss
from kali_tools.wifi_scanner import scan_wifi_aps, detect_rogue_aps, get_connected_ap
from kali_tools.os_fingerprint import passive_os_fingerprint, fingerprint_subnet
from kali_tools.passive_intel import harvest_passive, get_intel, get_all_intel, start_continuous_harvest
from kali_tools.smart_scanner import detect_isolation, get_gateway, get_infrastructure_subnet, scan_infrastructure, smart_port_scan
from kali_tools.hikvision_scanner import full_hikvision_scan, detect_hikvision
from kali_tools.rtsp_proxy import mjpeg_stream, probe_rtsp
from kali_tools.ipv6_scanner import discover_ipv6_devices, ipv6_port_scan, ipv6_service_scan, ipv6_os_detect, get_ipv6_for_mac, get_ndp_table, get_arp_table
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
        # Skip deep scan entirely for ghost devices — run passive fingerprint only
        if not ports:
            fp = passive_os_fingerprint(ip)
            os_info = fp["os_guess"] if fp["os_guess"] != "Unknown" else os_detect(ip)
            result.update({"os": os_info, "passive_fp": fp})
            save_scan_result(ip, result)
            socketio.emit("device_update", {"ip": ip, "data": result})
            log(f"[{ip}] Ghost — passive fingerprint: {fp['detail'] or os_info}", "info")
            return

        log(f"[{ip}] Starting deep scan ({len(ports)} open ports)", "tool")

        # ── Fast tools first ──────────────────────────────────────────────
        log(f"[{ip}] Running service/version detection...", "tool")
        ipv6_addr = result.get("ipv6") or get_ipv6_for_mac(result.get("mac",""))
        if ipv6_addr and ports:
            services = ipv6_service_scan(ipv6_addr, ports, iface="wlan0")
            log(f"[{ip}] Service scan (IPv6) done: {len(services)} service(s)", "success")
        else:
            services = service_scan(ip)
            log(f"[{ip}] Service scan done: {len(services)} service(s)", "success")

        log(f"[{ip}] Running OS fingerprinting...", "tool")
        if ipv6_addr:
            os_info = ipv6_os_detect(ipv6_addr, iface="wlan0")
        else:
            os_info = os_detect(ip)
        log(f"[{ip}] OS detected: {os_info}", "success")

        log(f"[{ip}] Running nmap vuln scripts...", "tool")
        vulns = vuln_scan(ip, ports)
        log(f"[{ip}] Vuln scan done: {len(vulns)} finding(s)", "warn" if vulns else "success")

        # Netcat banner grab (fast)
        log(f"[{ip}] Running Netcat banner grab...", "tool")
        nc_banners = netcat_banner(ip, ports)
        log(f"[{ip}] Netcat done: {len(nc_banners)} banner(s)", "success")

        # SearchSploit (fast — offline DB)
        log(f"[{ip}] Running SearchSploit for CVE matches...", "tool")
        searchsploit_results = searchsploit_scan(services)
        log(f"[{ip}] SearchSploit done: {len(searchsploit_results)} exploit(s) found", "warn" if searchsploit_results else "success")

        # CVE Lookup via NVD API
        log(f"[{ip}] Looking up CVEs via NVD API...", "tool")
        cve_results = lookup_cves(services)
        max_cvss = get_max_cvss(cve_results)
        if cve_results:
            log(f"[{ip}] CVE lookup: {sum(len(r['cves']) for r in cve_results)} CVE(s) found, max CVSS={max_cvss}", "warn")
            for r in cve_results:
                for cve in r["cves"]:
                    if cve["score"] >= 7.0:
                        msg = f"CVE {cve['id']} (CVSS {cve['score']}) on {ip}:{r['port']} [{r['product']}]"
                        save_alert(msg, "CRITICAL" if cve["score"] >= 9.0 else "HIGH")
                        socketio.emit("alert", {"message": msg, "severity": "CRITICAL" if cve["score"] >= 9.0 else "HIGH"})
        else:
            log(f"[{ip}] CVE lookup: no CVEs found", "success")
            cve_results = []

        # ── Web tools — only if web ports open ───────────────────────────
        web_port = next((p for p in ports if p in (80, 443, 8080, 8443)), None)
        nikto_results, whatweb_results, wpscan_results = [], [], []
        sqlmap_results, gobuster_results, wfuzz_results, sslscan_results = [], [], [], []

        if web_port:
            log(f"[{ip}] Running Nikto on port {web_port}...", "tool")
            nikto_results = nikto_scan(ip, web_port)
            log(f"[{ip}] Nikto done: {len(nikto_results)} finding(s)", "warn" if nikto_results else "success")

            log(f"[{ip}] Running WhatWeb on port {web_port}...", "tool")
            whatweb_results = whatweb_scan(ip, web_port)
            log(f"[{ip}] WhatWeb done: {len(whatweb_results)} finding(s)", "success")

            log(f"[{ip}] Running WPScan on port {web_port}...", "tool")
            wpscan_results = wpscan(ip, web_port)
            log(f"[{ip}] WPScan done: {len(wpscan_results)} finding(s)", "warn" if wpscan_results else "success")

            log(f"[{ip}] Running SQLMap on port {web_port}...", "tool")
            sqlmap_results = sqlmap_scan(ip, web_port)
            log(f"[{ip}] SQLMap done: {len(sqlmap_results)} finding(s)", "warn" if sqlmap_results else "success")

            log(f"[{ip}] Running Gobuster on port {web_port}...", "tool")
            gobuster_results = gobuster_scan(ip, web_port)
            log(f"[{ip}] Gobuster done: {len(gobuster_results)} path(s)", "success")

            log(f"[{ip}] Running Wfuzz on port {web_port}...", "tool")
            wfuzz_results = wfuzz_scan(ip, web_port)
            log(f"[{ip}] Wfuzz done: {len(wfuzz_results)} finding(s)", "success")

        ssl_port = next((p for p in ports if p in (443, 8443)), None)
        if ssl_port:
            log(f"[{ip}] Running SSLScan on port {ssl_port}...", "tool")
            sslscan_results = sslscan_scan(ip, ssl_port)
            log(f"[{ip}] SSLScan done: {len(sslscan_results)} finding(s)", "warn" if sslscan_results else "success")

        # ── MSF — only if relevant ports open ────────────────────────────
        msf_ports = {21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5432, 6667, 8080}
        msf_results = []
        if any(p in msf_ports for p in ports):
            log(f"[{ip}] Running Metasploit auxiliary scanners...", "tool")
            msf_results = msf_check(ip, ports)
            log(f"[{ip}] MSF done: {len(msf_results)} finding(s)", "warn" if msf_results else "success")

        # ── Hydra — only if auth ports open ──────────────────────────────
        auth_ports = {21, 22, 23, 3306, 5432, 3389}
        hydra_results = []
        if any(p in auth_ports for p in ports):
            log(f"[{ip}] Running Hydra brute-force check...", "tool")
            hydra_results = hydra_scan(ip, ports)
            log(f"[{ip}] Hydra done: {len(hydra_results)} credential(s) found", "warn" if hydra_results else "success")

        # ── John — only if hash-extractable ports open (NOT web ports) ────────
        john_ports = {21, 22, 23, 139, 445, 3306, 5432, 3389}
        john_results = []
        if any(p in john_ports for p in ports):
            log(f"[{ip}] Running John the Ripper hash cracker...", "tool")
            john_results = john_scan(ip, ports)
            if john_results:
                log(f"[{ip}] John done: {len(john_results)} finding(s)", "warn")
            else:
                log(f"[{ip}] John done: no hashes extracted", "success")

        # ── Hikvision camera scan — if camera ports open ─────────────────
        hik_results = {}
        if any(p in ports for p in (80, 554, 8000, 8080, 443)):
            hik_info = detect_hikvision(ip)
            if hik_info.get("is_hikvision"):
                log(f"[{ip}] Hikvision camera detected! Running full assessment...", "warn")
                hik_results = full_hikvision_scan(ip)
                for s in hik_results.get("summary", []):
                    save_alert(f"HIKVISION {ip}: {s}", "CRITICAL")
                    socketio.emit("alert", {"message": f"HIKVISION {ip}: {s}", "severity": "CRITICAL"})
                log(f"[{ip}] Hikvision scan done: {hik_results.get('risk_level')} - {hik_results.get('summary')}", "warn")

        # ── Enum4linux — only if SMB ports open ──────────────────────────
        enum4linux_results = []
        if any(p in ports for p in (139, 445)):
            log(f"[{ip}] Running Enum4linux...", "tool")
            enum4linux_results = enum4linux_scan(ip)
            log(f"[{ip}] Enum4linux done: {len(enum4linux_results)} finding(s)", "success")

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
            # Only alert on real findings, not informational messages
            if any(kw in j for kw in ["cracked", "login", "allowed", "plaintext", "empty password", "auth methods"]):
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
            "cve_results": cve_results, "max_cvss": max_cvss,
        })
        save_scan_result(ip, result)
        socketio.emit("device_update", {"ip": ip, "data": result})
        log(f"[{ip}] ✔ Deep scan complete", "success")
    except Exception as e:
        log(f"[{ip}] Deep scan error: {e}", "error")

def run_scan():
    subnet = get_target_subnet()
    log(f"Scanning WiFi subnet: {subnet}", "info")

    gw_ip, gw_mac = get_gateway()
    log(f"Gateway: {gw_ip} ({gw_mac})", "info")
    infra_subnet = get_infrastructure_subnet(gw_ip) if gw_ip else None

    log("Running ARP scan + netdiscover...", "tool")
    devices = scan_network(subnet, iface="wlan0")
    nd_devices = netdiscover_scan(subnet)
    known_ips = {d["ip"] for d in devices}
    subnet_prefix = subnet.rsplit(".", 1)[0]
    for d in nd_devices:
        if d["ip"] not in known_ips and d["ip"].startswith(subnet_prefix + "."):
            devices.append(d)
    devices = [d for d in devices if d["ip"] not in ("0.0.0.0", "127.0.0.1") and d["ip"] != ""]
    devices = [d for d in devices if d["ip"].startswith(subnet_prefix + ".")]
    log(f"Device discovery done: {len(devices)} device(s) found", "success")

    # Detect client isolation
    isolated = True
    if devices:
        test_ip = next((d["ip"] for d in devices if d["ip"] != gw_ip), None)
        if test_ip:
            isolated = detect_isolation(test_ip, gw_ip)
            status = "ACTIVE - using passive intel" if isolated else "NOT active - direct scan"
            log(f"Client isolation: {status}", "warn" if isolated else "success")

    # Scan infrastructure subnet (NOT behind client isolation)
    if infra_subnet and infra_subnet != subnet:
        log(f"Scanning infrastructure subnet {infra_subnet}...", "tool")
        infra_devices = scan_infrastructure(gw_ip)
        if infra_devices:
            log(f"Infrastructure scan: {len(infra_devices)} device(s) found", "success")
            for d in infra_devices:
                ip  = d["ip"]
                mac = d["mac"]
                if ip in known_ips:
                    continue
                save_device(ip, mac)
                socketio.emit("device_found", {"ip": ip, "mac": mac})
                dtype = d.get("device_type", "")
                result = {
                    "ip": ip, "mac": mac,
                    "hostname": dtype or d.get("vendor") or "Network Device",
                    "ports": d["ports"], "services": d["services"],
                    "os": d.get("vendor", "Unknown"),
                    "device_type": dtype,
                    "threats": scan_threats(d["ports"]),
                    "vulns": [], "nikto": [], "msf": [],
                    "whatweb": [], "wpscan": [], "sqlmap": [],
                    "gobuster": [], "wfuzz": [], "sslscan": [],
                    "hydra": [], "john": [], "enum4linux": [],
                    "searchsploit": [], "nc_banners": {},
                    "comment": f"Infrastructure device - {dtype}",
                    "intel_sources": ["infrastructure_scan"],
                }
                save_scan_result(ip, result)
                socketio.emit("device_update", {"ip": ip, "data": result})
                known_ips.add(ip)
                log(f"[Infra] {ip} - {dtype} ports={d['ports']}", "success")
                for t in result["threats"]:
                    msg = f"Port {t['port']} open on {ip} - {t['reason']}"
                    save_alert(msg, t["risk"])
                    socketio.emit("alert", {"message": msg, "severity": t["risk"]})

    results = []
    for d in devices:
        ip  = d["ip"]
        mac = d["mac"]
        save_device(ip, mac)
        socketio.emit("device_found", {"ip": ip, "mac": mac})
        log(f"Found device: {ip} ({mac})", "info")

        log(f"[{ip}] Running port scan...", "tool")
        if isolated:
            # IPv6 bypass: PSPF blocks IPv4 but NOT IPv6 link-local
            ipv6_addr = get_ipv6_for_mac(mac)
            if ipv6_addr:
                log(f"[{ip}] Client isolation detected - using IPv6 bypass ({ipv6_addr})", "warn")
                ports = ipv6_port_scan(ipv6_addr, iface="wlan0", top_ports=1000)
                result["ipv6"] = ipv6_addr
            else:
                ports = smart_port_scan(ip, mac, gw_ip, use_mitm=False)
        else:
            ports = smart_port_scan(ip, mac, gw_ip, use_mitm=False)
        log(f"[{ip}] Port scan done: {len(ports)} open port(s): {ports[:10]}", "success")

        threats = scan_threats(ports)
        comment = analyze(ports, {})
        if threats:
            log(f"[{ip}] {len(threats)} threat(s) detected!", "warn")

        for t in threats:
            msg = f"Port {t['port']} open on {ip} - {t['reason']}"
            save_alert(msg, t["risk"])
            socketio.emit("alert", {"message": msg, "severity": t["risk"]})

        result = {
            "ip": ip, "mac": mac, "hostname": d.get("hostname", "unknown"),
            "ports": ports, "services": {},
            "os": "Unknown", "threats": threats,
            "vulns": [], "nikto": [], "msf": [],
            "whatweb": [], "wpscan": [], "sqlmap": [],
            "gobuster": [], "wfuzz": [], "sslscan": [],
            "hydra": [], "john": [], "enum4linux": [], "searchsploit": [],
            "nc_banners": {}, "comment": comment
        }
        intel = get_intel(mac=mac) or get_intel(ip=ip)
        if intel:
            if intel.get("hostname") and result["hostname"] in ("unknown", ""):
                result["hostname"] = intel["hostname"]
            if intel.get("os_hint"):
                result["os"] = intel["os_hint"]
            result["device_type"] = intel.get("device_type", "")
            result["intel_sources"] = intel.get("sources", [])
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

    from database.models import get_all_devices as _get_devs
    known_macs = {d["mac"] for d in _get_devs() if d["mac"]}
    for result in results:
        if len(result["ports"]) == 0 and not is_spoofing(result["ip"]):
            mac = result.get("mac", "")
            if mac and mac in known_macs:
                log(f"[Auto-MITM] {result['ip']} persistent ghost - starting ARP spoof", "warn")
                sr = start_spoof(result["ip"], iface="wlan0")
                if sr.get("status") == "started":
                    log(f"[Auto-MITM] Spoofing {result['ip']} - traffic now visible", "warn")
                    socketio.emit("alert", {
                        "message": f"Auto-MITM on {result['ip']} (persistent ghost)",
                        "severity": "MEDIUM"
                    })

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

@app.route("/activity")
def activity_page():
    return render_template("activity.html")

@app.route("/api/activity")
def api_activity():
    count   = int(request.args.get("count", 100))
    timeout = int(request.args.get("timeout", 15))
    from kali_tools.traffic_watcher import _run_tshark, _resolve, _detect_activity, PORT_LABELS
    out = _run_tshark([
        "-i", "wlan0", "-c", str(count),
        "-T", "fields",
        "-e", "ip.src", "-e", "ip.dst",
        "-e", "tcp.srcport", "-e", "tcp.dstport",
        "-e", "udp.srcport", "-e", "udp.dstport",
        "-e", "_ws.col.Protocol", "-e", "frame.len",
    ], timeout=timeout)
    seen = {}
    for line in out.splitlines():
        parts = line.strip().split("\t")
        if len(parts) < 2: continue
        src, dst = parts[0], parts[1]
        if not src or not dst: continue
        proto  = parts[6] if len(parts) > 6 else ""
        length = parts[7] if len(parts) > 7 else "0"
        tcp_dp = parts[3] if len(parts) > 3 else ""
        udp_dp = parts[5] if len(parts) > 5 else ""
        dport  = tcp_dp or udp_dp
        # Only local src IPs (support both 192.168.x.x and 10.x.x.x)
        if not (src.startswith("192.168.") or src.startswith("10.") or src.startswith("172.")):
            continue
        key = src
        remote_host = _resolve(dst)
        activity = _detect_activity(remote_host, dport)
        if key not in seen:
            seen[key] = {"ip": src, "bytes": 0, "packets": 0, "activities": set(), "destinations": set()}
        seen[key]["bytes"]   += int(length) if length.isdigit() else 0
        seen[key]["packets"] += 1
        seen[key]["activities"].add(activity)
        if dst and not dst.startswith("224.") and not dst.startswith("239."):
            seen[key]["destinations"].add(dst)
    result = []
    for v in sorted(seen.values(), key=lambda x: x["bytes"], reverse=True):
        result.append({
            "ip":           v["ip"],
            "bytes":        v["bytes"],
            "packets":      v["packets"],
            "activities":   list(v["activities"]),
            "destinations": list(v["destinations"])[:5],
        })
    return jsonify(result)

@app.route("/api/spoof/start/<ip>")
def api_spoof_start(ip):
    result = start_spoof(ip, iface="wlan0")
    if result.get("status") == "started":
        log(f"[MITM] ARP spoof started on {ip} — traffic now visible", "warn")
    return jsonify(result)

@app.route("/api/spoof/stop/<ip>")
def api_spoof_stop(ip):
    result = stop_spoof(ip)
    log(f"[MITM] ARP spoof stopped on {ip}", "info")
    return jsonify(result)

@app.route("/api/spoof/status")
def api_spoof_status():
    return jsonify({"spoofing": list_spoofs()})

@app.route("/watch/<ip>")
def watch_page(ip):
    return render_template("watch.html", ip=ip)

@app.route("/api/watch/<ip>")
def api_watch(ip):
    count   = int(request.args.get("count", 500))
    timeout = int(request.args.get("timeout", 20))
    import subprocess as _sp, re as _re
    try:
        _out = _sp.check_output(["ip", "route", "show", "default"], text=True)
        _m = _re.search(r"dev (\S+)", _out)
        iface = _m.group(1) if _m else "wlan0"
    except Exception:
        iface = "wlan0"
    packets = watch_ip(ip, iface=iface, count=count, timeout=timeout)
    enrich_packets(packets)
    beacons = detect_beacons(packets)
    # Emit beacon alerts via WebSocket
    for b in beacons:
        msg = f"BEACON {ip} → {b['host']} every ~{b['interval']}s ({b['count']} hits) {b.get('country','')}"
        save_alert(msg, "HIGH")
        socketio.emit("alert", {"message": msg, "severity": "HIGH"})
    return jsonify({"packets": packets, "beacons": beacons})

@app.route("/api/dns/<ip>")
def api_dns(ip):
    timeout = int(request.args.get("timeout", 20))
    count   = int(request.args.get("count", 500))
    queries = get_dns_queries(ip, iface="wlan0", count=count, timeout=timeout)
    return jsonify(queries)

@app.route("/api/dns_subnet")
def api_dns_subnet():
    timeout = int(request.args.get("timeout", 15))
    return jsonify(get_subnet_dns(iface="wlan0", timeout=timeout))

@app.route("/api/geo/<ip>")
def api_geo(ip):
    return jsonify(geo_lookup(ip))

@app.route("/api/beacons/<ip>")
def api_beacons(ip):
    timeout = int(request.args.get("timeout", 30))
    count   = int(request.args.get("count", 999))
    import subprocess as _sp, re as _re
    try:
        _out = _sp.check_output(["ip", "route", "show", "default"], text=True)
        _m = _re.search(r"dev (\S+)", _out)
        iface = _m.group(1) if _m else "wlan0"
    except Exception:
        iface = "wlan0"
    packets = watch_ip(ip, iface=iface, count=count, timeout=timeout)
    enrich_packets(packets)
    beacons = detect_beacons(packets)
    for b in beacons:
        msg = f"BEACON {ip} → {b['host']} every ~{b['interval']}s ({b['count']} hits) {b.get('country','')}"
        save_alert(msg, "HIGH")
        socketio.emit("alert", {"message": msg, "severity": "HIGH"})
    return jsonify(beacons)

@app.route("/api/john")
def api_john():
    target = request.args.get("target", "")
    ports  = [int(p) for p in request.args.get("ports", "").split(",") if p.isdigit()]
    if not target:
        return jsonify({"error": "target required"}), 400
    return jsonify(john_scan(target, ports))

@app.route("/api/passive_intel")
def api_passive_intel():
    """Get all passively harvested device intelligence."""
    return jsonify(get_all_intel())

@app.route("/api/passive_intel/harvest")
def api_passive_intel_harvest():
    """Trigger a fresh passive harvest, add new devices, enrich existing ones."""
    timeout = int(request.args.get("timeout", 30))
    log(f"Passive harvest started ({timeout}s)...", "tool")
    results = harvest_passive(timeout=timeout)
    from database.models import get_scan_results as _gsr, save_scan_result as _ssr, save_device as _sd
    import json as _json

    # Build lookup
    intel_by_mac = {mac.lower(): d for mac, d in results.items()}
    intel_by_ip  = {d.get("ip",""): d for d in results.values() if d.get("ip") and d.get("ip") != "0.0.0.0"}

    db_results = _gsr()
    db_ips  = {r["ip"] for r in db_results}
    db_macs = {r["data"].get("mac","").lower() for r in db_results}

    enriched = 0
    added    = 0

    # 1. Enrich existing DB devices
    for row in db_results:
        ip   = row["ip"]
        data = row["data"]
        mac  = data.get("mac","").lower()
        d    = intel_by_mac.get(mac) or intel_by_ip.get(ip)
        if not d:
            continue
        changed = False
        if d.get("hostname") and data.get("hostname") in ("unknown","",None):
            data["hostname"] = d["hostname"]; changed = True
        if d.get("os_hint") and data.get("os") in ("Unknown","Scanning...","",None):
            data["os"] = d["os_hint"]; changed = True
        if d.get("device_type"):
            data["device_type"] = d["device_type"]; changed = True
        if changed:
            _ssr(ip, data)
            socketio.emit("device_update", {"ip": ip, "data": data})
            enriched += 1

    # 2. Add NEW devices discovered via passive intel (have real IP, not in DB)
    subnet_prefix = get_target_subnet().rsplit(".", 1)[0]
    for mac, d in intel_by_mac.items():
        ip = d.get("ip","")
        if not ip or ip == "0.0.0.0":
            continue
        if ip in db_ips or mac in db_macs:
            continue
        # Only add if in our subnet
        if not ip.startswith(subnet_prefix + "."):
            continue
        hostname    = d.get("hostname", "unknown")
        os_hint     = d.get("os_hint", "Unknown")
        device_type = d.get("device_type", "")
        _sd(ip, mac)
        new_result = {
            "ip": ip, "mac": mac, "hostname": hostname,
            "os": os_hint, "device_type": device_type,
            "ports": [], "services": {}, "threats": [],
            "vulns": [], "nikto": [], "msf": [],
            "whatweb": [], "wpscan": [], "sqlmap": [],
            "gobuster": [], "wfuzz": [], "sslscan": [],
            "hydra": [], "john": [], "enum4linux": [],
            "searchsploit": [], "nc_banners": {},
            "comment": f"Discovered via {'+'.join(d.get('sources',[]))}",
            "intel_sources": d.get("sources", []),
        }
        _ssr(ip, new_result)
        socketio.emit("device_found", {"ip": ip, "mac": mac})
        socketio.emit("device_update", {"ip": ip, "data": new_result})
        db_ips.add(ip); db_macs.add(mac)
        added += 1
        log(f"[Passive] New device: {ip} ({mac}) = {hostname} [{device_type}]", "success")

    log(f"Passive harvest done: {len(results)} seen, {added} new, {enriched} enriched", "success")
    return jsonify({"harvested": len(results), "added": added, "enriched": enriched, "intel": results})

@app.route("/api/oui")
def api_oui():
    """Return OUI lookup for a batch of MACs."""
    macs = request.args.get("macs", "").split(",")
    from scanner.device_scanner import mac_vendor, vendor_to_label
    result = {}
    for mac in macs:
        mac = mac.strip()
        if mac:
            vendor = mac_vendor(mac)
            result[mac] = vendor_to_label(vendor) or vendor
    return jsonify(result)


@app.route("/api/ipv6_scan")
def api_ipv6_scan():
    """Discover and scan all devices via IPv6 (bypasses client isolation)."""
    from kali_tools.ipv6_scanner import discover_ipv6_devices, ipv6_port_scan, ipv6_ping, get_arp_table
    log("IPv6 bypass scan started...", "tool")
    devices = discover_ipv6_devices(iface="wlan0")
    arp = get_arp_table()
    results = []
    for d in devices:
        ipv6 = d["ipv6"]
        mac  = d["mac"]
        ipv4 = d.get("ipv4") or arp.get(mac, "")
        if not ipv6_ping(ipv6, "wlan0"):
            continue
        ports = ipv6_port_scan(ipv6, "wlan0", top_ports=500)
        entry = {"ipv6": ipv6, "mac": mac, "ipv4": ipv4, "ports": ports}
        results.append(entry)
        if ports:
            log(f"[IPv6] {ipv6} ({mac}) ipv4={ipv4} ports={ports}", "success")
            socketio.emit("alert", {
                "message": f"IPv6 bypass: {ipv6} ({mac}) has open ports {ports}",
                "severity": "HIGH"
            })
    log(f"IPv6 scan done: {len(results)} reachable, {sum(1 for r in results if r['ports'])} with open ports", "success")
    return jsonify(results)




@app.route("/api/cameras")
def api_cameras():
    """Return all detected cameras from scan results."""
    results = get_scan_results()
    cameras = []
    for r in results:
        d = r.get("data", {})
        h = (d.get("hostname", "") or "").lower()
        ports = d.get("ports", []) or []
        dtype = (d.get("device_type", "") or "").lower()
        mac = (d.get("mac", "") or "").lower()
        vendor = mac  # will be enriched client-side
        is_cam = (
            any(k in h for k in ["hik", "camera", "nvr", "dahua", "cam", "axis", "rtsp"]) or
            any(p in ports for p in [554, 8000, 8554, 9010]) or
            "camera" in dtype or
            "hikvision" in mac.replace(":","")
        )
        if is_cam:
            cameras.append({
                "ip": r["ip"],
                "mac": d.get("mac", ""),
                "hostname": d.get("hostname", ""),
                "ports": ports,
                "os": d.get("os", ""),
                "device_type": d.get("device_type", ""),
                "timestamp": r.get("timestamp", ""),
            })
    # Also add any known camera IPs not in scan results
    return jsonify(cameras)

@app.route("/cameras")
def cameras_page():
    return render_template("cameras.html")

@app.route("/api/camera/snapshot")
def api_camera_snapshot():
    import requests, base64
    from requests.auth import HTTPDigestAuth
    ip   = request.args.get("ip", "")
    user = request.args.get("user", "admin")
    pwd  = request.args.get("pass", "12345")
    if not ip:
        return jsonify({"error": "ip required"}), 400
    endpoints = [
        f"http://{ip}/ISAPI/Streaming/channels/101/picture",
        f"http://{ip}/ISAPI/Streaming/channels/1/picture",
        f"http://{ip}/Streaming/channels/101/picture",
        f"http://{ip}/cgi-bin/snapshot.cgi",
        f"http://{ip}/snapshot.jpg",
        f"http://{ip}/image/jpeg.cgi",
    ]
    for url in endpoints:
        try:
            r = requests.get(url, auth=HTTPDigestAuth(user, pwd),
                             timeout=8, verify=False, stream=True)
            if r.status_code == 200 and "image" in r.headers.get("Content-Type", ""):
                img_b64 = base64.b64encode(r.content).decode()
                return jsonify({"image_b64": img_b64, "url": url, "size": len(r.content)})
            # Try basic auth
            r2 = requests.get(url, auth=(user, pwd), timeout=8, verify=False, stream=True)
            if r2.status_code == 200 and "image" in r2.headers.get("Content-Type", ""):
                img_b64 = base64.b64encode(r2.content).decode()
                return jsonify({"image_b64": img_b64, "url": url, "size": len(r2.content)})
        except Exception:
            pass
    return jsonify({"error": "Could not capture snapshot - check credentials"}), 404

@app.route("/api/camera/test_creds")
def api_camera_test_creds():
    import requests
    from requests.auth import HTTPDigestAuth
    ip   = request.args.get("ip", "")
    user = request.args.get("user", "admin")
    pwd  = request.args.get("pass", "")
    if not ip:
        return jsonify({"error": "ip required"}), 400
    try:
        r = requests.get(f"http://{ip}/ISAPI/System/deviceInfo",
                         auth=HTTPDigestAuth(user, pwd), timeout=5, verify=False)
        if r.status_code == 200:
            return jsonify({"success": True, "data": r.text[:200]})
        r2 = requests.get(f"http://{ip}/ISAPI/System/deviceInfo",
                          auth=(user, pwd), timeout=5, verify=False)
        if r2.status_code == 200:
            return jsonify({"success": True, "data": r2.text[:200]})
        return jsonify({"success": False, "status": r.status_code})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/camera/intercept/<ip>")
def api_camera_intercept(ip):
    """Start MITM + hash capture on camera. Runs in background."""
    def run():
        import subprocess, os
        env = os.environ.copy()
        env['CYBERSCOPE_SUDO_PASS'] = 'dogs'
        log(f'[Camera] Starting credential interceptor on {ip}...', 'warn')
        log(f'[Camera] Open http://{ip} in browser and log in to capture hash', 'warn')
        socketio.emit('alert', {'message': f'MITM interceptor active on {ip} - waiting for login', 'severity': 'MEDIUM'})
        try:
            out = subprocess.check_output(
                ['python3', 'kali_tools/cam_interceptor.py', ip],
                env=env, text=True, timeout=360
            )
            for line in out.splitlines():
                log(f'[Interceptor] {line}', 'warn' if 'CRACKED' in line or 'FOUND' in line else 'info')
                if 'PASSWORD CRACKED' in line or 'CAMERA ACCESS' in line:
                    socketio.emit('alert', {'message': f'CAMERA {ip}: {line}', 'severity': 'CRITICAL'})
                    save_alert(f'CAMERA {ip}: {line}', 'CRITICAL')
        except Exception as e:
            log(f'[Interceptor] Error: {e}', 'error')
    threading.Thread(target=run, daemon=True).start()
    return jsonify({'status': 'started', 'message': f'Interceptor running on {ip} - open camera web UI and log in'})

@app.route("/api/camera/stream/<ip>")
def api_camera_stream(ip):
    """Stream RTSP camera as MJPEG directly to browser."""
    from flask import Response, stream_with_context
    user = request.args.get("user", "admin")
    pwd  = request.args.get("pass", "")
    path = request.args.get("path", None)
    return Response(
        stream_with_context(mjpeg_stream(ip, user, pwd, path)),
        mimetype="multipart/x-mixed-replace; boundary=frame"
    )

@app.route("/api/camera/probe/<ip>")
def api_camera_probe(ip):
    """Find a working RTSP URL for the camera."""
    user = request.args.get("user", "admin")
    pwd  = request.args.get("pass", "")
    url  = probe_rtsp(ip, user, pwd)
    if url:
        # Strip credentials from returned URL for display
        import re
        display = re.sub(r"rtsp://[^@]+@", "rtsp://***:***@", url)
        return jsonify({"found": True, "url": url, "display": display})
    return jsonify({"found": False})

@app.route("/api/camera/brute")
def api_camera_brute():
    ip = request.args.get("ip", "")
    if not ip:
        return jsonify({"error": "ip required"}), 400
    from kali_tools.hikvision_scanner import brute_force_hikvision
    log(f"[Camera] Brute forcing {ip}...", "tool")
    result = brute_force_hikvision(ip)
    if result.get("found"):
        log(f"[Camera] Credentials found: {result['username']}:{result['password']}", "warn")
        save_alert(f"CAMERA {ip}: Default creds {result['username']}:{result['password']}", "CRITICAL")
        socketio.emit("alert", {"message": f"CAMERA {ip}: Credentials found {result['username']}:{result['password']}", "severity": "CRITICAL"})
    return jsonify(result)

@app.route("/api/hikvision/<ip>")
def api_hikvision(ip):
    """Full Hikvision camera assessment."""
    port = int(request.args.get("port", 80))
    log(f"[Hikvision] Scanning {ip}:{port}...", "tool")
    findings = full_hikvision_scan(ip, port)
    if findings.get("risk_level") in ("CRITICAL", "HIGH"):
        for s in findings.get("summary", []):
            save_alert(f"HIKVISION {ip}: {s}", "CRITICAL")
            socketio.emit("alert", {"message": f"HIKVISION {ip}: {s}", "severity": "CRITICAL"})
    log(f"[Hikvision] Done: {findings.get('risk_level')} - {findings.get('summary')}", "warn" if findings.get('risk_level') != 'LOW' else "success")
    return jsonify(findings)

@app.route("/api/ndp_table")
def api_ndp_table():
    """Return full NDP table with MAC-to-IPv6 mapping."""
    from kali_tools.ipv6_scanner import get_ndp_table, get_arp_table
    ndp = get_ndp_table("wlan0")
    arp = get_arp_table()
    result = []
    for ipv6, mac in ndp.items():
        result.append({"ipv6": ipv6, "mac": mac, "ipv4": arp.get(mac, "")})
    return jsonify(result)

@app.route("/api/fierce")
def api_fierce():
    target = request.args.get("target", "")
    if not target:
        return jsonify({"error": "target required"}), 400
    return jsonify(fierce_scan(target))

@app.route("/recon")
def recon_page():
    return render_template("recon.html")

@app.route("/api/wifi_scan")
def api_wifi_scan():
    iface = request.args.get("iface", "wlan0")
    aps = scan_wifi_aps(iface)
    rogues = detect_rogue_aps(aps)
    connected = get_connected_ap(iface)
    # Emit rogue AP alerts
    for r in rogues:
        if r["type"] == "EVIL_TWIN":
            msg = f"EVIL TWIN: '{r['ssid']}' — {r['detail']}"
            save_alert(msg, "CRITICAL")
            socketio.emit("alert", {"message": msg, "severity": "CRITICAL"})
        elif r["type"] == "OPEN_NETWORK":
            msg = f"OPEN WIFI: '{r['ssid']}' ({r['mac']}) — no encryption"
            save_alert(msg, "HIGH")
    return jsonify({"aps": aps, "rogues": rogues, "connected": connected})

@app.route("/api/cve_lookup")
def api_cve_lookup():
    ip = request.args.get("ip", "")
    if not ip:
        return jsonify({"error": "ip required"}), 400
    results = get_scan_results()
    row = next((r for r in results if r["ip"] == ip), None)
    if not row:
        return jsonify({"error": "no scan data for this IP"}), 404
    services = row["data"].get("services", {})
    cves = lookup_cves(services)
    return jsonify({"ip": ip, "cves": cves, "max_cvss": get_max_cvss(cves)})

@app.route("/api/passive_fp")
def api_passive_fp():
    """Run passive OS fingerprinting on all known devices."""
    results = get_scan_results()
    devices = [r["data"] for r in results if r.get("data")]
    fps = fingerprint_subnet(devices)
    return jsonify(fps)

@app.route("/api/passive_fp/<ip>")
def api_passive_fp_ip(ip):
    results = get_scan_results()
    row = next((r for r in results if r["ip"] == ip), None)
    ports = row["data"].get("ports", []) if row else []
    fp = passive_os_fingerprint(ip, ports)
    return jsonify(fp)

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
        time.sleep(1800)  # 30 minutes between auto-scans

if __name__ == "__main__":
    t = threading.Thread(target=background_scan, daemon=True)
    t.start()
    # Start continuous passive intelligence harvest (DHCP/mDNS/NetBIOS)
    start_continuous_harvest(interval=45)
    socketio.run(app, debug=False, use_reloader=False, host="0.0.0.0", port=5000)
