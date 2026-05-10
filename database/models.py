import sqlite3
import json
from datetime import datetime

DB = "logs/cyberscope.db"

def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE, mac TEXT, status TEXT DEFAULT 'active',
            last_seen TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert TEXT, severity TEXT, timestamp TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT, data TEXT, timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_device(ip, mac):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT id FROM devices WHERE ip=?", (ip,))
    if c.fetchone():
        c.execute("UPDATE devices SET last_seen=?, mac=? WHERE ip=?",
                  (datetime.now().isoformat(), mac, ip))
    else:
        c.execute("INSERT INTO devices (ip, mac, last_seen) VALUES (?,?,?)",
                  (ip, mac, datetime.now().isoformat()))
    conn.commit()
    conn.close()

def save_alert(alert, severity):
    conn = sqlite3.connect(DB)
    conn.execute("INSERT INTO alerts (alert, severity, timestamp) VALUES (?,?,?)",
                 (alert, severity, datetime.now().isoformat()))
    conn.commit()
    conn.close()

def save_scan_result(ip, data):
    conn = sqlite3.connect(DB)
    conn.execute("INSERT INTO scan_results (ip, data, timestamp) VALUES (?,?,?)",
                 (ip, json.dumps(data), datetime.now().isoformat()))
    conn.commit()
    conn.close()

def get_all_devices():
    conn = sqlite3.connect(DB)
    rows = conn.execute("SELECT ip, mac, status, last_seen FROM devices").fetchall()
    conn.close()
    return [{"ip": r[0], "mac": r[1], "status": r[2], "last_seen": r[3]} for r in rows]

def get_all_alerts():
    conn = sqlite3.connect(DB)
    rows = conn.execute("SELECT alert, severity, timestamp FROM alerts ORDER BY id DESC LIMIT 100").fetchall()
    conn.close()
    return [{"alert": r[0], "severity": r[1], "timestamp": r[2]} for r in rows]

def get_scan_results():
    conn = sqlite3.connect(DB)
    rows = conn.execute("SELECT ip, data, timestamp FROM scan_results ORDER BY id DESC LIMIT 50").fetchall()
    conn.close()
    return [{"ip": r[0], "data": json.loads(r[1]), "timestamp": r[2]} for r in rows]
