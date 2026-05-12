const socket = io();

socket.on("connect", () => {
    log("WebSocket connected to server", "success");
});
socket.on("disconnect", () => {
    log("WebSocket disconnected", "error");
});

// ── Clock ──
setInterval(() => {
    const el = document.getElementById("clock");
    if (el) el.textContent = new Date().toLocaleTimeString();
}, 1000);

// ── Logging ──
let logFilter = "ALL";
let autoScroll = true;
const logLines = [];

function log(msg, type = "info") {
    const feed = document.getElementById("terminal-log");
    if (!feed) return;
    logLines.unshift({ msg, type, time: new Date().toLocaleTimeString() });
    if (logLines.length > 300) logLines.pop();
    renderLog();
}

function renderLog() {
    const feed = document.getElementById("terminal-log");
    if (!feed) return;
    const filtered = logFilter === "ALL" ? logLines : logLines.filter(l => {
        if (logFilter === "ERRORS")  return l.type === "error";
        if (logFilter === "TOOLS")   return l.type === "tool";
        if (logFilter === "SUCCESS") return l.type === "success";
        return true;
    });
    feed.innerHTML = filtered.slice(0, 200).map(l =>
        `<div class="log-line ${l.type}">[${l.time}] ${l.msg}</div>`
    ).join("");
    if (autoScroll) feed.scrollTop = 0;
}

function clearLog() {
    logLines.length = 0;
    renderLog();
}

function setLogFilter(btn, filter) {
    logFilter = filter;
    document.querySelectorAll(".log-filter-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    renderLog();
}

function toggleAutoScroll(btn) {
    autoScroll = !autoScroll;
    btn.textContent = autoScroll ? "⏬ Auto" : "⏸ Manual";
    btn.classList.toggle("btn-cyan", autoScroll);
}

socket.on("log", (data) => log(data.msg, data.type || "info"));

// ── Charts ──
let deviceChart, threatChart;

function initCharts() {
    const deviceCtx = document.getElementById("deviceChart");
    const threatCtx  = document.getElementById("threatChart");
    if (!deviceCtx || !threatCtx) return;

    deviceChart = new Chart(deviceCtx.getContext("2d"), {
        type: "line",
        data: { labels: [], datasets: [{ label: "Active Devices", data: [], borderColor: "#00ff88", backgroundColor: "rgba(0,255,136,0.1)", tension: 0.4, fill: true }] },
        options: { scales: { x: { ticks: { color: "#555" } }, y: { ticks: { color: "#555" }, beginAtZero: true } }, plugins: { legend: { labels: { color: "#00ff88" } } } }
    });

    threatChart = new Chart(threatCtx.getContext("2d"), {
        type: "bar",
        data: { labels: [], datasets: [{ label: "Threats", data: [], borderColor: "#ff4444", backgroundColor: "rgba(255,68,68,0.2)" }] },
        options: { scales: { x: { ticks: { color: "#555" } }, y: { ticks: { color: "#555" }, beginAtZero: true } }, plugins: { legend: { labels: { color: "#ff4444" } } } }
    });
}

function pushChart(chart, label, value) {
    if (!chart) return;
    if (chart.data.labels.length > 10) {
        chart.data.labels.shift();
        chart.data.datasets[0].data.shift();
    }
    chart.data.labels.push(label);
    chart.data.datasets[0].data.push(value);
    chart.update();
}

// ── MAC Vendor Lookup ──
// Vendor map loaded from /api/oui on init
let _OUI_MAP = {};

function _macVendor(mac) {
    if (!mac || mac === "00:00:00:00:00:00") return "";
    const oui = mac.replace(/:/g, "").toUpperCase().slice(0, 6);
    try {
        if ([2, 6, 0xA, 0xE].includes(parseInt(oui[1], 16))) return "[Randomized MAC]";
    } catch(e) {}
    return _OUI_MAP[oui] || "";
}

function _deviceLabel(d) {
    // Priority: real hostname > device_type from passive intel > vendor label > MAC
    const hn = d.hostname || "";
    if (hn && hn !== "unknown" && hn !== "") return hn;
    if (d.device_type) return d.device_type;
    const v = _macVendor(d.mac || "");
    if (v && v !== "[Randomized MAC]") return v;
    if (v === "[Randomized MAC]") return "📱 Phone/Laptop";
    return "";
}

// ── Risk Scoring ──
function getRiskScore(d) {
    let s = 0;
    s += (d.threats?.length || 0) * 15;
    s += (d.vulns?.length || 0) * 20;
    s += (d.nikto?.length || 0) * 5;
    s += (d.msf?.length || 0) * 10;
    s += (d.hydra?.length || 0) * 25;
    s += (d.sqlmap?.length || 0) * 20;
    s += (d.wpscan?.length || 0) * 10;
    // CVSS score contribution (max 40 points)
    const cvss = d.max_cvss || 0;
    if (cvss >= 9.0) s += 40;
    else if (cvss >= 7.0) s += 25;
    else if (cvss >= 4.0) s += 10;
    return Math.min(s, 100);
}

function getRiskClass(score) {
    if (score >= 70) return "critical";
    if (score >= 50) return "high";
    if (score >= 20) return "medium";
    if (score > 0)   return "low";
    return "safe";
}

function getRiskColor(score) {
    if (score >= 70) return "var(--critical)";
    if (score >= 50) return "var(--red)";
    if (score >= 20) return "var(--yellow)";
    if (score > 0)   return "var(--cyan)";
    return "var(--green)";
}

function getDeviceIcon(d) {
    const h = (_deviceLabel(d) || d.hostname || "").toLowerCase();
    const o = (d.os || "").toLowerCase();
    if (h.includes("router") || h.includes("gateway") || h.includes("jio") || h.includes("fiber")) return "🌐";
    if (h.includes("camera") || h.includes("nvr") || h.includes("hikvision") || h.includes("dahua")) return "📷";
    if (h.includes("printer")) return "🖨️";
    if (h.includes("playstation") || h.includes("xbox") || h.includes("nintendo") || h.includes("steam")) return "🎮";
    if (h.includes("raspberry") || h.includes("esp32") || h.includes("iot") || h.includes("arduino") || h.includes("tuya")) return "🧠";
    if (h.includes("apple") || h.includes("iphone") || h.includes("ipad") || h.includes("macbook")) return "🍎";
    if (h.includes("dell") || h.includes("lenovo") || h.includes("hp ") || h.includes("acer") || h.includes("asus") || h.includes("msi") || h.includes("toshiba")) return "💻";
    if (h.includes("intel") || h.includes("broadcom") || h.includes("realtek") || o.includes("windows") || h.includes("desktop") || h.includes("pc")) return "🖥️";
    if (h.includes("xiaomi") || h.includes("samsung") || h.includes("vivo") || h.includes("oppo") || h.includes("realme") || h.includes("oneplus") || h.includes("huawei") || h.includes("motorola") || h.includes("zte") || h.includes("phone") || h.includes("randomized")) return "📱";
    if (h.includes("wifi device") || h.includes("azurewave") || h.includes("lite-on") || h.includes("murata") || h.includes("mediatek") || h.includes("qualcomm")) return "📱";
    if (o.includes("linux")) return "🐧";
    return "📡";
}

// ── Scan Progress ──
let scanTotal = 0;
let scanDone  = 0;
let scanRunning = false;

function setScanRunning(running, total) {
    scanRunning = running;
    scanTotal = total || 0;
    scanDone  = 0;
    const bar = document.getElementById("scan-progress-bar");
    const label = document.getElementById("scan-progress-label");
    const btns = document.querySelectorAll(".scan-btn");
    if (running) {
        if (bar) bar.style.display = "block";
        btns.forEach(b => b.disabled = true);
        updateScanProgress();
    } else {
        if (bar) bar.style.display = "none";
        if (label) label.textContent = "";
        btns.forEach(b => b.disabled = false);
    }
}

function updateScanProgress() {
    const label = document.getElementById("scan-progress-label");
    const fill  = document.getElementById("scan-progress-fill");
    if (!label || !fill) return;
    const pct = scanTotal > 0 ? Math.round((scanDone / scanTotal) * 100) : 0;
    label.textContent = `Scanning ${scanDone}/${scanTotal} devices...`;
    fill.style.width = pct + "%";
}

// ── Device Table ──
function buildToolBadges(d) {
    const badges = [
        d.wpscan?.length    ? `<span class="tool-badge warn" title="WPScan">WP:${d.wpscan.length}</span>` : "",
        d.sqlmap?.length    ? `<span class="tool-badge vuln" title="SQLMap">SQL:${d.sqlmap.length}</span>` : "",
        d.hydra?.length     ? `<span class="tool-badge vuln" title="Hydra">HYD:${d.hydra.length}</span>` : "",
        d.gobuster?.length  ? `<span class="tool-badge warn" title="Gobuster">DIR:${d.gobuster.length}</span>` : "",
        d.sslscan?.length   ? `<span class="tool-badge warn" title="SSLScan">SSL:${d.sslscan.length}</span>` : "",
        d.searchsploit?.length ? `<span class="tool-badge vuln" title="SearchSploit">CVE:${d.searchsploit.length}</span>` : "",
        d.enum4linux?.length   ? `<span class="tool-badge warn" title="Enum4linux">SMB:${d.enum4linux.length}</span>` : "",
        d.nikto?.length     ? `<span class="tool-badge warn" title="Nikto">NK:${d.nikto.length}</span>` : "",
        d.msf?.length       ? `<span class="tool-badge vuln" title="Metasploit">MSF:${d.msf.length}</span>` : "",
        d.john?.length      ? `<span class="tool-badge vuln" title="John the Ripper">JTR:${d.john.length}</span>` : "",
    ].filter(Boolean);
    return badges.length ? `<div class="tool-badges">${badges.join("")}</div>` : `<span class="text-dim">—</span>`;
}

function buildExpandedRow(d, colSpan) {
    const score = getRiskScore(d);
    const services = d.services || {};
    const portRows = (d.ports || []).map(p => {
        const svc = services[p] || services[String(p)] || {};
        const danger = [21,22,23,25,445,3389,4444,27017,3306,5432].includes(p);
        return `<span class="port-tag ${danger ? 'danger' : ''}">${danger ? '⚠' : '●'} ${p}${svc.name ? ' <small style="opacity:0.6">' + svc.name + '</small>' : ''}</span>`;
    }).join("");

    const sections = [
        { label: "💀 Vulns",      items: d.vulns,        cls: "critical" },
        { label: "🕷️ Nikto",      items: d.nikto,        cls: "medium"   },
        { label: "💣 MSF",        items: d.msf,          cls: "high"     },
        { label: "🔑 Hydra",      items: d.hydra,        cls: "critical" },
        { label: "💉 SQLMap",     items: d.sqlmap,       cls: "critical" },
        { label: "🔎 CVEs",       items: d.searchsploit, cls: "high"     },
        { label: "🔍 WPScan",     items: d.wpscan,       cls: "high"     },
        { label: "📁 Gobuster",   items: d.gobuster,     cls: "medium"   },
        { label: "🌐 WhatWeb",    items: d.whatweb,      cls: "info"     },
        { label: "🔑 John",        items: d.john,         cls: "critical" },
    ].filter(s => s.items?.length);

    return `<tr class="expanded-row">
        <td colspan="${colSpan}" style="padding:0">
            <div class="expanded-content">
                <div style="margin-bottom:12px">
                    <div class="text-dim" style="font-size:0.7rem;margin-bottom:6px">OPEN PORTS</div>
                    <div style="display:flex;flex-wrap:wrap">${portRows || '<span class="text-dim">No open ports</span>'}</div>
                </div>
                ${sections.length ? `<div class="expanded-findings">
                    ${sections.map(s => `
                    <div class="expanded-section">
                        <div class="expanded-section-title">${s.label} <span class="risk-badge ${s.cls}">${s.items.length}</span></div>
                        ${s.items.slice(0, 5).map(i => `<div class="finding-item ${s.cls}">${i}</div>`).join("")}
                        ${s.items.length > 5 ? `<div class="text-dim" style="font-size:0.72rem;padding:4px 0">+${s.items.length - 5} more — <a href="/device/${d.ip}" class="text-cyan">view all</a></div>` : ""}
                    </div>`).join("")}
                </div>` : '<div class="text-dim" style="font-size:0.78rem">No tool findings yet — deep scan may still be running</div>'}
                <div style="margin-top:12px">
                    <a href="/device/${d.ip}" class="btn btn-sm btn-cyan">🔍 Full Device Report →</a>
                </div>
            </div>
        </td>
    </tr>`;
}

function updateDeviceTable(devices) {
    const tbody = document.getElementById("device-body");
    if (!tbody) return;
    if (!devices || !devices.length) {
        tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No devices found — click ▶ Full Scan to start</td></tr>';
        return;
    }

    const unique = [];
    const seen = new Set();
    for (let i = devices.length - 1; i >= 0; i--) {
        if (!seen.has(devices[i].ip)) { unique.unshift(devices[i]); seen.add(devices[i].ip); }
    }

    const label = document.getElementById("device-count-label");
    if (label) label.textContent = unique.length + " device(s)";

    tbody.innerHTML = unique.map(d => {
        const score  = getRiskScore(d);
        const cls    = getRiskClass(score);
        const color  = getRiskColor(score);
        const icon   = getDeviceIcon(d);
        const label  = _deviceLabel(d);
        const dtype  = d.device_type || "";
        const ipv6   = d.ipv6 || "";
        const rowBg  = score >= 70 ? "background:#ff00aa08" : score >= 50 ? "background:#ff444408" : score >= 20 ? "background:#ffd70008" : "";
        return `<tr class="device-row" style="${rowBg}" onclick="toggleExpand(this, '${d.ip}')" data-ip="${d.ip}">
            <td>
                <a href="/device/${d.ip}" class="ip-link" onclick="event.stopPropagation()">
                    <span class="device-icon">${icon}</span>${d.ip}
                </a>
                ${label ? `<div style="color:var(--cyan);font-size:0.82rem;font-weight:600;margin-top:2px">${label}</div>` : ""}
                ${ipv6 ? `<div style="color:var(--text-dim);font-size:0.68rem;font-family:'Courier New',monospace" title="IPv6 link-local">${ipv6.slice(0,28)}...</div>` : ""}
                ${dtype && dtype !== label ? `<div style="color:var(--text-dim);font-size:0.72rem">${dtype}</div>` : ""}
                <a href="/watch/${d.ip}" onclick="event.stopPropagation()" style="font-size:0.68rem;color:var(--text-dim);margin-top:2px;display:inline-block">👁️ Watch</a>
            </td>
            <td class="mac-text">${d.mac || "—"}</td>
            <td>${d.os && d.os !== 'Scanning...' ? d.os : d.os === 'Scanning...' && (d.ports?.length > 0) ? '<span class="text-yellow">⏳ Scanning...</span>' : '<span class="text-dim">Unknown</span>'}</td>
            <td>
                <div class="risk-score-wrap">
                    <div class="risk-score-bar"><div class="risk-score-fill" style="width:${score}%;background:${color}"></div></div>
                    <span class="risk-score-num"><span class="risk-badge ${cls}">${score}</span></span>
                </div>
            </td>
            <td>${d.threats?.length ? `<span class="risk-badge high">⚠ ${d.threats.length}</span>` : '<span class="risk-badge safe">✓ SAFE</span>'}</td>
            <td>${d.vulns?.length ? `<span class="risk-badge critical">💀 ${d.vulns.length}</span>` : '<span class="text-dim">—</span>'}</td>
            <td>${buildToolBadges(d)}</td>
            <td style="color:var(--text-dim);font-size:0.72rem">${d.comment ? d.comment.slice(0, 50) + (d.comment.length > 50 ? "…" : "") : "—"}</td>
        </tr>`;
    }).join("");
}

function toggleExpand(row, ip) {
    const next = row.nextElementSibling;
    if (next && next.classList.contains("expanded-row")) {
        next.remove();
        row.classList.remove("expanded");
        return;
    }
    // Close any other open expanded rows
    document.querySelectorAll(".expanded-row").forEach(r => r.remove());
    document.querySelectorAll(".device-row.expanded").forEach(r => r.classList.remove("expanded"));

    fetch("/api/scan_results")
        .then(r => r.json())
        .then(results => {
            const found = results.find(r => r.ip === ip);
            if (!found) return;
            const d = found.data;
            const colSpan = row.cells.length;
            row.insertAdjacentHTML("afterend", buildExpandedRow(d, colSpan));
            row.classList.add("expanded");
        });
}

// ── Alerts ──
function addAlert(message, severity) {
    const feed = document.getElementById("alert-feed");
    if (!feed) return;
    const empty = feed.querySelector(".empty-state");
    if (empty) empty.remove();
    const div = document.createElement("div");
    div.className = "alert-item";
    const sevCls = severity === "CRITICAL" ? "CRITICAL" : severity === "HIGH" ? "HIGH" : severity === "MEDIUM" ? "MEDIUM" : "LOW";
    div.innerHTML = `
        <span class="alert-sev ${sevCls}">${severity}</span>
        <span class="alert-msg">${message}</span>
        <span class="alert-time">${new Date().toLocaleTimeString()}</span>
    `;
    feed.prepend(div);
    while (feed.children.length > 50) feed.removeChild(feed.lastChild);
}

// ── Socket Events ──
socket.on("scan_complete", (data) => {
    hideSpinner();
    setScanRunning(false);
    const devices = data.devices || [];
    const statusEl = document.getElementById("status-text");
    if (statusEl) statusEl.textContent = "MONITORING ACTIVE";
    if (data.subnet) {
        const badge = document.getElementById("subnet-badge");
        if (badge) badge.textContent = "WiFi: " + data.subnet;
    }
    updateDeviceTable(devices);
    scanTotal = devices.length;
    const now = new Date().toLocaleTimeString();
    const threatCount = devices.reduce((s, d) => s + (d.threats?.length || 0), 0);
    const vulnCount   = devices.reduce((s, d) => s + (d.vulns?.length  || 0), 0);
    pushChart(deviceChart, now, devices.length);
    pushChart(threatChart, now, threatCount);
    setStatValue("total-devices", devices.length);
    setStatValue("total-threats", threatCount);
    setStatValue("total-vulns",   vulnCount);
    setStatValue("total-ports",   devices.reduce((s, d) => s + (d.ports?.length || 0), 0));
    const topComment = devices.find(d => d.comment);
    if (topComment) {
        const ai = document.getElementById("ai-comment");
        if (ai) ai.textContent = "🤖 AI: " + topComment.comment;
    }
    log(`✔ Scan complete — ${devices.length} device(s) found`, "success");
});

socket.on("device_update", (data) => {
    scanDone++;
    updateScanProgress();
    const ip = data.ip;
    const d  = data.data;
    // Update existing row if visible
    const row = document.querySelector(`.device-row[data-ip="${ip}"]`);
    if (row) {
        const score = getRiskScore(d);
        const cls   = getRiskClass(score);
        const color = getRiskColor(score);
        const rowBg = score >= 70 ? "background:#ff00aa08" : score >= 50 ? "background:#ff444408" : score >= 20 ? "background:#ffd70008" : "";
        row.style.cssText = rowBg;
        row.cells[2].textContent = d.os || "?";
        row.cells[3].innerHTML = `<div class="risk-score-wrap"><div class="risk-score-bar"><div class="risk-score-fill" style="width:${score}%;background:${color}"></div></div><span class="risk-score-num"><span class="risk-badge ${cls}">${score}</span></span></div>`;
        row.cells[4].innerHTML = d.threats?.length ? `<span class="risk-badge high">⚠ ${d.threats.length}</span>` : '<span class="risk-badge safe">✓ SAFE</span>';
        row.cells[5].innerHTML = d.vulns?.length ? `<span class="risk-badge critical">💀 ${d.vulns.length}</span>` : '<span class="text-dim">—</span>';
        row.cells[6].innerHTML = buildToolBadges(d);
        row.cells[7].textContent = d.comment ? d.comment.slice(0, 50) + (d.comment.length > 50 ? "…" : "") : "—";
    }
    log(`[${ip}] Deep scan updated`, "success");
});

socket.on("device_found", (data) => {
    log(`Device found: ${data.ip} (${data.mac})`, "info");
});

socket.on("alert", (data) => {
    addAlert(data.message, data.severity);
    const cur = parseInt(document.getElementById("total-alerts")?.textContent) || 0;
    setStatValue("total-alerts", cur + 1);
});

// ── Helpers ──
function setStatValue(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
}

function showSpinner(text) {
    const overlay = document.getElementById("scan-overlay");
    const overlayText = document.getElementById("scan-overlay-text");
    if (overlay) overlay.classList.add("active");
    if (overlayText) overlayText.textContent = text || "SCANNING NETWORK...";
}
function hideSpinner() {
    const overlay = document.getElementById("scan-overlay");
    if (overlay) overlay.classList.remove("active");
}

function scrollToDevices() {
    document.getElementById("devices-section")?.scrollIntoView({ behavior: "smooth" });
}

// ── Scan Actions ──
function triggerScan() {
    log("▶ FULL SCAN triggered by user", "info");
    const ai = document.getElementById("ai-comment");
    if (ai) ai.textContent = "🤖 AI: Scanning WiFi network with Nmap + Nikto + Metasploit... 🔍";
    const statusEl = document.getElementById("status-text");
    if (statusEl) statusEl.textContent = "SCANNING...";
    showSpinner("SCANNING NETWORK...");
    setScanRunning(true, 0);
    fetch("/api/scan")
        .then(r => r.json())
        .then(() => {
            log("✔ Scan started — results will appear via live updates...", "success");
        })
        .catch(err => {
            hideSpinner();
            setScanRunning(false);
            log(`Scan error: ${err}`, "error");
        });
}

function triggerMasscan() {
    log("⚡ MASSCAN triggered by user", "tool");
    fetch("/api/masscan")
        .then(r => r.json())
        .then(data => {
            data.forEach(r => addAlert(`Masscan: ${r.ip}:${r.port}/${r.proto} open`, "MEDIUM"));
            log(`⚡ Masscan complete — ${data.length} open port(s) found`, "tool");
        });
}

function triggerSniff() {
    log("📡 Packet sniff started on wlan0", "info");
    fetch("/api/sniff?count=30")
        .then(r => r.json())
        .then(packets => {
            const feed = document.getElementById("packet-feed");
            if (!feed) return;
            feed.innerHTML = packets.map(p =>
                `<div class="packet-item">${p.src ? `${p.src}:${p.sport||"?"} → ${p.dst}:${p.dport||"?"} [${p.proto}]` : p.summary}</div>`
            ).join("");
            log(`📡 Sniff complete — ${packets.length} packets captured`, "success");
        });
}

function loadAlerts() {
    log("⚠ Loading saved alerts...", "info");
    fetch("/api/alerts")
        .then(r => r.json())
        .then(alerts => {
            const feed = document.getElementById("alert-feed");
            if (!feed) return;
            feed.innerHTML = "";
            setStatValue("total-alerts", alerts.length);
            if (!alerts.length) {
                feed.innerHTML = '<div class="empty-state"><div class="empty-icon">🛡️</div>No alerts yet...</div>';
            } else {
                alerts.forEach(a => addAlert(a.alert, a.severity));
            }
            log(`✔ Loaded ${alerts.length} alert(s)`, "success");
        })
        .catch(err => log(`Error loading alerts: ${err}`, "error"));
}

function clearDB() {
    if (!confirm("Clear all saved devices, alerts and scan results?")) return;
    fetch("/api/clear_db", { method: "POST" })
        .then(r => r.json())
        .then(() => {
            const tbody = document.getElementById("device-body");
            if (tbody) tbody.innerHTML = '<tr><td colspan="8" class="empty-state">Database cleared — run a new scan</td></tr>';
            const feed = document.getElementById("alert-feed");
            if (feed) feed.innerHTML = '<div class="empty-state"><div class="empty-icon">🛡️</div>No alerts yet...</div>';
            ["total-devices","total-alerts","total-ports","total-threats","total-vulns"].forEach(id => setStatValue(id, "0"));
            log("✔ Database cleared", "success");
        });
}

function triggerTcpdump() {
    log("📡 Tcpdump capture started on wlan0", "info");
    fetch("/api/tcpdump?count=20")
        .then(r => r.json())
        .then(packets => {
            const feed = document.getElementById("packet-feed");
            if (!feed) return;
            feed.innerHTML = packets.map(p => `<div class="packet-item">${p}</div>`).join("");
            log(`📡 Tcpdump done — ${packets.length} packets`, "success");
        });
}

function triggerTshark() {
    log("🔍 Tshark capture started on wlan0", "info");
    fetch("/api/tshark?count=20")
        .then(r => r.json())
        .then(packets => {
            const feed = document.getElementById("packet-feed");
            if (!feed) return;
            feed.innerHTML = packets.map(p =>
                `<div class="packet-item">${p.src}:${p.sport} → ${p.dst}:${p.dport} [${p.proto}] ${p.len}B</div>`
            ).join("");
            log(`🔍 Tshark done — ${packets.length} packets`, "success");
        });
}

function triggerJohn() {
    const ip = prompt("Enter target IP for John the Ripper analysis:");
    if (!ip) return;
    log(`🔑 John the Ripper started on ${ip}`, "tool");
    fetch(`/api/john?ip=${encodeURIComponent(ip)}`)
        .then(r => r.json())
        .then(data => {
            const findings = data.findings || data;
            if (findings.length) {
                findings.forEach(f => addAlert(`John [${ip}]: ${f}`, "HIGH"));
                log(`🔑 John done — ${findings.length} finding(s) on ${ip}`, "warn");
            } else {
                log(`🔑 John done — no findings on ${ip}`, "success");
            }
        })
        .catch(err => log(`John error: ${err}`, "error"));
}


function triggerIPv6Scan() {
    log("🔓 IPv6 bypass scan started...", "tool");
    const btn = document.querySelector('[onclick="triggerIPv6Scan()"]');
    if (btn) { btn.disabled = true; btn.textContent = "⏳ Scanning..."; }
    fetch("/api/ipv6_scan")
        .then(r => r.json())
        .then(data => {
            const withPorts = data.filter(d => d.ports && d.ports.length > 0);
            log("✔ IPv6 scan done: " + data.length + " reachable, " + withPorts.length + " with open ports", "success");
            if (btn) { btn.disabled = false; btn.textContent = "🔓 IPv6 Bypass"; }
            withPorts.forEach(d => {
                log("[IPv6] " + (d.ipv4 || d.ipv6) + " (" + d.mac + ") ports=" + d.ports.join(","), "warn");
                addAlert("IPv6 bypass: " + (d.ipv4 || d.ipv6) + " has open ports " + d.ports.join(","), "HIGH");
            });
            // Reload device table
            fetch("/api/scan_results").then(r=>r.json()).then(results => {
                const devices = results.map(r => r.data).filter(d => d && d.ip);
                if (devices.length) updateDeviceTable(devices);
            });
        })
        .catch(err => {
            log("IPv6 scan error: " + err, "error");
            if (btn) { btn.disabled = false; btn.textContent = "🔓 IPv6 Bypass"; }
        });
}

function triggerPassiveHarvest() {
    log("🕵️ Passive Intel harvest started (30s)...", "tool");
    const btn = document.querySelector('[onclick="triggerPassiveHarvest()"]');
    if (btn) { btn.disabled = true; btn.textContent = "⏳ Harvesting..."; }
    fetch("/api/passive_intel/harvest?timeout=30")
        .then(r => r.json())
        .then(data => {
            log(`✔ Passive harvest done: ${data.harvested} device(s) identified, ${data.enriched} enriched`, "success");
            if (btn) { btn.disabled = false; btn.textContent = "🕵️ Passive Intel"; }
            // Reload device table with enriched data
            fetch("/api/scan_results").then(r => r.json()).then(results => {
                const devices = results.map(r => r.data).filter(d => d && d.ip);
                if (devices.length) updateDeviceTable(devices);
            });
            // Show what we found
            const intel = data.intel || {};
            Object.values(intel).forEach(d => {
                if (d.hostname) log(`🔍 ${d.ip || d.mac} → ${d.hostname} [${d.device_type || ""}] via ${(d.sources||[]).join("+")}`, "success");
            });
        })
        .catch(err => {
            log(`Passive harvest error: ${err}`, "error");
            if (btn) { btn.disabled = false; btn.textContent = "🕵️ Passive Intel"; }
        });
}

function generateReport() {
    log("📄 Generating report...", "info");
    fetch("/api/report")
        .then(r => r.json())
        .then(data => {
            const ai = document.getElementById("ai-comment");
            if (ai) ai.textContent = `🤖 AI: Report saved! Devices: ${data.total_devices} | Alerts: ${data.total_alerts} | High Risk: ${data.high_risk_alerts} | File: ${data.report_file}`;
            log(`✔ Report generated: ${data.report_file}`, "success");
        })
        .catch(err => log(`Error generating report: ${err}`, "error"));
}

// ── Init ──
document.addEventListener("DOMContentLoaded", () => {
    initCharts();

    fetch("/api/subnet")
        .then(r => r.json())
        .then(data => {
            if (data.subnet) {
                const badge = document.getElementById("subnet-badge");
                if (badge) badge.textContent = "WiFi: " + data.subnet;
            }
        });

    Promise.all([
        fetch("/api/scan_results").then(r => r.json()),
        fetch("/api/alerts").then(r => r.json())
    ]).then(([results, alerts]) => {
        const devices = results.map(r => r.data).filter(d => d && d.ip);
        const macs = [...new Set(devices.map(d => d.mac).filter(Boolean))];
        const ouiP = macs.length
            ? fetch("/api/oui?macs=" + macs.join(",")).then(r => r.json()).then(m => { _OUI_MAP = m; })
            : Promise.resolve();
        ouiP.then(() => {
            if (devices.length) {
                updateDeviceTable(devices);
                const tc = devices.reduce((s,d) => s+(d.threats?.length||0),0);
                const vc = devices.reduce((s,d) => s+(d.vulns?.length||0),0);
                const pc = devices.reduce((s,d) => s+(d.ports?.length||0),0);
                setStatValue("total-devices", devices.length);
                setStatValue("total-threats", tc);
                setStatValue("total-vulns",   vc);
                setStatValue("total-ports",   pc);
                const top = devices.find(d => d.comment);
                if (top) { const ai = document.getElementById("ai-comment"); if (ai) ai.textContent = "\u{1F916} AI: " + top.comment; }
                const now = new Date().toLocaleTimeString();
                pushChart(deviceChart, now, devices.length);
                pushChart(threatChart, now, tc);
            }
            setStatValue("total-alerts", alerts.length);
            const feed = document.getElementById("alert-feed");
            if (!feed) return;
            if (!alerts.length) {
                feed.innerHTML = '<div class="empty-state"><div class="empty-icon">\u{1F6E1}\uFE0F</div>No alerts yet...</div>';
            } else {
                alerts.slice(0, 20).forEach(a => addAlert(a.alert, a.severity));
            }
        });
    }).catch(err => log("Init load error: " + err, "error"));
});
