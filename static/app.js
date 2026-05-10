const socket = io();

socket.on("connect", () => {
    console.log("✓ WebSocket connected");
    log("WebSocket connected to server", "success");
});

socket.on("disconnect", () => {
    console.log("✗ WebSocket disconnected");
    log("WebSocket disconnected", "error");
});

function log(msg, type="info") {
    const feed = document.getElementById("terminal-log");
    const div = document.createElement("div");
    div.className = "log-line " + type;
    div.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
    feed.prepend(div);
    // Keep max 200 lines
    while (feed.children.length > 200) feed.removeChild(feed.lastChild);
}

function clearLog() {
    document.getElementById("terminal-log").innerHTML = "";
}

socket.on("log", (data) => {
    log(data.msg, data.type || "info");
});

setInterval(() => {
    document.getElementById("clock").textContent = new Date().toLocaleTimeString();
}, 1000);

const deviceCtx = document.getElementById("deviceChart").getContext("2d");
const threatCtx  = document.getElementById("threatChart").getContext("2d");

const chartDefaults = {
    borderColor: "#00ff00",
    backgroundColor: "rgba(0,255,0,0.1)",
    tension: 0.4, fill: true,
};

const deviceChart = new Chart(deviceCtx, {
    type: "line",
    data: { labels: [], datasets: [{ label: "Active Devices", data: [], ...chartDefaults }] },
    options: { scales: { x: { ticks: { color: "#555" } }, y: { ticks: { color: "#555" }, beginAtZero: true } }, plugins: { legend: { labels: { color: "#00ff00" } } } }
});

const threatChart = new Chart(threatCtx, {
    type: "bar",
    data: { labels: [], datasets: [{ label: "Threats", data: [], borderColor: "#ff4444", backgroundColor: "rgba(255,68,68,0.2)" }] },
    options: { scales: { x: { ticks: { color: "#555" } }, y: { ticks: { color: "#555" }, beginAtZero: true } }, plugins: { legend: { labels: { color: "#ff4444" } } } }
});

function pushChart(chart, label, value) {
    if (chart.data.labels.length > 10) {
        chart.data.labels.shift();
        chart.data.datasets[0].data.shift();
    }
    chart.data.labels.push(label);
    chart.data.datasets[0].data.push(value);
    chart.update();
}

// Severity color map
const sevColor = { CRITICAL: "critical", HIGH: "red", MEDIUM: "yellow", LOW: "green", SAFE: "green" };

socket.on("scan_complete", (data) => {
    const devices = data.devices || [];
    if (data.subnet) document.getElementById("subnet-badge").textContent = "WiFi: " + data.subnet;
    updateDeviceTable(devices);
    const now = new Date().toLocaleTimeString();
    pushChart(deviceChart, now, devices.length);
    const threatCount = devices.reduce((s, d) => s + (d.threats?.length || 0), 0);
    const vulnCount   = devices.reduce((s, d) => s + (d.vulns?.length  || 0), 0);
    pushChart(threatChart, now, threatCount);
    document.getElementById("total-devices").textContent  = devices.length;
    document.getElementById("total-threats").textContent  = threatCount;
    document.getElementById("total-vulns").textContent    = vulnCount;
    const totalPorts = devices.reduce((s, d) => s + (d.ports?.length || 0), 0);
    document.getElementById("total-ports").textContent = totalPorts;
    if (devices.length > 0 && devices[0].comment) {
        document.getElementById("ai-comment").textContent = "🤖 AI: " + devices[0].comment;
    }
});

socket.on("device_update", (data) => {
    // Update a single row in the table when deep scan completes
    const tbody = document.getElementById("device-body");
    const rows = tbody.querySelectorAll("tr");
    rows.forEach(row => {
        if (row.cells[0] && row.cells[0].textContent === data.ip) {
            const d = data.data;
            const ports = (Array.isArray(d.ports) && d.ports.length)
                ? d.ports.slice(0, 8).join(", ") + (d.ports.length > 8 ? "..." : "")
                : "—";
            const threatBadge = d.threats?.length
                ? `<span class="red">⚠ ${d.threats.length} THREAT(S)</span>`
                : `<span class="green">✓ SAFE</span>`;
            const vulnBadge = d.vulns?.length
                ? `<span class="critical">💀 ${d.vulns.length} VULN(S)</span>`
                : `<span class="green">—</span>`;
            row.cells[2].textContent = d.os || "?";
            row.cells[3].innerHTML   = `<span class="yellow">${ports}</span>`;
            row.cells[4].innerHTML   = threatBadge;
            row.cells[5].innerHTML   = vulnBadge;
            row.cells[6].textContent = d.comment || "—";
        }
    });
});

socket.on("device_found", (data) => {
    log(`Device found: ${data.ip} (${data.mac})`, "info");
});

socket.on("alert", (data) => {
    addAlert(data.message, data.severity);
    const cur = parseInt(document.getElementById("total-alerts").textContent) || 0;
    document.getElementById("total-alerts").textContent = cur + 1;
});

function updateDeviceTable(devices) {
    const tbody = document.getElementById("device-body");
    if (!devices || !devices.length) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty">No devices found on WiFi</td></tr>';
        return;
    }
    // Remove duplicates by IP (keep last occurrence)
    const uniqueDevices = [];
    const seenIPs = new Set();
    for (let i = devices.length - 1; i >= 0; i--) {
        if (!seenIPs.has(devices[i].ip)) {
            uniqueDevices.unshift(devices[i]);
            seenIPs.add(devices[i].ip);
        }
    }
    tbody.innerHTML = uniqueDevices.map(d => {
        const threatBadge = d.threats?.length
            ? `<span class="red">⚠ ${d.threats.length} THREAT(S)</span>`
            : `<span class="green">✓ SAFE</span>`;
        const vulnBadge = d.vulns?.length
            ? `<span class="critical">💀 ${d.vulns.length} VULN(S)</span>`
            : `<span class="green">—</span>`;
        const ports = (Array.isArray(d.ports) && d.ports.length)
            ? d.ports.slice(0, 8).join(", ") + (d.ports.length > 8 ? "..." : "")
            : "—";
        return `<tr>
            <td>${d.ip}</td>
            <td>${d.mac}</td>
            <td>${d.os || "?"}</td>
            <td class="yellow">${ports}</td>
            <td>${threatBadge}</td>
            <td>${vulnBadge}</td>
            <td>${d.comment || "—"}</td>
        </tr>`;
    }).join("");
}

function addAlert(message, severity) {
    const feed = document.getElementById("alert-feed");
    const empty = feed.querySelector(".empty");
    if (empty) empty.remove();
    const div = document.createElement("div");
    const cls = severity === "CRITICAL" ? "critical" : severity === "HIGH" ? "" : "safe";
    div.className = "alert-item " + cls;
    div.textContent = `[${new Date().toLocaleTimeString()}] [${severity}] ${message}`;
    feed.prepend(div);
}

function triggerScan() {
    log("▶ FULL SCAN triggered by user", "info");
    document.getElementById("ai-comment").textContent = "🤖 AI: Scanning WiFi network with Nmap + Nikto + Metasploit... 🔍";
    document.getElementById("status-text").textContent = "SCANNING...";
    fetch("/api/scan")
        .then(r => r.json())
        .then(data => {
            if (data && data.length > 0) {
                updateDeviceTable(data);
                document.getElementById("total-devices").textContent = data.length;
            }
            document.getElementById("status-text").textContent = "MONITORING ACTIVE";
            log(`✔ Fast scan done — ${data.length || 0} device(s) found. Deep scan running in background...`, "success");
        })
        .catch(err => {
            document.getElementById("status-text").textContent = "MONITORING ACTIVE";
            log(`Scan error: ${err}`, "error");
        });
}

function triggerMasscan() {
    log("⚡ MASSCAN triggered by user", "tool");
    document.getElementById("ai-comment").textContent = "🤖 AI: Running Masscan on WiFi subnet... ⚡";
    fetch("/api/masscan")
        .then(r => r.json())
        .then(data => {
            document.getElementById("ai-comment").textContent =
                `🤖 AI: Masscan found ${data.length} open ports across WiFi subnet`;
            data.forEach(r => addAlert(`Masscan: ${r.ip}:${r.port}/${r.proto} open`, "MEDIUM"));
            log(`⚡ Masscan complete — ${data.length} open port(s) found`, "tool");
        });
}

function triggerSniff() {
    log("📡 Packet sniff started on wlan0", "info");
    document.getElementById("ai-comment").textContent = "🤖 AI: Sniffing wlan0 packets... 📡";
    fetch("/api/sniff?count=30")
        .then(r => r.json())
        .then(packets => {
            const feed = document.getElementById("packet-feed");
            feed.innerHTML = "";
            packets.forEach(p => {
                const div = document.createElement("div");
                div.className = "packet-item";
                div.textContent = p.src
                    ? `${p.src}:${p.sport||"?"} → ${p.dst}:${p.dport||"?"} [${p.proto}]`
                    : p.summary;
                feed.appendChild(div);
            });
            document.getElementById("ai-comment").textContent =
                `🤖 AI: Captured ${packets.length} packets on wlan0`;
            log(`📡 Sniff complete — ${packets.length} packets captured`, "success");
        });
}

function loadAlerts() {
    log("⚠ Loading saved alerts...", "info");
    fetch("/api/alerts")
        .then(r => r.json())
        .then(alerts => {
            document.getElementById("alert-feed").innerHTML = "";
            document.getElementById("total-alerts").textContent = alerts.length;
            if (alerts.length === 0) {
                document.getElementById("alert-feed").innerHTML = '<div class="empty">No alerts yet...</div>';
                log("No alerts found in database", "info");
            } else {
                alerts.forEach(a => addAlert(a.alert, a.severity));
                log(`✔ Loaded ${alerts.length} alert(s)`, "success");
            }
        })
        .catch(err => log(`Error loading alerts: ${err}`, "error"));
}

function generateReport() {
    log("📄 Generating report...", "info");
    fetch("/api/report")
        .then(r => r.json())
        .then(data => {
            document.getElementById("ai-comment").textContent =
                `🤖 AI: Report saved! Devices: ${data.total_devices} | Alerts: ${data.total_alerts} | High Risk: ${data.high_risk_alerts} | File: ${data.report_file}`;
            log(`✔ Report generated: ${data.report_file}`, "success");
        })
        .catch(err => log(`Error generating report: ${err}`, "error"));
}

loadAlerts();
// Load last scan results (has ports/os/vulns) instead of bare device list
fetch("/api/scan_results")
    .then(r => r.json())
    .then(results => {
        if (results.length) {
            const devices = results.map(r => r.data);
            updateDeviceTable(devices);
            document.getElementById("total-devices").textContent = devices.length;
        } else {
            fetch("/api/devices").then(r => r.json()).then(updateDeviceTable);
        }
    });
