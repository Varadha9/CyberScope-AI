const socket = io();

// Clock
setInterval(() => {
    document.getElementById("clock").textContent = new Date().toLocaleTimeString();
}, 1000);

// Charts
const deviceCtx = document.getElementById("deviceChart").getContext("2d");
const threatCtx  = document.getElementById("threatChart").getContext("2d");

const chartDefaults = {
    borderColor: "#00ff00",
    backgroundColor: "rgba(0,255,0,0.1)",
    tension: 0.4,
    fill: true,
};

const deviceChart = new Chart(deviceCtx, {
    type: "line",
    data: {
        labels: [],
        datasets: [{ label: "Active Devices", data: [], ...chartDefaults }]
    },
    options: { scales: { x: { ticks: { color: "#555" } }, y: { ticks: { color: "#555" }, beginAtZero: true } }, plugins: { legend: { labels: { color: "#00ff00" } } } }
});

const threatChart = new Chart(threatCtx, {
    type: "bar",
    data: {
        labels: [],
        datasets: [{ label: "Threats", data: [], borderColor: "#ff4444", backgroundColor: "rgba(255,68,68,0.2)" }]
    },
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

// Socket Events
socket.on("scan_complete", (data) => {
    const devices = data.devices || [];
    updateDeviceTable(devices);
    const now = new Date().toLocaleTimeString();
    pushChart(deviceChart, now, devices.length);
    const threatCount = devices.reduce((s, d) => s + (d.threats?.length || 0), 0);
    pushChart(threatChart, now, threatCount);
    document.getElementById("total-devices").textContent = devices.length;
    document.getElementById("total-threats").textContent = threatCount;
    const totalPorts = devices.reduce((s, d) => s + (d.ports?.length || 0), 0);
    document.getElementById("total-ports").textContent = totalPorts;
    if (devices.length > 0 && devices[0].comment) {
        document.getElementById("ai-comment").textContent = "🤖 AI: " + devices[0].comment;
    }
});

socket.on("alert", (data) => {
    addAlert(data.message, data.severity);
    const cur = parseInt(document.getElementById("total-alerts").textContent) || 0;
    document.getElementById("total-alerts").textContent = cur + 1;
});

function updateDeviceTable(devices) {
    const tbody = document.getElementById("device-body");
    if (!devices.length) {
        tbody.innerHTML = '<tr><td colspan="4" class="empty">No devices found</td></tr>';
        return;
    }
    tbody.innerHTML = devices.map(d => `
        <tr>
            <td>${d.ip}</td>
            <td>${d.mac}</td>
            <td><span class="${d.threats?.length ? 'red' : 'green'}">${d.threats?.length ? "⚠ THREAT" : "✓ SAFE"}</span></td>
            <td>${d.comment || "—"}</td>
        </tr>
    `).join("");
}

function addAlert(message, severity) {
    const feed = document.getElementById("alert-feed");
    const div = document.createElement("div");
    div.className = "alert-item" + (severity !== "HIGH" ? " safe" : "");
    div.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
    feed.prepend(div);
}

function triggerScan() {
    document.getElementById("ai-comment").textContent = "🤖 AI: Scanning network... 🔍";
    fetch("/api/scan")
        .then(r => r.json())
        .then(data => {
            updateDeviceTable(data);
            document.getElementById("total-devices").textContent = data.length;
        });
}

function loadAlerts() {
    fetch("/api/alerts")
        .then(r => r.json())
        .then(alerts => {
            document.getElementById("alert-feed").innerHTML = "";
            document.getElementById("total-alerts").textContent = alerts.length;
            alerts.forEach(a => addAlert(a.alert, a.severity));
        });
}

function generateReport() {
    fetch("/api/report")
        .then(r => r.json())
        .then(data => {
            document.getElementById("ai-comment").textContent =
                `🤖 AI: Report generated! Devices: ${data.total_devices} | Alerts: ${data.total_alerts} | High Risk: ${data.high_risk_alerts} | File: ${data.report_file}`;
        });
}

// Auto-load on start
loadAlerts();
fetch("/api/devices").then(r => r.json()).then(updateDeviceTable);
