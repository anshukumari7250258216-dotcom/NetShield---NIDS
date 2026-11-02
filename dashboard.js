/**
 * NetShield-NIDS - Dashboard Charts & Telemetry Controller
 * Integrates Chart.js 4+ with real-time SOC backend polling.
 */

let trafficChart = null;
let threatChart = null;
let severityChart = null;
let portsChart = null;
let pollInterval = null;

document.addEventListener("DOMContentLoaded", () => {
    initCharts();
    fetchDashboardData();
    
    // Auto-refresh every 3.5 seconds
    pollInterval = setInterval(fetchDashboardData, 3500);

    // Re-theme charts when theme changes
    window.addEventListener("netshield:themechange", () => {
        updateChartThemes();
    });

    // Quick action buttons
    const btnQuickStartSim = document.getElementById("quick-start-sim-btn");
    if (btnQuickStartSim) {
        btnQuickStartSim.addEventListener("click", async () => {
            await startMonitoring("simulation");
        });
    }

    const btnQuickStop = document.getElementById("quick-stop-btn");
    if (btnQuickStop) {
        btnQuickStop.addEventListener("click", async () => {
            await stopMonitoring();
        });
    }
});

function getChartColors() {
    const isLight = document.body.classList.contains("light-theme");
    return {
        text: isLight ? "#475569" : "#94a3b8",
        grid: isLight ? "rgba(203, 213, 225, 0.5)" : "rgba(56, 189, 248, 0.08)",
        cardBg: isLight ? "#ffffff" : "#0f172a"
    };
}

function initCharts() {
    const colors = getChartColors();

    // 1. Traffic Velocity Timeline Chart
    const ctxTraffic = document.getElementById("trafficTimelineChart");
    if (ctxTraffic) {
        trafficChart = new Chart(ctxTraffic, {
            type: "line",
            data: {
                labels: [],
                datasets: [
                    {
                        label: "Normal Traffic",
                        data: [],
                        borderColor: "#00f2fe",
                        backgroundColor: "rgba(0, 242, 254, 0.12)",
                        borderWidth: 2,
                        fill: true,
                        tension: 0.35,
                        pointRadius: 2
                    },
                    {
                        label: "Suspicious / Attack",
                        data: [],
                        borderColor: "#ef4444",
                        backgroundColor: "rgba(239, 68, 68, 0.15)",
                        borderWidth: 2,
                        fill: true,
                        tension: 0.35,
                        pointRadius: 3
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: "index", intersect: false },
                plugins: {
                    legend: { labels: { color: colors.text, font: { family: "sans-serif", size: 11 } } },
                    tooltip: { backgroundColor: colors.cardBg, titleColor: "#fff", bodyColor: "#cbd5e1" }
                },
                scales: {
                    x: { grid: { color: colors.grid }, ticks: { color: colors.text, font: { size: 10 } } },
                    y: { grid: { color: colors.grid }, ticks: { color: colors.text, precision: 0 } }
                }
            }
        });
    }

    // 2. Threat Category Distribution Chart
    const ctxThreat = document.getElementById("threatDistributionChart");
    if (ctxThreat) {
        threatChart = new Chart(ctxThreat, {
            type: "doughnut",
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [
                        "#ef4444", "#f59e0b", "#8b5cf6", "#3b82f6", "#00f2fe", "#10b981"
                    ],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: "right", labels: { color: colors.text, font: { size: 11 } } }
                },
                cutout: "65%"
            }
        });
    }

    // 3. Severity Distribution Chart
    const ctxSeverity = document.getElementById("severityDistributionChart");
    if (ctxSeverity) {
        severityChart = new Chart(ctxSeverity, {
            type: "polarArea",
            data: {
                labels: ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: [
                        "rgba(239, 68, 68, 0.75)",
                        "rgba(245, 158, 11, 0.75)",
                        "rgba(59, 130, 246, 0.75)",
                        "rgba(16, 185, 129, 0.75)"
                    ],
                    borderWidth: 1,
                    borderColor: colors.cardBg
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: "bottom", labels: { color: colors.text, font: { size: 11 } } }
                },
                scales: {
                    r: { grid: { color: colors.grid }, ticks: { display: false } }
                }
            }
        });
    }

    // 4. Top Targeted Ports Bar Chart
    const ctxPorts = document.getElementById("topPortsChart");
    if (ctxPorts) {
        portsChart = new Chart(ctxPorts, {
            type: "bar",
            data: {
                labels: [],
                datasets: [{
                    label: "Connection Probes",
                    data: [],
                    backgroundColor: "rgba(139, 92, 246, 0.75)",
                    borderColor: "#8b5cf6",
                    borderWidth: 1,
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: "y",
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: { grid: { color: colors.grid }, ticks: { color: colors.text, precision: 0 } },
                    y: { grid: { display: false }, ticks: { color: colors.text } }
                }
            }
        });
    }
}

function updateChartThemes() {
    const colors = getChartColors();
    [trafficChart, portsChart].forEach(c => {
        if (!c) return;
        if (c.options.scales.x) {
            c.options.scales.x.grid.color = colors.grid;
            c.options.scales.x.ticks.color = colors.text;
        }
        if (c.options.scales.y) {
            c.options.scales.y.grid.color = colors.grid;
            c.options.scales.y.ticks.color = colors.text;
        }
        if (c.options.plugins.legend) c.options.plugins.legend.labels.color = colors.text;
        c.update();
    });

    [threatChart, severityChart].forEach(c => {
        if (!c) return;
        if (c.options.plugins.legend) c.options.plugins.legend.labels.color = colors.text;
        c.update();
    });
}

async function fetchDashboardData() {
    try {
        const res = await fetch("/api/dashboard");
        if (!res.ok) return;
        const payload = await res.json();
        
        // Update KPIs
        updateKPI("kpi-total-events", payload.kpis.total_events);
        updateKPI("kpi-suspicious-events", payload.kpis.suspicious_events);
        updateKPI("kpi-critical-alerts", payload.kpis.critical_alerts);
        updateKPI("kpi-unique-ips", payload.kpis.unique_ips);

        // Update Quick Monitor Status in Header
        updateDashboardMonitorControls(payload.monitoring);

        // Update Charts
        updateCharts(payload);

        // Update Recent Alerts Table
        renderRecentAlerts(payload.recent_alerts);

        // Update Recent Events Table
        renderRecentEvents(payload.recent_events);

    } catch (e) {
        console.error("Dashboard poll failed", e);
    }
}

function updateKPI(elementId, value) {
    const el = document.getElementById(elementId);
    if (el) {
        el.innerText = Number(value || 0).toLocaleString();
    }
}

function updateDashboardMonitorControls(monitoring) {
    const modeBadge = document.getElementById("dash-mode-badge");
    const btnStart = document.getElementById("quick-start-sim-btn");
    const btnStop = document.getElementById("quick-stop-btn");

    if (modeBadge) {
        if (monitoring.is_running) {
            modeBadge.innerHTML = `<span class="badge-soc badge-low"><i class="bi bi-activity"></i> ${monitoring.mode.toUpperCase()}</span>`;
            if (btnStart) btnStart.style.display = "none";
            if (btnStop) btnStop.style.display = "inline-flex";
        } else {
            modeBadge.innerHTML = `<span class="badge-soc badge-critical"><i class="bi bi-pause-circle"></i> STOPPED</span>`;
            if (btnStart) btnStart.style.display = "inline-flex";
            if (btnStop) btnStop.style.display = "none";
        }
    }
}

function updateCharts(data) {
    if (trafficChart && data.timeline) {
        trafficChart.data.labels = data.timeline.map(t => t.time);
        trafficChart.data.datasets[0].data = data.timeline.map(t => t.normal);
        trafficChart.data.datasets[1].data = data.timeline.map(t => t.suspicious);
        trafficChart.update("none");
    }

    if (threatChart && data.threat_dist) {
        threatChart.data.labels = data.threat_dist.map(t => t.detection_type);
        threatChart.data.datasets[0].data = data.threat_dist.map(t => t.count);
        threatChart.update("none");
    }

    if (severityChart && data.severity_dist) {
        const s = data.severity_dist;
        severityChart.data.datasets[0].data = [
            s.CRITICAL || 0,
            s.HIGH || 0,
            s.MEDIUM || 0,
            s.LOW || 0
        ];
        severityChart.update("none");
    }

    if (portsChart && data.top_ports) {
        portsChart.data.labels = data.top_ports.map(p => `Port ${p.dst_port}`);
        portsChart.data.datasets[0].data = data.top_ports.map(p => p.count);
        portsChart.update("none");
    }
}

function renderRecentAlerts(alerts) {
    const tbody = document.getElementById("recent-alerts-tbody");
    if (!tbody) return;

    if (!alerts || alerts.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="text-center text-muted py-3">No intrusion alerts recorded yet.</td></tr>`;
        return;
    }

    tbody.innerHTML = alerts.map(a => {
        const sevClass = `badge-${a.severity.toLowerCase()}`;
        return `
            <tr>
                <td class="font-mono text-dim">${formatDate(a.timestamp)}</td>
                <td><span class="badge-soc ${sevClass}">${a.severity}</span></td>
                <td class="fw-semibold">${escapeHtml(a.detection_type)}</td>
                <td class="font-mono"><a href="/ip-analysis?ip=${encodeURIComponent(a.src_ip)}" class="text-info text-decoration-none">${escapeHtml(a.src_ip)}</a></td>
                <td class="font-mono text-dim">${escapeHtml(a.dst_ip)}</td>
                <td>
                    <a href="/alerts" class="btn btn-sm btn-soc-outline py-0 px-2">Investigate</a>
                </td>
            </tr>
        `;
    }).join("");
}

function renderRecentEvents(events) {
    const tbody = document.getElementById("recent-events-tbody");
    if (!tbody) return;

    if (!events || events.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="text-center text-muted py-3">No network packets observed yet.</td></tr>`;
        return;
    }

    tbody.innerHTML = events.map(e => {
        const protoClass = `badge-${e.protocol.toLowerCase()}`;
        const suspBadge = e.is_suspicious 
            ? `<span class="badge-soc badge-critical">Flagged</span>` 
            : `<span class="badge-soc badge-low">Normal</span>`;
            
        return `
            <tr>
                <td class="font-mono text-dim">${formatDate(e.timestamp)}</td>
                <td class="font-mono">${escapeHtml(e.src_ip)}${e.src_port ? ':' + e.src_port : ''}</td>
                <td class="font-mono">${escapeHtml(e.dst_ip)}${e.dst_port ? ':' + e.dst_port : ''}</td>
                <td><span class="badge-proto ${protoClass}">${e.protocol}</span></td>
                <td>${suspBadge}</td>
                <td class="text-muted small">${escapeHtml(e.info || 'Packet exchange')}</td>
            </tr>
        `;
    }).join("");
}

async function startMonitoring(mode) {
    try {
        const res = await fetch("/api/monitoring/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ mode: mode })
        });
        const data = await res.json();
        showToast(data.message, data.status === "error" ? "error" : "success");
        fetchDashboardData();
    } catch (e) {
        showToast("Failed to start monitor.", "error");
    }
}

async function stopMonitoring() {
    try {
        const res = await fetch("/api/monitoring/stop", { method: "POST" });
        const data = await res.json();
        showToast(data.message, "info");
        fetchDashboardData();
    } catch (e) {
        showToast("Failed to stop monitor.", "error");
    }
}

