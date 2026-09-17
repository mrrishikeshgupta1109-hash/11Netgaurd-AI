const $ = (id) => document.getElementById(id);

let paused = false;
let uploadedDataset = null;
let alertHistory = [];
let showAllData = false;

function updateDashboard() {
    if (!uploadedDataset) {
        resetDashboard();
        return;
    }

    const data = uploadedDataset;
    const total = data.rows;
    const categories = Object.entries(data.predictions)
        .map(([name, count]) => [name, Number(count)])
        .sort((a, b) => b[1] - a[1]);
    const normalCount = categories
        .filter(([name]) => name.trim().toLowerCase() === "normal")
        .reduce((sum, [, count]) => sum + count, 0);
    const threatCount = total - normalCount;

    $("riskValue").textContent = `${data.risk}%`;
    $("prediction").textContent = data.dominant_category;
    $("forecastPrediction").textContent = data.dominant_category;
    $("confidence").textContent = `Confidence: ${data.confidence}%`;
    $("forecastConfidence").textContent = `AI confidence: ${data.confidence}%`;
    $("confidenceBar").style.width = `${data.confidence}%`;
    $("anomaly").textContent = data.anomaly_count ? `${data.anomaly_count} Detected` : "Normal";
    $("monitorMode").textContent = "DATASET";
    updateRiskLevel(data.risk);
    updateNetworkHealth(data.network_health);
    updateTraffic(data.metrics);
    updateReasons(data.reasons);
    updateThreatDistribution(data.predictions, total);
    updateAlerts(data.records);
    updateDatasetTelemetry(data.records);
    drawCharts();
}

function resetDashboard() {
    ["riskValue", "prediction", "anomaly"].forEach(id => $(id).textContent = "--");
    $("forecastPrediction").textContent = "Waiting...";
    $("forecastConfidence").textContent = "AI confidence: --";
    $("confidence").textContent = "Confidence: --";
    $("confidenceBar").style.width = "0%";
    $("monitorMode").textContent = "DATASET";
    $("riskLevel").textContent = "Awaiting dataset";
    updateNetworkHealth(null);
    updateTraffic(null);
    updateReasons([]);
    updateThreatDistribution();
    updateDatasetTelemetry([]);
    renderAlerts();
    drawCharts();
}

function updateNetworkHealth(health) {
    const score = health ? health.score : null;
    $("healthValue").textContent = score === null ? "--" : `${score.toFixed(2)}%`;
    $("healthStatus").textContent = health ? health.status : "Awaiting dataset";
    $("stabilityValue").textContent = health ? health.stability : "Awaiting dataset";
    $("healthEngineValue").textContent = health ? "Active" : "Awaiting dataset";
    $("healthMonitoringValue").textContent = health ? "Dataset" : "Awaiting dataset";
    $("healthValue").closest(".health-circle").style.setProperty(
        "--health-score",
        `${score || 0}%`
    );
}

function updateRiskLevel(risk) {
    $("riskLevel").textContent = risk >= 70 ? "CRITICAL" : risk >= 45 ? "HIGH" : risk >= 25 ? "MEDIUM" : "LOW";
}

function updateTraffic(traffic) {
    const values = traffic || {};
    $("packetRate").textContent = traffic ? formatNumber(values.packet_rate) : "--";
    $("bytesRate").textContent = traffic ? formatNumber(values.bytes_rate) : "--";
    $("connectionRate").textContent = traffic ? formatNumber(values.connection_rate) : "--";
    $("failedConnections").textContent = traffic ? formatNumber(values.failed_connections) : "--";
    $("uniquePorts").textContent = traffic ? formatNumber(values.unique_ports) : "--";
    $("avgPacketSize").textContent = traffic ? formatNumber(values.avg_packet_size) : "--";
}

function updateReasons(reasons) {
    const list = $("reasons");
    list.innerHTML = "";
    (reasons.length ? reasons : ["No dataset uploaded. Upload a CSV file to view network traffic analysis."])
        .forEach(reason => {
            const item = document.createElement("li");
            item.textContent = reason;
            list.appendChild(item);
        });
}

function updateThreatDistribution(predictions, total) {
    const container = $("threatDistribution");
    if (!predictions || !total) {
        container.className = "distribution-empty";
        container.innerHTML = "<span>No dataset uploaded. Upload a CSV file to view network traffic analysis.</span>";
        return;
    }
    container.className = "distribution-list";
    container.innerHTML = Object.entries(predictions)
        .sort(([, a], [, b]) => b - a)
        .map(([category, count]) => {
            const percentage = count / total * 100;
            const severity = analysisSeverity(category);
            return `<div class="distribution-row"><div class="distribution-row-label"><span><i class="analysis-severity-dot ${severity}"></i>${escapeHtml(category)}</span><strong>${percentage.toFixed(1)}%</strong></div><div class="distribution-row-track"><span class="distribution-row-fill ${severity}" style="width:${percentage}%"></span></div></div>`;
        }).join("");
}

function drawCharts() {
    document.querySelectorAll("canvas[data-feature]").forEach(canvas => {
        const feature = canvas.dataset.feature;
        const values = uploadedDataset?.features?.[feature] || [];
        drawLineChart(canvas, values);
    });
}

function updateDatasetTelemetry(records) {
    const packetRates = records.map(record => Number(record.packet_rate));
    const hasRecords = packetRates.length > 0;
    const minimum = hasRecords ? Math.min(...packetRates) : null;
    const maximum = hasRecords ? Math.max(...packetRates) : null;
    const average = hasRecords ? packetRates.reduce((sum, value) => sum + value, 0) / packetRates.length : null;
    const values = {
        packetRecordCount: hasRecords ? records.length.toLocaleString("en-IN") : "--",
        packetRateMin: hasRecords ? formatMetric(minimum) : "--",
        packetRateMax: hasRecords ? formatMetric(maximum) : "--",
        packetRateAverage: hasRecords ? formatMetric(average) : "--",
        summaryRecordCount: hasRecords ? records.length.toLocaleString("en-IN") : "--",
        summaryPacketMin: hasRecords ? `${formatMetric(minimum)} pps` : "--",
        summaryPacketMax: hasRecords ? `${formatMetric(maximum)} pps` : "--",
        summaryPacketAverage: hasRecords ? `${formatMetric(average)} pps` : "--"
    };
    Object.entries(values).forEach(([id, value]) => $(id).textContent = value);
    renderDataPoints(records);
}

function renderDataPoints(records) {
    const body = $("dataPointsBody");
    const button = $("viewAllDataBtn");
    button.hidden = records.length <= 10;
    button.textContent = showAllData ? "Show First 10" : "View All Data";
    if (!records.length) {
        body.innerHTML = '<tr><td colspan="7">No dataset uploaded. Upload a CSV file to view network traffic analysis.</td></tr>';
        return;
    }
    const visibleRecords = showAllData ? records : records.slice(0, 10);
    body.innerHTML = visibleRecords.map(record => `<tr>
        <td>${record.record}</td>
        <td>${formatDataValue(record.packet_rate)}</td>
        <td>${formatDataValue(record.bytes_rate)}</td>
        <td>${formatDataValue(record.connection_rate)}</td>
        <td>${formatDataValue(record.failed_connections)}</td>
        <td>${formatDataValue(record.unique_ports)}</td>
        <td>${formatDataValue(record.avg_packet_size)}</td>
    </tr>`).join("");
}

function formatMetric(value) {
    return Number(value).toLocaleString("en-IN", { maximumFractionDigits: 2 });
}

function formatDataValue(value) {
    return Number(value).toLocaleString("en-IN", { maximumFractionDigits: 12 });
}

function drawLineChart(canvas, values) {
    const rect = canvas.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    const width = Math.max(rect.width, 1);
    const height = Math.max(rect.height, 1);
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, width, height);
    canvas._chartPoints = [];
    if (!values.length) return;

    const max = Math.max(...values);
    const min = Math.min(...values);
    const range = max - min || 1;
    const step = values.length === 1 ? 0 : width / (values.length - 1);
    ctx.strokeStyle = "rgba(255,255,255,0.06)";
    ctx.lineWidth = 1;
    for (let index = 1; index < 5; index++) {
        const y = height / 5 * index;
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
    }
    ctx.beginPath();
    values.forEach((value, index) => {
        const x = index * step;
        const y = height - ((value - min) / range) * (height - 12) - 6;
        canvas._chartPoints.push({ x, y, index });
        index ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
    });
    ctx.strokeStyle = "#22d3ee";
    ctx.lineWidth = 2.5;
    ctx.stroke();
    if (values.length <= 200) {
        values.forEach((value, index) => {
            const x = index * step;
            const y = height - ((value - min) / range) * (height - 12) - 6;
            ctx.beginPath();
            ctx.arc(x, y, 2.5, 0, Math.PI * 2);
            ctx.fillStyle = "#22d3ee";
            ctx.fill();
        });
    }
}

function showTrafficTooltip(event) {
    const canvas = $("trafficChart");
    const tooltip = $("trafficTooltip");
    const points = canvas._chartPoints || [];
    const rect = canvas.getBoundingClientRect();
    const scaleX = canvas.width / (rect.width * (window.devicePixelRatio || 1));
    const pointerX = (event.clientX - rect.left) * scaleX / (window.devicePixelRatio || 1);
    const point = points.reduce((nearest, candidate) => Math.abs(candidate.x - pointerX) < Math.abs(nearest.x - pointerX) ? candidate : nearest, points[0]);
    if (!point || !uploadedDataset?.records?.[point.index]) {
        tooltip.classList.remove("visible");
        return;
    }
    const record = uploadedDataset.records[point.index];
    tooltip.innerHTML = `<strong>Record: ${record.record}</strong><span>Packet Rate: ${formatDataValue(record.packet_rate)} pps</span><span>Bytes Rate: ${formatDataValue(record.bytes_rate)} B/s</span><span>Connection Rate: ${formatDataValue(record.connection_rate)}/sec</span><span>Failed Connections: ${formatDataValue(record.failed_connections)}</span><span>Unique Ports: ${formatDataValue(record.unique_ports)}</span><span>Avg Packet Size: ${formatDataValue(record.avg_packet_size)} bytes</span>`;
    tooltip.style.left = `${Math.min(Math.max(event.clientX - rect.left + 12, 8), rect.width - tooltip.offsetWidth - 8)}px`;
    tooltip.style.top = `${Math.max(event.clientY - rect.top - tooltip.offsetHeight - 12, 8)}px`;
    tooltip.classList.add("visible");
}

$("trafficChart").addEventListener("mousemove", showTrafficTooltip);
$("trafficChart").addEventListener("mouseleave", () => $("trafficTooltip").classList.remove("visible"));
$("viewAllDataBtn").addEventListener("click", () => {
    showAllData = !showAllData;
    renderDataPoints(uploadedDataset?.records || []);
});

function updateAlerts(records) {
    alertHistory = (records || [])
        .filter(record => record.category.trim().toLowerCase() !== "normal" || record.anomaly)
        .slice(-8)
        .reverse()
        .map(record => ({ prediction: record.category, risk: record.anomaly ? "Anomaly" : "Threat", time: `Record ${record.record}` }));
    renderAlerts();
}

function renderAlerts() {
    const container = $("alertsList");
    $("alertCount").textContent = alertHistory.length;
    container.innerHTML = alertHistory.length ? alertHistory.map(alert => `<div class="alert"><strong><i class="fa-solid fa-triangle-exclamation"></i> ${escapeHtml(alert.prediction)}</strong><p>${alert.risk} &nbsp; | &nbsp; ${alert.time}</p></div>`).join("") : '<div class="empty-alert"><i class="fa-solid fa-shield-check"></i><p>No threats detected</p></div>';
}

$("resetBtn").addEventListener("click", () => {
    uploadedDataset = null;
    showAllData = false;
    alertHistory = [];
    resetDashboard();
});

$("pauseBtn").addEventListener("click", () => {
    paused = !paused;
    $("pauseBtn").querySelector("i").className = paused ? "fa-solid fa-play" : "fa-solid fa-pause";
});

$("uploadForm").addEventListener("submit", async function(event) {
    event.preventDefault();
    const fileInput = $("csvFile");
    const resultBox = $("uploadResult");
    const submitButton = this.querySelector("button[type='submit']");
    if (!fileInput.files.length) {
        renderAnalysisError("Please select a CSV file.");
        return;
    }
    const formData = new FormData();
    formData.append("file", fileInput.files[0]);
    uploadedDataset = null;
    showAllData = false;
    resetDashboard();
    submitButton.disabled = true;
    submitButton.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Analyzing...';
    resultBox.innerHTML = '<div class="analysis-loading"><i class="fa-solid fa-microchip"></i><div><strong>Analyzing network traffic...</strong><span>Running AI classification...</span></div></div>';
    try {
        const response = await fetch("/api/analyze", { method: "POST", body: formData });
        const result = await response.json();
        if (!response.ok) {
            renderAnalysisError(result.error || "Dataset analysis failed.", result.missing);
            return;
        }
        uploadedDataset = result;
        updateDashboard();
        renderAnalysisReport(result);
    } catch (error) {
        console.error("Dataset analysis error:", error);
        renderAnalysisError("Unable to analyze dataset. Please try again.");
    } finally {
        submitButton.disabled = false;
        submitButton.innerHTML = '<i class="fa-solid fa-magnifying-glass-chart"></i> Analyze Dataset';
    }
});

function renderAnalysisReport(result) {
    const predictions = result.predictions || {};
    const total = Number(result.rows) || 0;
    const categories = Object.entries(predictions).sort(([, a], [, b]) => b - a);
    const normalCount = categories.filter(([name]) => name.trim().toLowerCase() === "normal").reduce((sum, [, count]) => sum + count, 0);
    const threatCount = total - normalCount;
    const threatRate = total ? threatCount / total * 100 : 0;
    const distribution = categories.map(([name, count]) => {
        const percentage = total ? count / total * 100 : 0;
        const severity = analysisSeverity(name);
        return `<div class="analysis-distribution-item"><div class="analysis-distribution-label"><span><i class="analysis-severity-dot ${severity}"></i>${escapeHtml(name)}</span><strong>${percentage.toFixed(1)}%</strong></div><div class="analysis-distribution-track"><div class="analysis-distribution-fill ${severity}" style="width:${percentage}%"></div></div></div>`;
    }).join("");
    const breakdown = categories.map(([name, count]) => {
        const percentage = total ? count / total * 100 : 0;
        const severity = analysisSeverity(name);
        const status = name.trim().toLowerCase() === "normal" ? "NORMAL" : severity.toUpperCase();
        return `<tr><td><span class="analysis-category"><i class="analysis-severity-dot ${severity}"></i>${escapeHtml(name)}</span></td><td>${count.toLocaleString("en-IN")}</td><td>${percentage.toFixed(1)}%</td><td><span class="analysis-status ${severity}">${status}</span></td></tr>`;
    }).join("");
    $("uploadResult").innerHTML = `<section class="analysis-report" aria-live="polite"><div class="analysis-report-header"><div><span class="analysis-kicker"><i class="fa-solid fa-shield-halved"></i> DATASET ANALYSIS</span><h3>Analysis Complete</h3><p>${total.toLocaleString("en-IN")} network-flow records analyzed by AI detection engine</p></div><span class="analysis-complete">● ANALYSIS COMPLETE</span></div><div class="analysis-metrics"><div class="analysis-metric-card"><span>TOTAL FLOWS</span><strong>${total.toLocaleString("en-IN")}</strong></div><div class="analysis-metric-card normal"><span>NORMAL</span><strong>${normalCount.toLocaleString("en-IN")}</strong><small>${(total ? normalCount / total * 100 : 0).toFixed(1)}%</small></div><div class="analysis-metric-card threat"><span>THREATS</span><strong>${threatCount.toLocaleString("en-IN")}</strong><small>${threatRate.toFixed(1)}%</small></div><div class="analysis-metric-card rate"><span>THREAT RATE</span><strong>${threatRate.toFixed(1)}%</strong></div></div><div class="analysis-report-grid"><div class="analysis-card"><div class="analysis-card-title"><div><span class="analysis-kicker">THREAT DISTRIBUTION</span><h4>Prediction categories</h4></div><i class="fa-solid fa-chart-pie"></i></div>${distribution}</div><div class="analysis-card"><div class="analysis-card-title"><div><span class="analysis-kicker">DATASET INFORMATION</span><h4>Analysis metadata</h4></div><i class="fa-solid fa-database"></i></div><dl class="analysis-info"><div><dt>Dataset</dt><dd>${escapeHtml(result.dataset_name)}</dd></div><div><dt>Records analyzed</dt><dd>${total.toLocaleString("en-IN")}</dd></div><div><dt>Label column</dt><dd>${escapeHtml(result.label_column || "Model predictions")}</dd></div><div><dt>Detection engine</dt><dd>${escapeHtml(result.detection_engine)}</dd></div><div><dt>Anomaly engine</dt><dd>${escapeHtml(result.anomaly_engine)}</dd></div></dl></div></div><div class="analysis-card analysis-breakdown"><div class="analysis-card-title"><div><span class="analysis-kicker">DETECTION BREAKDOWN</span><h4>Classification results</h4></div><i class="fa-solid fa-table-list"></i></div><div class="analysis-table-wrapper"><table class="analysis-table"><thead><tr><th>Category</th><th>Count</th><th>Percentage</th><th>Status</th></tr></thead><tbody>${breakdown}</tbody></table></div></div></section>`;
}

function renderAnalysisError(message, missing = []) {
    const missingHtml = missing?.length ? `<div class="analysis-missing"><strong>Missing required features:</strong><ul>${missing.map(item => `<li>${escapeHtml(item)}</li>`).join("")}</ul></div>` : "";
    $("uploadResult").innerHTML = `<div class="analysis-error" role="alert"><i class="fa-solid fa-circle-exclamation"></i><div><strong>DATASET VALIDATION FAILED</strong><p>${escapeHtml(message)}</p>${missingHtml}</div></div>`;
}

function analysisSeverity(name) {
    const category = String(name).toLowerCase();
    if (category === "normal") return "normal";
    if (category === "ddos" || category === "botnet") return "critical";
    if (category === "port scan" || category === "brute force") return "high";
    return "detected";
}

function formatNumber(value) { return Number(value).toLocaleString("en-IN"); }
function escapeHtml(value) { return String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#039;"); }

resetDashboard();
window.addEventListener("resize", drawCharts);
