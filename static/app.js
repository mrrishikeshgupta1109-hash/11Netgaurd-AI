const $ = (id) => document.getElementById(id);

let paused = false;
let trafficHistory = [];
let alertHistory = [];
let predictionHistory = [];


/* =========================
   LIVE DATA
========================= */

async function loadLiveData() {

    if (paused) return;

    try {

        const response = await fetch("/api/live");

        if (!response.ok) {
            throw new Error("Server error");
        }

        const data = await response.json();

        updateDashboard(data);
        updateChart(data);
        updateAlerts(data);

    } catch (error) {

        console.error("Live data error:", error);

    }
}


/* =========================
   DASHBOARD UPDATE
========================= */

function updateDashboard(data) {

    $("riskValue").textContent = data.risk + "%";

    $("prediction").textContent = data.prediction;

    $("forecastPrediction").textContent = data.prediction;

    $("confidence").textContent =
        "Confidence: " + data.confidence + "%";

    $("forecastConfidence").textContent =
        "AI confidence: " + data.confidence + "%";

    $("confidenceBar").style.width =
        data.confidence + "%";

    $("anomaly").textContent =
        data.anomaly ? "Detected" : "Normal";

    $("monitorMode").textContent =
        String(data.mode).toUpperCase();

    updateRiskLevel(data.risk);

    updateTraffic(data.traffic);

    updateReasons(data.reasons);

    updateThreatDistribution(data.prediction);

}


/* =========================
   RISK LEVEL
========================= */

function updateRiskLevel(risk) {

    let level = "LOW";

    if (risk >= 70) {
        level = "CRITICAL";
    } else if (risk >= 45) {
        level = "HIGH";
    } else if (risk >= 25) {
        level = "MEDIUM";
    }

    $("riskLevel").textContent = level;

}


/* =========================
   TRAFFIC METRICS
========================= */

function updateTraffic(traffic) {

    $("packetRate").textContent =
        formatNumber(traffic.packet_rate);

    $("bytesRate").textContent =
        formatNumber(traffic.bytes_rate);

    $("connectionRate").textContent =
        formatNumber(traffic.connection_rate);

    $("failedConnections").textContent =
        formatNumber(traffic.failed_connections);

    $("uniquePorts").textContent =
        formatNumber(traffic.unique_ports);

    $("avgPacketSize").textContent =
        formatNumber(traffic.avg_packet_size);

}


/* =========================
   EXPLAINABLE AI
========================= */

function updateReasons(reasons) {

    const list = $("reasons");

    list.innerHTML = "";

    if (!reasons || reasons.length === 0) {

        const li = document.createElement("li");

        li.textContent = "No suspicious indicators detected.";

        list.appendChild(li);

        return;
    }

    reasons.forEach(reason => {

        const li = document.createElement("li");

        li.textContent = reason;

        list.appendChild(li);

    });

}


/* =========================
   CHART
========================= */

function updateChart(data) {

    trafficHistory.push({
        time: data.timestamp,
        value: data.traffic.packet_rate
    });

    if (trafficHistory.length > 25) {
        trafficHistory.shift();
    }

    drawChart();

}


function updateThreatDistribution(prediction) {

    const container = $("threatDistribution");

    if (!container) return;

    if (prediction) {
        predictionHistory.push(prediction);

        if (predictionHistory.length > 30) {
            predictionHistory.shift();
        }
    }

    if (predictionHistory.length === 0) {
        container.className = "distribution-empty";
        container.innerHTML = `
            <i class="fa-solid fa-wave-square"></i>
            <span>Waiting for network telemetry</span>
        `;
        return;
    }

    const counts = predictionHistory.reduce((result, category) => {
        result[category] = (result[category] || 0) + 1;
        return result;
    }, {});

    const total = predictionHistory.length;
    const rows = Object.entries(counts)
        .sort(([, first], [, second]) => second - first)
        .map(([category, count]) => {
            const percentage = count / total * 100;
            const severity = analysisSeverity(category);

            return `
                <div class="distribution-row">
                    <div class="distribution-row-label">
                        <span><i class="analysis-severity-dot ${severity}"></i>${escapeHtml(category)}</span>
                        <strong>${percentage.toFixed(0)}%</strong>
                    </div>
                    <div class="distribution-row-track">
                        <span class="distribution-row-fill ${severity}" style="width:${percentage}%"></span>
                    </div>
                </div>
            `;
        })
        .join("");

    container.className = "distribution-list";
    container.innerHTML = rows;
}


function drawChart() {

    const canvas = $("trafficChart");

    if (!canvas) return;

    const ctx = canvas.getContext("2d");

    const rect = canvas.getBoundingClientRect();

    const dpr = window.devicePixelRatio || 1;

    canvas.width = rect.width * dpr;

    canvas.height = rect.height * dpr;

    ctx.scale(dpr, dpr);

    const width = rect.width;
    const height = rect.height;

    ctx.clearRect(0, 0, width, height);


    /* GRID */

    ctx.strokeStyle = "rgba(255,255,255,0.06)";
    ctx.lineWidth = 1;

    for (let i = 1; i < 5; i++) {

        const y = (height / 5) * i;

        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();

    }


    if (trafficHistory.length < 2) return;


    const values =
        trafficHistory.map(item => item.value);

    const max =
        Math.max(...values, 500);

    const min = 0;

    const step =
        width / (trafficHistory.length - 1);


    /* LINE */

    ctx.beginPath();

    trafficHistory.forEach((item, index) => {

        const x = index * step;

        const y =
            height -
            ((item.value - min) / (max - min)) *
            (height - 25);

        if (index === 0) {

            ctx.moveTo(x, y);

        } else {

            ctx.lineTo(x, y);

        }

    });

    ctx.strokeStyle = "#22d3ee";
    ctx.lineWidth = 2.5;
    ctx.stroke();


    /* POINTS */

    trafficHistory.forEach((item, index) => {

        const x = index * step;

        const y =
            height -
            ((item.value - min) / (max - min)) *
            (height - 25);

        ctx.beginPath();

        ctx.arc(x, y, 3, 0, Math.PI * 2);

        ctx.fillStyle = "#22d3ee";

        ctx.fill();

    });

}


/* =========================
   ALERTS
========================= */

function updateAlerts(data) {

    if (data.prediction === "Normal" && !data.anomaly) {
        return;
    }

    const alert = {
        prediction: data.prediction,
        risk: data.risk,
        time: data.timestamp
    };

    alertHistory.unshift(alert);

    if (alertHistory.length > 8) {
        alertHistory.pop();
    }

    renderAlerts();

}


function renderAlerts() {

    const container = $("alertsList");

    container.innerHTML = "";

    $("alertCount").textContent =
        alertHistory.length;


    if (alertHistory.length === 0) {

        container.innerHTML = `
            <div class="empty-alert">
                <i class="fa-solid fa-shield-check"></i>
                <p>No threats detected</p>
            </div>
        `;

        return;
    }


    alertHistory.forEach(alert => {

        const div = document.createElement("div");

        div.className = "alert";

        div.innerHTML = `
            <strong>
                <i class="fa-solid fa-triangle-exclamation"></i>
                ${escapeHtml(alert.prediction)}
            </strong>

            <p>
                Risk Level: ${alert.risk}%
                &nbsp; • &nbsp;
                Time: ${alert.time}
            </p>
        `;

        container.appendChild(div);

    });

}


/* =========================
   ATTACK SIMULATION
========================= */

document.querySelectorAll(".attack-card")
    .forEach(button => {

        button.addEventListener("click", async () => {

            const mode =
                button.dataset.mode;

            try {

                const response =
                    await fetch("/api/simulate", {

                        method: "POST",

                        headers: {
                            "Content-Type": "application/json"
                        },

                        body: JSON.stringify({
                            mode: mode
                        })

                    });


                if (!response.ok) {
                    throw new Error("Simulation failed");
                }


                const result =
                    await response.json();

                console.log(
                    "Simulation:",
                    result.mode
                );


                document.querySelectorAll(".attack-card")
                    .forEach(card => {

                        card.style.outline = "none";

                    });


                button.style.outline =
                    "2px solid #22d3ee";

            } catch (error) {

                console.error(error);

            }

        });

    });


/* =========================
   RESET
========================= */

$("resetBtn").addEventListener("click", async () => {

    try {

        await fetch("/api/reset", {
            method: "POST"
        });

        trafficHistory = [];
        alertHistory = [];
        predictionHistory = [];

        $("alertCount").textContent = "0";

        $("monitorMode").textContent = "NORMAL";

        $("riskValue").textContent = "--";

        $("prediction").textContent = "--";

        $("anomaly").textContent = "--";

        $("forecastPrediction").textContent =
            "Waiting...";

        $("confidenceBar").style.width = "0%";

        renderAlerts();
        updateThreatDistribution();

        drawChart();

    } catch (error) {

        console.error(error);

    }

});


/* =========================
   PAUSE / RESUME
========================= */

$("pauseBtn").addEventListener("click", () => {

    paused = !paused;

    const icon =
        $("pauseBtn").querySelector("i");

    if (paused) {

        icon.className =
            "fa-solid fa-play";

    } else {

        icon.className =
            "fa-solid fa-pause";

        loadLiveData();

    }

});


/* =========================
   CSV UPLOAD
========================= */

$("uploadForm").addEventListener("submit", async function (event) {

    event.preventDefault();

    const fileInput = $("csvFile");
    const resultBox = $("uploadResult");
    const submitButton = this.querySelector("button[type='submit']");

    if (!fileInput.files.length) {
        renderAnalysisError("Please select a CSV file.");
        return;
    }

    const file = fileInput.files[0];
    const formData = new FormData();
    formData.append("file", file);

    submitButton.disabled = true;
    submitButton.innerHTML =
        '<i class="fa-solid fa-spinner fa-spin"></i> Analyzing...';

    resultBox.innerHTML = `
        <div class="analysis-loading">
            <i class="fa-solid fa-microchip"></i>
            <div>
                <strong>Analyzing network traffic...</strong>
                <span>Running AI classification...</span>
            </div>
        </div>
    `;

    try {
        const response = await fetch("/api/analyze", {
            method: "POST",
            body: formData
        });

        let result;
        try {
            result = await response.json();
        } catch {
            throw new Error("Invalid server response.");
        }

        if (!response.ok) {
            renderAnalysisError(
                result.error || "Dataset analysis failed.",
                result.missing
            );
            return;
        }

        renderAnalysisReport(result, file.name);
    } catch (error) {
        console.error("Dataset analysis error:", error);
        renderAnalysisError("Unable to analyze dataset. Please try again.");
    } finally {
        submitButton.disabled = false;
        submitButton.innerHTML =
            '<i class="fa-solid fa-magnifying-glass-chart"></i> Analyze Dataset';
    }
});

function renderAnalysisReport(result, filename) {

    const predictions = result.predictions || {};
    const total = Number(result.rows) || 0;
    const categories = Object.entries(predictions)
        .map(([name, count]) => [name, Number(count) || 0])
        .sort((a, b) => b[1] - a[1]);

    const normalCount = categories
        .filter(([name]) => name.toLowerCase() === "normal")
        .reduce((sum, [, count]) => sum + count, 0);
    const threatCount = Math.max(total - normalCount, 0);
    const normalRate = total ? normalCount / total * 100 : 0;
    const threatRate = total ? threatCount / total * 100 : 0;

    const distribution = categories.map(([name, count]) => {
        const percentage = total ? count / total * 100 : 0;
        const severity = analysisSeverity(name);

        return `
            <div class="analysis-distribution-item">
                <div class="analysis-distribution-label">
                    <span><i class="analysis-severity-dot ${severity}"></i>${escapeHtml(name)}</span>
                    <strong>${percentage.toFixed(1)}%</strong>
                </div>
                <div class="analysis-distribution-track">
                    <div class="analysis-distribution-fill ${severity}" style="width:${percentage}%"></div>
                </div>
            </div>
        `;
    }).join("");

    const breakdown = categories.map(([name, count]) => {
        const percentage = total ? count / total * 100 : 0;
        const severity = analysisSeverity(name);
        const status = name.toLowerCase() === "normal" ? "NORMAL" : severity.toUpperCase();

        return `
            <tr>
                <td><span class="analysis-category"><i class="analysis-severity-dot ${severity}"></i>${escapeHtml(name)}</span></td>
                <td>${count.toLocaleString("en-IN")}</td>
                <td>${percentage.toFixed(1)}%</td>
                <td><span class="analysis-status ${severity}">${status}</span></td>
            </tr>
        `;
    }).join("");

    $("uploadResult").innerHTML = `
        <section class="analysis-report" aria-live="polite">
            <div class="analysis-report-header">
                <div>
                    <span class="analysis-kicker"><i class="fa-solid fa-shield-halved"></i> DATASET ANALYSIS</span>
                    <h3>Analysis Complete</h3>
                    <p>${total.toLocaleString("en-IN")} network-flow records analyzed by AI detection engine</p>
                </div>
                <span class="analysis-complete">● ANALYSIS COMPLETE</span>
            </div>

            <div class="analysis-metrics">
                <div class="analysis-metric-card"><span>TOTAL FLOWS</span><strong>${total.toLocaleString("en-IN")}</strong></div>
                <div class="analysis-metric-card normal"><span>NORMAL</span><strong>${normalCount.toLocaleString("en-IN")}</strong><small>${normalRate.toFixed(1)}%</small></div>
                <div class="analysis-metric-card threat"><span>THREATS</span><strong>${threatCount.toLocaleString("en-IN")}</strong><small>${threatRate.toFixed(1)}%</small></div>
                <div class="analysis-metric-card rate"><span>THREAT RATE</span><strong>${threatRate.toFixed(1)}%</strong></div>
            </div>

            <div class="analysis-report-grid">
                <div class="analysis-card">
                    <div class="analysis-card-title"><div><span class="analysis-kicker">THREAT DISTRIBUTION</span><h4>Prediction categories</h4></div><i class="fa-solid fa-chart-pie"></i></div>
                    ${distribution || "<p>No predictions returned.</p>"}
                </div>
                <div class="analysis-card">
                    <div class="analysis-card-title"><div><span class="analysis-kicker">DATASET INFORMATION</span><h4>Analysis metadata</h4></div><i class="fa-solid fa-database"></i></div>
                    <dl class="analysis-info">
                        <div><dt>Dataset</dt><dd>${escapeHtml(filename)}</dd></div>
                        <div><dt>Records analyzed</dt><dd>${total.toLocaleString("en-IN")}</dd></div>
                        <div><dt>Required features</dt><dd>6</dd></div>
                        <div><dt>Detection engine</dt><dd>Random Forest</dd></div>
                        <div><dt>Anomaly engine</dt><dd>Isolation Forest</dd></div>
                    </dl>
                </div>
            </div>

            <div class="analysis-card analysis-breakdown">
                <div class="analysis-card-title"><div><span class="analysis-kicker">DETECTION BREAKDOWN</span><h4>Classification results</h4></div><i class="fa-solid fa-table-list"></i></div>
                <div class="analysis-table-wrapper">
                    <table class="analysis-table">
                        <thead><tr><th>Category</th><th>Count</th><th>Percentage</th><th>Status</th></tr></thead>
                        <tbody>${breakdown}</tbody>
                    </table>
                </div>
            </div>
        </section>
    `;
}

function renderAnalysisError(message, missing = []) {

    const missingHtml = Array.isArray(missing) && missing.length
        ? `<div class="analysis-missing"><strong>Missing required features:</strong><ul>${missing.map(item => `<li>${escapeHtml(item)}</li>`).join("")}</ul></div>`
        : "";

    $("uploadResult").innerHTML = `
        <div class="analysis-error" role="alert">
            <i class="fa-solid fa-circle-exclamation"></i>
            <div><strong>DATASET VALIDATION FAILED</strong><p>${escapeHtml(message)}</p>${missingHtml}</div>
        </div>
    `;
}

function analysisSeverity(name) {

    const category = String(name).toLowerCase();
    if (category === "normal") return "normal";
    if (category === "ddos" || category === "botnet") return "critical";
    if (category === "port scan" || category === "brute force") return "high";
    return "detected";
}


/* =========================
   NAVIGATION
========================= */

document.querySelectorAll(".sidebar nav a")
    .forEach(link => {

        link.addEventListener("click", () => {

            document.querySelectorAll(
                ".sidebar nav a"
            ).forEach(item => {

                item.classList.remove("active");

            });

            link.classList.add("active");

        });

    });


/* =========================
   HELPERS
========================= */

function formatNumber(value) {

    return Number(value).toLocaleString("en-IN");

}


function escapeHtml(value) {

    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");

}


/* =========================
   START
========================= */

loadLiveData();

setInterval(() => {

    loadLiveData();

}, 1500);


window.addEventListener("resize", () => {

    drawChart();

});