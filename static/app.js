const $ = (id) => document.getElementById(id);

let paused = false;
let trafficHistory = [];
let alertHistory = [];


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

        $("alertCount").textContent = "0";

        $("monitorMode").textContent = "NORMAL";

        $("riskValue").textContent = "--";

        $("prediction").textContent = "--";

        $("anomaly").textContent = "--";

        $("forecastPrediction").textContent =
            "Waiting...";

        $("confidenceBar").style.width = "0%";

        renderAlerts();

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

$("uploadForm").addEventListener(
    "submit",
    async function(event) {

        event.preventDefault();


        const fileInput =
            $("csvFile");

        if (!fileInput.files.length) {

            $("uploadResult").textContent =
                "Please select a CSV file.";

            return;
        }


        const formData =
            new FormData();

        formData.append(
            "file",
            fileInput.files[0]
        );


        $("uploadResult").textContent =
            "Analyzing dataset...";


        try {

            const response =
                await fetch("/api/analyze", {

                    method: "POST",

                    body: formData

                });


            const result =
                await response.json();


            if (!response.ok) {

                $("uploadResult").textContent =
                    result.error || "Analysis failed.";

                return;
            }


            let html = `
                <strong>
                    Analysis Complete
                </strong>
                <br>
                Rows analyzed: ${result.rows}
                <br>
            `;


            Object.entries(result.predictions)
                .forEach(([name, count]) => {

                    html += `
                        ${escapeHtml(name)}:
                        ${count}
                        <br>
                    `;

                });


            $("uploadResult").innerHTML = html;


        } catch (error) {

            $("uploadResult").textContent =
                "Unable to analyze dataset.";

            console.error(error);

        }

    }
);


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