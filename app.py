from flask import Flask, render_template, jsonify, request
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
import random
import time

app = Flask(__name__)

# =========================
# FEATURES
# =========================

FEATURES = [
    "packet_rate",
    "bytes_rate",
    "connection_rate",
    "failed_connections",
    "unique_ports",
    "avg_packet_size"
]

ATTACKS = [
    "Normal",
    "DDoS",
    "Port Scan",
    "Brute Force",
    "Botnet"
]

# =========================
# CREATE SYNTHETIC DATA
# =========================

def generate_data(n=7000):

    rows = []

    for _ in range(n):

        attack = random.choices(
            ATTACKS,
            weights=[50, 15, 15, 10, 10]
        )[0]

        if attack == "Normal":

            packet_rate = np.random.normal(300, 80)
            bytes_rate = np.random.normal(50000, 12000)
            connection_rate = np.random.normal(30, 8)
            failed_connections = np.random.normal(2, 1)
            unique_ports = np.random.normal(8, 3)
            avg_packet_size = np.random.normal(700, 100)

        elif attack == "DDoS":

            packet_rate = np.random.normal(5000, 1000)
            bytes_rate = np.random.normal(800000, 150000)
            connection_rate = np.random.normal(500, 100)
            failed_connections = np.random.normal(20, 5)
            unique_ports = np.random.normal(15, 5)
            avg_packet_size = np.random.normal(400, 80)

        elif attack == "Port Scan":

            packet_rate = np.random.normal(1200, 300)
            bytes_rate = np.random.normal(120000, 30000)
            connection_rate = np.random.normal(250, 50)
            failed_connections = np.random.normal(80, 20)
            unique_ports = np.random.normal(200, 40)
            avg_packet_size = np.random.normal(200, 50)

        elif attack == "Brute Force":

            packet_rate = np.random.normal(700, 150)
            bytes_rate = np.random.normal(90000, 20000)
            connection_rate = np.random.normal(100, 20)
            failed_connections = np.random.normal(150, 30)
            unique_ports = np.random.normal(10, 3)
            avg_packet_size = np.random.normal(500, 80)

        else:

            packet_rate = np.random.normal(900, 200)
            bytes_rate = np.random.normal(150000, 30000)
            connection_rate = np.random.normal(120, 30)
            failed_connections = np.random.normal(40, 10)
            unique_ports = np.random.normal(30, 8)
            avg_packet_size = np.random.normal(300, 70)

        rows.append([
            max(packet_rate, 1),
            max(bytes_rate, 1),
            max(connection_rate, 1),
            max(failed_connections, 0),
            max(unique_ports, 1),
            max(avg_packet_size, 1),
            attack
        ])

    columns = FEATURES + ["attack"]

    return pd.DataFrame(rows, columns=columns)


# =========================
# TRAIN AI MODEL
# =========================

data = generate_data()

X = data[FEATURES]
y = data["attack"]

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

classifier = RandomForestClassifier(
    n_estimators=180,
    class_weight="balanced_subsample",
    random_state=42
)

classifier.fit(X_scaled, y)

anomaly_model = IsolationForest(
    contamination=0.08,
    random_state=42
)

anomaly_model.fit(X_scaled)


# =========================
# GLOBAL STATE
# =========================

current_mode = "normal"

history = []


# =========================
# SIMULATION DATA
# =========================

def generate_traffic(mode="normal"):

    if mode == "ddos":

        values = {
            "packet_rate": random.randint(4000, 6500),
            "bytes_rate": random.randint(600000, 1000000),
            "connection_rate": random.randint(400, 700),
            "failed_connections": random.randint(10, 40),
            "unique_ports": random.randint(10, 30),
            "avg_packet_size": random.randint(300, 500)
        }

    elif mode == "scan":

        values = {
            "packet_rate": random.randint(800, 1500),
            "bytes_rate": random.randint(80000, 180000),
            "connection_rate": random.randint(180, 350),
            "failed_connections": random.randint(50, 120),
            "unique_ports": random.randint(150, 300),
            "avg_packet_size": random.randint(100, 300)
        }

    elif mode == "bruteforce":

        values = {
            "packet_rate": random.randint(500, 1000),
            "bytes_rate": random.randint(60000, 120000),
            "connection_rate": random.randint(70, 150),
            "failed_connections": random.randint(100, 200),
            "unique_ports": random.randint(5, 15),
            "avg_packet_size": random.randint(400, 600)
        }

    elif mode == "botnet":

        values = {
            "packet_rate": random.randint(700, 1200),
            "bytes_rate": random.randint(100000, 200000),
            "connection_rate": random.randint(80, 160),
            "failed_connections": random.randint(20, 60),
            "unique_ports": random.randint(20, 50),
            "avg_packet_size": random.randint(200, 400)
        }

    else:

        values = {
            "packet_rate": random.randint(150, 450),
            "bytes_rate": random.randint(25000, 70000),
            "connection_rate": random.randint(15, 50),
            "failed_connections": random.randint(0, 5),
            "unique_ports": random.randint(3, 15),
            "avg_packet_size": random.randint(500, 900)
        }

    return values


# =========================
# RISK SCORE
# =========================

def calculate_risk(values, prediction, anomaly):

    risk = 10

    if values["packet_rate"] > 2000:
        risk += 25

    if values["bytes_rate"] > 300000:
        risk += 20

    if values["connection_rate"] > 200:
        risk += 15

    if values["failed_connections"] > 50:
        risk += 15

    if values["unique_ports"] > 100:
        risk += 15

    if anomaly:
        risk += 10

    if prediction != "Normal":
        risk += 10

    return min(risk, 100)


# =========================
# EXPLANATION
# =========================

def get_reasons(values, prediction):

    reasons = []

    if values["packet_rate"] > 2000:
        reasons.append("Very high packet rate detected")

    if values["bytes_rate"] > 300000:
        reasons.append("Abnormally high bandwidth usage")

    if values["connection_rate"] > 200:
        reasons.append("High connection frequency")

    if values["failed_connections"] > 50:
        reasons.append("Large number of failed connections")

    if values["unique_ports"] > 100:
        reasons.append("Unusual number of destination ports")

    if prediction != "Normal":
        reasons.append(f"AI classified traffic as {prediction}")

    if not reasons:
        reasons.append("Traffic pattern appears normal")

    return reasons


# =========================
# HOME
# =========================

@app.route("/")
def home():

    return render_template("index.html")


# =========================
# STATUS
# =========================

@app.route("/api/status")
def status():

    return jsonify({
        "status": "online",
        "model": "Random Forest + Isolation Forest",
        "classes": ATTACKS
    })


# =========================
# LIVE API
# =========================

@app.route("/api/live")
def live():

    values = generate_traffic(current_mode)

    df = pd.DataFrame([values])

    scaled = scaler.transform(df[FEATURES])

    prediction = classifier.predict(scaled)[0]

    probabilities = classifier.predict_proba(scaled)[0]

    confidence = round(max(probabilities) * 100, 2)

    anomaly_result = anomaly_model.predict(scaled)[0]

    anomaly = bool(anomaly_result == -1)

    risk = calculate_risk(
        values,
        prediction,
        anomaly
    )

    reasons = get_reasons(
        values,
        prediction
    )

    result = {
        "timestamp": time.strftime("%H:%M:%S"),
        "prediction": prediction,
        "confidence": confidence,
        "risk": risk,
        "anomaly": anomaly,
        "mode": current_mode,
        "reasons": reasons,
        "traffic": values
    }

    history.append(result)

    if len(history) > 30:
        history.pop(0)

    return jsonify(result)


# =========================
# SIMULATE ATTACK
# =========================

@app.route("/api/simulate", methods=["POST"])
def simulate():

    global current_mode

    data = request.get_json()

    current_mode = data.get("mode", "normal")

    return jsonify({
        "success": True,
        "mode": current_mode
    })


# =========================
# RESET
# =========================

@app.route("/api/reset", methods=["POST"])
def reset():

    global current_mode

    current_mode = "normal"

    history.clear()

    return jsonify({
        "success": True
    })


# =========================
# CSV ANALYSIS
# =========================

@app.route("/api/analyze", methods=["POST"])
def analyze():

    if "file" not in request.files:

        return jsonify({
            "error": "No file uploaded"
        }), 400

    file = request.files["file"]

    try:

        df = pd.read_csv(file)

        if df.empty:
            return jsonify({
                "error": "The uploaded CSV contains no data rows."
            }), 400

        missing = [
            column for column in FEATURES
            if column not in df.columns
        ]

        if missing:

            return jsonify({
                "error": "Missing columns",
                "missing": missing
            }), 400

        X_test = df[FEATURES]

        scaled = scaler.transform(X_test)

        predictions = classifier.predict(scaled)

        counts = pd.Series(predictions).value_counts()

        return jsonify({
            "rows": len(df),
            "predictions": counts.to_dict(),
            "dataset_name": file.filename or "Uploaded dataset",
            "required_features": len(FEATURES),
            "detection_engine": "Random Forest",
            "anomaly_engine": "Isolation Forest"
        })

    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 400


# =========================
# RUN SERVER
# =========================

if __name__ == "__main__":

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )