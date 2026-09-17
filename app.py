from flask import Flask, render_template, jsonify, request
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler

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
# CREATE TRAINING DATA
# =========================

def generate_data(n=7000):
    profiles = {
        "Normal": [300, 50000, 30, 2, 8, 700],
        "DDoS": [5000, 800000, 500, 20, 15, 400],
        "Port Scan": [1200, 120000, 250, 80, 200, 200],
        "Brute Force": [700, 90000, 100, 150, 10, 500],
        "Botnet": [900, 150000, 120, 40, 30, 300]
    }
    rows = []
    for index in range(n):
        attack = ATTACKS[index % len(ATTACKS)]
        multiplier = 1 + (index % 11 - 5) / 100
        values = [max(value * multiplier, 0) for value in profiles[attack]]
        rows.append([*values, attack])
    return pd.DataFrame(rows, columns=FEATURES + ["attack"])


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
# RESET
# =========================

@app.route("/api/reset", methods=["POST"])
def reset():
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

        X_test = df[FEATURES].apply(pd.to_numeric, errors="raise")
        scaled = scaler.transform(X_test)
        predictions = classifier.predict(scaled)
        probabilities = classifier.predict_proba(scaled)
        anomaly_flags = anomaly_model.predict(scaled) == -1

        label_column = next(
            (column for column in df.columns if column.lower() in {
                "label", "category", "attack", "class", "classification"
            }),
            None
        )
        categories = [str(prediction) for prediction in predictions]
        counts = pd.Series(categories).value_counts()
        row_data = [
            {
                "record": index + 1,
                **{feature: float(row[feature]) for feature in FEATURES},
                "prediction": str(prediction),
                "category": str(category),
                "confidence": round(float(max(probabilities[index])) * 100, 2),
                "anomaly": bool(anomaly_flags[index])
            }
            for index, (row, prediction, category) in enumerate(
                zip(df.to_dict("records"), predictions, categories)
            )
        ]

        normal_count = sum(
            str(category).strip().lower() == "normal" for category in categories
        )
        threat_count = len(categories) - normal_count
        threat_rate = threat_count / len(categories) * 100
        average_confidence = float(np.mean([
            row["confidence"] for row in row_data
        ]))
        anomaly_count = int(anomaly_flags.sum())
        dominant_category = counts.index[0]
        failed_record_rate = float((X_test["failed_connections"] > 0).mean() * 100)
        anomaly_rate = float(anomaly_flags.mean() * 100)
        health_score = max(0, min(100, 100 - (threat_rate * 0.8)))
        stability_score = max(0, min(100, 100 - (
            threat_rate * 0.5
            + failed_record_rate * 0.3
            + anomaly_rate * 0.2
        )))
        metrics = {
            feature: float(X_test[feature].mean())
            for feature in FEATURES
        }
        sample_reasons = get_reasons(
            {feature: float(X_test.iloc[0][feature]) for feature in FEATURES},
            str(predictions[0])
        )

        return jsonify({
            "rows": len(df),
            "predictions": counts.to_dict(),
            "features": {
                feature: [float(value) for value in X_test[feature].tolist()]
                for feature in FEATURES
            },
            "records": row_data,
            "metrics": metrics,
            "network_health": {
                "score": round(health_score, 2),
                "status": (
                    "Healthy" if health_score >= 80 else
                    "Moderate" if health_score >= 60 else
                    "Warning" if health_score >= 40 else
                    "Critical"
                ),
                "stability": (
                    "Stable" if stability_score >= 80 else
                    "Moderate" if stability_score >= 60 else
                    "Unstable" if stability_score >= 40 else
                    "Critical"
                ),
                "stability_score": round(stability_score, 2)
            },
            "label_column": label_column,
            "dominant_category": str(dominant_category),
            "confidence": round(average_confidence, 2),
            "anomaly_count": anomaly_count,
            "risk": round(threat_rate),
            "reasons": sample_reasons,
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