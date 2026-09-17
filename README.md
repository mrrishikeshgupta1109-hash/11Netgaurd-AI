# CYBERCAST

CYBERCAST is an AI-powered Cyber Security Operations Center (SOC) platform for monitoring network behavior, detecting anomalies, forecasting potential attacks, and analyzing network traffic datasets.

## Features

- Live network telemetry monitoring with risk scoring and attack prediction.
- AI-based traffic classification using Random Forest.
- Anomaly detection using Isolation Forest.
- Attack simulation for DDoS, port scans, and brute-force activity.
- Explainable detection reasons and threat distribution history.
- Traffic charts, threat alerts, and system status indicators.
- CSV dataset analysis with prediction summaries.

## Requirements

- Python 3.9 or newer
- pip

## Installation

1. Clone or download this repository and open its directory.
2. Create and activate a virtual environment:

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

   On macOS or Linux:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. Install the dependencies:

   ```bash
   pip install -r requirements.txt
   ```

## Running CYBERCAST

Start the Flask development server:

```bash
python app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in a browser.

The application generates synthetic network telemetry at runtime. No external database or dataset is required for the dashboard to start.

## Dashboard Usage

- Use the attack simulation controls to switch between normal traffic and simulated attack modes.
- Use the pause and reset controls to manage the live monitoring stream.
- Upload a CSV file in Dataset Analysis to classify its network traffic.
- Review the risk score, prediction confidence, anomaly status, detection reasons, and alert history in the dashboard.

### CSV Analysis Format

Uploaded CSV files must include these columns:

- `packet_rate`
- `bytes_rate`
- `connection_rate`
- `failed_connections`
- `unique_ports`
- `avg_packet_size`

## API Endpoints

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/` | Serves the CYBERCAST dashboard. |
| `GET` | `/api/status` | Returns service status, model names, and supported attack classes. |
| `POST` | `/api/reset` | Confirms a dashboard reset; uploaded state is held in the browser. |
| `POST` | `/api/analyze` | Analyzes an uploaded CSV dataset. |

## Project Structure

```text
.
├── app.py
├── requirements.txt
├── static/
│   ├── app.js
│   └── style.css
└── templates/
    └── index.html
```

## Detection Models

CYBERCAST trains its models from generated synthetic traffic when the Flask application starts. The dashboard uses:

- `RandomForestClassifier` for attack classification.
- `IsolationForest` for anomaly detection.
- `StandardScaler` for feature normalization before model inference.
