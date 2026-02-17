from kafka import KafkaConsumer
import json
from datetime import datetime
import numpy as np
from collections import defaultdict, deque
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# -------------------------------
# KAFKA CONSUMER
# -------------------------------
consumer = KafkaConsumer(
    "logs_normalized",
    bootstrap_servers="localhost:29092",
    auto_offset_reset="earliest",
    group_id=None,
)

# -------------------------------
# TEMPORAL STATE
# -------------------------------
event_times = defaultdict(deque)

WINDOW_1M = 60
WINDOW_5M = 300

# -------------------------------
# ML CONFIGURATION
# -------------------------------
BUFFER_SIZE = 300
training_buffer = []
model = None
scaler = None
model_trained = False

# Risk thresholds (calibrate dacă vrei mai agresiv)
LOW_THRESHOLD = -0.05
HIGH_THRESHOLD = -0.03

ALERT_CONSECUTIVE_THRESHOLD = 1
consecutive_high_risk = 0

print("🚀 Real-time Anomaly Detection Started...\n")

for msg in consumer:
    payload = json.loads(msg.value.decode(errors="ignore"))
    features = payload["features"]

    template_id = features["template_id"]
    ts = features["timestamp"]

    # -------------------------------
    # TEMPORAL FEATURE ENGINEERING
    # -------------------------------
    dq = event_times[template_id]
    dq.append(ts)

    while dq and dq[0] < ts - WINDOW_5M:
        dq.popleft()

    count_1m = sum(1 for t in dq if t >= ts - WINDOW_1M)
    count_5m = len(dq)

    if len(dq) >= 2:
        inter_arrival = dq[-1] - dq[-2]
    else:
        inter_arrival = 0.0

    dt = datetime.fromtimestamp(ts)

    # FEATURE VECTOR (fără template_idx pentru stabilitate)
    ml_vector = np.array([
        count_1m,
        count_5m,
        inter_arrival,
        dt.hour,
        dt.weekday()
    ], dtype=float)

    # -------------------------------
    # TRAINING PHASE
    # -------------------------------
    if not model_trained:
        training_buffer.append(ml_vector)

        print(f"Warmup training data: {len(training_buffer)}/{BUFFER_SIZE}")

        if len(training_buffer) >= BUFFER_SIZE:
            scaler = StandardScaler()
            training_scaled = scaler.fit_transform(training_buffer)

            model = IsolationForest(
                n_estimators=200,
                contamination=0.03,
                random_state=42
            )

            model.fit(training_scaled)
            model_trained = True
            print("\n🔥 Isolation Forest Model Trained Successfully!\n")

        continue

    # -------------------------------
    # PREDICTION PHASE
    # -------------------------------
    ml_vector_scaled = scaler.transform([ml_vector])
    score = model.decision_function(ml_vector_scaled)[0]

    # Behavioral validation
    is_burst = count_1m > 10
    is_fast = inter_arrival < 2

    # -------------------------------
    # 🔴 HIGH RISK
    # -------------------------------
    if score < HIGH_THRESHOLD and (is_burst or is_fast):
        consecutive_high_risk += 1
    else:
        consecutive_high_risk = 0

    if consecutive_high_risk >= ALERT_CONSECUTIVE_THRESHOLD:
        risk_percent = min(abs(score) * 100, 100)

        print("\n🔴🔴🔴 HIGH RISK ALERT 🔴🔴🔴")
        print(f"Events last 1m: {count_1m}")
        print(f"Inter-arrival: {round(inter_arrival, 2)} sec")
        print(f"Model Score: {round(score, 4)}")
        print(f"Risk Level: {round(risk_percent, 2)}%")
        print("-----------------------------------\n")

    # -------------------------------
    # 🟡 SUSPICIOUS
    # -------------------------------
    elif score < LOW_THRESHOLD:
        risk_percent = min(abs(score) * 100, 100)
        print(f"🟡 Suspicious | Score: {round(score,4)} | Risk: {round(risk_percent,2)}%")

    # -------------------------------
    # 🟢 NORMAL
    # -------------------------------
    else:
        print(f"🟢 Normal | Score: {round(score,4)}")
