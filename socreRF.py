import numpy as np
from collections import deque
from normalizeazaDinamic import normalize_dynamic


def score_rf_model(model, scaler, vector: np.ndarray,
                   history: deque) -> float:

    X_scaled = scaler.transform(vector.reshape(1, -1))

    prob_malicious = model.predict_proba(X_scaled)[0][1]

    history.append(prob_malicious)
    return normalize_dynamic(prob_malicious, history)