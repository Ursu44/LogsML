from collections import deque
import numpy as np
from normalizeazaDinamic import normalize_dynamic


def score_if_model(model, scaler, vector: np.ndarray,
                   history: deque) -> float:
    scaled = scaler.transform(vector.reshape(1, -1))
    raw    = -model.score_samples(scaled)[0]
    history.append(raw)
    return normalize_dynamic(raw, history)