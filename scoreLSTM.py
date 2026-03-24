import os
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"

import numpy as np

from collections import deque
from sklearn.preprocessing import StandardScaler
from normalizeazaDinamic import normalize_dynamic

SEQ_LEN    = 10
INPUT_DIMS = 22


def score_lstm_model(model, scaler: StandardScaler,
                     sequence: list, history: deque) -> float:
    if len(sequence) < SEQ_LEN:
        pad_len = SEQ_LEN - len(sequence)
        padding = [np.zeros(INPUT_DIMS) for _ in range(pad_len)]
        seq = padding + list(sequence)
    else:
        seq = list(sequence)

    X = np.array(seq)
    X_flat   = X.reshape(SEQ_LEN, INPUT_DIMS)
    X_scaled = scaler.transform(X_flat)
    X_input  = X_scaled.reshape(1, SEQ_LEN, INPUT_DIMS)

    prob = float(model.predict(X_input, verbose=0)[0][0])

    history.append(prob)
    return normalize_dynamic(prob, history)