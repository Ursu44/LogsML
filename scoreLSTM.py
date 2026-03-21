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
    """
    Scorează o secvență de evenimente cu modelul LSTM.

    Args:
        model:    modelul LSTM antrenat
        scaler:   StandardScaler din antrenare
        sequence: listă de vectori combinați (stat+behav), maxim SEQ_LEN
        history:  deque cu istoricul scorurilor pentru normalizare dinamică

    Returnează:
        scor normalizat în [0, 1] — probabilitatea de anomalie secvențială
    """
    if len(sequence) < SEQ_LEN:
        # Secvență incompletă — padding cu zerouri la stânga
        pad_len = SEQ_LEN - len(sequence)
        padding = [np.zeros(INPUT_DIMS) for _ in range(pad_len)]
        seq = padding + list(sequence)
    else:
        seq = list(sequence)

    X = np.array(seq)                        # shape: (SEQ_LEN, INPUT_DIMS)
    X_flat   = X.reshape(SEQ_LEN, INPUT_DIMS)
    X_scaled = scaler.transform(X_flat)      # normalizare cu același scaler
    X_input  = X_scaled.reshape(1, SEQ_LEN, INPUT_DIMS)  # batch de 1

    # predict returnează probabilitatea clasei malițioase
    prob = float(model.predict(X_input, verbose=0)[0][0])

    history.append(prob)
    return normalize_dynamic(prob, history)