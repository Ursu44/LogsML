import os
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"

import numpy as np
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout
from tensorflow.keras.optimizers import Adam
from sklearn.preprocessing import StandardScaler
from sklearn.utils.class_weight import compute_class_weight


# Dimensiuni fixe
SEQ_LEN    = 10   # câte evenimente anterioare vede LSTM
INPUT_DIMS = 22   # stat_vector(12) + behavior_vector(10)


def build_lstm_model() -> object:
    """
    Construiește arhitectura LSTM pentru detecție anomalii secvențiale.

    Arhitectură:
        Input:   (SEQ_LEN, INPUT_DIMS) = (10, 22)
        LSTM:    64 unități — captează pattern-uri temporale
        Dropout: 0.2 — regularizare, previne overfitting
        LSTM:    32 unități — rafinare pattern-uri
        Dropout: 0.2
        Dense:   16 unități, activare relu
        Dense:   1 unitate, activare sigmoid → probabilitate [0, 1]
    """
    model = Sequential([
        LSTM(64, input_shape=(SEQ_LEN, INPUT_DIMS),
             return_sequences=True),
        Dropout(0.2),
        LSTM(32, return_sequences=False),
        Dropout(0.2),
        Dense(16, activation="relu"),
        Dense(1, activation="sigmoid")
    ])

    model.compile(
        optimizer=Adam(learning_rate=0.001),
        loss="binary_crossentropy",
        metrics=["accuracy"]
    )

    return model


def pad_sequence(seq, seq_len, input_dims):
    """Padding cu zerouri la stânga pentru secvențe mai scurte decât seq_len."""
    seq_list = list(seq)
    if len(seq_list) < seq_len:
        pad_len = seq_len - len(seq_list)
        padding = [np.zeros(input_dims) for _ in range(pad_len)]
        seq_list = padding + seq_list
    else:
        seq_list = seq_list[-seq_len:]
    return seq_list


def train_lstm_model(sequences: list, labels: list,
                     scaler: StandardScaler = None) -> tuple:
    """
    Antrenează modelul LSTM pe secvențele acumulate.

    Îmbunătățire față de versiunea anterioară:
    - class_weight='balanced' — compensează dezechilibrul claselor
      (ex: 17 malițioase vs 283 benigne → penalizare 16x mai mare
      pentru greșelile pe clasa malițioasă)
    - epochs=15 în loc de 10 — mai multe treceri pentru clase rare

    Args:
        sequences: listă de secvențe (fiecare e o listă de vectori)
        labels:    listă de labeluri 0/1
        scaler:    StandardScaler existent sau None (se creează unul nou)

    Returnează:
        (model, scaler) gata de utilizare
    """
    # Normalizare lungime — padding cu zerouri la stânga
    padded = []
    for seq in sequences:
        padded.append(pad_sequence(seq, SEQ_LEN, INPUT_DIMS))

    X = np.array(padded, dtype=float)  # shape: (N, SEQ_LEN, INPUT_DIMS)
    y = np.array(labels)               # shape: (N,)

    # Normalizare — reshape pentru scaler (lucrează pe 2D)
    N, T, F = X.shape
    X_flat  = X.reshape(N * T, F)

    if scaler is None:
        scaler = StandardScaler()
        X_flat = scaler.fit_transform(X_flat)
    else:
        X_flat = scaler.transform(X_flat)

    X_scaled = X_flat.reshape(N, T, F)

    # Calcul class weights — compensează dezechilibrul claselor
    # Dacă avem 17 malițioase și 283 benigne:
    #   weight_0 (benigni)   = 300 / (2 * 283) ≈ 0.53
    #   weight_1 (malițios)  = 300 / (2 * 17)  ≈ 8.82
    # → LSTM penalizează de ~16x mai mult greșelile pe malițios
    unique_classes = np.unique(y)
    if len(unique_classes) > 1:
        weights = compute_class_weight(
            class_weight='balanced',
            classes=unique_classes,
            y=y
        )
        class_weight_dict = dict(zip(unique_classes.astype(int), weights))
    else:
        class_weight_dict = None

    n_mal = int(y.sum())
    n_ben = int(len(y) - n_mal)

    if class_weight_dict:
        print(f"   class_weight: {{0: {class_weight_dict.get(0, 1.0):.2f}, "
              f"1: {class_weight_dict.get(1, 1.0):.2f}}} "
              f"(dezechilibru {n_ben}/{n_mal})")

    model = build_lstm_model()

    model.fit(
        X_scaled, y,
        epochs=15,                      # mai multe epoci pentru clase rare
        batch_size=32,
        validation_split=0.1,
        class_weight=class_weight_dict, # compensare dezechilibru clase
        verbose=0
    )

    print(f"✅ LSTM trained — {len(y)} secvențe "
          f"({n_mal} malițioase, {n_ben} benigne)")

    return model, scaler