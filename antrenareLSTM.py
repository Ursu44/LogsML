import os
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"

import numpy as np
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout
from tensorflow.keras.optimizers import Adam
from sklearn.preprocessing import StandardScaler
from sklearn.utils.class_weight import compute_class_weight


SEQ_LEN    = 10
INPUT_DIMS = 22


def build_lstm_model() -> object:
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

    padded = []
    for seq in sequences:
        padded.append(pad_sequence(seq, SEQ_LEN, INPUT_DIMS))

    X = np.array(padded, dtype=float)
    y = np.array(labels)


    N, T, F = X.shape
    X_flat  = X.reshape(N * T, F)

    if scaler is None:
        scaler = StandardScaler()
        X_flat = scaler.fit_transform(X_flat)
    else:
        X_flat = scaler.transform(X_flat)

    X_scaled = X_flat.reshape(N, T, F)

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
        epochs=15,
        batch_size=32,
        validation_split=0.1,
        class_weight=class_weight_dict,
        verbose=0
    )

    print(f"✅ LSTM trained — {len(y)} secvențe "
          f"({n_mal} malițioase, {n_ben} benigne)")

    return model, scaler