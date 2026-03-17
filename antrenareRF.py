from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import numpy as np


def train_rf_model(buffer_X: list, buffer_y: list) -> tuple:

    X = np.array(buffer_X)
    y = np.array(buffer_y)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=10,
        min_samples_leaf=5,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1              
    )
    model.fit(X_scaled, y)

    n_mal  = int(y.sum())
    n_ben  = int(len(y) - n_mal)
    print(f"✅ Random Forest trained — {len(y)} exemple "
          f"({n_mal} malițioase, {n_ben} benigne)")

    return model, scaler