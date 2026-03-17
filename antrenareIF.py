from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

def train_if_model(buffer: list, n_estimators: int,
                   contamination: float) -> tuple:
    scaler = StandardScaler()
    scaled = scaler.fit_transform(buffer)
    model  = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=42
    )
    model.fit(scaled)
    return model, scaler
