import numpy as np
from datetime import datetime

def build_stat_vector(feats: dict, ts: float,
                      count_1m: int, count_5m: int,
                      inter_arrival: float, burst_score: float) -> np.ndarray:
    dt = datetime.fromtimestamp(ts)
    return np.array([
        count_1m,
        count_5m,
        inter_arrival,
        burst_score,
        dt.hour,
        dt.weekday(),
        feats["mat_transition_prob"],
        feats["mat_is_rare"],
        feats["mat_user_rate_5m"],
        feats["entity_failed_auth_5m"],
        feats["entity_sudo_count_5m"],
        feats["entity_upload_count_5m"],
    ], dtype=float)
