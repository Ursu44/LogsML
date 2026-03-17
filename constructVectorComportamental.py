import numpy as np

def build_behavior_vector(feats: dict, template_rarity: float,
                          entity_deviation: float, burst_score: float) -> np.ndarray:
    return np.array([
        template_rarity,
        entity_deviation,
        burst_score,
        feats["mat_ip_diversity"],
        feats["mat_new_process"],
        feats["mat_first_seen_user"],
        feats["mat_first_seen_ip"],
        feats["entity_unique_processes"],
        feats["entity_lsass_count_5m"],
        feats["is_external_src"],
    ], dtype=float)