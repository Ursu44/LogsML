import numpy as np

def normalize_dynamic(score, history):
    if len(history) < 50:
        return 0.0
    p5  = np.percentile(history, 5)
    p95 = np.percentile(history, 95)
    if p95 - p5 == 0:
        return 0.0
    return float(np.clip((score - p5) / (p95 - p5), 0, 1))
