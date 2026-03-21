import os
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"

from kafka import KafkaConsumer
import json
import numpy as np
from collections import defaultdict, deque, Counter
import warnings
warnings.filterwarnings("ignore")

from antrenareIF import train_if_model
from aplicareReguliEngine import apply_rule_engine
from clasificareLoguri import classify_log_category
from constructStatiticVector import build_stat_vector
from constructVectorComportamental import build_behavior_vector
from esteMalitios import is_obviously_malicious
from extragereFeaturesSemantic import extract_semantic_features
from normalizeazaDinamic import normalize_dynamic
from preiaEntitate import get_entity
from socreIF import score_if_model
from vectorContaminatVerifcare import is_contaminated_entity_vector
from antrenareRF import train_rf_model
from socreRF import score_rf_model
from labelizare import derive_label
from antrenareLSTM import train_lstm_model, SEQ_LEN
from scoreLSTM import score_lstm_model

# =====================================================
# CONFIG EVALUARE
# =====================================================

EVAL_SIZE = 3000        # numărul de evenimente evaluate după warm-up
WARMUP_EVENTS = 1000    # evenimente consumate pentru warm-up modele

WINDOW_1M = 60
WINDOW_5M = 300
BUFFER_SIZE = 400
BUFFER_SIZE_BEHAV = 400
STAT_CONTAMINATION = 0.08
BEHAV_CONTAMINATION = 0.12
SCORE_HISTORY = 500
RETRAIN_INTERVAL = 300
RETRAIN_WINDOW = 600
LOG_CATEGORIES = ["auth", "web", "network", "system", "alert"]
RF_BUFFER_SIZE = 500
LSTM_BUFFER_SIZE = 300

# =====================================================
# KAFKA
# =====================================================

consumer = KafkaConsumer(
    "logs_normalized",
    bootstrap_servers="localhost:29092",
    auto_offset_reset="earliest",
    group_id=None,
)

# =====================================================
# STATE — identic cu main.py
# =====================================================

event_times = defaultdict(deque)
template_counter = Counter()
entity_template_counter = defaultdict(Counter)

training_buffer_stat  = []
training_buffer_behav = []
stat_model = behavior_model = None
stat_scaler = behavior_scaler = None
stat_trained = behavior_trained = False
stat_score_history     = deque(maxlen=SCORE_HISTORY)
behavior_score_history = deque(maxlen=SCORE_HISTORY)
events_since_retrain_stat  = 0
events_since_retrain_behav = 0
retrain_buffer_stat  = deque(maxlen=RETRAIN_WINDOW)
retrain_buffer_behav = deque(maxlen=RETRAIN_WINDOW)

category_models: dict = {
    cat: {
        "model": None, "scaler": None, "buffer": [],
        "retrain_buf": deque(maxlen=RETRAIN_WINDOW),
        "trained": False,
        "score_history": deque(maxlen=SCORE_HISTORY),
        "events_since": 0,
    }
    for cat in LOG_CATEGORIES
}

rf_model = rf_scaler = None
rf_trained = False
rf_buffer_X = []
rf_buffer_y = []
rf_score_history = deque(maxlen=SCORE_HISTORY)

lstm_model = lstm_scaler = None
lstm_trained = False
lstm_score_history = deque(maxlen=SCORE_HISTORY)
entity_sequences: dict = defaultdict(lambda: deque(maxlen=SEQ_LEN))
lstm_buffer_X = []
lstm_buffer_y = []

# =====================================================
# COLECTARE REZULTATE
# =====================================================

results = []   # fiecare element: dict cu scorurile și labelul

total_events  = 0   # toate evenimentele procesate
warmup_done   = False
eval_count    = 0   # evenimente în faza de evaluare

print(f"🔄 Pornind evaluare — warm-up: {WARMUP_EVENTS} eventi, evaluare: {EVAL_SIZE} eventi")
print("─" * 60)

# =====================================================
# MAIN LOOP — identic cu main.py + colectare rezultate
# =====================================================

for msg in consumer:

    payload     = json.loads(msg.value.decode(errors="ignore"))
    features    = payload.get("features", {})
    template_id = features.get("template_id", "unknown")
    ts          = features.get("timestamp", 0.0)
    entity_id   = get_entity(payload)

    total_events += 1

    # ── Temporal features ──────────────────────────────
    dq = event_times[template_id]
    dq.append(ts)
    while dq and dq[0] < ts - WINDOW_5M:
        dq.popleft()

    count_1m      = sum(1 for t in dq if t >= ts - WINDOW_1M)
    count_5m      = len(dq)
    inter_arrival = dq[-1] - dq[-2] if len(dq) >= 2 else 0.0
    burst_score   = min(count_1m / 30.0, 1.0)

    # ── Template rarity + entity deviation ─────────────
    template_counter[template_id] += 1
    total_templates = sum(template_counter.values())
    frequency       = template_counter[template_id] / total_templates
    template_rarity = 1 - frequency

    entity_template_counter[entity_id][template_id] += 1
    entity_total    = sum(entity_template_counter[entity_id].values())
    entity_freq     = entity_template_counter[entity_id][template_id] / entity_total
    entity_deviation = 1 - entity_freq

    # ── Feature engineering ────────────────────────────
    sem_feats       = extract_semantic_features(payload, entity_id, ts)
    stat_vector     = build_stat_vector(sem_feats, ts, count_1m, count_5m,
                                        inter_arrival, burst_score)
    behavior_vector = build_behavior_vector(sem_feats, template_rarity,
                                            entity_deviation, burst_score)
    log_category    = classify_log_category(payload)
    skip_training   = is_obviously_malicious(sem_feats) or \
                      is_contaminated_entity_vector(sem_feats)

    combined_vector = np.concatenate([stat_vector, behavior_vector])
    entity_sequences[entity_id].append(combined_vector)

    # ── IF Statistic Global ────────────────────────────
    if not stat_trained:
        if not skip_training:
            training_buffer_stat.append(stat_vector)
        if len(training_buffer_stat) >= BUFFER_SIZE:
            stat_model, stat_scaler = train_if_model(
                training_buffer_stat, n_estimators=250,
                contamination=STAT_CONTAMINATION)
            stat_trained = True
            retrain_buffer_stat.extend(training_buffer_stat)
            print("✅ IF Statistic trained")
        continue
    else:
        if not skip_training:
            retrain_buffer_stat.append(stat_vector)
            events_since_retrain_stat += 1
        if events_since_retrain_stat >= RETRAIN_INTERVAL:
            stat_model, stat_scaler = train_if_model(
                list(retrain_buffer_stat), n_estimators=250,
                contamination=STAT_CONTAMINATION)
            events_since_retrain_stat = 0

    # ── IF Comportamental Global ───────────────────────
    if not behavior_trained:
        if not skip_training:
            training_buffer_behav.append(behavior_vector)
        if len(training_buffer_behav) >= BUFFER_SIZE_BEHAV:
            behavior_model, behavior_scaler = train_if_model(
                training_buffer_behav, n_estimators=200,
                contamination=BEHAV_CONTAMINATION)
            behavior_trained = True
            retrain_buffer_behav.extend(training_buffer_behav)
            print("✅ IF Comportamental trained")
        continue
    else:
        if not skip_training:
            retrain_buffer_behav.append(behavior_vector)
            events_since_retrain_behav += 1
        if events_since_retrain_behav >= RETRAIN_INTERVAL:
            behavior_model, behavior_scaler = train_if_model(
                list(retrain_buffer_behav), n_estimators=200,
                contamination=BEHAV_CONTAMINATION)
            events_since_retrain_behav = 0

    # ── IF per Categorie ───────────────────────────────
    cat_state = category_models[log_category]
    if not cat_state["trained"]:
        if not skip_training:
            cat_state["buffer"].append(stat_vector)
        if len(cat_state["buffer"]) >= 200:
            cat_state["model"], cat_state["scaler"] = train_if_model(
                cat_state["buffer"], n_estimators=150,
                contamination=STAT_CONTAMINATION)
            cat_state["trained"] = True
            cat_state["retrain_buf"].extend(cat_state["buffer"])
            print(f"✅ IF Category [{log_category}] trained")
    else:
        if not skip_training:
            cat_state["retrain_buf"].append(stat_vector)
            cat_state["events_since"] += 1
        if cat_state["events_since"] >= RETRAIN_INTERVAL:
            cat_state["model"], cat_state["scaler"] = train_if_model(
                list(cat_state["retrain_buf"]), n_estimators=150,
                contamination=STAT_CONTAMINATION)
            cat_state["events_since"] = 0

    # ── Rule Engine ────────────────────────────────────
    rule_result = apply_rule_engine(sem_feats, payload)

    # ── IF Scoring ─────────────────────────────────────
    stat_scaled    = stat_scaler.transform([stat_vector])
    raw_stat       = -stat_model.score_samples(stat_scaled)[0]
    stat_score_history.append(raw_stat)
    stat_score     = normalize_dynamic(raw_stat, stat_score_history)

    behav_scaled   = behavior_scaler.transform([behavior_vector])
    raw_behav      = -behavior_model.score_samples(behav_scaled)[0]
    behavior_score_history.append(raw_behav)
    behavior_score = normalize_dynamic(raw_behav, behavior_score_history)

    cat_score = None
    if cat_state["trained"]:
        cat_score = score_if_model(cat_state["model"], cat_state["scaler"],
                                   stat_vector, cat_state["score_history"])

    if cat_score is not None:
        if_combined = (0.25*stat_score + 0.20*behavior_score +
                       0.10*cat_score + 0.15*template_rarity + 0.10*burst_score)
    else:
        if_combined = (0.30*stat_score + 0.25*behavior_score +
                       0.20*template_rarity + 0.15*burst_score)

    # ── RF ─────────────────────────────────────────────
    label = derive_label(rule_result, if_combined)

    if rule_result.shortcut:
        label = 1

    if label is not None and not skip_training:
        rf_buffer_X.append(combined_vector)
        rf_buffer_y.append(label)

    if not rf_trained and len(rf_buffer_y) >= RF_BUFFER_SIZE:
        rf_model, rf_scaler = train_rf_model(rf_buffer_X, rf_buffer_y)
        rf_trained = True
        print("✅ Random Forest trained")

    score_rf = None
    if rf_trained:
        score_rf = score_rf_model(rf_model, rf_scaler, combined_vector,
                                  rf_score_history)

    # ── LSTM ───────────────────────────────────────────
    if label is not None and not skip_training:
        current_seq = list(entity_sequences[entity_id])
        if len(current_seq) >= SEQ_LEN // 2:
            lstm_buffer_X.append(current_seq)
            lstm_buffer_y.append(label)

    if not lstm_trained and len(lstm_buffer_y) >= LSTM_BUFFER_SIZE:
        lstm_model, lstm_scaler = train_lstm_model(
            lstm_buffer_X, lstm_buffer_y)
        lstm_trained = True
        print("✅ LSTM trained")

    score_lstm = None
    if lstm_trained:
        score_lstm = score_lstm_model(
            lstm_model, lstm_scaler,
            list(entity_sequences[entity_id]),
            lstm_score_history)

    # ── Ensemble final ─────────────────────────────────
    if score_rf is not None and score_lstm is not None:
        if cat_score is not None:
            if_combined = (0.18*stat_score + 0.13*behavior_score +
                           0.07*cat_score + 0.18*score_rf +
                           0.15*score_lstm + 0.10*template_rarity +
                           0.07*burst_score)
        else:
            if_combined = (0.20*stat_score + 0.15*behavior_score +
                           0.18*score_rf + 0.15*score_lstm +
                           0.12*template_rarity + 0.08*burst_score)
    elif score_rf is not None:
        if cat_score is not None:
            if_combined = (0.20*stat_score + 0.15*behavior_score +
                           0.08*cat_score + 0.20*score_rf +
                           0.12*template_rarity + 0.08*burst_score)
        else:
            if_combined = (0.22*stat_score + 0.18*behavior_score +
                           0.20*score_rf + 0.15*template_rarity +
                           0.10*burst_score)

    if rule_result.triggered or rule_result.shortcut:
        rf_boost   = score_rf   if (score_rf   is not None and score_rf   > 0.85) else 0.0
        lstm_boost = score_lstm if (score_lstm is not None and score_lstm > 0.85) else 0.0
        final_risk = max(rule_result.score, if_combined, rf_boost, lstm_boost)
    else:
        final_risk = if_combined

    final_risk = min(final_risk, 1.0)

    # ── Warm-up check ──────────────────────────────────
    # Nu colectăm rezultate până când toate modelele sunt antrenate
    all_trained = (stat_trained and behavior_trained and
                   rf_trained and lstm_trained)

    if not all_trained or total_events < WARMUP_EVENTS:
        if total_events % 200 == 0:
            print(f"   warm-up: {total_events} eventi procesate "
                  f"(RF={'✅' if rf_trained else '⏳'}, "
                  f"LSTM={'✅' if lstm_trained else '⏳'})")
        continue

    if not warmup_done:
        warmup_done = True
        print(f"\n✅ Warm-up complet la {total_events} evenimente")
        print(f"🎯 Începe colectarea pentru evaluare ({EVAL_SIZE} evenimente)...\n")

    # ── Derivare label ground truth ────────────────────
    # Ground truth = ce decide Rule Engine cu certitudine
    # shortcut (≥0.9) = malițios sigur → label 1
    # score=0 și IF mic → benigni sigur → label 0
    # restul → excludem din calculul metricilor
    if rule_result.shortcut:
        gt_label = 1
    elif not rule_result.triggered and if_combined <= 0.25:
        gt_label = 0
    elif rule_result.score <= 0.4 and if_combined <= 0.3:
        gt_label = 0
    elif rule_result.score >= 0.7 and if_combined >= 0.5:
        gt_label = 1
    else:
        gt_label = None   # zonă gri — excludem din metrici

    # ── Colectare rezultat ─────────────────────────────
    results.append({
        "gt_label":     gt_label,
        "final_risk":   final_risk,
        "if_score":     if_combined,
        "stat_score":   stat_score,
        "rf_score":     score_rf,
        "lstm_score":   score_lstm,
        "rule_score":   rule_result.score,
        "rule_shortcut": rule_result.shortcut,
        "log_category": log_category,
    })

    eval_count += 1
    if eval_count % 500 == 0:
        print(f"   evaluare: {eval_count}/{EVAL_SIZE} evenimente colectate...")

    if eval_count >= EVAL_SIZE:
        break

# =====================================================
# CALCULUL METRICILOR
# =====================================================

print("\n" + "="*60)
print("📊 CALCUL METRICI")
print("="*60)

# Filtrăm doar evenimentele cu label cert (nu zona gri)
labeled = [r for r in results if r["gt_label"] is not None]
print(f"\nTotal colectate:  {len(results)}")
print(f"Cu label cert:    {len(labeled)}")
print(f"Zonă gri (excluși): {len(results) - len(labeled)}")

if len(labeled) < 100:
    print("\n⚠️  Prea puține exemple cu label cert pentru metrici fiabile.")
    exit()

gt   = np.array([r["gt_label"] for r in labeled])
n_pos = gt.sum()
n_neg = len(gt) - n_pos
print(f"Malițioase (1):   {int(n_pos)}")
print(f"Benigne (0):      {int(n_neg)}")


def compute_metrics(scores, gt, threshold=0.5, name=""):
    """Calculează TP, FP, TN, FN și metricile derivate."""
    pred = (np.array(scores) >= threshold).astype(int)

    TP = int(((pred == 1) & (gt == 1)).sum())
    FP = int(((pred == 1) & (gt == 0)).sum())
    TN = int(((pred == 0) & (gt == 0)).sum())
    FN = int(((pred == 0) & (gt == 1)).sum())

    precision = TP / (TP + FP) if (TP + FP) > 0 else 0.0
    recall    = TP / (TP + FN) if (TP + FN) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0.0)
    fpr       = FP / (FP + TN) if (FP + TN) > 0 else 0.0
    accuracy  = (TP + TN) / len(gt) if len(gt) > 0 else 0.0

    return {
        "name": name,
        "TP": TP, "FP": FP, "TN": TN, "FN": FN,
        "precision": precision,
        "recall":    recall,
        "f1":        f1,
        "fpr":       fpr,
        "accuracy":  accuracy,
    }


# Scoruri per model — normalizare la [0,1] cu threshold 0.5
if_scores   = [r["if_score"]   for r in labeled]
rf_scores   = [r["rf_score"]   if r["rf_score"]   is not None else 0.5 for r in labeled]
lstm_scores = [r["lstm_score"] if r["lstm_score"] is not None else 0.5 for r in labeled]
rule_scores = [min(r["rule_score"], 1.0) for r in labeled]
final_scores = [r["final_risk"] for r in labeled]

# Threshold pentru IF: 0.4 (pragul MEDIUM)
# Threshold pentru RF/LSTM/Ensemble: 0.5
metrics = [
    compute_metrics(rule_scores,  gt, threshold=0.5,  name="Rule Engine"),
    compute_metrics(if_scores,    gt, threshold=0.4,  name="Isolation Forest"),
    compute_metrics(rf_scores,    gt, threshold=0.5,  name="Random Forest"),
    compute_metrics(lstm_scores,  gt, threshold=0.5,  name="LSTM"),
    compute_metrics(final_scores, gt, threshold=0.65, name="Ensemble Final"),
]

# =====================================================
# RAPORT FINAL
# =====================================================

print("\n")
print("╔" + "═"*62 + "╗")
print("║" + "       RAPORT EVALUARE SISTEM DE DETECȚIE ANOMALII       ".center(62) + "║")
print("╠" + "═"*62 + "╣")
print(f"║  Evenimente evaluate: {len(labeled):<38}║")
print(f"║  Malițioase (GT=1):   {int(n_pos):<38}║")
print(f"║  Benigne (GT=0):      {int(n_neg):<38}║")
print("╠" + "═"*62 + "╣")
print("║  {:<20} {:>9} {:>9} {:>9} {:>9} ║".format(
    "MODEL", "PRECISION", "RECALL", "F1", "FPR"))
print("╠" + "═"*62 + "╣")

for m in metrics:
    print("║  {:<20} {:>9.3f} {:>9.3f} {:>9.3f} {:>9.3f} ║".format(
        m["name"],
        m["precision"],
        m["recall"],
        m["f1"],
        m["fpr"]
    ))

print("╠" + "═"*62 + "╣")

# Cel mai bun model după F1
best = max(metrics, key=lambda x: x["f1"])
print(f"║  Cel mai bun F1: {best['name']} ({best['f1']:.3f}){'':>20}║")

# Ensemble vs IF (îmbunătățire)
if_m  = next(m for m in metrics if "Isolation" in m["name"])
ens_m = next(m for m in metrics if "Ensemble"  in m["name"])
delta_f1 = ens_m["f1"] - if_m["f1"]
print(f"║  Ensemble vs IF: Δ F1 = {delta_f1:+.3f}{'':>32}║")

print("╠" + "═"*62 + "╣")

# Statistici suplimentare
shortcut_count = sum(1 for r in results if r["rule_shortcut"])
shortcut_rate  = shortcut_count / len(results) * 100 if results else 0

high_count   = sum(1 for r in results if r["final_risk"] > 0.65)
medium_count = sum(1 for r in results if 0.4 < r["final_risk"] <= 0.65)
low_count    = sum(1 for r in results if r["final_risk"] <= 0.4)

print(f"║  Shortcut Rate (Rule Engine):  {shortcut_rate:>5.1f}%{'':>22}║")
print(f"║  Distribuție: HIGH={high_count} MEDIUM={medium_count} LOW={low_count}{'':>14}║")

# Agreement: câte HIGH au IF + RF + LSTM toate > 0.5
agreement = sum(
    1 for r in results
    if (r["final_risk"] > 0.65 and
        r["if_score"] > 0.4 and
        r["rf_score"] is not None and r["rf_score"] > 0.5 and
        r["lstm_score"] is not None and r["lstm_score"] > 0.5)
)
total_high = sum(1 for r in results if r["final_risk"] > 0.65)
agreement_rate = agreement / total_high * 100 if total_high > 0 else 0
print(f"║  Model Agreement pe HIGH:      {agreement_rate:>5.1f}%{'':>22}║")

print("╠" + "═"*62 + "╣")

# Matrice de confuzie pentru Ensemble
ens = next(m for m in metrics if "Ensemble" in m["name"])
print(f"║  Matrice confuzie Ensemble Final:{'':>27}║")
print(f"║    TP={ens['TP']:>5}  FP={ens['FP']:>5}  TN={ens['TN']:>5}  FN={ens['FN']:>5}{'':>13}║")
print("╚" + "═"*62 + "╝")

print("\n✅ Evaluare completă.\n")