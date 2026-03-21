from kafka import KafkaConsumer
import json
import numpy as np
from collections import defaultdict, deque, Counter
import warnings
warnings.filterwarnings("ignore", category=UserWarning)
import os
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
os.environ["ABSL_FLAGS_ENABLE_NOABORT"] = "1"

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

# =====================================================
# LOC 1 — Importuri Etapa 5: LSTM
# =====================================================
from antrenareLSTM import train_lstm_model, SEQ_LEN
from scoreLSTM import score_lstm_model

# =====================================================
# CONFIG
# =====================================================

WINDOW_1M = 60
WINDOW_5M = 300

BUFFER_SIZE = 400
BUFFER_SIZE_BEHAV = 400

STAT_CONTAMINATION = 0.08
BEHAV_CONTAMINATION = 0.12

SCORE_HISTORY = 500

RETRAIN_INTERVAL = 300
RETRAIN_WINDOW   = 600

LOG_CATEGORIES = ["auth", "web", "network", "system", "alert"]

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
# STATE — IF
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
        "model":         None,
        "scaler":        None,
        "buffer":        [],
        "retrain_buf":   deque(maxlen=RETRAIN_WINDOW),
        "trained":       False,
        "score_history": deque(maxlen=SCORE_HISTORY),
        "events_since":  0,
    }
    for cat in LOG_CATEGORIES
}

# =====================================================
# STATE — RF
# =====================================================

rf_model         = None
rf_scaler        = None
rf_trained       = False
rf_buffer_X      = []
rf_buffer_y      = []
rf_score_history = deque(maxlen=SCORE_HISTORY)
RF_BUFFER_SIZE   = 500

# =====================================================
# LOC 2 — STATE Etapa 5: LSTM
# =====================================================

lstm_model         = None
lstm_scaler        = None
lstm_trained       = False
lstm_score_history = deque(maxlen=SCORE_HISTORY)
LSTM_BUFFER_SIZE   = 300   # minim secvențe complete pentru antrenare

# Coada glisantă per entitate — ultimele SEQ_LEN vectori combinați
entity_sequences: dict = defaultdict(lambda: deque(maxlen=SEQ_LEN))

# Buffer de antrenare LSTM
lstm_buffer_X = []   # list of arrays shape (SEQ_LEN, 22)
lstm_buffer_y = []   # list of 0/1

# =====================================================
# MAIN LOOP
# =====================================================

for msg in consumer:

    payload     = json.loads(msg.value.decode(errors="ignore"))
    features    = payload.get("features", {})
    template_id = features.get("template_id", "unknown")
    ts          = features.get("timestamp", 0.0)
    entity_id   = get_entity(payload)

    # =====================================================
    # TEMPORAL FEATURES
    # =====================================================

    dq = event_times[template_id]
    dq.append(ts)
    while dq and dq[0] < ts - WINDOW_5M:
        dq.popleft()

    count_1m      = sum(1 for t in dq if t >= ts - WINDOW_1M)
    count_5m      = len(dq)
    inter_arrival = dq[-1] - dq[-2] if len(dq) >= 2 else 0.0
    burst_score   = min(count_1m / 30.0, 1.0)

    # =====================================================
    # TEMPLATE RARITY + ENTITY DEVIATION
    # =====================================================

    template_counter[template_id] += 1
    total_templates  = sum(template_counter.values())
    frequency        = template_counter[template_id] / total_templates
    template_rarity  = 1 - frequency

    entity_template_counter[entity_id][template_id] += 1
    entity_total     = sum(entity_template_counter[entity_id].values())
    entity_freq      = entity_template_counter[entity_id][template_id] / entity_total
    entity_deviation = 1 - entity_freq

    # =====================================================
    # ETAPA 1 — FEATURE ENGINEERING
    # =====================================================

    sem_feats       = extract_semantic_features(payload, entity_id, ts)
    stat_vector     = build_stat_vector(sem_feats, ts, count_1m, count_5m,
                                        inter_arrival, burst_score)
    behavior_vector = build_behavior_vector(sem_feats, template_rarity,
                                            entity_deviation, burst_score)

    log_category  = classify_log_category(payload)
    skip_training = is_obviously_malicious(sem_feats) or \
                    is_contaminated_entity_vector(sem_feats)

    # =====================================================
    # LOC 3 — Actualizare secvență per entitate
    # ÎNAINTE de orice model — secvența trebuie să fie
    # disponibilă și în shortcut path
    # =====================================================
    combined_vector = np.concatenate([stat_vector, behavior_vector])
    entity_sequences[entity_id].append(combined_vector)

    # =====================================================
    # ETAPA 3A — IF Statistic Global
    # =====================================================

    if not stat_trained:
        if not skip_training:
            training_buffer_stat.append(stat_vector)
        if len(training_buffer_stat) >= BUFFER_SIZE:
            stat_model, stat_scaler = train_if_model(
                training_buffer_stat, n_estimators=250,
                contamination=STAT_CONTAMINATION
            )
            stat_trained = True
            retrain_buffer_stat.extend(training_buffer_stat)
            print("✅ Statistical Model (global) trained — antrenare inițială")
        continue
    else:
        if not skip_training:
            retrain_buffer_stat.append(stat_vector)
            events_since_retrain_stat += 1
        if events_since_retrain_stat >= RETRAIN_INTERVAL:
            new_model, new_scaler = train_if_model(
                list(retrain_buffer_stat), n_estimators=250,
                contamination=STAT_CONTAMINATION
            )
            stat_model, stat_scaler = new_model, new_scaler
            events_since_retrain_stat = 0
            print(f"🔄 Statistical Model (global) retrained "
                  f"(buffer={len(retrain_buffer_stat)} vectori)")

    # =====================================================
    # ETAPA 3B — IF Comportamental Global
    # =====================================================

    if not behavior_trained:
        if not skip_training:
            training_buffer_behav.append(behavior_vector)
        if len(training_buffer_behav) >= BUFFER_SIZE_BEHAV:
            behavior_model, behavior_scaler = train_if_model(
                training_buffer_behav, n_estimators=200,
                contamination=BEHAV_CONTAMINATION
            )
            behavior_trained = True
            retrain_buffer_behav.extend(training_buffer_behav)
            print("✅ Behavioral Model (global) trained — antrenare inițială")
        continue
    else:
        if not skip_training:
            retrain_buffer_behav.append(behavior_vector)
            events_since_retrain_behav += 1
        if events_since_retrain_behav >= RETRAIN_INTERVAL:
            new_model, new_scaler = train_if_model(
                list(retrain_buffer_behav), n_estimators=200,
                contamination=BEHAV_CONTAMINATION
            )
            behavior_model, behavior_scaler = new_model, new_scaler
            events_since_retrain_behav = 0
            print(f"🔄 Behavioral Model (global) retrained "
                  f"(buffer={len(retrain_buffer_behav)} vectori)")

    # =====================================================
    # ETAPA 3C — IF per Categorie
    # =====================================================

    cat_state = category_models[log_category]

    if not cat_state["trained"]:
        if not skip_training:
            cat_state["buffer"].append(stat_vector)
        if len(cat_state["buffer"]) >= 200:
            cat_state["model"], cat_state["scaler"] = train_if_model(
                cat_state["buffer"], n_estimators=150,
                contamination=STAT_CONTAMINATION
            )
            cat_state["trained"] = True
            cat_state["retrain_buf"].extend(cat_state["buffer"])
            print(f"✅ Category Model [{log_category}] trained "
                  f"({len(cat_state['buffer'])} vectori)")
    else:
        if not skip_training:
            cat_state["retrain_buf"].append(stat_vector)
            cat_state["events_since"] += 1
        if cat_state["events_since"] >= RETRAIN_INTERVAL:
            cat_state["model"], cat_state["scaler"] = train_if_model(
                list(cat_state["retrain_buf"]), n_estimators=150,
                contamination=STAT_CONTAMINATION
            )
            cat_state["events_since"] = 0
            print(f"🔄 Category Model [{log_category}] retrained "
                  f"(buffer={len(cat_state['retrain_buf'])} vectori)")

    # =====================================================
    # ETAPA 2 — RULE ENGINE
    # =====================================================

    rule_result = apply_rule_engine(sem_feats, payload)

    if rule_result.shortcut:
        final_risk = rule_result.score
        level      = "HIGH"
        stat_score = behavior_score = None

        # RF — label 1 sigur pe shortcut
        rf_buffer_X.append(combined_vector)
        rf_buffer_y.append(1)
        if not rf_trained and len(rf_buffer_y) >= RF_BUFFER_SIZE:
            rf_model, rf_scaler = train_rf_model(rf_buffer_X, rf_buffer_y)
            rf_trained = True

        # LOC 4A — LSTM: label 1 sigur pe shortcut
        current_seq = list(entity_sequences[entity_id])
        if len(current_seq) >= SEQ_LEN // 2:
            lstm_buffer_X.append(current_seq)
            lstm_buffer_y.append(1)
            if not lstm_trained and len(lstm_buffer_y) >= LSTM_BUFFER_SIZE:
                lstm_model, lstm_scaler = train_lstm_model(
                    lstm_buffer_X, lstm_buffer_y
                )
                lstm_trained = True

        print(f"""
{'='*50}
🔴 RULE ENGINE SHORTCUT — HIGH CONFIDENCE ALERT
{'='*50}
Template:  {template_id}
Entity:    {entity_id}
Log:       {payload.get('log', '')[:100]}

Reguli active ({len(rule_result.rules)}):
{chr(10).join('  ✦ ' + r for r in rule_result.rules)}

Rule Score:  {rule_result.score}
Final Risk:  {round(final_risk, 3)}
Risk Level:  {level}
[ML skipped — rule shortcut activat]
{'='*50}
""")
        continue

    # =====================================================
    # SCORING IF
    # =====================================================

    stat_scaled        = stat_scaler.transform([stat_vector])
    raw_stat_score     = -stat_model.score_samples(stat_scaled)[0]
    stat_score_history.append(raw_stat_score)
    stat_score         = normalize_dynamic(raw_stat_score, stat_score_history)

    behavior_scaled    = behavior_scaler.transform([behavior_vector])
    raw_behavior_score = -behavior_model.score_samples(behavior_scaled)[0]
    behavior_score_history.append(raw_behavior_score)
    behavior_score     = normalize_dynamic(raw_behavior_score, behavior_score_history)

    cat_score = None
    if cat_state["trained"]:
        cat_score = score_if_model(
            cat_state["model"], cat_state["scaler"],
            stat_vector, cat_state["score_history"]
        )

    # =====================================================
    # ENSEMBLE IF
    # =====================================================

    if cat_score is not None:
        if_combined = (
            0.25 * stat_score +
            0.20 * behavior_score +
            0.10 * cat_score +
            0.15 * template_rarity +
            0.10 * burst_score
        )
    else:
        if_combined = (
            0.30 * stat_score +
            0.25 * behavior_score +
            0.20 * template_rarity +
            0.15 * burst_score
        )

    # =====================================================
    # ETAPA 4 — Random Forest
    # =====================================================

    label = derive_label(rule_result, if_combined)

    if label is not None and not skip_training:
        rf_buffer_X.append(combined_vector)
        rf_buffer_y.append(label)

    if not rf_trained and len(rf_buffer_y) >= RF_BUFFER_SIZE:
        rf_model, rf_scaler = train_rf_model(rf_buffer_X, rf_buffer_y)
        rf_trained = True

    score_rf = None
    if rf_trained:
        score_rf = score_rf_model(rf_model, rf_scaler, combined_vector,
                                  rf_score_history)

    # =====================================================
    # LOC 4B — ETAPA 5: LSTM
    # =====================================================

    # Adaugă secvența în buffer LSTM cu același label ca RF
    if label is not None and not skip_training:
        current_seq = list(entity_sequences[entity_id])
        if len(current_seq) >= SEQ_LEN // 2:
            lstm_buffer_X.append(current_seq)
            lstm_buffer_y.append(label)

    # Antrenare LSTM când avem suficiente secvențe
    if not lstm_trained and len(lstm_buffer_y) >= LSTM_BUFFER_SIZE:
        lstm_model, lstm_scaler = train_lstm_model(
            lstm_buffer_X, lstm_buffer_y
        )
        lstm_trained = True

    # Scorare LSTM dacă modelul e antrenat
    score_lstm = None
    if lstm_trained:
        score_lstm = score_lstm_model(
            lstm_model, lstm_scaler,
            list(entity_sequences[entity_id]),
            lstm_score_history
        )

    # =====================================================
    # ENSEMBLE FINAL (IF + RF + LSTM + Rule Engine)
    # =====================================================

    if score_rf is not None and score_lstm is not None:
        # Ensemble complet
        if cat_score is not None:
            if_combined = (
                0.18 * stat_score +
                0.13 * behavior_score +
                0.07 * cat_score +
                0.18 * score_rf +
                0.15 * score_lstm +
                0.10 * template_rarity +
                0.07 * burst_score
            )
        else:
            if_combined = (
                0.20 * stat_score +
                0.15 * behavior_score +
                0.18 * score_rf +
                0.15 * score_lstm +
                0.12 * template_rarity +
                0.08 * burst_score
            )
    elif score_rf is not None:
        # RF disponibil, LSTM în bootstrap
        if cat_score is not None:
            if_combined = (
                0.20 * stat_score +
                0.15 * behavior_score +
                0.08 * cat_score +
                0.20 * score_rf +
                0.12 * template_rarity +
                0.08 * burst_score
            )
        else:
            if_combined = (
                0.22 * stat_score +
                0.18 * behavior_score +
                0.20 * score_rf +
                0.15 * template_rarity +
                0.10 * burst_score
            )
    # else: if_combined rămâne din IF — faza bootstrap

    if rule_result.triggered:
        rf_boost   = score_rf   if (score_rf   is not None and score_rf   > 0.85) else 0.0
        lstm_boost = score_lstm if (score_lstm is not None and score_lstm > 0.85) else 0.0
        final_risk = max(rule_result.score, if_combined, rf_boost, lstm_boost)
    else:
        final_risk = if_combined

    final_risk = min(final_risk, 1.0)

    if final_risk > 0.65:
        level = "HIGH"
    elif final_risk > 0.4:
        level = "MEDIUM"
    else:
        level = "LOW"

    # =====================================================
    # OUTPUT
    # =====================================================

    icon           = "🔴" if level == "HIGH" else ("🟡" if level == "MEDIUM" else "🟢")
    cat_score_str  = f"{round(cat_score, 3)}"   if cat_score  is not None else "N/A (training)"
    rf_score_str   = f"{round(score_rf, 3)}"    if score_rf   is not None else "N/A (training)"
    lstm_score_str = f"{round(score_lstm, 3)}"  if score_lstm is not None else "N/A (training)"

    print(f"""
{icon} EVENT ANALYSIS  [{level}]
Template:  {template_id}
Entity:    {entity_id}
Log:       {payload.get('log', '')[:100]}

--- Etapa 2: Rule Engine ---
Triggered:   {rule_result.triggered}
Rule Score:  {rule_result.score}
Rules:       {rule_result.rules if rule_result.rules else ['none']}

--- Etapa 3: Isolation Forest ---
Stat Score:      {round(stat_score, 3) if stat_score is not None else 'N/A'}
Behavior Score:  {round(behavior_score, 3) if behavior_score is not None else 'N/A'}
Category [{log_category}]: {cat_score_str}
Rarity:          {round(template_rarity, 3)}
Burst:           {round(burst_score, 3)}

--- Etapa 4: Random Forest ---
RF Score:        {rf_score_str}
RF Buffer:       {len(rf_buffer_y)}/{RF_BUFFER_SIZE} exemple labelate
Labels (1/0):    {sum(rf_buffer_y)}/{len(rf_buffer_y) - sum(rf_buffer_y)}

--- Etapa 5: LSTM ---
LSTM Score:      {lstm_score_str}
LSTM Buffer:     {len(lstm_buffer_y)}/{LSTM_BUFFER_SIZE} secvențe labelate
Seq Length:      {len(entity_sequences[entity_id])}/{SEQ_LEN} evenimente

--- Context Entitate (5 min) ---
failed_auth:  {sem_feats['entity_failed_auth_5m']}
sudo_count:   {sem_feats['entity_sudo_count_5m']}
uploads:      {sem_feats['entity_upload_count_5m']}
lsass:        {sem_feats['entity_lsass_count_5m']}

Final Risk:  {round(final_risk, 3)}
Risk Level:  {level}
{'[shortcut: N/A — reguli sub threshold]' if rule_result.triggered else '[rule engine: no match — IF + RF + LSTM decide]'}
{'─'*50}
""")