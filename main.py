import os
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
os.environ["ABSL_FLAGS_ENABLE_NOABORT"] = "1"

import warnings
warnings.filterwarnings("ignore")

from kafka import KafkaConsumer, KafkaProducer
import json
import uuid
import numpy as np
from collections import defaultdict, deque, Counter
from datetime import datetime

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

WINDOW_1M = 60
WINDOW_5M = 300

BUFFER_SIZE       = 400
BUFFER_SIZE_BEHAV = 400

STAT_CONTAMINATION  = 0.08
BEHAV_CONTAMINATION = 0.12

SCORE_HISTORY = 500

RETRAIN_INTERVAL = 300
RETRAIN_WINDOW   = 600

LOG_CATEGORIES = ["auth", "web", "network", "system", "alert"]

# ── Praguri per categorie ─────────────────────────────────────────
# Justificare:
#   auth HIGH=0.55:    template-uri frecvente → behavior_score mic sistematic
#                      pragul mic compensează această limitare IF
#   network HIGH=0.75: IP-uri unice → rarity=1.0 artificial
#                      pragul mare filtrează zgomotul
#   web HIGH=0.65:     request-uri frecvente dar context malițios trebuie prins
#   system HIGH=0.62:  system events variate
#   alert HIGH=0.55:   alertele externe au deja filtrat zgomotul

THRESHOLDS = {
    "auth":    {"HIGH": 0.65, "MEDIUM": 0.45},
    "network": {"HIGH": 0.80, "MEDIUM": 0.55},
    "web":     {"HIGH": 0.70, "MEDIUM": 0.48},
    "system":  {"HIGH": 0.70, "MEDIUM": 0.48},
    "alert":   {"HIGH": 0.65, "MEDIUM": 0.42},
}

# ── Boost threshold ───────────────────────────────────────────────
# 0.92 în loc de 0.85 — mai restrictiv pentru a evita false pozitive
# RF=0.87 → no boost (ambiguu)
# RF=0.97 → boost activat (certitudine ridicată)
BOOST_THRESHOLD = 0.92

# ── LSTM confidence minimum pentru boost ─────────────────────────
# Sub 0.5 = mai puțin de 5 evenimente → predicție instabilă
LSTM_CONFIDENCE_MIN = 0.5

# ── Fereastră temporală adaptivă per categorie ───────────────────
ENTITY_WINDOWS = {
    "auth":    300,
    "network": 60,
    "system":  600,
    "web":     120,
    "alert":   300,
}

consumer = KafkaConsumer(
    "logs_normalized",
    bootstrap_servers="kafka:9092",
    auto_offset_reset="earliest",
    group_id=None,
)

producer = KafkaProducer(
    bootstrap_servers="kafka:9092",
    value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8")
)

event_times                    = defaultdict(deque)
template_counter               = Counter()
template_counter_per_category  = defaultdict(Counter)
entity_template_counter        = defaultdict(Counter)

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

rf_model         = None
rf_scaler        = None
rf_trained       = False
rf_buffer_X      = []
rf_buffer_y      = []
rf_score_history = deque(maxlen=SCORE_HISTORY)
RF_BUFFER_SIZE   = 500

lstm_model         = None
lstm_scaler        = None
lstm_trained       = False
lstm_score_history = deque(maxlen=SCORE_HISTORY)
LSTM_BUFFER_SIZE   = 300

entity_sequences: dict = defaultdict(lambda: deque(maxlen=SEQ_LEN))

lstm_buffer_X = []
lstm_buffer_y = []


def build_alert_payload(
    template_id, entity_id, ts, log_category,
    raw_log, rule_result,
    stat_score, behavior_score, cat_score,
    template_rarity, burst_score,
    score_rf, score_lstm,
    sem_feats, final_risk, level
) -> dict:

    if cat_score is not None and stat_score is not None:
        if_score = round(
            0.25 * stat_score +
            0.20 * (behavior_score or 0) +
            0.10 * cat_score, 4
        )
    elif stat_score is not None:
        if_score = round(
            0.30 * stat_score +
            0.25 * (behavior_score or 0), 4
        )
    else:
        if_score = None

    return {
        "event_id":      str(uuid.uuid4()),
        "timestamp":     round(float(ts), 3),
        "timestamp_iso": datetime.fromtimestamp(ts).isoformat(),

        "raw_log":      raw_log[:500],
        "template_id":  template_id,
        "log_category": log_category,
        "entity_id":    entity_id,

        "rule_triggered": bool(rule_result.triggered),
        "rule_score":     round(float(rule_result.score), 4),
        "rule_shortcut":  bool(rule_result.shortcut),
        "rules_fired":    list(rule_result.rules),

        "stat_score":     round(float(stat_score), 4)     if stat_score     is not None else None,
        "behavior_score": round(float(behavior_score), 4) if behavior_score is not None else None,
        "cat_score":      round(float(cat_score), 4)      if cat_score      is not None else None,
        "rarity":         round(float(template_rarity), 4),
        "burst":          round(float(burst_score), 4),

        "rf_score":   round(float(score_rf), 4)   if score_rf   is not None else None,
        "lstm_score": round(float(score_lstm), 4) if score_lstm is not None else None,

        "entity_context": {
            "failed_auth": int(sem_feats["entity_failed_auth_5m"]),
            "sudo_count":  int(sem_feats["entity_sudo_count_5m"]),
            "uploads":     int(sem_feats["entity_upload_count_5m"]),
            "lsass":       int(sem_feats["entity_lsass_count_5m"]),
        },

        "score_breakdown": {
            "rule_engine":      round(float(rule_result.score), 4),
            "isolation_forest": if_score,
            "random_forest":    round(float(score_rf), 4)   if score_rf   is not None else None,
            "lstm":             round(float(score_lstm), 4) if score_lstm is not None else None,
        },

        "final_risk": round(float(final_risk), 4),
        "risk_level": level,
    }


for msg in consumer:

    payload     = json.loads(msg.value.decode(errors="ignore"))
    features    = payload.get("features", {})
    template_id = features.get("template_id", "unknown")
    ts          = features.get("timestamp", 0.0)
    entity_id   = get_entity(payload)

    # ── Clasificare categorie ─────────────────────────────────────────
    log_category = classify_log_category(payload)

    # ── Fereastră temporală adaptivă ──────────────────────────────────
    window = ENTITY_WINDOWS.get(log_category, WINDOW_5M)

    dq = event_times[template_id]
    dq.append(ts)
    while dq and dq[0] < ts - window:
        dq.popleft()

    count_1m      = sum(1 for t in dq if t >= ts - WINDOW_1M)
    count_5m      = len(dq)
    inter_arrival = dq[-1] - dq[-2] if len(dq) >= 2 else 0.0
    burst_score   = min(count_1m / 30.0, 1.0)

    # ── Template rarity per categorie ────────────────────────────────
    template_counter[template_id] += 1

    template_counter_per_category[log_category][template_id] += 1
    cat_total       = sum(template_counter_per_category[log_category].values())
    cat_frequency   = template_counter_per_category[log_category][template_id] / cat_total
    template_rarity = 1 - cat_frequency

    entity_template_counter[entity_id][template_id] += 1
    entity_total     = sum(entity_template_counter[entity_id].values())
    entity_freq      = entity_template_counter[entity_id][template_id] / entity_total
    entity_deviation = 1 - entity_freq

    sem_feats       = extract_semantic_features(payload, entity_id, ts)
    stat_vector     = build_stat_vector(sem_feats, ts, count_1m, count_5m,
                                        inter_arrival, burst_score)
    behavior_vector = build_behavior_vector(sem_feats, template_rarity,
                                            entity_deviation, burst_score)

    skip_training = (is_obviously_malicious(sem_feats) or
                     is_contaminated_entity_vector(sem_feats))

    combined_vector = np.concatenate([stat_vector, behavior_vector])
    entity_sequences[entity_id].append(combined_vector)

    # ── Antrenare IF Statistic ────────────────────────────────────────
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
            print("✅ Statistical Model trained")
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
            print(f"🔄 Statistical Model retrained ({len(retrain_buffer_stat)} vectori)")

    # ── Antrenare IF Comportamental ───────────────────────────────────
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
            print("✅ Behavioral Model trained")
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
            print(f"🔄 Behavioral Model retrained ({len(retrain_buffer_behav)} vectori)")

    # ── Antrenare IF per Categorie ────────────────────────────────────
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
            print(f"✅ Category Model [{log_category}] trained")
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
            print(f"🔄 Category Model [{log_category}] retrained")

    # ── Rule Engine ───────────────────────────────────────────────────
    rule_result = apply_rule_engine(sem_feats, payload)

    # ── Shortcut — HIGH imediat fără ML ──────────────────────────────
    if rule_result.shortcut:
        final_risk = rule_result.score
        level      = "HIGH"
        stat_score = behavior_score = None

        # Folosit pentru antrenarea RF și LSTM — cert malițios
        rf_buffer_X.append(combined_vector)
        rf_buffer_y.append(1)
        if not rf_trained and len(rf_buffer_y) >= RF_BUFFER_SIZE:
            rf_model, rf_scaler = train_rf_model(rf_buffer_X, rf_buffer_y)
            rf_trained = True

        current_seq = list(entity_sequences[entity_id])
        if len(current_seq) >= SEQ_LEN // 2:
            lstm_buffer_X.append(current_seq)
            lstm_buffer_y.append(1)
            if not lstm_trained and len(lstm_buffer_y) >= LSTM_BUFFER_SIZE:
                lstm_model, lstm_scaler = train_lstm_model(
                    lstm_buffer_X, lstm_buffer_y
                )
                lstm_trained = True

        alert = build_alert_payload(
            template_id, entity_id, ts, log_category,
            payload.get("log", ""), rule_result,
            None, None, None,
            template_rarity, burst_score,
            None, None,
            sem_feats, final_risk, level
        )
        producer.send("ml_alerts", value=alert)

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

    # ── Scorare IF ────────────────────────────────────────────────────
    stat_scaled        = stat_scaler.transform([stat_vector])
    raw_stat_score     = -stat_model.score_samples(stat_scaled)[0]
    stat_score_history.append(raw_stat_score)
    stat_score         = normalize_dynamic(raw_stat_score, stat_score_history)

    behavior_scaled    = behavior_scaler.transform([behavior_vector])
    raw_behavior_score = -behavior_model.score_samples(behavior_scaled)[0]
    behavior_score_history.append(raw_behavior_score)
    behavior_score     = normalize_dynamic(raw_behavior_score,
                                           behavior_score_history)

    cat_score = None
    if cat_state["trained"]:
        cat_score = score_if_model(
            cat_state["model"], cat_state["scaler"],
            stat_vector, cat_state["score_history"]
        )

    # ── if_combined inițial (fără RF și LSTM) ────────────────────────
    if cat_score is not None:
        if_combined = (
            0.25 * stat_score     +
            0.20 * behavior_score +
            0.10 * cat_score      +
            0.15 * template_rarity +
            0.10 * burst_score
        )
    else:
        if_combined = (
            0.30 * stat_score      +
            0.25 * behavior_score  +
            0.20 * template_rarity +
            0.15 * burst_score
        )

    # ── derive_label + antrenare RF ───────────────────────────────────
    label = derive_label(rule_result, if_combined, sem_feats)

    if label is not None and not skip_training:
        rf_buffer_X.append(combined_vector)
        rf_buffer_y.append(label)

    if not rf_trained and len(rf_buffer_y) >= RF_BUFFER_SIZE:
        rf_model, rf_scaler = train_rf_model(rf_buffer_X, rf_buffer_y)
        rf_trained = True

    score_rf = None
    if rf_trained:
        score_rf = score_rf_model(rf_model, rf_scaler,
                                  combined_vector, rf_score_history)

    # ── Antrenare LSTM ────────────────────────────────────────────────
    if label is not None and not skip_training:
        current_seq = list(entity_sequences[entity_id])
        if len(current_seq) >= SEQ_LEN // 2:
            lstm_buffer_X.append(current_seq)
            lstm_buffer_y.append(label)

    if not lstm_trained and len(lstm_buffer_y) >= LSTM_BUFFER_SIZE:
        lstm_model, lstm_scaler = train_lstm_model(
            lstm_buffer_X, lstm_buffer_y
        )
        lstm_trained = True

    score_lstm = None
    if lstm_trained:
        score_lstm = score_lstm_model(
            lstm_model, lstm_scaler,
            list(entity_sequences[entity_id]),
            lstm_score_history
        )

    # ── LSTM confidence scalar ────────────────────────────────────────
    # Proporțional cu lungimea secvenței entității
    # Secvențe scurte → predicții instabile → penalizare
    current_seq_len = len(entity_sequences[entity_id])
    lstm_confidence = min(current_seq_len / SEQ_LEN, 1.0)
    # Seq=1/10  → confidence=0.10 → lstm_weight=0.015
    # Seq=5/10  → confidence=0.50 → lstm_weight=0.075
    # Seq=10/10 → confidence=1.00 → lstm_weight=0.150
    lstm_weight = 0.15 * lstm_confidence

    # ── Recalcul if_combined cu RF + LSTM ────────────────────────────
    if score_rf is not None and score_lstm is not None:
        if cat_score is not None:
            if_combined = (
                0.18 * stat_score      +
                0.13 * behavior_score  +
                0.07 * cat_score       +
                0.18 * score_rf        +
                lstm_weight * score_lstm +
                0.10 * template_rarity +
                0.07 * burst_score
            )
        else:
            if_combined = (
                0.20 * stat_score      +
                0.15 * behavior_score  +
                0.18 * score_rf        +
                lstm_weight * score_lstm +
                0.12 * template_rarity +
                0.08 * burst_score
            )

    elif score_rf is not None:
        if cat_score is not None:
            if_combined = (
                0.20 * stat_score      +
                0.15 * behavior_score  +
                0.08 * cat_score       +
                0.20 * score_rf        +
                0.12 * template_rarity +
                0.08 * burst_score
            )
        else:
            if_combined = (
                0.22 * stat_score      +
                0.18 * behavior_score  +
                0.20 * score_rf        +
                0.15 * template_rarity +
                0.10 * burst_score
            )

    # ── Decizia finală ────────────────────────────────────────────────
    if rule_result.triggered:
        # Boost RF — doar dacă certitudine ridicată (> BOOST_THRESHOLD)
        rf_boost = (score_rf
                    if score_rf is not None and
                       score_rf > BOOST_THRESHOLD
                    else 0.0)

        # Boost LSTM — doar dacă certitudine ridicată ȘI secvență suficientă
        lstm_boost = (score_lstm
                      if score_lstm is not None and
                         score_lstm > BOOST_THRESHOLD and
                         lstm_confidence >= LSTM_CONFIDENCE_MIN
                      else 0.0)

        final_risk = max(rule_result.score, if_combined,
                         rf_boost, lstm_boost)
    else:
        # Fără Rule Engine — if_combined decide singur
        # lstm_weight deja aplicat în recalculul if_combined
        final_risk = if_combined

    final_risk = min(final_risk, 1.0)

    # ── Clasificare cu praguri per categorie ─────────────────────────
    thresholds = THRESHOLDS.get(log_category,
                                {"HIGH": 0.65, "MEDIUM": 0.40})

    if final_risk > thresholds["HIGH"]:
        level = "HIGH"
    elif final_risk > thresholds["MEDIUM"]:
        level = "MEDIUM"
    else:
        level = "LOW"

    # ── Construire și publicare alertă ───────────────────────────────
    alert = build_alert_payload(
        template_id, entity_id, ts, log_category,
        payload.get("log", ""), rule_result,
        stat_score, behavior_score, cat_score,
        template_rarity, burst_score,
        score_rf, score_lstm,
        sem_feats, final_risk, level
    )
    producer.send("ml_alerts", value=alert)

    icon           = "🔴" if level == "HIGH" else ("🟡" if level == "MEDIUM" else "🟢")
    cat_score_str  = f"{round(cat_score, 3)}"  if cat_score  is not None else "N/A (training)"
    rf_score_str   = f"{round(score_rf, 3)}"   if score_rf   is not None else "N/A (training)"
    lstm_score_str = f"{round(score_lstm, 3)}" if score_lstm is not None else "N/A (training)"

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
LSTM Confidence: {round(lstm_confidence, 2)} (weight={round(lstm_weight, 3)})

--- Context Entitate (5 min) ---
failed_auth:  {sem_feats['entity_failed_auth_5m']}
sudo_count:   {sem_feats['entity_sudo_count_5m']}
uploads:      {sem_feats['entity_upload_count_5m']}
lsass:        {sem_feats['entity_lsass_count_5m']}

Final Risk:  {round(final_risk, 3)}
Risk Level:  {level}
Thresholds:  HIGH>{thresholds['HIGH']} MEDIUM>{thresholds['MEDIUM']}
{'[shortcut: N/A — reguli sub threshold]' if rule_result.triggered else '[rule engine: no match — IF + RF + LSTM decide]'}
{'─'*50}
""")