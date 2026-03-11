from kafka import KafkaConsumer
import json
from datetime import datetime
import numpy as np
from collections import defaultdict, deque, Counter
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import re

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

# =====================================================
# SEMANTIC FEATURE DEFINITIONS
# =====================================================

# Procese LOLBins - Living off the Land Binaries
# Binare Windows legitime folosite frecvent in atacuri
LOLBINS = {
    "certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "wmic.exe", "cscript.exe", "wscript.exe", "msiexec.exe",
    "installutil.exe", "regasm.exe", "regsvcs.exe", "msconfig.exe",
    "mimikatz.exe", "procdump.exe"
}

# Procese suspecte dar nu neaparat LOLBins
SUSPICIOUS_PROCESSES = {
    "cmd.exe", "powershell.exe", "nc.exe", "netcat.exe",
    "psexec.exe", "at.exe", "schtasks.exe"
}

# Extensii de fisiere malitioase uploadate
MALICIOUS_EXTENSIONS = {
    ".jsp", ".jspx", ".aspx", ".asp", ".php", ".php5", ".php7",
    ".phtml", ".ps1", ".psm1", ".vbs", ".js", ".hta",
    ".bat", ".cmd", ".scr", ".pif"
}

# Executabile malitioase cunoscute ca nume de fisier
MALICIOUS_FILENAMES = {
    "webshell", "backdoor", "shell", "cmd", "dropper",
    "payload", "exploit", "rev", "bind", "nc", "netcat",
    "mimikatz", "meterpreter", "empire", "cobalt"
}

# Cai sensibile din sistem - scriere in ele e critica
SENSITIVE_WRITE_PATHS = {
    "/root/.ssh/authorized_keys",
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/etc/cron", "/etc/crontab", "/var/spool/cron",
    "/tmp/", "/dev/shm/", "/var/tmp/",
    ".bashrc", ".bash_profile", ".profile",
    "/etc/ld.so.preload", "/etc/rc.local"
}

# Cai sensibile - citire (mai putin critic dar relevant)
SENSITIVE_READ_PATHS = {
    "/etc/shadow", "/etc/passwd", "/root/.ssh/",
    "/home/", "id_rsa", "id_ecdsa", ".aws/credentials",
    ".env", "config.yaml", "config.json", "secrets"
}

# Domenii DNS suspecte - TLD-uri comune pentru C2
SUSPICIOUS_TLDS = {".xyz", ".ru", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw"}
KNOWN_C2_KEYWORDS = {"c2-server", "malware", "callback", "botnet", "payload", "dropper"}

# Porturi neconventionale suspecte pentru anumite protocoale
SUSPICIOUS_PORT_COMBOS = {
    (22, "UDP"),    # SSH pe UDP e neobisnuit
    (3389, "UDP"),  # RDP pe UDP e neobisnuit
    (4444, "TCP"),  # Port clasic Metasploit
    (1337, "TCP"),  # Port clasic hacker
    (31337, "TCP"), # Port clasic backdoor
}

# Range-uri IP interne
INTERNAL_RANGES = [
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2[0-9]|3[0-1])\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^127\."),
    re.compile(r"^::1$"),
    re.compile(r"^fc"), re.compile(r"^fd"),
]

# =====================================================
# KAFKA
# =====================================================

consumer = KafkaConsumer(
    "logs_normalized",
    bootstrap_servers="localhost:29092",
    auto_offset_reset="earliest",
    group_id=None,
)

print("🚀 Advanced Multi-Model Anomaly Detection - Etapa 1 Completa\n")

# =====================================================
# STATE
# =====================================================

event_times = defaultdict(deque)
template_counter = Counter()
entity_template_counter = defaultdict(Counter)

# State aditional pentru features semantice agregate
entity_failed_auth   = defaultdict(lambda: deque(maxlen=50))
entity_sudo_events   = defaultdict(lambda: deque(maxlen=50))
entity_uploads       = defaultdict(lambda: deque(maxlen=50))
entity_lsass_events  = defaultdict(lambda: deque(maxlen=50))
entity_process_set   = defaultdict(set)

training_buffer_stat = []
training_buffer_behav = []

stat_model = behavior_model = None
stat_scaler = behavior_scaler = None
stat_trained = behavior_trained = False

stat_score_history    = deque(maxlen=SCORE_HISTORY)
behavior_score_history = deque(maxlen=SCORE_HISTORY)


# =====================================================
# HELPER: IP classification
# =====================================================

def is_external_ip(ip: str) -> bool:
    if not ip or ip == "unknown":
        return False
    return not any(p.match(ip) for p in INTERNAL_RANGES)


# =====================================================
# ETAPA 1 - FEATURE ENGINEERING COMPLET
# =====================================================

def extract_semantic_features(payload: dict, entity_id: str, ts: float) -> dict:
    """
    Extrage TOATE features semantice din campurile normalizate Matryoshka.
    Returneaza un dict cu valori binare (0/1) sau continue [0,1].
    """

    raw_log   = payload.get("log", "").lower()
    template  = payload.get("template", "").lower()
    semantic  = payload.get("semantic", "")
    cluster   = payload.get("cluster", "").lower()
    features  = payload.get("features", {})

    # Campuri semantice extrase de Matryoshka
    sem_user    = features.get("user", "") or ""
    sem_ip      = features.get("src_ip", "") or ""
    sem_process = features.get("process", "") or ""
    sem_path    = features.get("path", "") or ""
    sem_url     = features.get("url", "") or ""
    sem_cmd     = features.get("cmd", "") or ""

    # Fallback - extrage din raw log daca campurile semantice sunt goale
    if not sem_process and "process=" in raw_log:
        m = re.search(r"process=(\S+)", raw_log)
        if m:
            sem_process = m.group(1).lower()

    if not sem_cmd and 'cmd="' in raw_log:
        m = re.search(r'cmd="([^"]+)"', raw_log)
        if m:
            sem_cmd = m.group(1).lower()

    if not sem_path and 'name="' in raw_log:
        m = re.search(r'name="([^"]+)"', raw_log)
        if m:
            sem_path = m.group(1).lower()

    if not sem_url and "file=" in raw_log:
        m = re.search(r"file=(\S+)", raw_log)
        if m:
            sem_url = m.group(1).lower()

    # --------------------------------------------------
    # BLOC 1: Features legate de procese / executie
    # --------------------------------------------------

    # Reverse shell - comenzi clasice de stabilire shell invers
    has_reverse_shell = int(
        "nc -e" in raw_log or
        "nc.exe -e" in raw_log or
        "/bin/sh" in raw_log or
        "/bin/bash" in raw_log and ("nc " in raw_log or "ncat" in raw_log) or
        "import socket,os,pty" in raw_log or
        "import socket" in raw_log and "os.dup2" in raw_log or
        "bash -i >& /dev/tcp" in raw_log or
        "0>&1" in raw_log or
        "/dev/tcp/" in raw_log
    )

    # Download + executie - pattern clasic dropper
    has_download_exec = int(
        ("wget" in raw_log or "curl" in raw_log) and
        ("chmod" in raw_log or "bash" in raw_log or
         "sh" in raw_log or "|" in raw_log or
         ">/tmp" in raw_log or "/dev/shm" in raw_log)
    )

    # LOLBin - binare Windows legitime folosite ca arme
    proc_lower = sem_process.lower()
    is_lolbin = int(
        any(lb in proc_lower for lb in LOLBINS) or
        any(lb in raw_log for lb in LOLBINS)
    )

    # PowerShell suspect - fara profil = evitare logging
    is_suspicious_powershell = int(
        "powershell" in raw_log and (
            "-noprofile" in raw_log or
            "-encodedcommand" in raw_log or
            "-enc " in raw_log or
            "-w hidden" in raw_log or
            "-windowstyle hidden" in raw_log or
            "-exec bypass" in raw_log or
            "-executionpolicy bypass" in raw_log or
            "iex(" in raw_log or
            "invoke-expression" in raw_log or
            "downloadstring" in raw_log
        )
    )

    # lsass.exe accesat - dump de credentiale
    is_lsass_access = int(
        "lsass.exe" in raw_log and
        ("credential" in raw_log or "t1003" in raw_log or
         "access" in raw_log or "dump" in raw_log)
    )

    # Lateral movement - detectat explicit de EDR
    is_lateral_movement = int(
        "lateral movement" in raw_log or
        "psexec" in raw_log.lower() or
        "pass-the-hash" in raw_log.lower() or
        "wmi lateral" in raw_log.lower() or
        "remote service creation" in raw_log.lower()
    )

    # Sudo escape - obtinere shell root prin sudo
    sudo_shell_escape = int(
        ("sudo" in raw_log or "tty=pts" in raw_log) and
        ("command=/bin/bash" in raw_log or
         "command=/bin/sh" in raw_log or
         "command=/usr/bin/python" in raw_log or
         "command=/usr/bin/perl" in raw_log or
         "command=/usr/bin/ruby" in raw_log or
         "command=/usr/bin/vim" in raw_log or
         "command=/usr/bin/less" in raw_log or
         "command=/usr/bin/awk" in raw_log)
    )

    # Sudo recon - verificare privilegii
    sudo_recon = int(
        "tty=pts" in raw_log and
        ("command=/usr/bin/id" in raw_log or
         "command=/usr/bin/whoami" in raw_log or
         "command=/usr/bin/w" in raw_log)
    )

    # --------------------------------------------------
    # BLOC 2: Features legate de fisiere
    # --------------------------------------------------

    # Upload fisier malitios - extensie periculoasa
    file_lower = sem_url.lower() if sem_url else ""
    if not file_lower:
        m = re.search(r"file=(\S+)", raw_log)
        if m:
            file_lower = m.group(1).lower()

    is_malicious_file_upload = int(
        ("file uploaded" in raw_log or "upload" in raw_log) and
        (
            any(file_lower.endswith(ext) for ext in MALICIOUS_EXTENSIONS) or
            any(kw in file_lower for kw in MALICIOUS_FILENAMES)
        )
    )

    # Scriere in cai sensibile
    perm_is_write = "perm=\"w\"" in raw_log or "perm=w" in raw_log
    path_lower = sem_path.lower() if sem_path else raw_log

    writes_sensitive_path = int(
        perm_is_write and
        any(sp in path_lower for sp in SENSITIVE_WRITE_PATHS)
    )

    # Citire fisiere sensibile (credentiale, chei SSH etc.)
    perm_is_read = "perm=\"r\"" in raw_log or "perm=r" in raw_log
    reads_sensitive_path = int(
        perm_is_read and
        any(sp in path_lower for sp in SENSITIVE_READ_PATHS)
    )

    # --------------------------------------------------
    # BLOC 3: Features legate de web / HTTP
    # --------------------------------------------------

    has_sqli = int(
        "or 1=1" in raw_log or
        "' or '" in raw_log or
        "union select" in raw_log or
        "' --" in raw_log or
        "1=1--" in raw_log or
        "admin'--" in raw_log or
        "sleep(" in raw_log or
        "benchmark(" in raw_log or
        "waitfor delay" in raw_log
    )

    has_xss = int(
        "<script>" in raw_log or
        "javascript:" in raw_log or
        "onerror=" in raw_log or
        "onload=" in raw_log or
        "alert(" in raw_log and "<" in raw_log
    )

    has_path_traversal = int(
        "../" in raw_log or
        "..%2f" in raw_log or
        "%2e%2e" in raw_log or
        "/etc/passwd" in raw_log or
        "/etc/shadow" in raw_log
    )

    has_debug_endpoint = int(
        "debug=true" in raw_log or
        "/debug" in raw_log or
        "/actuator" in raw_log or
        "/swagger" in raw_log or
        "/.env" in raw_log or
        "/phpinfo" in raw_log
    )

    # Metoda HTTP distructiva pe resursa sensibila
    has_destructive_http = int(
        ('"delete ' in raw_log or '"put ' in raw_log) and
        any(r in raw_log for r in ["/settings", "/admin", "/config", "/users", "/login"])
    )

    # --------------------------------------------------
    # BLOC 4: Features legate de retea / autentificare
    # --------------------------------------------------

    is_external_src = int(is_external_ip(sem_ip))

    is_failed_auth = int(
        "failed password" in raw_log or
        "failed publickey" in raw_log or
        "failed keyboard" in raw_log or
        "authentication failure" in raw_log or
        "invalid user" in raw_log or
        "permission denied" in raw_log
    )

    # Login acceptat de pe IP extern - potential suspicious
    is_external_login_accepted = int(
        ("accepted password" in raw_log or
         "accepted publickey" in raw_log or
         "accepted keyboard" in raw_log) and
        is_external_ip(sem_ip)
    )

    # Firewall ACCEPT pe port neconventional
    is_suspicious_firewall_accept = 0
    if "firewall accept" in raw_log:
        for port, proto in SUSPICIOUS_PORT_COMBOS:
            if str(port) in raw_log and proto.lower() in raw_log:
                is_suspicious_firewall_accept = 1
                break

    # --------------------------------------------------
    # BLOC 5: Features legate de DNS / domenii
    # --------------------------------------------------

    is_suspicious_dns = 0
    if "query:" in raw_log or "in a" in raw_log:
        m = re.search(r"query:\s+(\S+)\s+in", raw_log)
        if m:
            domain = m.group(1).lower()
            if (any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS) or
                    any(kw in domain for kw in KNOWN_C2_KEYWORDS)):
                is_suspicious_dns = 1

    # --------------------------------------------------
    # BLOC 6: Features legate de alerte de securitate
    # --------------------------------------------------

    is_av_alert = int(
        "av alert" in raw_log or
        "malware detected" in raw_log or
        "ransomware" in raw_log or
        "trojan detected" in raw_log or
        "spyware detected" in raw_log or
        "worm detected" in raw_log
    )

    is_ids_alert = int(
        "et scan" in raw_log or
        "et trojan" in raw_log or
        "et data" in raw_log or
        "et policy" in raw_log or
        "suricata" in raw_log and ("[1:" in raw_log)
    )

    is_dlp_alert = int("dlp alert" in raw_log)

    is_siem_alert = int("siem alert" in raw_log)

    is_edr_alert = int(
        "edr alert" in raw_log or
        "edr warn" in raw_log
    )

    # --------------------------------------------------
    # BLOC 7: Features agregate per entitate (window 5min)
    # --------------------------------------------------

    # Actualizeaza cozile per entitate
    if is_failed_auth:
        entity_failed_auth[entity_id].append(ts)
    if sudo_shell_escape or sudo_recon:
        entity_sudo_events[entity_id].append(ts)
    if is_malicious_file_upload:
        entity_uploads[entity_id].append(ts)
    if is_lsass_access:
        entity_lsass_events[entity_id].append(ts)
    if sem_process:
        entity_process_set[entity_id].add(sem_process)

    # Curata evenimentele vechi din ferestra 5 min
    cutoff = ts - WINDOW_5M
    for dq_ref in [
        entity_failed_auth[entity_id],
        entity_sudo_events[entity_id],
        entity_uploads[entity_id],
        entity_lsass_events[entity_id],
    ]:
        while dq_ref and dq_ref[0] < cutoff:
            dq_ref.popleft()

    entity_failed_auth_5m   = len(entity_failed_auth[entity_id])
    entity_sudo_count_5m    = len(entity_sudo_events[entity_id])
    entity_upload_count_5m  = len(entity_uploads[entity_id])
    entity_lsass_count_5m   = len(entity_lsass_events[entity_id])
    entity_unique_processes = len(entity_process_set[entity_id])

    # --------------------------------------------------
    # BLOC 8: Features din Matryoshka (deja calculate)
    # --------------------------------------------------

    mat_rate_1m         = features.get("rate_1m", 0)
    mat_rate_5m         = features.get("rate_5m", 0)
    mat_is_rare         = features.get("is_rare", 0)
    mat_is_new          = int(payload.get("is_new", False))
    mat_burst           = features.get("burst", 0)
    mat_transition_prob = features.get("transition_prob", 0) or 0
    mat_user_rate_5m    = features.get("user_rate_5m", 0) or 0
    mat_ip_diversity    = features.get("user_ip_diversity", 0) or 0
    mat_new_process     = features.get("new_process_for_user", 0) or 0
    mat_first_seen_user = features.get("is_first_seen_for_user", 0) or 0
    mat_first_seen_ip   = features.get("is_first_seen_for_ip", 0) or 0

    # --------------------------------------------------
    # COMPILEAZA FEATURE DICT FINAL
    # --------------------------------------------------

    return {
        # === Bloc 1: Procese / Executie ===
        "has_reverse_shell":         has_reverse_shell,
        "has_download_exec":         has_download_exec,
        "is_lolbin":                 is_lolbin,
        "is_suspicious_powershell":  is_suspicious_powershell,
        "is_lsass_access":           is_lsass_access,
        "is_lateral_movement":       is_lateral_movement,
        "sudo_shell_escape":         sudo_shell_escape,
        "sudo_recon":                sudo_recon,

        # === Bloc 2: Fisiere ===
        "is_malicious_file_upload":  is_malicious_file_upload,
        "writes_sensitive_path":     writes_sensitive_path,
        "reads_sensitive_path":      reads_sensitive_path,

        # === Bloc 3: Web / HTTP ===
        "has_sqli":                  has_sqli,
        "has_xss":                   has_xss,
        "has_path_traversal":        has_path_traversal,
        "has_debug_endpoint":        has_debug_endpoint,
        "has_destructive_http":      has_destructive_http,

        # === Bloc 4: Retea / Auth ===
        "is_external_src":           is_external_src,
        "is_failed_auth":            is_failed_auth,
        "is_external_login_accepted": is_external_login_accepted,
        "is_suspicious_firewall":    is_suspicious_firewall_accept,

        # === Bloc 5: DNS ===
        "is_suspicious_dns":         is_suspicious_dns,

        # === Bloc 6: Alerte securitate ===
        "is_av_alert":               is_av_alert,
        "is_ids_alert":              is_ids_alert,
        "is_dlp_alert":              is_dlp_alert,
        "is_siem_alert":             is_siem_alert,
        "is_edr_alert":              is_edr_alert,

        # === Bloc 7: Agregate per entitate (5 min) ===
        "entity_failed_auth_5m":     entity_failed_auth_5m,
        "entity_sudo_count_5m":      entity_sudo_count_5m,
        "entity_upload_count_5m":    entity_upload_count_5m,
        "entity_lsass_count_5m":     entity_lsass_count_5m,
        "entity_unique_processes":   entity_unique_processes,

        # === Bloc 8: Matryoshka features (imbogatite) ===
        "mat_rate_1m":               mat_rate_1m,
        "mat_rate_5m":               mat_rate_5m,
        "mat_is_rare":               mat_is_rare,
        "mat_is_new":                mat_is_new,
        "mat_burst":                 mat_burst,
        "mat_transition_prob":       mat_transition_prob,
        "mat_user_rate_5m":          mat_user_rate_5m,
        "mat_ip_diversity":          mat_ip_diversity,
        "mat_new_process":           mat_new_process,
        "mat_first_seen_user":       mat_first_seen_user,
        "mat_first_seen_ip":         mat_first_seen_ip,
    }


def build_stat_vector(feats: dict, ts: float,
                      count_1m: int, count_5m: int,
                      inter_arrival: float, burst_score: float) -> np.ndarray:
    """
    Vector pentru Isolation Forest statistic.
    Features temporale + rate + context.
    """
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


def build_behavior_vector(feats: dict, template_rarity: float,
                          entity_deviation: float, burst_score: float) -> np.ndarray:
    """
    Vector pentru Isolation Forest comportamental.
    Features de raritate + deviatie + context entitate.
    """
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


# =====================================================
# ETAPA 2 — RULE ENGINE
# =====================================================
#
# Primul layer de detecție — fără ML, bazat pe reguli semantice.
# Returnează un RuleResult cu:
#   score     : float [0.0 – 1.0]  — certitudinea că evenimentul e malițios
#   triggered : bool               — True dacă cel puțin o regulă s-a activat
#   rules     : list[str]          — lista regulilor care au tras
#   shortcut  : bool               — True dacă scorul e ≥ RULE_SHORTCUT_THRESHOLD
#                                    (evenimentul NU mai trece prin modele ML)
#
# Logica de scor:
#   1.0  = certitudine absolută    → alertă HIGH imediată, fără ML
#   0.9  = certitudine foarte mare → aproape sigur malițios
#   0.7  = suspiciune ridicată     → semnal puternic, dar ML confirmă
#   0.5  = suspiciune moderată     → mai mult context necesar
#   0.3  = suspiciune slabă        → contribuie la scor ensemble
#
# SHORTCUT: dacă score_rule >= 0.9, evenimentul e emis direct ca alertă HIGH
# fără a mai consuma resurse pe IF / RF / LSTM.
# =====================================================

from dataclasses import dataclass, field
from typing import List

RULE_SHORTCUT_THRESHOLD = 0.9   # peste acest prag nu mai rulam ML

@dataclass
class RuleResult:
    score:     float       = 0.0
    triggered: bool        = False
    rules:     List[str]   = field(default_factory=list)
    shortcut:  bool        = False   # True = skip ML, emite direct


def apply_rule_engine(sem_feats: dict, payload: dict) -> RuleResult:
    """
    Aplică toate regulile semantice asupra unui eveniment normalizat.
    Returnează un RuleResult cu scorul agregat și lista regulilor active.

    Strategia de agregare:
    - Fiecare regulă contribuie cu propriul scor.
    - Scorul final = max(toate scorurile individuale) + bonus de coroborare.
    - Bonus: +0.05 pentru fiecare regulă activă suplimentară, cap la 1.0.
    - Logica max() garantează că o singură regulă de certitudine absolută
      produce scor 1.0 indiferent de restul.
    """

    scores = []   # scorurile regulilor active
    rules  = []   # numele regulilor active

    # --------------------------------------------------
    # GRUP A — Execuție de cod / shell
    # Certitudine foarte mare: aceste comenzi nu au uz legitim
    # în contextul unui sistem monitorizat de producție.
    # --------------------------------------------------

    # A1 — Reverse shell detectat
    # nc -e, bash /dev/tcp, python socket, etc.
    # Un proces normal NU creează un socket invers spre un IP extern.
    if sem_feats.get("has_reverse_shell"):
        scores.append(1.0)
        rules.append("A1:reverse_shell")

    # A2 — Download urmat imediat de execuție
    # wget/curl | bash sau chmod după download — pattern dropper clasic.
    if sem_feats.get("has_download_exec"):
        scores.append(0.9)
        rules.append("A2:download_exec")

    # A3 — LOLBin detectat
    # Binar Windows legitim folosit ca armă (certutil, mshta, rundll32...).
    # Singur: 0.7. Combinat cu IP extern: 0.85.
    if sem_feats.get("is_lolbin"):
        base = 0.85 if sem_feats.get("is_external_src") else 0.7
        scores.append(base)
        rules.append("A3:lolbin" + ("+ext_ip" if sem_feats.get("is_external_src") else ""))

    # A4 — PowerShell cu flags de evazie
    # -EncodedCommand, -Exec Bypass, IEX, DownloadString etc.
    # Singur: 0.7. Cu IP extern sau first_seen: 0.85.
    if sem_feats.get("is_suspicious_powershell"):
        boost = sem_feats.get("is_external_src") or sem_feats.get("mat_first_seen_user", 0)
        base = 0.85 if boost else 0.7
        scores.append(base)
        rules.append("A4:suspicious_powershell" + ("+boost" if boost else ""))

    # A5 — Sudo shell escape
    # COMMAND=/bin/bash sau /bin/sh prin sudo — obținere shell root direct.
    if sem_feats.get("sudo_shell_escape"):
        scores.append(0.9)
        rules.append("A5:sudo_shell_escape")

    # A6 — Sudo recon
    # sudo whoami / id — verificare privilegii, semn de explorare post-compromise.
    if sem_feats.get("sudo_recon"):
        scores.append(0.5)
        rules.append("A6:sudo_recon")

    # --------------------------------------------------
    # GRUP B — Credentiale și escaladare de privilegii
    # --------------------------------------------------

    # B1 — Acces lsass.exe
    # Dump credentiale din memorie (Mimikatz, procdump etc.) — T1003.
    # Singur: 1.0. Nu există scenariu benign în producție.
    if sem_feats.get("is_lsass_access"):
        scores.append(1.0)
        rules.append("B1:lsass_credential_dump")

    # B2 — Multiple accese lsass în 5 minute per entitate
    # 3+ dump-uri = campanie de credential harvesting activa.
    lsass_5m = sem_feats.get("entity_lsass_count_5m", 0)
    if lsass_5m >= 3:
        scores.append(1.0)
        rules.append(f"B2:lsass_campaign({lsass_5m}x/5min)")
    elif lsass_5m == 2:
        scores.append(0.8)
        rules.append(f"B2:lsass_repeated({lsass_5m}x/5min)")

    # B3 — Mișcare laterală detectată explicit de EDR
    # SMB/WMI/PsExec/RDP între hosturi — pivot între mașini.
    if sem_feats.get("is_lateral_movement"):
        scores.append(1.0)
        rules.append("B3:lateral_movement")

    # B4 — Multiple autentificări eșuate per entitate în 5 minute
    # ≥10 = brute force activ; 5-9 = suspiciune.
    failed_5m = sem_feats.get("entity_failed_auth_5m", 0)
    if failed_5m >= 10:
        scores.append(0.9)
        rules.append(f"B4:brute_force({failed_5m}x/5min)")
    elif failed_5m >= 5:
        scores.append(0.6)
        rules.append(f"B4:auth_failures({failed_5m}x/5min)")

    # B5 — Login acceptat de pe IP extern
    # Singur nu e critic, dar e semn de acces neașteptat.
    # Combinat cu alte reguli active: boost prin coroborare.
    if sem_feats.get("is_external_login_accepted"):
        scores.append(0.4)
        rules.append("B5:external_login_accepted")

    # --------------------------------------------------
    # GRUP C — Fișiere malițioase
    # --------------------------------------------------

    # C1 — Upload de fișier cu extensie sau nume malițios
    # webshell.jsp, backdoor.py, cmd.aspx etc.
    if sem_feats.get("is_malicious_file_upload"):
        scores.append(0.95)
        rules.append("C1:malicious_file_upload")

    # C2 — Scriere în cale sensibilă de sistem
    # /root/.ssh/authorized_keys, /etc/shadow, /etc/sudoers etc.
    # Persistență sau escaladare.
    if sem_feats.get("writes_sensitive_path"):
        scores.append(0.9)
        rules.append("C2:writes_sensitive_path")

    # C3 — Citire fișiere sensibile
    # /etc/shadow, id_rsa, .aws/credentials etc.
    # Mai puțin critic decât scrierea, dar semn de reconnaissance.
    if sem_feats.get("reads_sensitive_path"):
        scores.append(0.5)
        rules.append("C3:reads_sensitive_path")

    # C4 — Multiple upload-uri malițioase per entitate în 5 minute
    # 2+ webshell-uri = campanie de implantare activă.
    uploads_5m = sem_feats.get("entity_upload_count_5m", 0)
    if uploads_5m >= 2:
        scores.append(0.95)
        rules.append(f"C4:upload_campaign({uploads_5m}x/5min)")

    # --------------------------------------------------
    # GRUP D — Web attacks
    # --------------------------------------------------

    # D1 — SQL Injection detectat în URL/request
    if sem_feats.get("has_sqli"):
        scores.append(0.85)
        rules.append("D1:sql_injection")

    # D2 — Cross-Site Scripting
    if sem_feats.get("has_xss"):
        scores.append(0.8)
        rules.append("D2:xss")

    # D3 — Path traversal (../../etc/passwd)
    if sem_feats.get("has_path_traversal"):
        scores.append(0.8)
        rules.append("D3:path_traversal")

    # D4 — Endpoint de debug/admin accesat
    # /.env, /actuator, /debug etc. — reconnaissance aplicație.
    if sem_feats.get("has_debug_endpoint"):
        scores.append(0.5)
        rules.append("D4:debug_endpoint_access")

    # D5 — Metodă HTTP distructivă pe resursă sensibilă
    # DELETE /settings, PUT /admin etc.
    if sem_feats.get("has_destructive_http"):
        scores.append(0.7)
        rules.append("D5:destructive_http_method")

    # --------------------------------------------------
    # GRUP E — Rețea și DNS
    # --------------------------------------------------

    # E1 — Query DNS spre domeniu suspect
    # TLD-uri .xyz, .ru, .tk sau keyword-uri C2 în domeniu.
    if sem_feats.get("is_suspicious_dns"):
        scores.append(0.7)
        rules.append("E1:suspicious_dns_query")

    # E2 — Firewall ACCEPT pe port neconvențional (4444, 1337 etc.)
    if sem_feats.get("is_suspicious_firewall"):
        scores.append(0.6)
        rules.append("E2:suspicious_firewall_accept")

    # --------------------------------------------------
    # GRUP F — Alerte de la sisteme de securitate externe
    # Acestea vin cu propriul lor scor de la AV/EDR/IDS/DLP/SIEM.
    # Rule Engine-ul le ia ca semnal de confirmare — nu ca sursă primară.
    # --------------------------------------------------

    # F1 — Alertă AV: malware, ransomware, trojan, spyware, worm
    if sem_feats.get("is_av_alert"):
        scores.append(0.95)
        rules.append("F1:av_alert")

    # F2 — Alertă IDS/IPS: ET SCAN, ET TROJAN, ET DATA, ET POLICY
    if sem_feats.get("is_ids_alert"):
        scores.append(0.85)
        rules.append("F2:ids_alert")

    # F3 — Alertă DLP: exfiltrare de date blocată
    if sem_feats.get("is_dlp_alert"):
        scores.append(0.8)
        rules.append("F3:dlp_alert")

    # F4 — Alertă SIEM: regulă de corelație internă declanșată
    if sem_feats.get("is_siem_alert"):
        scores.append(0.85)
        rules.append("F4:siem_correlation_alert")

    # F5 — Alertă EDR: process injection, credential access, lateral movement
    if sem_feats.get("is_edr_alert"):
        scores.append(0.9)
        rules.append("F5:edr_alert")

    # --------------------------------------------------
    # GRUP G — Reguli compuse (coroborare între grupuri)
    # Combină semnale slabe care împreună devin puternice.
    # Acestea se calculează DUPĂ grupurile individuale.
    # --------------------------------------------------

    # G1 — IP extern + first_seen + proces nou pentru entitate
    # Un utilizator nevăzut anterior vine de pe un IP extern
    # și rulează un proces nou — pattern de intruziune.
    if (sem_feats.get("is_external_src") and
            sem_feats.get("mat_first_seen_user", 0) and
            sem_feats.get("mat_new_process", 0)):
        scores.append(0.75)
        rules.append("G1:new_user_ext_ip_new_process")

    # G2 — Sudo events + failed auth în aceeași fereastră 5min
    # Eșecuri de autentificare urmate de sudo = privilege escalation tentativă.
    if (sem_feats.get("entity_sudo_count_5m", 0) >= 1 and
            sem_feats.get("entity_failed_auth_5m", 0) >= 2):
        scores.append(0.7)
        rules.append("G2:failed_auth_then_sudo")

    # G3 — Upload malițios + scriere cale sensibilă de la aceeași entitate
    # Plantare webshell + modificare configurare = compromis complet.
    if (sem_feats.get("entity_upload_count_5m", 0) >= 1 and
            sem_feats.get("writes_sensitive_path")):
        scores.append(0.95)
        rules.append("G3:upload_plus_sensitive_write")

    # G4 — AV alert + IDS alert simultan
    # Două sisteme independente detectează același eveniment.
    if sem_feats.get("is_av_alert") and sem_feats.get("is_ids_alert"):
        scores.append(0.98)
        rules.append("G4:av_and_ids_correlation")

    # G5 — Lateral movement + lsass în aceeași fereastră 5min
    # Mișcare laterală + dump credentiale = APT activ.
    if (sem_feats.get("is_lateral_movement") and
            sem_feats.get("entity_lsass_count_5m", 0) >= 1):
        scores.append(1.0)
        rules.append("G5:lateral_plus_credential_dump")

    # --------------------------------------------------
    # AGREGARE FINALĂ
    # --------------------------------------------------

    if not scores:
        # Nicio regulă nu s-a activat
        return RuleResult(score=0.0, triggered=False, rules=[], shortcut=False)

    # Scorul de bază = scorul maxim dintre toate regulile active
    # Logica: o regulă de certitudine absolută (1.0) trebuie să producă
    # scor 1.0 indiferent de câte reguli slabe mai există.
    base_score = max(scores)

    # Bonus de coroborare — fiecare regulă activă suplimentară adaugă +0.05
    # Exemplu: 3 reguli active cu max=0.7 → 0.7 + 2*0.05 = 0.80
    # Justificare: mai multe semnale independente cresc certitudinea.
    n_extra = len(scores) - 1
    corroboration_bonus = n_extra * 0.05

    final_score = min(base_score + corroboration_bonus, 1.0)

    shortcut = final_score >= RULE_SHORTCUT_THRESHOLD

    return RuleResult(
        score=round(final_score, 4),
        triggered=True,
        rules=rules,
        shortcut=shortcut
    )


# =====================================================
# NORMALIZE DYNAMIC
# =====================================================

def normalize_dynamic(score, history):
    if len(history) < 50:
        return 0.0
    p5  = np.percentile(history, 5)
    p95 = np.percentile(history, 95)
    if p95 - p5 == 0:
        return 0.0
    return float(np.clip((score - p5) / (p95 - p5), 0, 1))


def get_entity(payload: dict) -> str:
    features = payload.get("features", {})
    user = features.get("user") or features.get("semantic", {}).get("user") if isinstance(features.get("semantic"), dict) else None
    ip   = features.get("src_ip") or features.get("semantic", {}).get("src_ip") if isinstance(features.get("semantic"), dict) else None

    raw = payload.get("log", "")
    if not user:
        m = re.search(r"\buser[=:](\S+)", raw)
        if m:
            user = m.group(1).strip('"\'')
    if not ip:
        m = re.search(r"from\s+(\d{1,3}(?:\.\d{1,3}){3})", raw)
        if m:
            ip = m.group(1)

    if user and user not in ("unknown", ""):
        return user
    if ip and ip not in ("unknown", ""):
        return ip
    return "generic_entity"


# =====================================================
# MAIN LOOP
# =====================================================

for msg in consumer:

    payload    = json.loads(msg.value.decode(errors="ignore"))
    features   = payload.get("features", {})
    template_id = features.get("template_id", "unknown")
    ts          = features.get("timestamp", 0.0)
    entity_id   = get_entity(payload)

    # =============================
    # TEMPORAL FEATURES
    # =============================

    dq = event_times[template_id]
    dq.append(ts)
    while dq and dq[0] < ts - WINDOW_5M:
        dq.popleft()

    count_1m      = sum(1 for t in dq if t >= ts - WINDOW_1M)
    count_5m      = len(dq)
    inter_arrival = dq[-1] - dq[-2] if len(dq) >= 2 else 0.0
    burst_score   = min(count_1m / 30.0, 1.0)

    # =============================
    # TEMPLATE RARITY
    # =============================

    template_counter[template_id] += 1
    total_templates   = sum(template_counter.values())
    frequency         = template_counter[template_id] / total_templates
    template_rarity   = 1 - frequency

    # =============================
    # ENTITY DEVIATION
    # =============================

    entity_template_counter[entity_id][template_id] += 1
    entity_total    = sum(entity_template_counter[entity_id].values())
    entity_freq     = entity_template_counter[entity_id][template_id] / entity_total
    entity_deviation = 1 - entity_freq

    # =============================
    # ETAPA 1 — FEATURE ENGINEERING
    # =============================

    sem_feats = extract_semantic_features(payload, entity_id, ts)

    # Vectori pentru modele
    stat_vector     = build_stat_vector(sem_feats, ts, count_1m, count_5m,
                                        inter_arrival, burst_score)
    behavior_vector = build_behavior_vector(sem_feats, template_rarity,
                                            entity_deviation, burst_score)

    # =============================
    # TRAINING (nemodificat logic)
    # =============================

    if not stat_trained:
        # Filtrare: nu antrenam pe evenimente evident malitioase
        is_obvious_malicious = (
            sem_feats["has_reverse_shell"] or
            sem_feats["is_lsass_access"] or
            sem_feats["is_malicious_file_upload"] or
            sem_feats["is_lateral_movement"]
        )
        if not is_obvious_malicious:
            training_buffer_stat.append(stat_vector)

        if len(training_buffer_stat) >= BUFFER_SIZE:
            stat_scaler = StandardScaler()
            scaled      = stat_scaler.fit_transform(training_buffer_stat)
            stat_model  = IsolationForest(
                n_estimators=250, contamination=STAT_CONTAMINATION, random_state=42
            )
            stat_model.fit(scaled)
            stat_trained = True
            print("✅ Statistical Model trained (buffer curat)")
        continue

    if not behavior_trained:
        training_buffer_behav.append(behavior_vector)

        if len(training_buffer_behav) >= BUFFER_SIZE_BEHAV:
            behavior_scaler = StandardScaler()
            scaled          = behavior_scaler.fit_transform(training_buffer_behav)
            behavior_model  = IsolationForest(
                n_estimators=200, contamination=BEHAV_CONTAMINATION, random_state=42
            )
            behavior_model.fit(scaled)
            behavior_trained = True
            print("✅ Behavioral Model trained")
        continue

    # =============================
    # ETAPA 2 — RULE ENGINE
    # =============================
    # Se aplică ÎNAINTEA oricărui model ML.
    # Dacă rule_result.shortcut == True, evenimentul e emis direct
    # ca alertă HIGH fără a mai consuma resurse pe IF/RF/LSTM.

    rule_result = apply_rule_engine(sem_feats, payload)

    if rule_result.shortcut:
        # ------------------------------------------------
        # SHORTCUT PATH: certitudine >= 0.9 din reguli
        # Nu mai rulăm IF sau alte modele ML.
        # Emitem alerta direct.
        # ------------------------------------------------
        final_risk = rule_result.score
        level      = "HIGH"
        stat_score = behavior_score = None   # nu au fost calculate

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
        # Continua la urmatorul eveniment fara sa ruleze IF
        continue

    # =============================
    # PREDICTION IF
    # =============================
    # Ajung aici doar evenimentele care NU au declansat shortcut.
    # Pot include: reguli slabe activate (score 0.3-0.89)
    # sau zero reguli activate (score 0.0).

    stat_scaled        = stat_scaler.transform([stat_vector])
    raw_stat_score     = -stat_model.score_samples(stat_scaled)[0]
    stat_score_history.append(raw_stat_score)
    stat_score         = normalize_dynamic(raw_stat_score, stat_score_history)

    behavior_scaled    = behavior_scaler.transform([behavior_vector])
    raw_behavior_score = -behavior_model.score_samples(behavior_scaled)[0]
    behavior_score_history.append(raw_behavior_score)
    behavior_score     = normalize_dynamic(raw_behavior_score, behavior_score_history)

    # =============================
    # ENSEMBLE SCORE (Etapa 2 + Etapa 3)
    # =============================
    # Formula curentă combină Rule Engine (layer 1) cu IF (layer 2).
    # Etapele 4 și 5 (RF și LSTM) vor fi adăugate ulterior la același ensemble.
    #
    # Logica max() + weighted sum:
    #   - dacă Rule Engine are scor ridicat (0.7-0.89), max() îl păstrează
    #   - IF contribuie cu 0.35*stat + 0.25*behavior
    #   - raritate și burst rămân ca semnale de context
    #
    # Coeficienții IF sunt reduși față de versiunea anterioară (0.45→0.30,
    # 0.35→0.25) deoarece Rule Engine preia o parte din responsabilitate.

    if rule_result.triggered:
        # Reguli active dar sub threshold shortcut (score 0.3 – 0.89)
        # Combinăm cu IF folosind max() ca să nu diluăm semnalul semantic.
        if_combined = (
            0.30 * stat_score +
            0.25 * behavior_score +
            0.20 * template_rarity +
            0.15 * burst_score
        )
        final_risk = max(rule_result.score, if_combined)
    else:
        # Zero reguli active — IF decide singur
        final_risk = (
            0.45 * stat_score +
            0.35 * behavior_score +
            0.25 * template_rarity +
            0.20 * burst_score
        )

    final_risk = min(final_risk, 1.0)

    if final_risk > 0.65:
        level = "HIGH"
    elif final_risk > 0.4:
        level = "MEDIUM"
    else:
        level = "LOW"

    # =============================
    # OUTPUT
    # =============================

    # Prefix vizual bazat pe nivel de risc
    icon = "🔴" if level == "HIGH" else ("🟡" if level == "MEDIUM" else "🟢")

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
Rarity:          {round(template_rarity, 3)}
Burst:           {round(burst_score, 3)}

--- Context Entitate (5 min) ---
failed_auth:  {sem_feats['entity_failed_auth_5m']}
sudo_count:   {sem_feats['entity_sudo_count_5m']}
uploads:      {sem_feats['entity_upload_count_5m']}
lsass:        {sem_feats['entity_lsass_count_5m']}

Final Risk:  {round(final_risk, 3)}
Risk Level:  {level}
{'[shortcut: N/A — reguli sub threshold]' if rule_result.triggered else '[rule engine: no match — IF decides]'}
{'─'*50}
""")