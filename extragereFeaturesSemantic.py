from collections import defaultdict, deque

from externalIPCheck import *
from listeConstante import *

WINDOW_5M = 90
entity_failed_auth   = defaultdict(lambda: deque(maxlen=50))
entity_sudo_events   = defaultdict(lambda: deque(maxlen=50))
entity_uploads       = defaultdict(lambda: deque(maxlen=50))
entity_lsass_events  = defaultdict(lambda: deque(maxlen=50))
entity_process_set   = defaultdict(set)
def extract_semantic_features(payload: dict, entity_id: str, ts: float) -> dict:
    raw_log   = payload.get("log", "").lower()
    features  = payload.get("features", {})

    sem_ip      = features.get("src_ip", "") or ""
    sem_process = features.get("process", "") or ""
    sem_path    = features.get("path", "") or ""
    sem_url     = features.get("url", "") or ""
    sem_cmd     = features.get("cmd", "") or ""

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

    if not sem_ip:
        m = re.search(r"\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})\b", raw_log)
        if m:
            sem_ip = m.group(1)
    if not sem_ip:
        m = re.search(r"\bip=(\d{1,3}(?:\.\d{1,3}){3})\b", raw_log)
        if m:
            sem_ip = m.group(1)

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

    has_download_exec = int(
        ("wget" in raw_log or "curl" in raw_log) and
        ("chmod" in raw_log or "bash" in raw_log or
         "sh" in raw_log or "|" in raw_log or
         ">/tmp" in raw_log or "/dev/shm" in raw_log)
    )

    proc_lower = sem_process.lower()
    is_lolbin = int(
        any(lb in proc_lower for lb in LOLBINS) or
        any(lb in raw_log for lb in LOLBINS)
    )

    is_suspicious_powershell = int(
        "powershell" in raw_log and (
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

    is_lsass_access = int(
        "lsass.exe" in raw_log and
        ("credential" in raw_log or "t1003" in raw_log or
         "access" in raw_log or "dump" in raw_log)
    )

    is_lateral_movement = int(
        "lateral movement" in raw_log or
        "psexec" in raw_log.lower() or
        "pass-the-hash" in raw_log.lower() or
        "wmi lateral" in raw_log.lower() or
        "remote service creation" in raw_log.lower()
    )

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

    sudo_recon = int(
        "tty=pts" in raw_log and
        ("command=/usr/bin/id" in raw_log or
         "command=/usr/bin/whoami" in raw_log or
         "command=/usr/bin/w" in raw_log)
    )

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

    perm_is_write = "perm=\"w\"" in raw_log or "perm=w" in raw_log
    path_lower = sem_path.lower() if sem_path else raw_log

    writes_sensitive_path = int(
        perm_is_write and
        any(sp in path_lower for sp in SENSITIVE_WRITE_PATHS)
    )

    perm_is_read = "perm=\"r\"" in raw_log or "perm=r" in raw_log
    reads_sensitive_path = int(
        perm_is_read and
        any(sp in path_lower for sp in SENSITIVE_READ_PATHS)
    )

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
        "/phpinfo" in raw_log or
        "/admin.php" in raw_log or
        "/wp-admin" in raw_log or
        "/cgi-bin" in raw_log
    )

    has_destructive_http = int(
        ('"delete ' in raw_log or '"put ' in raw_log) and
        any(r in raw_log for r in ["/settings", "/admin", "/config", "/users", "/login"])
    )

    is_external_src = int(is_external_ip(sem_ip))

    is_failed_auth = int(
        "failed password" in raw_log or
        "failed publickey" in raw_log or
        "failed keyboard" in raw_log or
        "authentication failure" in raw_log or
        "invalid user" in raw_log or
        "permission denied" in raw_log
    )

    is_external_login_accepted = int(
        ("accepted password" in raw_log or
         "accepted publickey" in raw_log or
         "accepted keyboard" in raw_log) and
        is_external_ip(sem_ip)
    )

    is_suspicious_firewall_accept = 0
    if "firewall accept" in raw_log:
        for port, proto in SUSPICIOUS_PORT_COMBOS:
            if str(port) in raw_log and proto.lower() in raw_log:
                is_suspicious_firewall_accept = 1
                break

    is_firewall_block_external = 0
    if "firewall block" in raw_log:
        m = re.search(r'firewall block\s+\w+\s+(\d{1,3}(?:\.\d{1,3}){3})', raw_log)
        if m and is_external_ip(m.group(1)):
            is_firewall_block_external = 1

    is_bgp_reset = int("bgp session reset" in raw_log)
    is_account_manipulation = int(
        ("ad:" in raw_log or "user account" in raw_log) and
        any(a in raw_log for a in ["deleted", "disabled", "locked"])
    )

    is_suspicious_dns = 0
    if "query:" in raw_log or "in a" in raw_log:
        m = re.search(r"query:\s+(\S+)\s+in", raw_log)
        if m:
            domain = m.group(1).lower()
            if (any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS) or
                    any(kw in domain for kw in KNOWN_C2_KEYWORDS)):
                is_suspicious_dns = 1

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

    if is_failed_auth and entity_id != "generic_entity":
        entity_failed_auth[entity_id].append(ts)
    if (sudo_shell_escape or sudo_recon or "sudo[" in raw_log) and entity_id != "generic_entity":
        entity_sudo_events[entity_id].append(ts)
    if is_malicious_file_upload and entity_id != "generic_entity":
        entity_uploads[entity_id].append(ts)
    if is_lsass_access and entity_id != "generic_entity":
        entity_lsass_events[entity_id].append(ts)
    if sem_process:
        entity_process_set[entity_id].add(sem_process)

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

    return {
        "entity_id":                 entity_id,

        "has_reverse_shell":         has_reverse_shell,
        "has_download_exec":         has_download_exec,
        "is_lolbin":                 is_lolbin,
        "is_suspicious_powershell":  is_suspicious_powershell,
        "is_lsass_access":           is_lsass_access,
        "is_lateral_movement":       is_lateral_movement,
        "sudo_shell_escape":         sudo_shell_escape,
        "sudo_recon":                sudo_recon,

        "is_malicious_file_upload":  is_malicious_file_upload,
        "writes_sensitive_path":     writes_sensitive_path,
        "reads_sensitive_path":      reads_sensitive_path,

        "has_sqli":                  has_sqli,
        "has_xss":                   has_xss,
        "has_path_traversal":        has_path_traversal,
        "has_debug_endpoint":        has_debug_endpoint,
        "has_destructive_http":      has_destructive_http,

        "is_external_src":           is_external_src,
        "is_failed_auth":            is_failed_auth,
        "is_external_login_accepted": is_external_login_accepted,
        "is_suspicious_firewall":    is_suspicious_firewall_accept,

        "is_firewall_block_external": is_firewall_block_external,

        "is_suspicious_dns":         is_suspicious_dns,

        "is_bgp_reset":              is_bgp_reset,

        "is_av_alert":               is_av_alert,
        "is_ids_alert":              is_ids_alert,
        "is_dlp_alert":              is_dlp_alert,
        "is_siem_alert":             is_siem_alert,
        "is_edr_alert":              is_edr_alert,

        "is_account_manipulation":   is_account_manipulation,

        "entity_failed_auth_5m":     entity_failed_auth_5m,
        "entity_sudo_count_5m":      entity_sudo_count_5m,
        "entity_upload_count_5m":    entity_upload_count_5m,
        "entity_lsass_count_5m":     entity_lsass_count_5m,
        "entity_unique_processes":   entity_unique_processes,

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
