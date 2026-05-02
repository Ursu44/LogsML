from rezultatRegula import RuleResult, _fire

RULE_SHORTCUT_THRESHOLD = 0.9

def apply_rule_engine(sem_feats: dict, payload: dict) -> RuleResult:
    result = RuleResult()

    failed  = sem_feats.get("entity_failed_auth_5m", 0)
    sudo    = sem_feats.get("entity_sudo_count_5m",  0)
    lsass   = sem_feats.get("entity_lsass_count_5m", 0)
    uploads = sem_feats.get("entity_upload_count_5m", 0)

    # ── Grupul A — Execuție malițioasă ───────────────────────────
    if sem_feats.get("has_download_exec", 0):
        _fire(result, "A2:download_exec", 0.90, shortcut=True)

    if sem_feats.get("is_lolbin", 0):
        _fire(result, "A3:lolbin", 0.95, shortcut=True)

    if sem_feats.get("sudo_shell_escape", 0):
        _fire(result, "A5:sudo_shell_escape", 0.95, shortcut=True)

    if sem_feats.get("has_reverse_shell", 0):
        _fire(result, "A1:reverse_shell", 0.95, shortcut=True)

    # ── Grupul B — Credențiale ───────────────────────────────────
    if lsass >= 5:
        _fire(result, f"B1:lsass_access({lsass}x)", 0.95,
              shortcut=True)
    elif lsass == 4:
        _fire(result, f"B1:lsass_access({lsass}x)", 0.82)
    elif lsass == 3:
        _fire(result, f"B1:lsass_access({lsass}x)", 0.72)
    elif lsass == 2:
        _fire(result, f"B1:lsass_access({lsass}x)", 0.62)
    elif lsass == 1:
        _fire(result, "B1:lsass_single_access", 0.48)

    if lsass >= 4 and failed >= 12:
        _fire(result,
              f"B2:lsass_campaign({lsass}x)+brute_force({failed}x)",
              0.95, shortcut=True)
    elif lsass >= 3 and failed >= 10:
        _fire(result,
              f"B2:lsass_campaign({lsass}x)+brute_force({failed}x)",
              0.82)
    elif lsass >= 3:
        _fire(result,
              f"B2:lsass_campaign({lsass}x)",
              0.70)

    if sem_feats.get("is_lateral_movement", 0):
        _fire(result, "B3:lateral_movement", 1.0, shortcut=True)

    if failed >= 18:
        score = min(0.65 + failed * 0.01, 0.92)
        _fire(result, f"B4:auth_failures({failed}x/5min)",
              score, shortcut=True)
    elif failed >= 12:
        score = min(0.50 + failed * 0.02, 0.78)
        _fire(result, f"B4:auth_failures({failed}x/5min)", score)
    elif failed >= 8:
        score = min(0.40 + failed * 0.02, 0.65)
        _fire(result, f"B4:auth_failures({failed}x/5min)", score)

    # ── Grupul C — Fișiere ───────────────────────────────────────
    if sem_feats.get("is_malicious_file_upload", 0):
        _fire(result, "C1:malicious_file_upload", 0.95, shortcut=True)

    if sem_feats.get("writes_sensitive_path", 0):
        _fire(result, "C2:writes_sensitive_path", 1.0, shortcut=True)

    # ── Grupul D — Web ───────────────────────────────────────────
    if sem_feats.get("has_debug_endpoint", 0):
        _fire(result, "D4:debug_endpoint_access", 0.5)

    if sem_feats.get("has_destructive_http", 0):
        _fire(result, "D5:destructive_http_method", 0.7)

    if sem_feats.get("has_sqli", 0):
        _fire(result, "D1:sql_injection", 0.75)

    if sem_feats.get("has_xss", 0):
        _fire(result, "D2:xss_attempt", 0.65)

    if sem_feats.get("has_path_traversal", 0):
        _fire(result, "D3:path_traversal", 0.70)

    # ── Grupul E — Rețea ─────────────────────────────────────────
    if sem_feats.get("is_suspicious_dns", 0):
        _fire(result, "E1:suspicious_dns_query", 0.7)

    if sem_feats.get("is_firewall_block_external", 0):
        _fire(result, "E3:firewall_block_external", 0.65)

    # ── Grupul F — Alerte externe ────────────────────────────────
    if sem_feats.get("is_ids_alert", 0):
        _fire(result, "F2:ids_alert", 0.85)

    if sem_feats.get("is_dlp_alert", 0):
        _fire(result, "F3:dlp_alert", 0.8)

    if sem_feats.get("is_edr_alert", 0):
        _fire(result, "F5:edr_alert", 0.85)

    if sem_feats.get("is_av_alert", 0):
        _fire(result, "F1:av_alert", 0.75)

    if sem_feats.get("is_siem_alert", 0):
        _fire(result, "F4:siem_alert", 0.80)

    # ── Grupul G — Pattern-uri compuse ───────────────────────────
    if failed >= 10 and sudo >= 6:
        _fire(result, "G2:failed_auth_then_sudo", 0.68)

    if sem_feats.get("entity_upload_count_5m", 0) >= 1 and \
       sem_feats.get("writes_sensitive_path", 0):
        _fire(result, "G3:upload_plus_sensitive_write",
              1.0, shortcut=True)

    if sem_feats.get("is_lateral_movement", 0) and lsass >= 1:
        _fire(result, "G5:lateral_plus_credential_dump",
              1.0, shortcut=True)

    # ── Grupul H — Context masiv ─────────────────────────────────
    if lsass >= 3 and failed >= 14:
        _fire(result,
              f"H1:lsass({lsass}x)+brute_force({failed}x)",
              0.95, shortcut=True)
    elif lsass >= 2 and failed >= 12:
        _fire(result,
              f"H1:lsass({lsass}x)+brute_force({failed}x)",
              0.78)

    if failed >= 15 and sudo >= 12:
        _fire(result,
              f"H2:brute_force({failed}x)+escaladare({sudo}x)",
              0.90, shortcut=True)
    elif failed >= 20:
        _fire(result,
              f"H3:extreme_brute_force({failed}x)",
              0.85, shortcut=True)

    if sudo >= 14 and uploads >= 4:
        _fire(result,
              f"H4:escaladare({sudo}x)+exfiltrare({uploads}x)",
              0.85, shortcut=True)
    elif sudo >= 10 and uploads >= 3:
        _fire(result,
              f"H4:escaladare({sudo}x)+exfiltrare({uploads}x)",
              0.72)

    if failed >= 12 and sudo >= 10 and uploads >= 4:
        _fire(result,
              f"H5:triada_failed({failed})+sudo({sudo})+uploads({uploads})",
              0.88, shortcut=True)

    return result