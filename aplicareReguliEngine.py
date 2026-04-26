from rezultatRegula import RuleResult, _fire

RULE_SHORTCUT_THRESHOLD = 0.9
def apply_rule_engine(sem_feats: dict, payload: dict) -> RuleResult:
    result = RuleResult()

    failed  = sem_feats.get("entity_failed_auth_5m", 0)
    sudo    = sem_feats.get("entity_sudo_count_5m",  0)
    lsass   = sem_feats.get("entity_lsass_count_5m", 0)
    uploads = sem_feats.get("entity_upload_count_5m", 0)

    # ── Grupul A — Execuție malițioasă ───────────────────────────
    if sem_feats.get("download_exec", 0):
        _fire(result, "A2:download_exec", 0.90, shortcut=True)

    if sem_feats.get("lolbin_detected", 0):
        _fire(result, "A3:lolbin", 0.95, shortcut=True)

    if sem_feats.get("sudo_shell_escape", 0):
        _fire(result, "A5:sudo_shell_escape", 0.95, shortcut=True)

    # ── Grupul B — Credențiale ───────────────────────────────────
    if lsass >= 1:
        _fire(result, "B1:lsass_access", 1.0, shortcut=True)

    if lsass >= 3 and failed >= 8:
        _fire(result,
              f"B2:lsass_campaign({lsass}x)+brute_force({failed}x)",
              0.95, shortcut=True)
    elif lsass >= 3:
        _fire(result,
              f"B2:lsass_campaign({lsass}x)",
              0.90, shortcut=True)

    if sem_feats.get("lateral_movement", 0):
        _fire(result, "B3:lateral_movement", 1.0, shortcut=True)

    if failed >= 5:
        score = min(0.5 + failed * 0.04, 0.95)
        _fire(result, f"B4:auth_failures({failed}x/5min)", score)

    # ── Grupul C — Fișiere ───────────────────────────────────────
    if sem_feats.get("malicious_file_upload", 0):
        _fire(result, "C1:malicious_file_upload", 0.95, shortcut=True)

    if sem_feats.get("writes_sensitive_path", 0):
        _fire(result, "C2:writes_sensitive_path", 1.0, shortcut=True)

    # ── Grupul D — Web ───────────────────────────────────────────
    if sem_feats.get("debug_endpoint_access", 0):
        _fire(result, "D4:debug_endpoint_access", 0.5)

    if sem_feats.get("destructive_http_method", 0):
        _fire(result, "D5:destructive_http_method", 0.7)

    # ── Grupul E — Rețea ─────────────────────────────────────────
    if sem_feats.get("suspicious_dns", 0):
        _fire(result, "E1:suspicious_dns_query", 0.7)

    if sem_feats.get("firewall_block_external", 0):
        _fire(result, "E3:firewall_block_external", 0.65)

    # ── Grupul F — Alerte externe ────────────────────────────────
    if sem_feats.get("ids_alert", 0):
        _fire(result, "F2:ids_alert", 0.85)

    if sem_feats.get("dlp_alert", 0):
        _fire(result, "F3:dlp_alert", 0.8)

    if sem_feats.get("edr_alert", 0):
        _fire(result, "F5:edr_alert", 0.85)

    # ── Grupul G — Pattern-uri compuse ───────────────────────────
    if failed >= 3 and sudo >= 1:
        _fire(result, "G2:failed_auth_then_sudo", 0.70)

    if sem_feats.get("entity_upload_count_5m", 0) >= 1 and \
       sem_feats.get("writes_sensitive_path", 0):
        _fire(result, "G3:upload_plus_sensitive_write",
              1.0, shortcut=True)

    if sem_feats.get("lateral_movement", 0) and lsass >= 1:
        _fire(result, "G5:lateral_plus_credential_dump",
              1.0, shortcut=True)

    # ── Grupul H — Context masiv ─────────────────────────────────
    # Rezolvă cazurile cu IF behavior=0 și template frecvent
    # dar context cert malițios — independent de template

    # H1: Lsass campanie + brute force
    if lsass >= 2 and failed >= 8:
        _fire(result,
              f"H1:lsass({lsass}x)+brute_force({failed}x)",
              0.95, shortcut=True)

    # H2: Brute force masiv + escaladare masivă
    if failed >= 10 and sudo >= 8:
        _fire(result,
              f"H2:brute_force({failed}x)+escaladare({sudo}x)",
              0.90, shortcut=True)

    # H3: Brute force extrem singur
    elif failed >= 15:
        _fire(result,
              f"H3:extreme_brute_force({failed}x)",
              0.85, shortcut=True)

    # H4: Escaladare + exfiltrare
    if sudo >= 8 and uploads >= 3:
        _fire(result,
              f"H4:escaladare({sudo}x)+exfiltrare({uploads}x)",
              0.85, shortcut=True)

    # H5: Triada completă fără lsass
    if failed >= 8 and sudo >= 6 and uploads >= 3:
        _fire(result,
              f"H5:triada_failed({failed})+sudo({sudo})+uploads({uploads})",
              0.88, shortcut=True)

    return result