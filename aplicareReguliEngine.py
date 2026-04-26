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

    # B1: lsass singur — NU mai e shortcut la 1
    # lsass=1 poate fi AV scan sau diagnostic legitim
    # shortcut doar de la lsass >= 2
    if lsass >= 2:
        _fire(result, f"B1:lsass_access({lsass}x)", 0.95,
              shortcut=True)
    elif lsass == 1:
        # lsass=1 → suspect dar nu cert → scor moderat fără shortcut
        _fire(result, "B1:lsass_single_access", 0.65)

    # B2: campanie lsass + brute force
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

    # B4: brute force — ridicat pragul de la 5 la 8
    # 5-7 failed auth poate fi utilizator care uită parola
    # shortcut doar de la 12+
    if failed >= 12:
        score = min(0.6 + failed * 0.03, 0.95)
        _fire(result, f"B4:auth_failures({failed}x/5min)",
              score, shortcut=True)
    elif failed >= 8:
        score = min(0.5 + failed * 0.03, 0.85)
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

    # G2: ridicat pragul — failed >= 6 și sudo >= 3
    # failed=3 + sudo=1 e prea comun și normal
    if failed >= 6 and sudo >= 3:
        _fire(result, "G2:failed_auth_then_sudo", 0.65)

    if sem_feats.get("entity_upload_count_5m", 0) >= 1 and \
       sem_feats.get("writes_sensitive_path", 0):
        _fire(result, "G3:upload_plus_sensitive_write",
              1.0, shortcut=True)

    if sem_feats.get("lateral_movement", 0) and lsass >= 1:
        _fire(result, "G5:lateral_plus_credential_dump",
              1.0, shortcut=True)

    # ── Grupul H — Context masiv ─────────────────────────────────

    # H1: lsass >= 2 deja prins de B1
    # Păstrăm doar pentru combinație cu brute force masiv
    if lsass >= 2 and failed >= 10:
        _fire(result,
              f"H1:lsass({lsass}x)+brute_force({failed}x)",
              0.95, shortcut=True)

    # H2: Brute force masiv + escaladare masivă — ridicat pragul
    if failed >= 12 and sudo >= 10:
        _fire(result,
              f"H2:brute_force({failed}x)+escaladare({sudo}x)",
              0.90, shortcut=True)

    # H3: Brute force extrem singur — ridicat la 18
    elif failed >= 18:
        _fire(result,
              f"H3:extreme_brute_force({failed}x)",
              0.85, shortcut=True)

    # H4: Escaladare + exfiltrare — ridicat pragul sudo la 10
    if sudo >= 10 and uploads >= 3:
        _fire(result,
              f"H4:escaladare({sudo}x)+exfiltrare({uploads}x)",
              0.85, shortcut=True)

    # H5: Triada completă — ridicat pragurile
    if failed >= 10 and sudo >= 8 and uploads >= 3:
        _fire(result,
              f"H5:triada_failed({failed})+sudo({sudo})+uploads({uploads})",
              0.88, shortcut=True)

    return result