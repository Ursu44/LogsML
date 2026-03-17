from rezultatRegula import RuleResult

RULE_SHORTCUT_THRESHOLD = 0.9
def apply_rule_engine(sem_feats: dict, payload: dict) -> RuleResult:

    scores = []
    rules  = []

    if sem_feats.get("has_reverse_shell"):
        scores.append(1.0)
        rules.append("A1:reverse_shell")

    if sem_feats.get("has_download_exec"):
        scores.append(0.9)
        rules.append("A2:download_exec")

    if sem_feats.get("is_lolbin"):
        base = 0.85 if sem_feats.get("is_external_src") else 0.7
        scores.append(base)
        rules.append("A3:lolbin" + ("+ext_ip" if sem_feats.get("is_external_src") else ""))

    if sem_feats.get("is_suspicious_powershell"):
        boost = sem_feats.get("is_external_src") or sem_feats.get("mat_first_seen_user", 0)
        base = 0.85 if boost else 0.7
        scores.append(base)
        rules.append("A4:suspicious_powershell" + ("+boost" if boost else ""))

    if sem_feats.get("sudo_shell_escape"):
        scores.append(0.9)
        rules.append("A5:sudo_shell_escape")

    if sem_feats.get("sudo_recon"):
        scores.append(0.5)
        rules.append("A6:sudo_recon")


    if sem_feats.get("is_lsass_access"):
        scores.append(1.0)
        rules.append("B1:lsass_credential_dump")

    lsass_5m = sem_feats.get("entity_lsass_count_5m", 0)
    if sem_feats.get("is_lsass_access"):
        if lsass_5m >= 3:
            scores.append(1.0)
            rules.append(f"B2:lsass_campaign({lsass_5m}x/5min)")
        elif lsass_5m == 2:
            scores.append(0.8)
            rules.append(f"B2:lsass_repeated({lsass_5m}x/5min)")

    if sem_feats.get("is_lateral_movement"):
        scores.append(1.0)
        rules.append("B3:lateral_movement")

    failed_5m = sem_feats.get("entity_failed_auth_5m", 0)
    entity_id_re = sem_feats.get("entity_id", "generic_entity")
    if entity_id_re != "generic_entity" and sem_feats.get("is_failed_auth"):
        if failed_5m >= 10:
            scores.append(0.9)
            rules.append(f"B4:brute_force({failed_5m}x/5min)")
        elif failed_5m >= 5:
            scores.append(0.6)
            rules.append(f"B4:auth_failures({failed_5m}x/5min)")

    if sem_feats.get("is_external_login_accepted"):
        scores.append(0.4)
        rules.append("B5:external_login_accepted")


    if sem_feats.get("is_malicious_file_upload"):
        scores.append(0.95)
        rules.append("C1:malicious_file_upload")

    if sem_feats.get("writes_sensitive_path"):
        scores.append(0.9)
        rules.append("C2:writes_sensitive_path")

    if sem_feats.get("reads_sensitive_path"):
        scores.append(0.5)
        rules.append("C3:reads_sensitive_path")


    uploads_5m = sem_feats.get("entity_upload_count_5m", 0)
    if uploads_5m >= 2 and sem_feats.get("is_malicious_file_upload"):
        scores.append(0.95)
        rules.append(f"C4:upload_campaign({uploads_5m}x/5min)")

    if sem_feats.get("has_sqli"):
        scores.append(0.85)
        rules.append("D1:sql_injection")

    if sem_feats.get("has_xss"):
        scores.append(0.8)
        rules.append("D2:xss")

    if sem_feats.get("has_path_traversal"):
        scores.append(0.8)
        rules.append("D3:path_traversal")

    if sem_feats.get("has_debug_endpoint"):
        scores.append(0.5)
        rules.append("D4:debug_endpoint_access")

    if sem_feats.get("has_destructive_http"):
        scores.append(0.7)
        rules.append("D5:destructive_http_method")

    if sem_feats.get("is_suspicious_dns"):
        scores.append(0.7)
        rules.append("E1:suspicious_dns_query")

    if sem_feats.get("is_suspicious_firewall"):
        scores.append(0.6)
        rules.append("E2:suspicious_firewall_accept")

    if sem_feats.get("is_av_alert"):
        scores.append(0.95)
        rules.append("F1:av_alert")

    if sem_feats.get("is_ids_alert"):
        scores.append(0.85)
        rules.append("F2:ids_alert")

    if sem_feats.get("is_dlp_alert"):
        scores.append(0.8)
        rules.append("F3:dlp_alert")

    if sem_feats.get("is_siem_alert"):
        scores.append(0.85)
        rules.append("F4:siem_correlation_alert")

    if sem_feats.get("is_edr_alert"):
        scores.append(0.9)
        rules.append("F5:edr_alert")

    if (sem_feats.get("is_external_src") and
            sem_feats.get("mat_first_seen_user", 0) and
            sem_feats.get("mat_new_process", 0)):
        scores.append(0.75)
        rules.append("G1:new_user_ext_ip_new_process")

    is_auth_or_sudo_event = (
        sem_feats.get("is_failed_auth") or
        sem_feats.get("sudo_shell_escape") or
        sem_feats.get("sudo_recon") or
        "sudo[" in payload.get("log", "").lower()
    )
    if (entity_id_re != "generic_entity" and
            is_auth_or_sudo_event and
            sem_feats.get("entity_sudo_count_5m", 0) >= 1 and
            sem_feats.get("entity_failed_auth_5m", 0) >= 2):
        scores.append(0.7)
        rules.append("G2:failed_auth_then_sudo")

    if (sem_feats.get("entity_upload_count_5m", 0) >= 1 and
            sem_feats.get("writes_sensitive_path")):
        scores.append(0.95)
        rules.append("G3:upload_plus_sensitive_write")

    if sem_feats.get("is_av_alert") and sem_feats.get("is_ids_alert"):
        scores.append(0.98)
        rules.append("G4:av_and_ids_correlation")

    if (sem_feats.get("is_lateral_movement") and
            sem_feats.get("entity_lsass_count_5m", 0) >= 1):
        scores.append(1.0)
        rules.append("G5:lateral_plus_credential_dump")

    if sem_feats.get("is_firewall_block_external"):
        scores.append(0.65)
        rules.append("E3:firewall_block_external")

    if sem_feats.get("is_bgp_reset"):
        scores.append(0.55)
        rules.append("E4:bgp_session_reset")

    if sem_feats.get("is_account_manipulation"):
        scores.append(0.6)
        rules.append("B6:account_manipulation")

    if not scores:
        return RuleResult(score=0.0, triggered=False, rules=[], shortcut=False)

    base_score = max(scores)
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