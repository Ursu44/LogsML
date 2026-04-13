def derive_label(rule_result, if_combined, sem_feats):
    if rule_result.shortcut:
        return 1
    if rule_result.score >= 0.7 and if_combined >= 0.5:
        return 1
    if if_combined >= 0.75:
        return 1

    failed = sem_feats.get("entity_failed_auth_5m", 0)
    sudo = sem_feats.get("entity_sudo_count_5m", 0)
    lsass = sem_feats.get("entity_lsass_count_5m", 0)
    uploads = sem_feats.get("entity_upload_count_5m", 0)

    if lsass >= 3:
        return 1

    if failed >= 8 and sudo >= 8:
        return 1

    if uploads >= 5 and failed >= 8:
        return 1

    if (not rule_result.triggered and
            if_combined <= 0.25 and
            failed == 0 and sudo == 0 and lsass == 0):
        return 0

    return None