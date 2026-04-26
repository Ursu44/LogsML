def derive_label(rule_result, if_combined: float,
                 sem_feats: dict):

    failed  = sem_feats.get("entity_failed_auth_5m", 0)
    sudo    = sem_feats.get("entity_sudo_count_5m",  0)
    lsass   = sem_feats.get("entity_lsass_count_5m", 0)
    uploads = sem_feats.get("entity_upload_count_5m", 0)


    if rule_result.shortcut:
        return 1

    if rule_result.score >= 0.7 and if_combined >= 0.5:
        return 1

    if if_combined >= 0.80:
        return 1

    if lsass >= 3:
        return 1

    if lsass >= 2 and failed >= 8:
        return 1

    if failed >= 10 and sudo >= 8:
        return 1

    if uploads >= 5 and failed >= 8:
        return 1

    if sudo >= 8 and uploads >= 3:
        return 1


    if (not rule_result.triggered and
            if_combined <= 0.30 and
            failed == 0 and sudo == 0 and
            lsass == 0 and uploads == 0):
        return 0

    if rule_result.score <= 0.4 and if_combined <= 0.35:
        return 0

    if (failed <= 2 and sudo <= 2 and
            lsass == 0 and uploads == 0 and
            if_combined <= 0.40):
        return 0

    return None