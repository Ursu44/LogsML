def is_obviously_malicious(sem_feats: dict) -> bool:
    lsass   = sem_feats.get("entity_lsass_count_5m", 0)
    failed  = sem_feats.get("entity_failed_auth_5m", 0)
    sudo    = sem_feats.get("entity_sudo_count_5m",  0)
    uploads = sem_feats.get("entity_upload_count_5m", 0)

    if lsass >= 1:
        return True
    if sem_feats.get("download_exec", 0):
        return True
    if sem_feats.get("malicious_file_upload", 0):
        return True
    if sem_feats.get("lateral_movement", 0):
        return True
    if sem_feats.get("lolbin_detected", 0):
        return True

    if failed >= 8 and sudo >= 6:
        return True
    if failed >= 8 and uploads >= 3:
        return True
    if sudo >= 8 and uploads >= 3:
        return True

    return False


def is_contaminated_entity_vector(sem_feats: dict) -> bool:
    failed  = sem_feats.get("entity_failed_auth_5m", 0)
    sudo    = sem_feats.get("entity_sudo_count_5m",  0)
    lsass   = sem_feats.get("entity_lsass_count_5m", 0)
    uploads = sem_feats.get("entity_upload_count_5m", 0)

    if failed > 12:  return True
    if sudo > 10:    return True
    if lsass > 0:    return True
    if uploads > 4:  return True

    return False