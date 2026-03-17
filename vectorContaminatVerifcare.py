def is_contaminated_entity_vector(feats: dict) -> bool:
    failed  = feats.get("entity_failed_auth_5m", 0)
    sudo    = feats.get("entity_sudo_count_5m", 0)
    lsass   = feats.get("entity_lsass_count_5m", 0)
    uploads = feats.get("entity_upload_count_5m", 0)

    if failed >= 5:
        return True
    if lsass >= 2:
        return True
    if sudo >= 6 and failed >= 2:
        return True
    if uploads >= 3 and (failed >= 1 or sudo >= 3):
        return True

    return False