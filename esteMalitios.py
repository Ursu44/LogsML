def is_obviously_malicious(feats: dict) -> bool:
    return bool(
        feats.get("has_reverse_shell") or
        feats.get("is_lsass_access") or
        feats.get("is_malicious_file_upload") or
        feats.get("is_lateral_movement") or
        feats.get("has_download_exec") or
        feats.get("writes_sensitive_path")
    )