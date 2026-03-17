def derive_label(rule_result, if_combined: float):
    if rule_result.shortcut:
        return 1

    if rule_result.score >= 0.7 and if_combined >= 0.5:
        return 1

    if if_combined >= 0.75 and not rule_result.triggered:
        return 1

    if not rule_result.triggered and if_combined <= 0.25:
        return 0

    if rule_result.score <= 0.4 and if_combined <= 0.3:
        return 0

    return None