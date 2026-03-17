from listeConstante import INTERNAL_RANGES

def is_external_ip(ip: str) -> bool:
    if not ip or ip == "unknown":
        return False
    return not any(p.match(ip) for p in INTERNAL_RANGES)