import re


def get_entity(payload: dict) -> str:
    features = payload.get("features", {})
    sem = features.get("semantic", {}) if isinstance(features.get("semantic"), dict) else {}

    user = features.get("user") or sem.get("user")
    ip   = features.get("src_ip") or sem.get("src_ip")

    raw = payload.get("log", "")

    if not user:
        m = re.search(r"\buser[=:]([^\s;,\"\']+)", raw)
        if m:
            user = m.group(1).strip('"\'')

    if not user:
        m = re.search(r"sudo\[\d+\]:\s+(\w+)\s+:", raw)
        if m:
            user = m.group(1)

    if not user:
        m = re.search(r"(?:failed|accepted)\s+\S+\s+for\s+(\S+)\s+from", raw, re.IGNORECASE)
        if m:
            user = m.group(1)

    if not user:
        m = re.search(r"password changed for user\s+(\S+)", raw, re.IGNORECASE)
        if m:
            user = m.group(1)

    if not user:
        m = re.search(r"user account \w+ for\s+(\S+)", raw, re.IGNORECASE)
        if m:
            user = m.group(1)

    if not user:
        m = re.search(r"\buser=(\S+)", raw)
        if m:
            user = m.group(1).strip('"\'')

    if not ip:
        m = re.search(r"\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})\b", raw)
        if m:
            ip = m.group(1)

    if not ip:
        m = re.search(r"\bip=(\d{1,3}(?:\.\d{1,3}){3})\b", raw)
        if m:
            ip = m.group(1)

    if not ip:
        m = re.search(r'firewall\s+(?:accept|block)\s+\w+\s+(\d{1,3}(?:\.\d{1,3}){3})', raw, re.IGNORECASE)
        if m:
            ip = m.group(1)

    if not ip:
        m = re.search(r'client\s+(\d{1,3}(?:\.\d{1,3}){3})#', raw)
        if m:
            ip = m.group(1)

    if not ip:
        m = re.search(r'(?:\{tcp\}|flow tcp)\s+(\d{1,3}(?:\.\d{1,3}){3})', raw, re.IGNORECASE)
        if m:
            ip = m.group(1)

    if not user and not ip:
        m = re.search(r'^\S+\s+-\s+(\w+)\s+\[', raw)
        if m and m.group(1) != "-":
            user = m.group(1)

    if not user and not ip:
        raw_lower = raw.lower()
        if ("av alert" in raw_lower or "malware detected" in raw_lower or
                "ransomware" in raw_lower or "trojan" in raw_lower):
            m = re.search(r'file=(\S+)', raw)
            if m:
                return m.group(1).strip('"\'')

    BAD_VALUES = {"unknown", "", "none", "null", "-"}
    if user and user.lower() not in BAD_VALUES:
        return user
    if ip and ip not in BAD_VALUES:
        return ip
    return "generic_entity"