def classify_log_category(payload: dict) -> str:
    raw = payload.get("log", "").lower()

    if any(k in raw for k in ["av alert", "av warn", "ids alert", "siem alert",
                               "edr alert", "dlp alert", "spyware", "trojan",
                               "malware", "virus detected"]):
        return "alert"

    if any(k in raw for k in ["sshd[", "passwd[", "sudo[", " su[",
                               "user account", "authentication failure",
                               "accepted password", "accepted publickey",
                               "failed password", "failed publickey",
                               "accepted keyboard"]):
        return "auth"

    if any(k in raw for k in ['"get ', '"post ', '"put ', '"delete ',
                               '"patch ', 'http/1.', 'http/2.']):
        return "web"

    if any(k in raw for k in ["firewall", "named[", "suricata[", "routerd",
                               "bgp ", "flow tcp", "flow udp", "block tcp",
                               "block udp", "accept tcp", "accept udp"]):
        return "network"

    return "system"