import re

LOLBINS = {
    "certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "wmic.exe", "cscript.exe", "wscript.exe", "msiexec.exe",
    "installutil.exe", "regasm.exe", "regsvcs.exe", "msconfig.exe",
    "mimikatz.exe", "procdump.exe"
}

SUSPICIOUS_PROCESSES = {
    "cmd.exe", "powershell.exe", "nc.exe", "netcat.exe",
    "psexec.exe", "at.exe", "schtasks.exe"
}

MALICIOUS_EXTENSIONS = {
    ".jsp", ".jspx", ".aspx", ".asp", ".php", ".php5", ".php7",
    ".phtml", ".ps1", ".psm1", ".vbs", ".js", ".hta",
    ".bat", ".cmd", ".scr", ".pif"
}

MALICIOUS_FILENAMES = {
    "webshell", "backdoor", "shell", "cmd", "dropper",
    "payload", "exploit", "rev", "bind", "nc", "netcat",
    "mimikatz", "meterpreter", "empire", "cobalt"
}

SENSITIVE_WRITE_PATHS = {
    "/root/.ssh/authorized_keys",
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/etc/cron", "/etc/crontab", "/var/spool/cron",
    "/tmp/", "/dev/shm/", "/var/tmp/",
    ".bashrc", ".bash_profile", ".profile",
    "/etc/ld.so.preload", "/etc/rc.local"
}

SENSITIVE_READ_PATHS = {
    "/etc/shadow", "/etc/passwd", "/root/.ssh/",
    "id_rsa", "id_ecdsa", ".aws/credentials",
    ".env", "/etc/app/secrets", "/root/config",
    "/home/root", "private.key", ".pgpass"
}

SUSPICIOUS_TLDS = {".xyz", ".ru", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw"}

KNOWN_C2_KEYWORDS = {"c2-server", "malware", "callback", "botnet", "payload", "dropper"}

SUSPICIOUS_PORT_COMBOS = {
    (22, "UDP"),
    (3389, "UDP"),
    (4444, "TCP"),
    (1337, "TCP"),
    (31337, "TCP"),
}

INTERNAL_RANGES = [
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2[0-9]|3[0-1])\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^127\."),
    re.compile(r"^::1$"),
    re.compile(r"^fc"), re.compile(r"^fd"),
]