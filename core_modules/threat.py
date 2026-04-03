import re, math, time

class ThreatScorer:
    SQL_PATTERNS = [
        (r"(?i)(union\s+select|select\s+\*|drop\s+table|insert\s+into)",    40, "SQL injection"),
        (r"(?i)('\s*(or|and)\s*'?\d|\d'\s*(or|and)\s*'\d)",                 35, "SQL auth bypass"),
        (r"(?i)(exec\s*\(|xp_cmdshell|sp_executesql)",                       45, "SQL exec"),
        (r"(?i)(sleep\s*\(\d|benchmark\s*\(|waitfor\s+delay)",               30, "SQL time-based"),
        (r"(?i)(information_schema|sys\.tables|sysobjects)",                  25, "SQL enumeration"),
        (r"'|--|#|/\*.*?\*/",                                                 10, "SQL comment/quote"),
    ]
    CMD_PATTERNS = [
        (r"(?i)(cat\s+/etc/passwd|cat\s+/etc/shadow)",                        50, "Credential read"),
        (r"(?i)(wget|curl)\s+https?://",                                       35, "Remote download"),
        (r"(?i)(chmod\s+[0-7]{3,4}|chown\s+root)",                           30, "Privilege change"),
        (r"(?i)(nc\s+-[a-z]*e|netcat|/bin/sh|/bin/bash)",                    45, "Reverse shell"),
        (r"(?i)(python.*-c|perl.*-e|ruby.*-e)\s*['\"]",                      40, "Script exec"),
        (r"(?i)(rm\s+-rf|rmdir\s+/|mkfs\.)",                                  50, "Destructive cmd"),
        (r"(?i)(base64\s+--decode|base64\s+-d)",                              35, "Encoded payload"),
        (r"(?i)(sudo|su\s+-|passwd\s+root)",                                  30, "Privilege escalation"),
        (r"(?i)(crontab|/etc/cron|at\s+now)",                                 25, "Persistence"),
        (r"(?i)(whoami|id\b|uname\s+-a)",                                     10, "Recon command"),
    ]
    PATH_PATTERNS = [
        (r"\.\./|\.\.\\",                                                      30, "Path traversal"),
        (r"(?i)(/etc/passwd|/etc/shadow|/proc/self)",                         40, "Sensitive file"),
        (r"(?i)\.(php|asp|aspx|jsp|cgi)\?",                                    15, "Script endpoint"),
        (r"(?i)(phpmyadmin|wp-admin|wp-login|admin\.php)",                     20, "Admin panel"),
        (r"(?i)(shell|cmd|eval|exec|system)\.",                                35, "Shell endpoint"),
        (r"(?i)(/\.env|/config\.php|/database\.yml|/settings\.py)",            30, "Config leak"),
        (r"(?i)(\.git/|\.svn/|\.htaccess)",                                    20, "Source leak"),
    ]
    PAYLOAD_PATTERNS = [
        (r"(?i)(<script|javascript:|onerror=|onload=)",                         35, "XSS"),
        (r"(?i)(eval\s*\(|assert\s*\(|system\s*\(|passthru\s*\()",            40, "Code injection"),
        (r"(?i)(\$\{.*\}|\{\{.*\}\}|<%.*%>)",                                  30, "Template injection"),
        (r"(?i)(ldap://|file://|ftp://|gopher://|dict://)",                    35, "SSRF protocol"),
        (r"(?i)(jndi:|rmi://|ldap://)",                                         50, "Log4Shell/JNDI"),
        (r"(?i)(zzz|aaa|xxx){3,}",                                              15, "Fuzzing pattern"),
    ]
    CRED_PATTERNS = [
        (r"(?i)^(root|admin|administrator|toor|kali)$",                         10, "Default user"),
        (r"(?i)^(password|123456|admin123|root123|pass@123)$",                  5,  "Common password"),
        (r"(?i)(reverse_shell|payload|exploit|shellcode)",                       40, "Malicious cred"),
    ]
    TOOL_SIGNATURES = [
        "sqlmap", "nikto", "nmap", "masscan", "hydra",
        "metasploit", "zgrab", "nuclei", "dirbuster", "gobuster",
        "burpsuite", "acunetix", "nessus", "openvas", "shodan",
    ]

    def __init__(self):
        self._compile()
        self.history = {}

    def _compile(self):
        self._sql  = [(re.compile(p), s, l) for p, s, l in self.SQL_PATTERNS]
        self._cmd  = [(re.compile(p), s, l) for p, s, l in self.CMD_PATTERNS]
        self._path = [(re.compile(p), s, l) for p, s, l in self.PATH_PATTERNS]
        self._pay  = [(re.compile(p), s, l) for p, s, l in self.PAYLOAD_PATTERNS]
        self._cred = [(re.compile(p), s, l) for p, s, l in self.CRED_PATTERNS]

    def _entropy(self, s: str) -> float:
        if not s: return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        n = len(s)
        return -sum((f/n) * math.log2(f/n) for f in freq.values())

    def _rate_score(self, ip: str) -> int:
        now = time.time()
        times = self.history.setdefault(ip, [])
        times.append(now)
        self.history[ip] = [t for t in times if now - t < 60]
        count = len(self.history[ip])
        if count > 50: return 30
        if count > 20: return 20
        if count > 10: return 10
        if count > 5:  return 5
        return 0

    def score(self, event: dict) -> dict:
        svc      = event.get("service", "")
        ip       = event.get("ip", "")
        username = event.get("username", "") or ""
        password = event.get("password", "") or ""
        path     = event.get("path", "") or ""
        method   = event.get("method", "") or ""
        command  = event.get("command", "") or ""
        ua       = event.get("user_agent", "") or ""

        total   = 0
        reasons = []

        target = f"{path} {username} {password}"
        for pat, score, label in self._sql:
            if pat.search(target):
                total += score
                reasons.append(f"SQL: {label}")

        cmd_target = f"{command} {password} {path}"
        for pat, score, label in self._cmd:
            if pat.search(cmd_target):
                total += score
                reasons.append(f"CMD: {label}")

        for pat, score, label in self._path:
            if pat.search(path):
                total += score
                reasons.append(f"PATH: {label}")

        full_payload = f"{path} {password} {command}"
        for pat, score, label in self._pay:
            if pat.search(full_payload):
                total += score
                reasons.append(f"PAYLOAD: {label}")

        for pat, score, label in self._cred:
            if pat.search(username) or pat.search(password):
                total += score
                reasons.append(f"CRED: {label}")

        entropy = self._entropy(password + path + command)
        if entropy > 4.5:
            ent_score = int((entropy - 4.5) * 15)
            total += ent_score
            reasons.append(f"ENTROPY: {entropy:.2f} (obfuscated?)")

        payload_len = len(path) + len(command) + len(password)
        if payload_len > 500:
            total += 20
            reasons.append(f"LENGTH: {payload_len} chars (long payload)")
        elif payload_len > 200:
            total += 10
            reasons.append(f"LENGTH: {payload_len} chars")

        ua_lower = ua.lower()
        for tool in self.TOOL_SIGNATURES:
            if tool in ua_lower:
                total += 25
                reasons.append(f"TOOL: {tool} detected")
                break

        if method in ("CONNECT", "TRACE", "TRACK"):
            total += 20
            reasons.append(f"METHOD: {method} abuse")

        rate = self._rate_score(ip)
        if rate:
            total += rate
            reasons.append(f"RATE: {len(self.history.get(ip,[]))} req/60s")

        score = min(100, total)

        if score >= 86:
            label = "CRITICAL"; color = "#f38ba8"
        elif score >= 61:
            label = "HIGH";     color = "#fab387"
        elif score >= 31:
            label = "SUSPICIOUS"; color = "#f9e2af"
        else:
            label = "SAFE";    color = "#a6e3a1"

        return {"score": score, "label": label, "color": color,
                "reasons": reasons, "entropy": round(entropy, 2)}

    def label_to_emoji(self, label: str) -> str:
        return {"CRITICAL":"🔴","HIGH":"🟠","SUSPICIOUS":"🟡","SAFE":"🟢"}.get(label,"⚪")


# Global instance
ML = ThreatScorer()
print("[ML] ThreatScorer ready — payload analysis active")
