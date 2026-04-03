"""
Honeypot Control Center v2 — main.py
Advanced GUI: Live Map, Charts, Dark/Light Theme, PDF Reports, Auto-Ban, GeoIP, Threat Intel
FIXED:
  - Koi bhi port START button dabane se pehle open nahi hoga
  - Fake/test attacks completely hataye
  - Map pe sirf REAL attacks dikhenge
  - Discord webhook alert jab bhi attack aaye
  - Screenshot on high threat
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading, datetime, json, os, sys, queue, csv, math, time
from collections import defaultdict

# ── Optional imports ──────────────────────────────────────────────────────────
try:
    import matplotlib
    matplotlib.use("TkAgg")
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    MPL_OK = True
except ImportError:
    MPL_OK = False

try:
    import tkintermapview
    MAP_OK = True
except ImportError:
    MAP_OK = False

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors as rl_colors
    PDF_OK = True
except ImportError:
    PDF_OK = False

try:
    from wordcloud import WordCloud
    WC_OK = True
except ImportError:
    WC_OK = False

try:
    from PIL import ImageGrab
    PIL_OK = True
except ImportError:
    PIL_OK = False

SCREENSHOT_DIR = "screenshots"
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

try:
    import whois
    WHOIS_OK = True
except ImportError:
    WHOIS_OK = False

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

# ── GeoIP Resolver ────────────────────────────────────────────────────────────
import os as _os

class GeoResolver:
    MMDB_SEARCH = [
        "GeoLite2-City.mmdb",
        _os.path.expanduser("~/GeoLite2-City.mmdb"),
        "/usr/share/GeoIP/GeoLite2-City.mmdb",
        "/etc/GeoIP/GeoLite2-City.mmdb",
    ]

    def __init__(self, mmdb_path=None):
        self._reader  = None
        self.mmdb_ok  = False
        self.mmdb_path = None
        self._cache   = {}
        self._lock    = threading.Lock()
        paths = ([mmdb_path] if mmdb_path else []) + self.MMDB_SEARCH
        try:
            import geoip2.database
            for p in paths:
                if p and _os.path.isfile(p):
                    self._reader  = geoip2.database.Reader(p)
                    self.mmdb_ok  = True
                    self.mmdb_path = p
                    print(f"[GeoIP] MaxMind DB loaded: {p}")
                    break
            if not self.mmdb_ok:
                print("[GeoIP] mmdb not found — using ip-api.com fallback")
        except ImportError:
            print("[GeoIP] geoip2 not installed — using ip-api.com fallback")

    def lookup(self, ip: str) -> dict:
        if not ip or ip in ("127.0.0.1", "0.0.0.0", "::1"):
            return {}
        with self._lock:
            if ip in self._cache:
                return self._cache[ip]
        geo = {}
        if self.mmdb_ok and self._reader:
            try:
                r = self._reader.city(ip)
                geo = {
                    "lat":         r.location.latitude  or 0.0,
                    "lon":         r.location.longitude or 0.0,
                    "city":        r.city.name          or "Unknown",
                    "state":       r.subdivisions.most_specific.name if r.subdivisions else "",
                    "country":     r.country.name       or "Unknown",
                    "country_iso": r.country.iso_code   or "??",
                    "timezone":    r.location.time_zone or "",
                    "isp":         "",
                    "source":      "MaxMind",
                }
            except Exception:
                pass
        if not geo:
            geo = self._ipapi(ip)
        if geo:
            with self._lock:
                self._cache[ip] = geo
        return geo

    def lookup_async(self, ip: str, callback):
        def _run():
            geo = self.lookup(ip)
            callback(ip, geo)
        threading.Thread(target=_run, daemon=True).start()

    def _ipapi(self, ip: str) -> dict:
        try:
            import urllib.request, json as _json
            url = (f"http://ip-api.com/json/{ip}"
                   f"?fields=status,lat,lon,city,regionName,country,countryCode,isp,org")
            with urllib.request.urlopen(url, timeout=4) as resp:
                d = _json.loads(resp.read())
            if d.get("status") == "success":
                return {
                    "lat":         d.get("lat", 0.0),
                    "lon":         d.get("lon", 0.0),
                    "city":        d.get("city", "Unknown"),
                    "state":       d.get("regionName", ""),
                    "country":     d.get("country", "Unknown"),
                    "country_iso": d.get("countryCode", "??"),
                    "timezone":    "",
                    "isp":         d.get("isp", ""),
                    "source":      "ip-api.com",
                }
        except Exception:
            pass
        return {}

    def status(self) -> str:
        if self.mmdb_ok:
            return f"MaxMind ({self.mmdb_path})"
        return "ip-api.com (online fallback)"


GEO = GeoResolver(mmdb_path=None)
GEOIP2_OK = GEO.mmdb_ok

# ── Discord Alert ─────────────────────────────────────────────────────────────
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1487676121934725181/OZIkQSjicLj2KbcSuDqJKkyje4GUIAhH8ih6KSMeco-APoiZI8Pd5zzfbBI2esciRwnv"   # Config tab se set hoga ya seedha yahan daalo

def send_discord_alert(event: dict, geo: dict, ml_score: int, ml_label: str):
    """
    Jab bhi honeypot pe koi attack aaye, Discord pe message bhejo.
    Sirf SUSPICIOUS / HIGH / CRITICAL events pe alert.
    """
    if not DISCORD_WEBHOOK_URL or not DISCORD_WEBHOOK_URL.startswith("https://"):
        return
    if ml_label == "SAFE":
        return

    def _send():
        try:
            import urllib.request, json as _json
            svc     = event.get("service", "?")
            ip      = event.get("ip", "?")
            ts      = event.get("timestamp", "")[:19]
            city    = geo.get("city", "Unknown")
            country = geo.get("country", "??")
            user    = event.get("username", "")
            pwd     = event.get("password", "")
            path    = event.get("path", event.get("command", ""))[:60]

            emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "SUSPICIOUS": "🟡"}.get(ml_label, "⚪")

            # Discord embed
            embed = {
                "title": f"{emoji} Honeypot Alert — {ml_label}",
                "color": {"CRITICAL": 0xf38ba8, "HIGH": 0xfab387,
                           "SUSPICIOUS": 0xf9e2af}.get(ml_label, 0xaaaaaa),
                "fields": [
                    {"name": "🕐 Time",     "value": ts,           "inline": True},
                    {"name": "🌐 Service",  "value": svc,          "inline": True},
                    {"name": "🤖 ML Score", "value": f"{ml_score}/100", "inline": True},
                    {"name": "🖥️ IP",       "value": f"`{ip}`",    "inline": True},
                    {"name": "📍 Location", "value": f"{city}, {country}", "inline": True},
                ],
                "footer": {"text": "Honeypot Control Center v2"},
                "timestamp": datetime.datetime.utcnow().isoformat(),
            }
            if user or pwd:
                embed["fields"].append(
                    {"name": "🔑 Credentials", "value": f"user=`{user}` pass=`{pwd[:30]}`", "inline": False})
            if path:
                embed["fields"].append(
                    {"name": "📂 Path/Cmd", "value": f"`{path}`", "inline": False})

            payload = json.dumps({"embeds": [embed]}).encode()
            req = urllib.request.Request(
                DISCORD_WEBHOOK_URL,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                pass  # 204 No Content = success
        except Exception as ex:
            print(f"[Discord] Alert failed: {ex}")

    threading.Thread(target=_send, daemon=True).start()


# ── ML-Powered Threat Scorer ──────────────────────────────────────────────────
import re, math

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


ML = ThreatScorer()
print("[ML] ThreatScorer ready — payload analysis active")

# ── Service imports ───────────────────────────────────────────────────────────
SVC_MODULES = {}
for name, mod in [("HTTP","HTTP"),("SSH","SSH"),("FTP","FTP"),
                   ("TELNET","TELNET"),("SMTP","SMTP"),("MYSQL","MYSQL")]:
    try:
        m = __import__(mod)
        SVC_MODULES[name] = getattr(m, f"start_{name.lower()}_honeypot")
    except ImportError:
        pass

try:
    from core import CONFIG, get_banned_ips, get_all_attempts
    CORE_OK = True
except ImportError:
    CORE_OK = False
    CONFIG = {}

# ── Themes ────────────────────────────────────────────────────────────────────
THEMES = {
    "dark": {
        "BG": "#0d0f14", "BG2": "#13161e", "BG3": "#1a1e2a",
        "PANEL": "#1e2230", "BORDER": "#2a2f42",
        "FG": "#cdd6f4", "FG_DIM": "#6e738d",
        "ACCENT": "#89b4fa", "GREEN": "#a6e3a1", "RED": "#f38ba8",
        "YELLOW": "#f9e2af", "PURPLE": "#cba6f7", "TEAL": "#94e2d5",
        "ORANGE": "#fab387", "PINK": "#f5c2e7",
        "MPL_BG": "#13161e", "MPL_FG": "#cdd6f4",
    },
    "light": {
        "BG": "#eff1f5", "BG2": "#e6e9ef", "BG3": "#dce0e8",
        "PANEL": "#ccd0da", "BORDER": "#bcc0cc",
        "FG": "#4c4f69", "FG_DIM": "#9ca0b0",
        "ACCENT": "#1e66f5", "GREEN": "#40a02b", "RED": "#d20f39",
        "YELLOW": "#df8e1d", "PURPLE": "#8839ef", "TEAL": "#179299",
        "ORANGE": "#fe640b", "PINK": "#ea76cb",
        "MPL_BG": "#e6e9ef", "MPL_FG": "#4c4f69",
    }
}

T = THEMES["dark"]


def svc_color(svc):
    return {"HTTP": T["ACCENT"], "SSH": T["GREEN"], "FTP": T["ORANGE"],
            "TELNET": T["YELLOW"], "SMTP": T["PURPLE"], "MYSQL": T["TEAL"],
            "TARPIT": T["RED"]}.get(svc, T["FG"])


# ── Canvas Ping Animation ─────────────────────────────────────────────────────
class PingAnimator:
    def __init__(self, canvas, app):
        self.canvas = canvas
        self.app    = app
        self.active = []

    def fire(self, x, y, color, label):
        ring_ids = []
        for i in range(3):
            r = self.canvas.create_oval(x-4, y-4, x+4, y+4,
                                         outline=color, width=2, fill="")
            ring_ids.append(r)
        dot = self.canvas.create_oval(x-4, y-4, x+4, y+4, fill=color, outline="")
        txt = self.canvas.create_text(x, y-18, text=label,
                                       fill=color, font=("Courier New", 7, "bold"),
                                       anchor=tk.CENTER)
        bb  = self.canvas.bbox(txt)
        if bb:
            box = self.canvas.create_rectangle(bb[0]-2, bb[1]-1, bb[2]+2, bb[3]+1,
                                                fill="#0d0f14", outline=color, width=1)
            self.canvas.tag_raise(txt, box)
        else:
            box = None

        ping = {"rings": ring_ids, "dot": dot, "txt": txt, "box": box,
                "x": x, "y": y, "color": color,
                "radii": [1,1,1], "max_r": [28,42,56], "alpha": 255,
                "delay": [0,6,12], "frame": 0, "alive": True}
        self.active.append(ping)
        self._animate()

    def _animate(self):
        if not self.active: return
        still_alive = []
        for p in self.active:
            if not p["alive"]: continue
            p["frame"] += 1
            f = p["frame"]
            x, y = p["x"], p["y"]
            all_done = True
            for i, (ring_id, delay, max_r) in enumerate(zip(p["rings"], p["delay"], p["max_r"])):
                if f < delay:
                    all_done = False; continue
                r = p["radii"][i]
                if r < max_r:
                    r = min(r + 2.5, max_r)
                    p["radii"][i] = r
                    alpha_ratio = 1 - (r / max_r)
                    faded = self._blend_hex(p["color"], T["BG"], alpha_ratio)
                    try:
                        self.canvas.coords(ring_id, x-r, y-r, x+r, y+r)
                        self.canvas.itemconfig(ring_id, outline=faded)
                    except tk.TclError: pass
                    all_done = False
            if f > 60:
                try:
                    self.canvas.itemconfig(p["dot"], state=tk.HIDDEN)
                    self.canvas.itemconfig(p["txt"], state=tk.HIDDEN)
                    if p["box"]: self.canvas.itemconfig(p["box"], state=tk.HIDDEN)
                except tk.TclError: pass
            if all_done or f > 120:
                self._cleanup(p); p["alive"] = False
            else:
                still_alive.append(p)
        self.active = still_alive
        if self.active: self.app.after(30, self._animate)

    def _cleanup(self, p):
        for rid in p["rings"]:
            try: self.canvas.delete(rid)
            except: pass
        for key in ("dot","txt","box"):
            try:
                if p[key]: self.canvas.delete(p[key])
            except: pass

    @staticmethod
    def _blend_hex(hex1, hex2, t):
        try:
            r1,g1,b1 = int(hex1[1:3],16),int(hex1[3:5],16),int(hex1[5:7],16)
            r2,g2,b2 = int(hex2[1:3],16),int(hex2[3:5],16),int(hex2[5:7],16)
            r = int(r1+(r2-r1)*t); g = int(g1+(g2-g1)*t); b = int(b1+(b2-b1)*t)
            return f"#{r:02x}{g:02x}{b:02x}"
        except: return hex1


# ── Live Attack Feed Widget ───────────────────────────────────────────────────
class LiveAttackFeed(tk.Frame):
    MAX = 15

    def __init__(self, parent, **kw):
        super().__init__(parent, bg=T["BG2"], **kw)
        tk.Label(self, text="⚡ LIVE ATTACKS", font=("Courier New",8,"bold"),
                 fg=T["RED"], bg=T["BG2"], pady=4).pack(anchor=tk.W, padx=8)
        tk.Frame(self, bg=T["BORDER"], height=1).pack(fill=tk.X)
        self.inner = tk.Frame(self, bg=T["BG2"])
        self.inner.pack(fill=tk.BOTH, expand=True)
        self.rows = []

    def push(self, ip, city, country, svc, ts):
        if len(self.rows) >= self.MAX:
            oldest = self.rows.pop()
            try: oldest.destroy()
            except: pass

        color    = svc_color(svc)
        time_str = ts[11:19] if len(ts) > 11 else ts
        location = f"📍 {city}, {country}" if city and city != "Unknown" else f"📍 {country}"

        row = tk.Frame(self.inner, bg=T["PANEL"], pady=3, padx=6)
        children = self.inner.winfo_children()
        packed_children = [c for c in children if c.winfo_manager() == "pack"]
        if packed_children:
            row.pack(fill=tk.X, padx=4, pady=2, before=packed_children[0])
        else:
            row.pack(fill=tk.X, padx=4, pady=2)

        tk.Label(row, text=f"[{svc}]", font=("Courier New",7,"bold"),
                 fg=color, bg=T["PANEL"], width=8, anchor=tk.W
                 ).grid(row=0, column=0, sticky=tk.W)
        tk.Label(row, text=ip, font=("Courier New",7),
                 fg=T["YELLOW"], bg=T["PANEL"]
                 ).grid(row=0, column=1, sticky=tk.W, padx=(4,0))
        tk.Label(row, text=location, font=("Courier New",7),
                 fg=T["TEAL"], bg=T["PANEL"]
                 ).grid(row=1, column=0, columnspan=2, sticky=tk.W)
        tk.Label(row, text=time_str, font=("Courier New",6),
                 fg=T["FG_DIM"], bg=T["PANEL"]
                 ).grid(row=1, column=2, sticky=tk.E)

        self.rows.insert(0, row)
        self._flash(row, color, 0)

    def _flash(self, row, color, step):
        flash_colors = [color]*2 + [T["PANEL"]]*2
        if step < len(flash_colors):
            try:
                row.configure(bg=flash_colors[step])
                for w in row.winfo_children():
                    try: w.configure(bg=flash_colors[step])
                    except: pass
            except: pass
            self.after(120, lambda: self._flash(row, color, step+1))


# ── Tarpit Session & Monitor ──────────────────────────────────────────────────
class TarpitSession:
    def __init__(self, ip, trap_name, city="Unknown", country="??"):
        self.ip          = ip
        self.trap_name   = trap_name
        self.city        = city
        self.country     = country
        self.start_time  = time.time()
        self.last_seen   = time.time()
        self.bytes_sent  = 0
        self.attempts    = 0
        self.lures_taken = []
        self.creds_captured = []
        self.alive       = True

    def duration_str(self) -> str:
        secs = int(time.time() - self.start_time)
        h, r = divmod(secs, 3600)
        m, s = divmod(r, 60)
        if h: return f"{h}h {m}m {s}s"
        if m: return f"{m}m {s}s"
        return f"{s}s"

    def duration_secs(self) -> int:
        return int(time.time() - self.start_time)


class TarpitMonitor:
    def __init__(self):
        self.sessions          = {}
        self.completed         = []
        self.total_time_wasted = 0
        self.total_connections = 0
        self.total_creds       = []
        self.lure_hits         = defaultdict(int)
        self._lock             = threading.Lock()

    def process_event(self, e: dict) -> TarpitSession:
        ip     = e.get("ip", "unknown")
        trap   = e.get("trap", "unknown")
        status = e.get("status", "activity")
        city   = e.get("city", "Unknown")
        country= e.get("country", "??")

        with self._lock:
            if ip not in self.sessions:
                sess = TarpitSession(ip, trap, city, country)
                self.sessions[ip] = sess
                self.total_connections += 1
            else:
                sess = self.sessions[ip]

            sess.last_seen  = time.time()
            sess.bytes_sent += e.get("bytes_sent", 0)
            sess.attempts   += e.get("attempts", 0)

            if status == "lure":
                lure = e.get("lure", "unknown")
                if lure not in sess.lures_taken:
                    sess.lures_taken.append(lure)
                self.lure_hits[lure] += 1

            if status == "cred":
                u = e.get("username", "")
                p = e.get("password", "")
                if (u, p) not in sess.creds_captured:
                    sess.creds_captured.append((u, p))
                    self.total_creds.append({"ip": ip, "user": u, "pass": p,
                                              "time": datetime.datetime.now().isoformat()})

            if status == "disconnected":
                sess.alive = False
                self.total_time_wasted += sess.duration_secs()
                self.completed.insert(0, sess)
                if len(self.completed) > 100:
                    self.completed.pop()
                del self.sessions[ip]

        return sess

    def active_sessions(self):
        with self._lock:
            return list(self.sessions.values())

    def total_wasted_str(self) -> str:
        secs = self.total_time_wasted + sum(
            s.duration_secs() for s in self.sessions.values())
        h, r = divmod(int(secs), 3600)
        m, s = divmod(r, 60)
        return f"{h}h {m}m {s}s"


TARPIT = TarpitMonitor()

# ── Main App ──────────────────────────────────────────────────────────────────
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🍯  Honeypot Control Center  v2")
        self.geometry("1440x900")
        self.minsize(1200, 750)

        self.theme_name = tk.StringVar(value="dark")
        self._apply_theme("dark")

        self.log_queue   = queue.Queue()
        self.all_events  = []
        self.stats       = defaultdict(int)
        self.ip_counts   = defaultdict(int)
        self.hourly      = defaultdict(int)
        self.svc_counts  = defaultdict(int)
        self.geo_points  = []

        self._tarpit_tree_ids       = {}
        self._tarpit_ticker_running = False

        # ── FIX: Koi bhi service default OFF hogi ──
        self.svc_running = {s: False for s in SVC_MODULES}
        self.svc_ports   = {s: tk.IntVar(value=p) for s, p in
                            [("HTTP",8080),("SSH",2222),("FTP",2121),
                             ("TELNET",2323),("SMTP",2525),("MYSQL",3306)]}

        self.current_filter = "ALL"
        self.ping_animator  = None

        # Screenshot / Discord cooldown tracking
        self._last_discord_alert = {}   # ip → timestamp (per-IP cooldown)
        self._discord_cooldown   = 30   # seconds between same-IP alerts
        self._local_banned = set()

        self._build_ui()
        self._poll_queue()
        self._tick_clock()
        # ── FIX: Koi auto-start / fake inject nahi ──

    # ── Theme ─────────────────────────────────────────────────────────────────
    def _apply_theme(self, name):
        global T
        T = THEMES[name]
        self.configure(bg=T["BG"])

    def toggle_theme(self):
        new = "light" if self.theme_name.get() == "dark" else "dark"
        self.theme_name.set(new)
        self._apply_theme(new)
        messagebox.showinfo("Theme", f"Switched to {new} theme.\nRestart app to fully apply.")

    # ── UI Build ──────────────────────────────────────────────────────────────
    def _build_ui(self):
        top = tk.Frame(self, bg=T["BG"], pady=6)
        top.pack(fill=tk.X, padx=14)
        tk.Label(top, text="🍯  HONEYPOT CONTROL CENTER  v2",
                 font=("Courier New",14,"bold"), fg=T["ACCENT"], bg=T["BG"]).pack(side=tk.LEFT)

        self.live_counter = tk.Label(top, text="⚡ 0 attacks",
                                      font=("Courier New",9,"bold"),
                                      fg=T["RED"], bg=T["BG"])
        self.live_counter.pack(side=tk.LEFT, padx=20)

        self.tarpit_counter = tk.Label(top, text="🕷 0 trapped",
                                        font=("Courier New",9,"bold"),
                                        fg=T["ORANGE"], bg=T["BG"])
        self.tarpit_counter.pack(side=tk.LEFT, padx=8)

        # Discord status indicator
        self.discord_lbl = tk.Label(top, text="🔔 Discord: OFF",
                                     font=("Courier New",8),
                                     fg=T["FG_DIM"], bg=T["BG"])
        self.discord_lbl.pack(side=tk.LEFT, padx=12)

        self.clock_lbl = tk.Label(top, text="", font=("Courier New",9),
                                   fg=T["FG_DIM"], bg=T["BG"])
        self.clock_lbl.pack(side=tk.RIGHT, padx=8)
        tk.Button(top, text="☀ Theme", font=("Courier New",9,"bold"),
                  fg=T["YELLOW"], bg=T["BG3"], bd=0, relief=tk.FLAT, cursor="hand2",
                  command=self.toggle_theme).pack(side=tk.RIGHT, padx=4)

        tk.Frame(self, bg=T["BORDER"], height=1).pack(fill=tk.X)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook", background=T["BG"], borderwidth=0)
        style.configure("TNotebook.Tab", background=T["BG3"], foreground=T["FG_DIM"],
                        font=("Courier New",9,"bold"), padding=[12,5])
        style.map("TNotebook.Tab",
                  background=[("selected", T["PANEL"])],
                  foreground=[("selected", T["ACCENT"])])

        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

        self.tab_dash    = tk.Frame(nb, bg=T["BG"])
        self.tab_map     = tk.Frame(nb, bg=T["BG"])
        self.tab_charts  = tk.Frame(nb, bg=T["BG"])
        self.tab_wc      = tk.Frame(nb, bg=T["BG"])
        self.tab_ml      = tk.Frame(nb, bg=T["BG"])
        self.tab_bans    = tk.Frame(nb, bg=T["BG"])
        self.tab_tarpit  = tk.Frame(nb, bg=T["BG"])
        self.tab_cfg     = tk.Frame(nb, bg=T["BG"])
        self.tab_osint   = tk.Frame(nb, bg=T["BG"])

        nb.add(self.tab_dash,   text="📡  Dashboard")
        nb.add(self.tab_map,    text="🗺  Attack Map")
        nb.add(self.tab_charts, text="📊  Charts")
        nb.add(self.tab_wc,     text="☁  Wordcloud")
        nb.add(self.tab_ml,     text="🤖  ML Threats")
        nb.add(self.tab_bans,   text="🚫  Banned IPs")
        nb.add(self.tab_tarpit, text="🕷️  Tarpit")
        nb.add(self.tab_cfg,    text="⚙  Config")
        nb.add(self.tab_osint,  text="🕵️  OSINT")

        self._build_dashboard()
        self._build_map_tab()
        self._build_charts_tab()
        self._build_wordcloud_tab()
        self._build_ml_tab()
        self._build_bans_tab()
        self._build_tarpit_tab()
        self._build_config_tab()
        self._build_osint_tab()

        bot = tk.Frame(self, bg=T["BG3"], pady=5)
        bot.pack(fill=tk.X, side=tk.BOTTOM)
        self._build_bottom_bar(bot)

    # ── Dashboard Tab ─────────────────────────────────────────────────────────
    def _build_dashboard(self):
        p = self.tab_dash
        left = tk.Frame(p, bg=T["BG2"], width=270)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(6,6), pady=6)
        left.pack_propagate(False)
        self._build_service_panel(left)

        right = tk.Frame(p, bg=T["BG"])
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, pady=6, padx=(0,6))
        self._build_log_panel(right)

    def _build_service_panel(self, parent):
        tk.Label(parent, text="SERVICES", font=("Courier New",8,"bold"),
                 fg=T["FG_DIM"], bg=T["BG2"], pady=6).pack(anchor=tk.W, padx=10)

        self.svc_dot = {}; self.svc_lbl = {}; self.svc_btn = {}

        for svc in ["HTTP","SSH","FTP","TELNET","SMTP","MYSQL"]:
            card = tk.Frame(parent, bg=T["PANEL"], pady=6, padx=8)
            card.pack(fill=tk.X, padx=6, pady=3)
            r1 = tk.Frame(card, bg=T["PANEL"])
            r1.pack(fill=tk.X)
            dot = tk.Label(r1, text="●", font=("Courier New",13),
                           fg=T["FG_DIM"], bg=T["PANEL"])
            dot.pack(side=tk.LEFT)
            tk.Label(r1, text=f"  {svc}", font=("Courier New",10,"bold"),
                     fg=svc_color(svc), bg=T["PANEL"]).pack(side=tk.LEFT)
            sl = tk.Label(r1, text="OFF", font=("Courier New",8,"bold"),
                          fg=T["RED"], bg=T["PANEL"])
            sl.pack(side=tk.RIGHT)
            self.svc_dot[svc] = dot; self.svc_lbl[svc] = sl
            r2 = tk.Frame(card, bg=T["PANEL"])
            r2.pack(fill=tk.X, pady=2)
            tk.Label(r2, text="Port:", font=("Courier New",8),
                     fg=T["FG_DIM"], bg=T["PANEL"]).pack(side=tk.LEFT)
            e = tk.Entry(r2, textvariable=self.svc_ports[svc],
                         font=("Courier New",8), bg=T["BG3"], fg=T["FG"],
                         insertbackground=T["FG"], relief=tk.FLAT, width=7,
                         highlightthickness=1, highlightbackground=T["BORDER"])
            e.pack(side=tk.LEFT, padx=4)
            btn = tk.Button(card, text="▶ START", font=("Courier New",8,"bold"),
                            fg=T["GREEN"], bg=T["BG3"], bd=0, relief=tk.FLAT,
                            cursor="hand2", pady=3,
                            command=lambda s=svc: self.toggle_svc(s))
            btn.pack(fill=tk.X, pady=(3,0))
            self.svc_btn[svc] = btn

        tk.Frame(parent, bg=T["BORDER"], height=1).pack(fill=tk.X, padx=6, pady=8)
        tk.Label(parent, text="STATS", font=("Courier New",8,"bold"),
                 fg=T["FG_DIM"], bg=T["BG2"]).pack(anchor=tk.W, padx=10)
        sc = tk.Frame(parent, bg=T["PANEL"], pady=6, padx=10)
        sc.pack(fill=tk.X, padx=6, pady=3)
        self.stat_w = {}
        for lbl, key in [("Total Events","total"),("Unique IPs","uniq"),
                          ("Banned IPs","banned"),("Decoy Hits","decoy"),
                          ("High Threat","threat"),("Tarpit Trapped","tarpit")]:
            row = tk.Frame(sc, bg=T["PANEL"])
            row.pack(fill=tk.X, pady=1)
            tk.Label(row, text=lbl, font=("Courier New",8),
                     fg=T["FG_DIM"], bg=T["PANEL"]).pack(side=tk.LEFT)
            v = tk.Label(row, text="0", font=("Courier New",9,"bold"),
                         fg=T["ACCENT"] if key != "tarpit" else T["ORANGE"],
                         bg=T["PANEL"])
            v.pack(side=tk.RIGHT)
            self.stat_w[key] = v

        tk.Frame(parent, bg=T["BORDER"], height=1).pack(fill=tk.X, padx=6, pady=6)
        tk.Label(parent, text="TOP ATTACKERS", font=("Courier New",8,"bold"),
                 fg=T["FG_DIM"], bg=T["BG2"]).pack(anchor=tk.W, padx=10)
        ic = tk.Frame(parent, bg=T["PANEL"], pady=4, padx=8)
        ic.pack(fill=tk.X, padx=6)
        self.ip_board = tk.Text(ic, height=7, font=("Courier New",8),
                                bg=T["PANEL"], fg=T["FG"], bd=0, state=tk.DISABLED)
        self.ip_board.pack(fill=tk.X)

    def _build_log_panel(self, parent):
        hdr = tk.Frame(parent, bg=T["BG3"], pady=5, padx=8)
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text="LIVE CAPTURE", font=("Courier New",10,"bold"),
                 fg=T["FG"], bg=T["BG3"]).pack(side=tk.LEFT)
        ff = tk.Frame(hdr, bg=T["BG3"])
        ff.pack(side=tk.RIGHT)
        for tag in ("ALL","HTTP","SSH","FTP","TELNET","SMTP","MYSQL"):
            c = svc_color(tag) if tag != "ALL" else T["FG"]
            tk.Button(ff, text=tag, font=("Courier New",7,"bold"),
                      fg=c, bg=T["BG3"], bd=0, relief=tk.FLAT, cursor="hand2", padx=6,
                      command=lambda t=tag: self.set_filter(t)).pack(side=tk.LEFT, padx=1)

        self.log_txt = tk.Text(parent, font=("Courier New",9),
                                bg=T["BG"], fg=T["FG"], bd=0, relief=tk.FLAT,
                                state=tk.DISABLED, wrap=tk.NONE,
                                padx=8, pady=4, selectbackground=T["BORDER"])
        sy = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.log_txt.yview)
        sx = ttk.Scrollbar(parent, orient=tk.HORIZONTAL, command=self.log_txt.xview)
        self.log_txt.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
        sy.pack(side=tk.RIGHT, fill=tk.Y)
        sx.pack(side=tk.BOTTOM, fill=tk.X)
        self.log_txt.pack(fill=tk.BOTH, expand=True)

        for tag in ["HTTP","SSH","FTP","TELNET","SMTP","MYSQL"]:
            self.log_txt.tag_configure(tag, foreground=svc_color(tag))
        self.log_txt.tag_configure("TS",     foreground=T["FG_DIM"])
        self.log_txt.tag_configure("IP",     foreground=T["YELLOW"])
        self.log_txt.tag_configure("KEY",    foreground=T["PURPLE"])
        self.log_txt.tag_configure("GEO",    foreground=T["TEAL"])
        self.log_txt.tag_configure("THREAT", foreground=T["RED"])
        self.log_txt.tag_configure("DECOY",  foreground=T["ORANGE"])

    # ── Map Tab ───────────────────────────────────────────────────────────────
    def _build_map_tab(self):
        p = self.tab_map
        ctrl = tk.Frame(p, bg=T["BG3"], pady=5, padx=10)
        ctrl.pack(fill=tk.X)
        tk.Label(ctrl, text="🗺  LIVE ATTACK MAP — Real attacks only",
                 font=("Courier New",10,"bold"),
                 fg=T["ACCENT"], bg=T["BG3"]).pack(side=tk.LEFT)
        leg = tk.Frame(ctrl, bg=T["BG3"])
        leg.pack(side=tk.RIGHT)
        for svc in ["HTTP","SSH","FTP","TELNET","SMTP","MYSQL"]:
            tk.Label(leg, text=f"● {svc}", font=("Courier New",7,"bold"),
                     fg=svc_color(svc), bg=T["BG3"]).pack(side=tk.LEFT, padx=4)

        main = tk.Frame(p, bg=T["BG"])
        main.pack(fill=tk.BOTH, expand=True)

        if MAP_OK:
            self.map_widget = tkintermapview.TkinterMapView(main, width=1100, height=680)
            self.map_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=8, pady=8)
            self.map_widget.set_position(20, 0); self.map_widget.set_zoom(2)
        else:
            self.canvas_map = tk.Canvas(main, bg="#0a1628", highlightthickness=0)
            self.canvas_map.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=8, pady=(0,8))
            self._draw_world_outline()
            self.ping_animator = PingAnimator(self.canvas_map, self)

        # FIX: map_markers empty rakhein — koi pre-loaded country nahi
        self.map_markers = {}

        self.live_feed = LiveAttackFeed(main, width=260)
        self.live_feed.pack(side=tk.RIGHT, fill=tk.Y, padx=(0,8), pady=8)
        self.live_feed.pack_propagate(False)

        self.last_attack_bar = tk.Label(p,
            text="⏳ Koi service start karo... Waiting for real attacks",
            font=("Courier New", 8, "bold"),
            fg=T["FG_DIM"], bg=T["BG2"], pady=4, padx=10, anchor=tk.W)
        self.last_attack_bar.pack(fill=tk.X, side=tk.BOTTOM)

    def _draw_world_outline(self):
        w, h = 1100, 600
        self.canvas_map.config(width=w, height=h)
        for i in range(0, w, 55):
            self.canvas_map.create_line(i, 0, i, h, fill="#0f1f3a", width=1)
        for i in range(0, h, 55):
            self.canvas_map.create_line(0, i, w, i, fill="#0f1f3a", width=1)
        self.canvas_map.create_line(0, h//2, w, h//2, fill="#1a2f50", width=1, dash=(4,4))
        self.canvas_map.create_line(w//2, 0, w//2, h, fill="#1a2f50", width=1, dash=(4,4))
        continents = {
            "N.America":  [(120,80),(280,80),(280,260),(200,300),(120,260)],
            "S.America":  [(200,300),(280,300),(260,460),(210,460),(190,380)],
            "Europe":     [(450,60),(560,60),(570,180),(450,190),(430,130)],
            "Africa":     [(450,190),(570,190),(560,410),(480,420),(440,350)],
            "Asia":       [(560,60),(900,60),(930,280),(700,290),(570,180)],
            "Australia":  [(750,330),(870,330),(880,430),(760,430)],
        }
        for name, pts in continents.items():
            scaled = [(x * w // 1100, y * h // 600) for x, y in pts]
            self.canvas_map.create_polygon(scaled, fill="#0d2040", outline="#1a3060", width=1)
        self.canvas_map.create_text(w//2, h-20,
            text="🌍  Live Attack Map  (pip install tkintermapview for full map)",
            fill=T["FG_DIM"], font=("Courier New", 9), justify=tk.CENTER)

    def _fire_live_ping(self, e):
        """
        FIX: Sirf real events pe map update hoga.
        Lat/Lon 0,0 pe kuch show nahi hoga (fake/unknown location).
        """
        geo     = e.get("geo", {})
        lat     = geo.get("lat", 0.0)
        lon     = geo.get("lon", 0.0)
        city    = geo.get("city", geo.get("city_name", "Unknown"))
        country = geo.get("country", geo.get("country_name", "??"))
        ip      = e.get("ip", "")
        svc     = e.get("service", "")
        ts      = e.get("timestamp", datetime.datetime.now().isoformat())

        # FIX: 0,0 coordinate pe kuch mat dikhao (ocean mein nahi girna chahiye)
        if lat == 0.0 and lon == 0.0:
            return

        color = svc_color(svc)
        if MAP_OK and hasattr(self, "map_widget"):
            try:
                marker = self.map_widget.set_marker(lat, lon,
                    text=f"⚡ {svc}\n{ip}\n{city}, {country}",
                    marker_color_circle=color, marker_color_outside=T["BG"])
                self.map_markers[ip] = marker
                self.after(30000, lambda m=marker: self._safe_remove_marker(m))
            except: pass
        elif hasattr(self, "canvas_map") and self.ping_animator:
            cw = self.canvas_map.winfo_width()  or 1100
            ch = self.canvas_map.winfo_height() or 600
            x = int((lon + 180) / 360 * cw)
            y = int((90 - lat) / 180 * ch)
            self.ping_animator.fire(x, y, color, f"{svc} | {ip} | {city}, {country}")

        if hasattr(self, "live_feed"):
            self.live_feed.push(ip, city, country, svc, ts)

        if hasattr(self, "last_attack_bar"):
            t_str = ts[11:19] if len(ts) > 11 else ts
            self.last_attack_bar.configure(
                text=f"⚡ Last: [{t_str}]  {svc}  {ip}  📍 {city}, {country}",
                fg=color)

        if hasattr(self, "live_counter"):
            self.live_counter.configure(text=f"⚡ {self.stats['total']} attacks")

    def _safe_remove_marker(self, marker):
        try: marker.delete()
        except: pass

    # ── Charts Tab ────────────────────────────────────────────────────────────
    def _build_charts_tab(self):
        p = self.tab_charts
        if not MPL_OK:
            tk.Label(p, text="Install matplotlib:\npip install matplotlib",
                     font=("Courier New",11), fg=T["FG_DIM"], bg=T["BG"]).pack(pady=40)
            return
        self.fig = Figure(figsize=(14, 6), facecolor=T["MPL_BG"])
        self.ax1 = self.fig.add_subplot(131)
        self.ax2 = self.fig.add_subplot(132)
        self.ax3 = self.fig.add_subplot(133)
        self._style_axes()
        self.chart_canvas = FigureCanvasTkAgg(self.fig, master=p)
        self.chart_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        tk.Button(p, text="🔄  Refresh Charts", font=("Courier New",9,"bold"),
                  fg=T["ACCENT"], bg=T["BG3"], bd=0, relief=tk.FLAT,
                  cursor="hand2", pady=4, padx=12,
                  command=self.refresh_charts).pack(pady=(0,6))

    def _style_axes(self):
        if not MPL_OK: return
        for ax in (self.ax1, self.ax2, self.ax3):
            ax.set_facecolor(T["MPL_BG"])
            ax.tick_params(colors=T["MPL_FG"], labelsize=8)
            for spine in ax.spines.values(): spine.set_color(T["BORDER"])
            ax.title.set_color(T["MPL_FG"])

    def refresh_charts(self):
        if not MPL_OK or not self.all_events: return
        self.ax1.clear(); self.ax2.clear(); self.ax3.clear()
        self._style_axes()
        svcs = defaultdict(int)
        for e in self.all_events: svcs[e.get("service","?")] += 1
        labels, sizes, clrs = [], [], []
        for s, c in svcs.items():
            labels.append(s); sizes.append(c); clrs.append(svc_color(s))
        if sizes:
            self.ax1.pie(sizes, labels=labels, colors=clrs, autopct="%1.0f%%",
                         textprops={"color": T["MPL_FG"], "fontsize": 8})
            self.ax1.set_title("By Service", color=T["MPL_FG"])
        hours = defaultdict(int)
        for e in self.all_events:
            h = e.get("timestamp","00:00:00")[11:13]
            hours[h] += 1
        if hours:
            ks = sorted(hours.keys()); vs = [hours[k] for k in ks]
            self.ax2.bar(ks, vs, color=T["ACCENT"], alpha=0.85)
            self.ax2.set_title("Hourly Attacks", color=T["MPL_FG"])
            for tick in self.ax2.get_xticklabels(): tick.set_rotation(45)
        top_ips = sorted(self.ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        if top_ips:
            ips, cnts = zip(*top_ips)
            y_pos = range(len(ips))
            self.ax3.barh(list(y_pos), list(cnts), color=T["RED"], alpha=0.85)
            self.ax3.set_yticks(list(y_pos))
            self.ax3.set_yticklabels([i[-12:] for i in ips], fontsize=7)
            self.ax3.set_title("Top Attackers", color=T["MPL_FG"])
            self.ax3.invert_yaxis()
        self.fig.tight_layout()
        self.chart_canvas.draw()

    # ── Wordcloud Tab ─────────────────────────────────────────────────────────
    def _build_wordcloud_tab(self):
        p = self.tab_wc
        hdr = tk.Frame(p, bg=T["BG3"], pady=6, padx=10)
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text="☁  PASSWORD WORDCLOUD", font=("Courier New",10,"bold"),
                 fg=T["ACCENT"], bg=T["BG3"]).pack(side=tk.LEFT)
        btn_frame = tk.Frame(hdr, bg=T["BG3"])
        btn_frame.pack(side=tk.RIGHT)
        self._wc_mode = tk.StringVar(value="passwords")
        tk.Radiobutton(btn_frame, text="Passwords", variable=self._wc_mode, value="passwords",
                       font=("Courier New",8), fg=T["RED"], bg=T["BG3"], selectcolor=T["PANEL"],
                       activebackground=T["BG3"], command=self.refresh_wordcloud).pack(side=tk.LEFT, padx=4)
        tk.Radiobutton(btn_frame, text="Usernames", variable=self._wc_mode, value="usernames",
                       font=("Courier New",8), fg=T["GREEN"], bg=T["BG3"], selectcolor=T["PANEL"],
                       activebackground=T["BG3"], command=self.refresh_wordcloud).pack(side=tk.LEFT, padx=4)
        tk.Button(btn_frame, text="🔄 Refresh", font=("Courier New",8,"bold"),
                  fg=T["ACCENT"], bg=T["BG3"], bd=0, relief=tk.FLAT, cursor="hand2", padx=8,
                  command=self.refresh_wordcloud).pack(side=tk.LEFT, padx=6)
        tk.Button(btn_frame, text="💾 Save PNG", font=("Courier New",8,"bold"),
                  fg=T["TEAL"], bg=T["BG3"], bd=0, relief=tk.FLAT, cursor="hand2", padx=8,
                  command=self.save_wordcloud).pack(side=tk.LEFT, padx=2)

        main = tk.Frame(p, bg=T["BG"])
        main.pack(fill=tk.BOTH, expand=True)
        if MPL_OK:
            self.wc_fig = Figure(figsize=(10, 6), facecolor=T["MPL_BG"])
            self.wc_ax  = self.wc_fig.add_subplot(111)
            self.wc_ax.set_facecolor(T["MPL_BG"]); self.wc_ax.axis("off")
            self.wc_canvas = FigureCanvasTkAgg(self.wc_fig, master=main)
            self.wc_canvas.get_tk_widget().pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=8, pady=8)
        else:
            tk.Label(main, text="pip install matplotlib", fg=T["FG_DIM"], bg=T["BG"],
                     font=("Courier New",10)).pack(side=tk.LEFT, expand=True)
        right = tk.Frame(main, bg=T["BG2"], width=220)
        right.pack(side=tk.RIGHT, fill=tk.Y, padx=(0,8), pady=8)
        right.pack_propagate(False)
        tk.Label(right, text="TOP 20", font=("Courier New",8,"bold"),
                 fg=T["FG_DIM"], bg=T["BG2"], pady=6).pack(anchor=tk.W, padx=8)
        tk.Frame(right, bg=T["BORDER"], height=1).pack(fill=tk.X)
        self.wc_list = tk.Text(right, font=("Courier New",8), bg=T["BG2"], fg=T["FG"],
                                bd=0, state=tk.DISABLED, padx=8, pady=4)
        self.wc_list.pack(fill=tk.BOTH, expand=True)
        self.wc_status = tk.Label(p, text="No data yet", font=("Courier New",8),
                                   fg=T["FG_DIM"], bg=T["BG2"], pady=3, anchor=tk.W, padx=10)
        self.wc_status.pack(fill=tk.X, side=tk.BOTTOM)
        if MPL_OK:
            self.wc_ax.text(0.5, 0.5, "No data yet\nStart honeypot to capture passwords",
                ha="center", va="center", fontsize=12, color=T["FG_DIM"],
                transform=self.wc_ax.transAxes, fontfamily="monospace")
            self.wc_canvas.draw()

    def refresh_wordcloud(self):
        if not MPL_OK: return
        mode = self._wc_mode.get()
        words = []
        for e in self.all_events:
            w = e.get("password","") if mode=="passwords" else e.get("username","")
            if w: words.append(w.strip())

        self.wc_ax.clear()
        self.wc_ax.set_facecolor(T["MPL_BG"]); self.wc_ax.axis("off")

        if not words:
            self.wc_ax.text(0.5, 0.5, f"No {mode} captured yet",
                ha="center", va="center", fontsize=14, color=T["FG_DIM"],
                transform=self.wc_ax.transAxes)
            self.wc_canvas.draw()
            return

        freq = defaultdict(int)
        for w in words: freq[w] += 1

        if WC_OK:
            try:
                wc = WordCloud(width=900, height=500, background_color="#13161e",
                               colormap="autumn" if mode=="passwords" else "cool",
                               max_words=150, prefer_horizontal=0.85, min_font_size=8)
                wc.generate_from_frequencies(dict(freq))
                self.wc_ax.imshow(wc, interpolation="bilinear")
                self.wc_ax.axis("off")
                self._wc_image = wc
            except Exception:
                self._draw_manual_wordcloud(freq, mode)
        else:
            self._draw_manual_wordcloud(freq, mode)

        self.wc_fig.tight_layout(pad=0)
        self.wc_canvas.draw()

        top20 = sorted(freq.items(), key=lambda x: x[1], reverse=True)[:20]
        self.wc_list.configure(state=tk.NORMAL)
        self.wc_list.delete("1.0", tk.END)
        for i, (word, count) in enumerate(top20, 1):
            bar = "█" * min(count, 20)
            self.wc_list.insert(tk.END, f"{i:>2}. {word:<20} {count:>4}\n")
            self.wc_list.insert(tk.END, f"    {bar}\n\n")
        self.wc_list.configure(state=tk.DISABLED)
        if top20:
            self.wc_status.configure(text=f"{len(words)} captured, {len(freq)} unique | Top: {top20[0][0]} ({top20[0][1]}x)")

    def _draw_manual_wordcloud(self, freq, mode):
        import random
        top = sorted(freq.items(), key=lambda x: x[1], reverse=True)[:60]
        if not top: return
        max_count = top[0][1]
        palette = [T["RED"],T["ORANGE"],T["YELLOW"],T["ACCENT"],T["TEAL"]]
        self.wc_ax.set_xlim(0,10); self.wc_ax.set_ylim(0,6)
        placed = []; rng = random.Random(42)
        for word, count in top:
            size  = 6 + (count/max_count)*28
            color = rng.choice(palette)
            for _ in range(50):
                x = rng.uniform(0.5,9.5); y = rng.uniform(0.3,5.7)
                ok = all(math.hypot(x-px,y-py) >= (size+ps)/40 for px,py,ps in placed)
                if ok:
                    self.wc_ax.text(x, y, word, fontsize=size, color=color,
                                     ha="center", va="center",
                                     fontweight="bold" if count>max_count*0.5 else "normal",
                                     alpha=0.85)
                    placed.append((x, y, size)); break

    def save_wordcloud(self):
        if not MPL_OK: messagebox.showinfo("Save","matplotlib nahi hai."); return
        mode = self._wc_mode.get()
        fn   = f"wordcloud_{mode}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        path = filedialog.asksaveasfilename(defaultextension=".png", initialfile=fn,
                                             filetypes=[("PNG","*.png")])
        if not path: return
        try:
            self.wc_fig.savefig(path, facecolor=T["MPL_BG"], dpi=150, bbox_inches="tight")
            messagebox.showinfo("Saved", f"Wordcloud saved:\n{path}")
        except Exception as ex:
            messagebox.showerror("Save Error", str(ex))

    # ── Screenshots ───────────────────────────────────────────────────────────
    _ss_counter = 0; _ss_every_n = 0   # FIX: 0 = auto screenshot band; sirf threat pe
    _ss_on_threat = True

    def take_screenshot(self, reason="attack"):
        if not PIL_OK: return
        def _capture():
            try:
                time.sleep(0.15)
                x=self.winfo_rootx(); y=self.winfo_rooty()
                w=self.winfo_width(); h=self.winfo_height()
                ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                fn = os.path.join(SCREENSHOT_DIR, f"honeypot_{reason}_{ts}.png")
                ImageGrab.grab(bbox=(x,y,x+w,y+h)).save(fn)
                self.after(0, lambda: self._status(f"📸 Screenshot → {fn}"))
            except Exception as ex:
                print(f"[Screenshot] Error: {ex}")
        threading.Thread(target=_capture, daemon=True).start()

    # ── ML Threats Tab ────────────────────────────────────────────────────────
    def _build_ml_tab(self):
        p = self.tab_ml
        hdr = tk.Frame(p, bg=T["BG3"], pady=6, padx=10)
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text="🤖  ML PAYLOAD ANALYSIS & THREAT SCORING",
                 font=("Courier New",10,"bold"), fg=T["ACCENT"], bg=T["BG3"]).pack(side=tk.LEFT)
        tk.Button(hdr, text="🔄 Refresh", font=("Courier New",8,"bold"),
                  fg=T["ACCENT"], bg=T["BG3"], bd=0, relief=tk.FLAT,
                  cursor="hand2", command=self.refresh_ml_tab).pack(side=tk.RIGHT)

        summary = tk.Frame(p, bg=T["BG2"], pady=6)
        summary.pack(fill=tk.X, padx=8, pady=(6,0))
        self.ml_stat = {}
        for label, color, key in [("🟢 SAFE",T["GREEN"],"SAFE"),
                                    ("🟡 SUSPICIOUS",T["YELLOW"],"SUSPICIOUS"),
                                    ("🟠 HIGH",T["ORANGE"],"HIGH"),
                                    ("🔴 CRITICAL",T["RED"],"CRITICAL")]:
            col = tk.Frame(summary, bg=T["PANEL"], padx=12, pady=6)
            col.pack(side=tk.LEFT, padx=4)
            tk.Label(col, text=label, font=("Courier New",8,"bold"), fg=color, bg=T["PANEL"]).pack()
            v = tk.Label(col, text="0", font=("Courier New",14,"bold"), fg=color, bg=T["PANEL"])
            v.pack(); self.ml_stat[key] = v

        cols = ("Time","Service","IP","City","Score","Label","Top Reason")
        self.ml_tree = ttk.Treeview(p, columns=cols, show="headings", height=18)
        widths = [90,70,130,120,60,90,280]
        for c, w in zip(cols, widths):
            self.ml_tree.heading(c, text=c); self.ml_tree.column(c, width=w)
        for tag, fg in [("CRITICAL",T["RED"]),("HIGH",T["ORANGE"]),
                         ("SUSPICIOUS",T["YELLOW"]),("SAFE",T["GREEN"])]:
            self.ml_tree.tag_configure(tag, foreground=fg)
        sb = ttk.Scrollbar(p, orient=tk.VERTICAL, command=self.ml_tree.yview)
        self.ml_tree.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y, padx=(0,4))
        self.ml_tree.pack(fill=tk.BOTH, expand=True, padx=(8,0), pady=6)

        detail_frame = tk.Frame(p, bg=T["BG3"], pady=4)
        detail_frame.pack(fill=tk.X, side=tk.BOTTOM)
        self.ml_detail = tk.Label(detail_frame, text="Click any row for ML analysis",
                                   font=("Courier New",8), fg=T["TEAL"], bg=T["BG3"], anchor=tk.W)
        self.ml_detail.pack(fill=tk.X, padx=10)
        self.ml_tree.bind("<<TreeviewSelect>>", self._on_ml_select)

    def refresh_ml_tab(self):
        for row in self.ml_tree.get_children(): self.ml_tree.delete(row)
        counts = {"SAFE":0,"SUSPICIOUS":0,"HIGH":0,"CRITICAL":0}
        for e in sorted(self.all_events, key=lambda e: e.get("ml_score",0), reverse=True)[:200]:
            ml_label = e.get("ml_label","SAFE"); ml_score = e.get("ml_score",0)
            ml_reasons = e.get("ml_reasons",[])
            geo = e.get("geo",{}); city = geo.get("city","?")[:14]
            ts  = e.get("timestamp","")[:16]
            top_reason = ml_reasons[0] if ml_reasons else "—"
            emoji = ML.label_to_emoji(ml_label)
            counts[ml_label] = counts.get(ml_label,0)+1
            self.ml_tree.insert("","end",
                values=(ts,e.get("service",""),e.get("ip",""),city,
                        f"{emoji} {ml_score}",ml_label,top_reason),
                tags=(ml_label,))
        for key, widget in self.ml_stat.items():
            widget.configure(text=str(counts.get(key,0)))

    def _on_ml_select(self, event):
        sel = self.ml_tree.selection()
        if not sel: return
        vals = self.ml_tree.item(sel[0],"values")
        if not vals: return
        ts_val, ip_val = vals[0], vals[2]
        for e in self.all_events:
            if e.get("ip")==ip_val and e.get("timestamp","")[:16]==ts_val:
                reasons = e.get("ml_reasons",[]); score = e.get("ml_score",0)
                detail = (f"Score:{score} | {e.get('ml_label','')} | "
                          f"{' | '.join(reasons) if reasons else 'No threats'}")
                self.ml_detail.configure(text=detail[:200]); break

    # ── Tarpit Tab ────────────────────────────────────────────────────────────
    def _build_tarpit_tab(self):
        p = self.tab_tarpit
        hdr = tk.Frame(p, bg=T["BG3"], pady=6, padx=10)
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text="🕷️  TARPIT MONITOR — Hacker Time Waste Tracker",
                 font=("Courier New",10,"bold"), fg=T["ORANGE"], bg=T["BG3"]).pack(side=tk.LEFT)
        tk.Button(hdr, text="🔄 Refresh", font=("Courier New",8,"bold"),
                  fg=T["ACCENT"], bg=T["BG3"], bd=0, relief=tk.FLAT,
                  cursor="hand2", command=self.refresh_tarpit_tab).pack(side=tk.RIGHT, padx=4)
        tk.Button(hdr, text="💾 Export Creds", font=("Courier New",8,"bold"),
                  fg=T["TEAL"], bg=T["BG3"], bd=0, relief=tk.FLAT,
                  cursor="hand2", command=self._export_tarpit_creds).pack(side=tk.RIGHT, padx=4)

        stats_bar = tk.Frame(p, bg=T["BG2"], pady=8)
        stats_bar.pack(fill=tk.X, padx=8, pady=(6,0))
        self._tp_stat = {}
        for label, key, color in [
            ("⏱ Total Time Wasted",   "time_wasted",  T["ORANGE"]),
            ("🕸 Active Sessions",     "active",       T["RED"]),
            ("📦 Total Connections",   "connections",  T["YELLOW"]),
            ("🎣 Lures Taken",         "lures",        T["TEAL"]),
            ("🔑 Fake Creds Captured", "creds",        T["PURPLE"]),
        ]:
            col = tk.Frame(stats_bar, bg=T["PANEL"], padx=14, pady=8)
            col.pack(side=tk.LEFT, padx=5)
            tk.Label(col, text=label, font=("Courier New",8), fg=T["FG_DIM"], bg=T["PANEL"]).pack()
            v = tk.Label(col, text="0" if key != "time_wasted" else "0h 0m 0s",
                          font=("Courier New",13,"bold"), fg=color, bg=T["PANEL"])
            v.pack()
            self._tp_stat[key] = v

        main = tk.Frame(p, bg=T["BG"])
        main.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

        left_frame = tk.Frame(main, bg=T["BG"])
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tk.Label(left_frame, text="🔴 ACTIVE TRAPPED SESSIONS",
                 font=("Courier New",9,"bold"), fg=T["RED"], bg=T["BG"], pady=4).pack(anchor=tk.W)

        active_cols = ("IP", "Trap Type", "City/Country", "Duration", "Attempts", "Bytes Wasted", "Lures")
        self.tarpit_active_tree = ttk.Treeview(left_frame, columns=active_cols, show="headings", height=8)
        col_widths = [130, 120, 140, 90, 70, 100, 180]
        for c, w in zip(active_cols, col_widths):
            self.tarpit_active_tree.heading(c, text=c); self.tarpit_active_tree.column(c, width=w)
        self.tarpit_active_tree.tag_configure("active", foreground=T["RED"])
        self.tarpit_active_tree.tag_configure("lured",  foreground=T["ORANGE"])
        sb1 = ttk.Scrollbar(left_frame, orient=tk.VERTICAL, command=self.tarpit_active_tree.yview)
        self.tarpit_active_tree.configure(yscrollcommand=sb1.set)
        sb1.pack(side=tk.RIGHT, fill=tk.Y)
        self.tarpit_active_tree.pack(fill=tk.BOTH, expand=False, pady=(0,8))

        tk.Label(left_frame, text="✅ COMPLETED SESSIONS (Hackers gave up)",
                 font=("Courier New",9,"bold"), fg=T["GREEN"], bg=T["BG"], pady=4).pack(anchor=tk.W)

        done_cols = ("IP", "Trap", "City", "Duration", "Attempts", "Lures Taken", "Creds Given")
        self.tarpit_done_tree = ttk.Treeview(left_frame, columns=done_cols, show="headings", height=7)
        for c in done_cols:
            self.tarpit_done_tree.heading(c, text=c); self.tarpit_done_tree.column(c, width=110)
        self.tarpit_done_tree.tag_configure("done", foreground=T["GREEN"])
        sb2 = ttk.Scrollbar(left_frame, orient=tk.VERTICAL, command=self.tarpit_done_tree.yview)
        self.tarpit_done_tree.configure(yscrollcommand=sb2.set)
        sb2.pack(side=tk.RIGHT, fill=tk.Y)
        self.tarpit_done_tree.pack(fill=tk.BOTH, expand=True)

        right_panel = tk.Frame(main, bg=T["BG2"], width=300)
        right_panel.pack(side=tk.RIGHT, fill=tk.Y, padx=(8,0))
        right_panel.pack_propagate(False)

        tk.Label(right_panel, text="🔑 CAPTURED FAKE CREDENTIALS",
                 font=("Courier New",8,"bold"), fg=T["PURPLE"], bg=T["BG2"], pady=6).pack(anchor=tk.W, padx=8)
        tk.Frame(right_panel, bg=T["BORDER"], height=1).pack(fill=tk.X)
        self.tarpit_creds_text = tk.Text(right_panel, font=("Courier New",8),
                                          bg=T["BG2"], fg=T["FG"], bd=0, state=tk.DISABLED, padx=8, pady=4, height=12)
        self.tarpit_creds_text.pack(fill=tk.X)

        tk.Frame(right_panel, bg=T["BORDER"], height=1).pack(fill=tk.X, pady=4)
        tk.Label(right_panel, text="🎣 LURE HIT STATS",
                 font=("Courier New",8,"bold"), fg=T["TEAL"], bg=T["BG2"], pady=4).pack(anchor=tk.W, padx=8)
        self.tarpit_lure_text = tk.Text(right_panel, font=("Courier New",8),
                                         bg=T["BG2"], fg=T["FG"], bd=0, state=tk.DISABLED, padx=8, pady=4, height=8)
        self.tarpit_lure_text.pack(fill=tk.BOTH, expand=True)

        tk.Label(p, text="TARPIT EVENT LOG", font=("Courier New",8,"bold"),
                 fg=T["FG_DIM"], bg=T["BG"], pady=3).pack(anchor=tk.W, padx=14)
        self.tarpit_log = tk.Text(p, font=("Courier New",8), height=5,
                                   bg=T["BG"], fg=T["FG"], bd=0, state=tk.DISABLED, padx=8, pady=4)
        self.tarpit_log.tag_configure("connected",    foreground=T["RED"])
        self.tarpit_log.tag_configure("lure",         foreground=T["ORANGE"])
        self.tarpit_log.tag_configure("cred",         foreground=T["PURPLE"])
        self.tarpit_log.tag_configure("disconnected", foreground=T["GREEN"])
        self.tarpit_log.tag_configure("ts",           foreground=T["FG_DIM"])
        self.tarpit_log.pack(fill=tk.X, padx=8, pady=(0,4))

        self._start_tarpit_ticker()

    def _start_tarpit_ticker(self):
        if not self._tarpit_ticker_running:
            self._tarpit_ticker_running = True
            self._tarpit_tick()

    def _tarpit_tick(self):
        try:
            active = TARPIT.active_sessions()
            for sess in active:
                item_id = self._tarpit_tree_ids.get(sess.ip)
                if item_id:
                    try:
                        vals = list(self.tarpit_active_tree.item(item_id, "values"))
                        vals[3] = sess.duration_str()
                        self.tarpit_active_tree.item(item_id, values=vals)
                    except tk.TclError: pass
            if hasattr(self, "_tp_stat"):
                self._tp_stat["time_wasted"].configure(text=TARPIT.total_wasted_str())
                self._tp_stat["active"].configure(text=str(len(active)))
        except Exception: pass
        self.after(1000, self._tarpit_tick)

    def _on_tarpit_event(self, e: dict):
        sess   = TARPIT.process_event(e)
        status = e.get("status", "activity")
        ip     = e.get("ip", "")
        trap   = e.get("trap", "")
        ts     = datetime.datetime.now().strftime("%H:%M:%S")

        if status in ("connected", "activity", "lure", "cred"):
            existing  = self._tarpit_tree_ids.get(ip)
            lures_str = ", ".join(sess.lures_taken) if sess.lures_taken else "—"
            tag       = "lured" if sess.lures_taken else "active"
            vals      = (ip, trap, f"{sess.city}, {sess.country}",
                         sess.duration_str(), str(sess.attempts), f"{sess.bytes_sent:,} B", lures_str)
            if existing:
                try: self.tarpit_active_tree.item(existing, values=vals, tags=(tag,))
                except tk.TclError: existing = None
            if not existing:
                item_id = self.tarpit_active_tree.insert("","end", values=vals, tags=(tag,))
                self._tarpit_tree_ids[ip] = item_id

        elif status == "disconnected":
            item_id = self._tarpit_tree_ids.pop(ip, None)
            if item_id:
                try: self.tarpit_active_tree.delete(item_id)
                except: pass
            lures_str = ", ".join(sess.lures_taken) if sess.lures_taken else "—"
            self.tarpit_done_tree.insert("","0",
                values=(ip, trap, sess.city, sess.duration_str(), str(sess.attempts),
                        lures_str, f"{len(sess.creds_captured)} sets"),
                tags=("done",))

        self.tarpit_log.configure(state=tk.NORMAL)
        icons = {"connected":"🔴","activity":"⚙","lure":"🎣","cred":"🔑","disconnected":"✅"}
        icon  = icons.get(status, "·")
        self.tarpit_log.insert(tk.END, f"[{ts}] ", "ts")
        self.tarpit_log.insert(tk.END, f"{icon} [{trap}] {ip}",
                                status if status in ("connected","lure","cred","disconnected") else "ts")
        if status == "lure":
            self.tarpit_log.insert(tk.END, f" → LURE: {e.get('lure','?')}", "lure")
        elif status == "cred":
            self.tarpit_log.insert(tk.END, f" → CRED: {e.get('username','')} / {e.get('password','')}", "cred")
        elif status == "disconnected":
            self.tarpit_log.insert(tk.END, f" → ESCAPED after {sess.duration_str()}", "disconnected")
        self.tarpit_log.insert(tk.END, "\n")
        self.tarpit_log.see(tk.END)
        self.tarpit_log.configure(state=tk.DISABLED)

        if status == "cred" and TARPIT.total_creds:
            self.tarpit_creds_text.configure(state=tk.NORMAL)
            self.tarpit_creds_text.delete("1.0", tk.END)
            for item in TARPIT.total_creds[-20:]:
                self.tarpit_creds_text.insert(tk.END,
                    f"[{item['time'][11:19]}] {item['ip']}\n  👤 {item['user']} / 🔑 {item['pass']}\n\n")
            self.tarpit_creds_text.configure(state=tk.DISABLED)

        if TARPIT.lure_hits:
            self.tarpit_lure_text.configure(state=tk.NORMAL)
            self.tarpit_lure_text.delete("1.0", tk.END)
            for lure, count in sorted(TARPIT.lure_hits.items(), key=lambda x: x[1], reverse=True):
                bar = "█" * min(count, 15)
                self.tarpit_lure_text.insert(tk.END, f"{lure[:18]:<18} {count:>3}x\n{bar}\n\n")
            self.tarpit_lure_text.configure(state=tk.DISABLED)

        self._tp_stat["connections"].configure(text=str(TARPIT.total_connections))
        self._tp_stat["lures"].configure(text=str(sum(TARPIT.lure_hits.values())))
        self._tp_stat["creds"].configure(text=str(len(TARPIT.total_creds)))
        self._tp_stat["time_wasted"].configure(text=TARPIT.total_wasted_str())

        if "tarpit" in self.stat_w:
            self.stat_w["tarpit"].configure(text=str(TARPIT.total_connections))
        if hasattr(self, "tarpit_counter"):
            self.tarpit_counter.configure(
                text=f"🕷 {len(TARPIT.active_sessions())} trapped ({TARPIT.total_wasted_str()} wasted)")

    def refresh_tarpit_tab(self):
        for row in self.tarpit_active_tree.get_children():
            self.tarpit_active_tree.delete(row)
        self._tarpit_tree_ids.clear()
        for sess in TARPIT.active_sessions():
            lures_str = ", ".join(sess.lures_taken) if sess.lures_taken else "—"
            tag = "lured" if sess.lures_taken else "active"
            item_id = self.tarpit_active_tree.insert("","end",
                values=(sess.ip, sess.trap_name, f"{sess.city}, {sess.country}",
                        sess.duration_str(), str(sess.attempts), f"{sess.bytes_sent:,} B", lures_str),
                tags=(tag,))
            self._tarpit_tree_ids[sess.ip] = item_id
        for row in self.tarpit_done_tree.get_children():
            self.tarpit_done_tree.delete(row)
        for sess in TARPIT.completed[:50]:
            lures_str = ", ".join(sess.lures_taken) if sess.lures_taken else "—"
            self.tarpit_done_tree.insert("","end",
                values=(sess.ip, sess.trap_name, sess.city,
                        sess.duration_str(), str(sess.attempts),
                        lures_str, f"{len(sess.creds_captured)} sets"),
                tags=("done",))
        self._tp_stat["connections"].configure(text=str(TARPIT.total_connections))
        self._tp_stat["lures"].configure(text=str(sum(TARPIT.lure_hits.values())))
        self._tp_stat["creds"].configure(text=str(len(TARPIT.total_creds)))
        self._tp_stat["active"].configure(text=str(len(TARPIT.active_sessions())))
        self._tp_stat["time_wasted"].configure(text=TARPIT.total_wasted_str())

    def _export_tarpit_creds(self):
        if not TARPIT.total_creds:
            messagebox.showinfo("Export", "No credentials captured yet."); return
        fn   = f"tarpit_creds_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        path = filedialog.asksaveasfilename(defaultextension=".json", initialfile=fn,
                                             filetypes=[("JSON","*.json")])
        if not path: return
        try:
            with open(path, "w") as f: json.dump(TARPIT.total_creds, f, indent=2)
            messagebox.showinfo("Exported", f"Credentials saved:\n{path}")
        except Exception as ex:
            messagebox.showerror("Export Error", str(ex))

    # ── OSINT Tab ─────────────────────────────────────────────────────────────
    def _build_osint_tab(self):
        p = self.tab_osint
        top_frame = tk.Frame(p, bg=T["BG3"], pady=8, padx=10)
        top_frame.pack(fill=tk.X, padx=8, pady=6)
        tk.Label(top_frame, text="Target IP:", font=("Courier New",9,"bold"),
                 fg=T["FG"], bg=T["BG3"]).pack(side=tk.LEFT, padx=(0,8))
        self.osint_ip_var = tk.StringVar()
        ip_entry = tk.Entry(top_frame, textvariable=self.osint_ip_var,
                            font=("Courier New",9), width=18,
                            bg=T["BG2"], fg=T["FG"], insertbackground=T["FG"])
        ip_entry.pack(side=tk.LEFT, padx=4)
        tk.Button(top_frame, text="🔍 LOOKUP", font=("Courier New",8,"bold"),
                  fg=T["ACCENT"], bg=T["PANEL"], bd=0, relief=tk.FLAT,
                  cursor="hand2", padx=8, pady=2,
                  command=self._osint_lookup).pack(side=tk.LEFT, padx=8)
        tk.Button(top_frame, text="📋 Copy IP", font=("Courier New",7,"bold"),
                  fg=T["TEAL"], bg=T["BG3"], bd=0, relief=tk.FLAT, cursor="hand2",
                  padx=6, pady=2,
                  command=lambda: self.clipboard_clear() or self.clipboard_append(self.osint_ip_var.get())
                  ).pack(side=tk.LEFT, padx=4)
        tk.Button(top_frame, text="🚫 Block IP", font=("Courier New",7,"bold"),
                  fg=T["RED"], bg=T["BG3"], bd=0, relief=tk.FLAT, cursor="hand2",
                  padx=6, pady=2, command=self._block_ip_from_osint).pack(side=tk.LEFT, padx=4)

        osint_nb = ttk.Notebook(p)
        osint_nb.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

        res_frame = tk.Frame(osint_nb, bg=T["BG"])
        osint_nb.add(res_frame, text="📄 Intel Results")
        self.osint_text = tk.Text(res_frame, font=("Courier New",9), bg=T["BG"], fg=T["FG"],
                                   wrap=tk.WORD, bd=0, state=tk.DISABLED,
                                   padx=10, pady=6, selectbackground=T["BORDER"])
        sy = ttk.Scrollbar(res_frame, orient=tk.VERTICAL, command=self.osint_text.yview)
        self.osint_text.configure(yscrollcommand=sy.set)
        sy.pack(side=tk.RIGHT, fill=tk.Y)
        self.osint_text.pack(fill=tk.BOTH, expand=True)

        hist_frame = tk.Frame(osint_nb, bg=T["BG"])
        osint_nb.add(hist_frame, text="📜 Attack History")
        cols = ("Time","Service","User","Password","Path/Command","Threat")
        self.osint_history = ttk.Treeview(hist_frame, columns=cols, show="headings", height=15)
        for c in cols:
            self.osint_history.heading(c, text=c); self.osint_history.column(c, width=100)
        self.osint_history.column("Path/Command", width=250); self.osint_history.column("Threat", width=60)
        self.osint_history.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        sb2 = ttk.Scrollbar(hist_frame, orient=tk.VERTICAL, command=self.osint_history.yview)
        self.osint_history.configure(yscrollcommand=sb2.set); sb2.pack(side=tk.RIGHT, fill=tk.Y)

        fp_frame = tk.Frame(osint_nb, bg=T["BG"])
        osint_nb.add(fp_frame, text="🖥️ Fingerprints")
        self.osint_fp = tk.Text(fp_frame, font=("Courier New",9), bg=T["BG"], fg=T["FG"],
                                 wrap=tk.WORD, bd=0, state=tk.DISABLED, padx=10, pady=6)
        sy3 = ttk.Scrollbar(fp_frame, orient=tk.VERTICAL, command=self.osint_fp.yview)
        self.osint_fp.configure(yscrollcommand=sy3.set); sy3.pack(side=tk.RIGHT, fill=tk.Y)
        self.osint_fp.pack(fill=tk.BOTH, expand=True)

        self.osint_status = tk.Label(p, text="Enter IP and click LOOKUP",
                                     font=("Courier New",8), fg=T["FG_DIM"],
                                     bg=T["BG2"], pady=2, anchor=tk.W, padx=10)
        self.osint_status.pack(fill=tk.X, side=tk.BOTTOM)

    def _osint_lookup(self):
        ip = self.osint_ip_var.get().strip()
        if not ip: messagebox.showwarning("OSINT", "Enter an IP address"); return
        self.osint_text.configure(state=tk.NORMAL)
        self.osint_text.delete("1.0", tk.END)
        self.osint_text.configure(state=tk.DISABLED)
        for row in self.osint_history.get_children(): self.osint_history.delete(row)
        self.osint_fp.configure(state=tk.NORMAL)
        self.osint_fp.delete("1.0", tk.END); self.osint_fp.configure(state=tk.DISABLED)
        self.osint_status.configure(text=f"⏳ Looking up {ip}...")

        def _lookup_thread():
            results = []
            if WHOIS_OK:
                try:
                    w = whois.whois(ip)
                    results += [f"🏛️ WHOIS\n{'-'*40}",
                                f"Registrar: {w.registrar}",
                                f"Creation: {w.creation_date}",
                                f"Name servers: {w.name_servers}\n"]
                except Exception as e:
                    results.append(f"WHOIS error: {e}\n")
            geo = GEO.lookup(ip)
            if geo:
                results += [f"🌍 GeoIP\n{'-'*40}",
                            f"Country: {geo.get('country','Unknown')} ({geo.get('country_iso','??')})",
                            f"City: {geo.get('city','Unknown')}",
                            f"ISP: {geo.get('isp','Unknown')}",
                            f"Source: {geo.get('source','Unknown')}\n"]
            tarpit_events = [c for c in TARPIT.total_creds if c.get("ip") == ip]
            if tarpit_events:
                results.append(f"🕷️ TARPIT HISTORY\n{'-'*40}")
                results.append(f"Captured {len(tarpit_events)} credential sets from this IP:")
                for ce in tarpit_events:
                    results.append(f"  [{ce['time'][11:19]}] {ce['user']} / {ce['pass']}")
                results.append("")
            try:
                import socket
                host = socket.gethostbyaddr(ip)[0]
                results += [f"🔁 Reverse DNS\n{'-'*40}", f"Hostname: {host}\n"]
            except: pass
            self.after(0, lambda: self._update_osint_results(results, ip))
        threading.Thread(target=_lookup_thread, daemon=True).start()

    def _update_osint_results(self, results, ip):
        self.osint_text.configure(state=tk.NORMAL)
        self.osint_text.insert(tk.END, "\n".join(results))
        self.osint_text.configure(state=tk.DISABLED)
        for e in self.all_events:
            if e.get("ip") == ip:
                ts = e.get("timestamp","")[11:19]; svc = e.get("service","")
                user = e.get("username",""); pwd = e.get("password","")
                path = e.get("path", e.get("command",""))[:40]
                threat = str(e.get("threat_score",0))
                self.osint_history.insert("","end",values=(ts,svc,user,pwd,path,threat))
        self.osint_fp.configure(state=tk.NORMAL)
        self.osint_fp.insert(tk.END, "Fingerprint collection: HTTP User-Agent, SSH version.\n")
        self.osint_fp.configure(state=tk.DISABLED)
        self.osint_status.configure(text=f"✅ Lookup completed for {ip}")

    def _block_ip_from_osint(self):
        ip = self.osint_ip_var.get().strip()
        if not ip: return
        if CORE_OK:
            try:
                from core import ban_ip
                ban_ip(ip, reason="OSINT manual block")
                self._status(f"IP {ip} blocked manually")
                self.refresh_bans()
                messagebox.showinfo("Blocked", f"IP {ip} has been banned.")
            except: messagebox.showerror("Error","core.ban_ip not available")
        else:
            messagebox.showwarning("No core","core.py missing, cannot block.")

    # ── Banned IPs Tab ────────────────────────────────────────────────────────
    def _build_bans_tab(self):
        p = self.tab_bans
        hdr = tk.Frame(p, bg=T["BG3"], pady=6, padx=10)
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text="🚫  AUTO-BANNED IPs", font=("Courier New",10,"bold"),
                 fg=T["RED"], bg=T["BG3"]).pack(side=tk.LEFT)
        tk.Button(hdr, text="🔄 Refresh", font=("Courier New",9,"bold"),
                  fg=T["ACCENT"], bg=T["BG3"], bd=0, relief=tk.FLAT,
                  cursor="hand2", command=self.refresh_bans).pack(side=tk.RIGHT)
        cols = ("IP","Attempts","First Seen","Services")
        self.ban_tree = ttk.Treeview(p, columns=cols, show="headings", height=20)
        for c in cols:
            self.ban_tree.heading(c, text=c); self.ban_tree.column(c, width=200)
        style = ttk.Style()
        style.configure("Treeview", background=T["BG2"], foreground=T["FG"],
                        fieldbackground=T["BG2"], rowheight=24, font=("Courier New",9))
        style.configure("Treeview.Heading", background=T["PANEL"],
                        foreground=T["ACCENT"], font=("Courier New",9,"bold"))
        sb = ttk.Scrollbar(p, orient=tk.VERTICAL, command=self.ban_tree.yview)
        self.ban_tree.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.ban_tree.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

    def refresh_bans(self):
        for row in self.ban_tree.get_children(): self.ban_tree.delete(row)
        if not CORE_OK: return
        banned = get_banned_ips()
        attempts = get_all_attempts()
        ip_svcs = defaultdict(set)
        for e in self.all_events: ip_svcs[e.get("ip","")].add(e.get("service",""))
        for ip in banned:
            cnt = attempts.get(ip,0)
            svcs = ", ".join(ip_svcs.get(ip,set()))
            self.ban_tree.insert("","end",values=(ip,cnt,"–",svcs))

    # ── Config Tab ────────────────────────────────────────────────────────────
    def _build_config_tab(self):
        p = self.tab_cfg
        scroll = tk.Frame(p, bg=T["BG"])
        scroll.pack(fill=tk.BOTH, expand=True, padx=20, pady=12)
        tk.Label(scroll, text="⚙  CONFIGURATION", font=("Courier New",12,"bold"),
                 fg=T["ACCENT"], bg=T["BG"]).pack(anchor=tk.W, pady=(0,12))

        # ── Discord Config Section ────────────────────────────────────────
        disc_card = tk.Frame(scroll, bg=T["PANEL"], pady=10, padx=12)
        disc_card.pack(fill=tk.X, pady=(0,12))
        tk.Label(disc_card, text="🔔  DISCORD WEBHOOK ALERTS",
                 font=("Courier New",9,"bold"), fg=T["YELLOW"], bg=T["PANEL"]).pack(anchor=tk.W)
        tk.Label(disc_card,
                 text="Jab bhi SUSPICIOUS/HIGH/CRITICAL attack aaye, Discord pe embed message aayega.",
                 font=("Courier New",8), fg=T["FG_DIM"], bg=T["PANEL"]).pack(anchor=tk.W, pady=2)

        wh_row = tk.Frame(disc_card, bg=T["PANEL"])
        wh_row.pack(fill=tk.X, pady=(6,0))
        tk.Label(wh_row, text="Webhook URL:", font=("Courier New",8),
                 fg=T["FG_DIM"], bg=T["PANEL"]).pack(side=tk.LEFT)
        self._discord_url_var = tk.StringVar(value=DISCORD_WEBHOOK_URL)
        tk.Entry(wh_row, textvariable=self._discord_url_var,
                 font=("Courier New",8), bg=T["BG3"], fg=T["FG"],
                 insertbackground=T["FG"], relief=tk.FLAT, width=55,
                 highlightthickness=1, highlightbackground=T["BORDER"]).pack(side=tk.LEFT, padx=6)
        tk.Button(wh_row, text="💾 Save", font=("Courier New",7,"bold"),
                  fg=T["GREEN"], bg=T["BG3"], bd=0, relief=tk.FLAT,
                  cursor="hand2", padx=6, command=self._save_discord_url).pack(side=tk.LEFT)
        tk.Button(wh_row, text="🧪 Test", font=("Courier New",7,"bold"),
                  fg=T["YELLOW"], bg=T["BG3"], bd=0, relief=tk.FLAT,
                  cursor="hand2", padx=6, command=self._test_discord).pack(side=tk.LEFT, padx=4)

        # Cooldown config
        cd_row = tk.Frame(disc_card, bg=T["PANEL"])
        cd_row.pack(fill=tk.X, pady=(4,0))
        tk.Label(cd_row, text="Alert Cooldown (sec, same IP):",
                 font=("Courier New",8), fg=T["FG_DIM"], bg=T["PANEL"]).pack(side=tk.LEFT)
        self._cooldown_var = tk.IntVar(value=self._discord_cooldown)
        tk.Spinbox(cd_row, from_=5, to=300, textvariable=self._cooldown_var,
                   font=("Courier New",8), bg=T["BG3"], fg=T["FG"], width=6,
                   relief=tk.FLAT).pack(side=tk.LEFT, padx=6)
        tk.Label(cd_row, text="(avoid spam for repeated attacks from same IP)",
                 font=("Courier New",7), fg=T["FG_DIM"], bg=T["PANEL"]).pack(side=tk.LEFT)

        # Alert level filter
        al_row = tk.Frame(disc_card, bg=T["PANEL"])
        al_row.pack(fill=tk.X, pady=(4,0))
        tk.Label(al_row, text="Alert pe sirf yeh levels:",
                 font=("Courier New",8), fg=T["FG_DIM"], bg=T["PANEL"]).pack(side=tk.LEFT)
        self._alert_levels = {}
        for level, color in [("SUSPICIOUS", T["YELLOW"]), ("HIGH", T["ORANGE"]), ("CRITICAL", T["RED"])]:
            var = tk.BooleanVar(value=True)
            tk.Checkbutton(al_row, text=level, variable=var, font=("Courier New",8),
                           fg=color, bg=T["PANEL"], selectcolor=T["BG"],
                           activebackground=T["PANEL"]).pack(side=tk.LEFT, padx=4)
            self._alert_levels[level] = var

        geo_card = tk.Frame(scroll, bg=T["PANEL"], pady=8, padx=12)
        geo_card.pack(fill=tk.X, pady=(0,12))
        geo_status_color = T["GREEN"] if GEO.mmdb_ok else T["YELLOW"]
        geo_status_text  = (f"✔  MaxMind mmdb: {GEO.mmdb_path}" if GEO.mmdb_ok
                            else "⚠  ip-api.com fallback — mmdb nahi mili")
        tk.Label(geo_card, text="🌍  GeoIP STATUS", font=("Courier New",8,"bold"),
                 fg=T["FG_DIM"], bg=T["PANEL"]).pack(anchor=tk.W)
        tk.Label(geo_card, text=geo_status_text, font=("Courier New",8),
                 fg=geo_status_color, bg=T["PANEL"]).pack(anchor=tk.W, pady=2)
        mmdb_row = tk.Frame(geo_card, bg=T["PANEL"])
        mmdb_row.pack(fill=tk.X, pady=(6,0))
        tk.Label(mmdb_row, text="mmdb Path:", font=("Courier New",8),
                 fg=T["FG_DIM"], bg=T["PANEL"]).pack(side=tk.LEFT)
        self._mmdb_var = tk.StringVar(value=GEO.mmdb_path or "")
        tk.Entry(mmdb_row, textvariable=self._mmdb_var, font=("Courier New",8),
                 bg=T["BG3"], fg=T["FG"], insertbackground=T["FG"],
                 relief=tk.FLAT, width=45,
                 highlightthickness=1, highlightbackground=T["BORDER"]).pack(side=tk.LEFT, padx=6)
        tk.Button(mmdb_row, text="📂 Browse", font=("Courier New",7,"bold"),
                  fg=T["ACCENT"], bg=T["BG3"], bd=0, relief=tk.FLAT,
                  cursor="hand2", padx=6, command=self._browse_mmdb).pack(side=tk.LEFT)
        tk.Button(mmdb_row, text="🔄 Load", font=("Courier New",7,"bold"),
                  fg=T["GREEN"], bg=T["BG3"], bd=0, relief=tk.FLAT,
                  cursor="hand2", padx=6, command=self._reload_mmdb).pack(side=tk.LEFT, padx=4)

        if not CORE_OK:
            tk.Label(scroll, text="core.py not found — CONFIG features unavailable",
                     fg=T["YELLOW"], bg=T["BG"]).pack()
            return

        self.cfg_vars = {}
        fields = [
            ("auto_ban_enabled",    "Auto-Ban Enabled",          "bool"),
            ("auto_ban_threshold",  "Ban Threshold (attempts)",   "int"),
            ("auto_ban_duration",   "Ban Duration (seconds)",     "int"),
            ("geoip_enabled",       "GeoIP Enabled",              "bool"),
            ("threat_intel_enabled","Threat Intel Enabled",       "bool"),
            ("abuseipdb_api_key",   "AbuseIPDB API Key",          "str"),
            ("shodan_api_key",      "Shodan API Key",             "str"),
        ]
        for key, label, kind in fields:
            row = tk.Frame(scroll, bg=T["BG"])
            row.pack(fill=tk.X, pady=3)
            tk.Label(row, text=f"{label}:", font=("Courier New",9),
                     fg=T["FG_DIM"], bg=T["BG"], width=30, anchor=tk.W).pack(side=tk.LEFT)
            val = CONFIG.get(key, "")
            if kind == "bool":
                var = tk.BooleanVar(value=bool(val))
                tk.Checkbutton(row, variable=var, bg=T["BG"], fg=T["FG"],
                               selectcolor=T["PANEL"], activebackground=T["BG"]).pack(side=tk.LEFT)
            else:
                var = tk.StringVar(value=str(val))
                tk.Entry(row, textvariable=var, font=("Courier New",9),
                         bg=T["BG3"], fg=T["FG"], insertbackground=T["FG"],
                         relief=tk.FLAT, width=40,
                         highlightthickness=1, highlightbackground=T["BORDER"]).pack(side=tk.LEFT, padx=4)
            self.cfg_vars[key] = (var, kind)

        tk.Button(scroll, text="💾  Save Config", font=("Courier New",9,"bold"),
                  fg=T["BG"], bg=T["GREEN"], bd=0, relief=tk.FLAT,
                  cursor="hand2", padx=14, pady=5, command=self.save_config).pack(anchor=tk.W, pady=12)

    def _save_discord_url(self):
        global DISCORD_WEBHOOK_URL
        url = self._discord_url_var.get().strip()
        DISCORD_WEBHOOK_URL = url
        self._discord_cooldown = self._cooldown_var.get()
        if url.startswith("https://discord.com/api/webhooks/"):
            self.discord_lbl.configure(text="🔔 Discord: ON", fg=T["GREEN"])
            self._status("Discord webhook saved!")
            messagebox.showinfo("Discord", "✅ Webhook URL save ho gaya!\nAb attacks pe Discord alerts aayenge.")
        elif url:
            messagebox.showwarning("Discord", "URL galat lag raha hai.\nhttps://discord.com/api/webhooks/... hona chahiye.")
        else:
            self.discord_lbl.configure(text="🔔 Discord: OFF", fg=T["FG_DIM"])
            self._status("Discord webhook removed.")

    def _test_discord(self):
        """Test Discord webhook se ek dummy message bhejo."""
        global DISCORD_WEBHOOK_URL
        url = self._discord_url_var.get().strip()
        DISCORD_WEBHOOK_URL = url
        if not url:
            messagebox.showwarning("Test", "Pehle Webhook URL daalo."); return

        test_event = {
            "service": "TEST",
            "ip": "1.2.3.4",
            "timestamp": datetime.datetime.now().isoformat(),
            "username": "admin",
            "password": "test123",
            "path": "/test",
        }
        test_geo = {"city": "Test City", "country": "Testland"}
        send_discord_alert(test_event, test_geo, 75, "HIGH")
        messagebox.showinfo("Test", "Test message Discord pe bhej diya!\n(kuch seconds mein aana chahiye)")

    def _browse_mmdb(self):
        path = filedialog.askopenfilename(title="GeoLite2-City.mmdb select karo",
            filetypes=[("MaxMind DB","*.mmdb"),("All files","*.*")])
        if path: self._mmdb_var.set(path)

    def _reload_mmdb(self):
        global GEO, GEOIP2_OK
        path = self._mmdb_var.get().strip()
        if not path: messagebox.showwarning("GeoIP","Pehle path daalo."); return
        if not os.path.isfile(path): messagebox.showerror("GeoIP",f"File nahi mili:\n{path}"); return
        GEO = GeoResolver(mmdb_path=path); GEOIP2_OK = GEO.mmdb_ok
        if GEO.mmdb_ok:
            messagebox.showinfo("GeoIP", f"✔  MaxMind DB load ho gaya!\n{path}")
        else:
            messagebox.showerror("GeoIP","mmdb load nahi hua.\npip install geoip2")

    def save_config(self):
        if not CORE_OK: return
        for key, (var, kind) in self.cfg_vars.items():
            raw = var.get()
            if kind == "bool": CONFIG[key] = bool(raw)
            elif kind == "int":
                try: CONFIG[key] = int(raw)
                except: pass
            else: CONFIG[key] = str(raw)
        messagebox.showinfo("Config","Configuration saved for this session.")

    # ── Bottom Bar ────────────────────────────────────────────────────────────
    def _build_bottom_bar(self, parent):
        for text, fg, cmd in [
            ("▶▶ START ALL", T["GREEN"], self.start_all),
            ("■  STOP ALL",  T["RED"],   self.stop_all),
        ]:
            tk.Button(parent, text=text, font=("Courier New",9,"bold"),
                      fg=T["BG"], bg=fg, bd=0, relief=tk.FLAT, cursor="hand2",
                      padx=12, pady=3, command=cmd).pack(side=tk.LEFT, padx=(10,3))

        tk.Frame(parent, bg=T["FG_DIM"], width=1).pack(side=tk.LEFT, fill=tk.Y, padx=8, pady=3)

        for text, fg, cmd in [
            ("📊 Charts",        T["ACCENT"],  self.refresh_charts),
            ("☁ Wordcloud",      T["PINK"],    self.refresh_wordcloud),
            ("🕷 Tarpit",        T["ORANGE"],  self.refresh_tarpit_tab),
            ("🚫 Bans",          T["RED"],     self.refresh_bans),
            ("💾 JSON",          T["TEAL"],    lambda: self.export("json")),
            ("📄 CSV",           T["PURPLE"],  lambda: self.export("csv")),
            ("📑 PDF",           T["YELLOW"],  self.export_pdf),
            ("📸 Screenshot",    T["GREEN"],   lambda: self.take_screenshot("manual")),
            ("🗑 Clear Log",     T["FG_DIM"],  self.clear_log),
        ]:
            tk.Button(parent, text=text, font=("Courier New",8,"bold"),
                      fg=fg, bg=T["BG3"], bd=0, relief=tk.FLAT, cursor="hand2",
                      padx=8, pady=3, command=cmd).pack(side=tk.LEFT, padx=2)

        tk.Button(parent, text="✕ Quit", font=("Courier New",8,"bold"),
                  fg=T["FG_DIM"], bg=T["BG3"], bd=0, relief=tk.FLAT,
                  cursor="hand2", padx=8, pady=3, command=self.quit_app).pack(side=tk.RIGHT, padx=10)

        self.status_lbl = tk.Label(parent, text="Ready — Koi service start karo.",
                                    font=("Courier New",8), fg=T["FG_DIM"], bg=T["BG3"])
        self.status_lbl.pack(side=tk.RIGHT, padx=10)

    # ── Service control ───────────────────────────────────────────────────────
    def toggle_svc(self, svc):
        self.stop_svc(svc) if self.svc_running.get(svc) else self.start_svc(svc)

    def start_svc(self, svc):
        if svc not in SVC_MODULES:
            messagebox.showerror("Missing", f"{svc}.py not found.\n{svc} honeypot module install karo.")
            return
        if self.svc_running.get(svc): return
        port = self.svc_ports[svc].get()
        def cb(entry): self.log_queue.put(entry)
        threading.Thread(target=SVC_MODULES[svc], kwargs={"port":port,"callback":cb},
                          daemon=True).start()
        self.svc_running[svc] = True
        self._update_svc_ui(svc, True)
        self._status(f"✅ {svc} started on :{port}")

    def stop_svc(self, svc):
        self.svc_running[svc] = False
        self._update_svc_ui(svc, False)
        self._status(f"⛔ {svc} stopped.")

    def start_all(self):
        started = 0
        for s in SVC_MODULES:
            if not self.svc_running.get(s):
                self.start_svc(s); started += 1
        if started == 0:
            messagebox.showinfo("Start All", "Koi naya service start nahi hua.")

    def stop_all(self):
        for s in list(self.svc_running): self.stop_svc(s)

    def _update_svc_ui(self, svc, on):
        if svc not in self.svc_dot: return
        self.svc_dot[svc].configure(fg=T["GREEN"] if on else T["FG_DIM"])
        self.svc_lbl[svc].configure(text="ON" if on else "OFF",
                                     fg=T["GREEN"] if on else T["RED"])
        self.svc_btn[svc].configure(text="■ STOP" if on else "▶ START",
                                     fg=T["RED"] if on else T["GREEN"])

    # ── Log / event handling ──────────────────────────────────────────────────
    def _poll_queue(self):
        while not self.log_queue.empty():
            e = self.log_queue.get_nowait()

            # Tarpit events
            if e.get("source") == "tarpit":
                self._on_tarpit_event(e)
                continue

            # GeoIP lookup
            ip  = e.get("ip","")
            geo = e.get("geo",{})
            if ip and (not geo or not geo.get("lat") or not geo.get("city")):
                if GEO.mmdb_ok:
                    resolved = GEO.lookup(ip)
                    if resolved: e["geo"] = resolved
                else:
                    def _on_geo(resolved_ip, resolved_geo, ev=e):
                        if resolved_geo:
                            ev["geo"] = resolved_geo
                            self.after(0, lambda: self._fire_live_ping(ev))
                    GEO.lookup_async(ip, _on_geo)

            # ML Scoring
            ml_result = ML.score(e)
            e["ml_score"]   = ml_result["score"]
            e["ml_label"]   = ml_result["label"]
            e["ml_color"]   = ml_result["color"]
            e["ml_reasons"] = ml_result["reasons"]
            if ml_result["score"] > e.get("threat_score",0):
                e["threat_score"] = ml_result["score"]

            self.all_events.append(e)
            self._update_stats(e)
            if self.current_filter in ("ALL", e.get("service","")):
                self._append_log(e)
            self._fire_live_ping(e)

            # ── Discord Alert ──────────────────────────────────────────────
            ml_label = e.get("ml_label","SAFE")
            # Check alert level filter
            should_alert = self._alert_levels.get(ml_label, tk.BooleanVar(value=False)).get() \
                           if hasattr(self, "_alert_levels") else ml_label != "SAFE"
            if should_alert and DISCORD_WEBHOOK_URL:
                now = time.time()
                last = self._last_discord_alert.get(ip, 0)
                if now - last >= self._discord_cooldown:
                    self._last_discord_alert[ip] = now
                    geo_data = e.get("geo", {})
                    send_discord_alert(e, geo_data, e["ml_score"], ml_label)

        self.after(120, self._poll_queue)

    def _append_log(self, e):
        svc    = e.get("service","???")
        ts     = e.get("timestamp","")
        ip     = e.get("ip","")
        geo    = e.get("geo",{})
        country = geo.get("country_iso", geo.get("country","??"))[:8]
        city    = geo.get("city", geo.get("city_name",""))[:10]
        threat  = e.get("threat_score",0)
        decoy   = e.get("decoy")

        self.log_txt.configure(state=tk.NORMAL)
        self.log_txt.insert(tk.END, f"[{ts}] ", "TS")
        self.log_txt.insert(tk.END, f"[{svc:<6}]", svc)
        self.log_txt.insert(tk.END, f" {ip:<18}", "IP")
        loc_str = f"{city},{country}" if city else country
        self.log_txt.insert(tk.END, f" {loc_str:<14}", "GEO")

        if threat and threat > 50:
            self.log_txt.insert(tk.END, f" ⚠{threat}", "THREAT")
        ml_label = e.get("ml_label",""); ml_score = e.get("ml_score",0)
        if ml_label and ml_label != "SAFE":
            emoji = ML.label_to_emoji(ml_label)
            self.log_txt.insert(tk.END, f" {emoji}ML:{ml_score}",
                                 "THREAT" if ml_score>60 else "DECOY")
        if decoy:
            self.log_txt.insert(tk.END, f" 🎣{decoy}", "DECOY")

        if svc == "HTTP":
            m = e.get("method",""); p2 = e.get("path",""); c = e.get("response","")
            self.log_txt.insert(tk.END, f" {m:<7}", "KEY")
            self.log_txt.insert(tk.END, f"{p2:<30} [{c}]")
        elif svc in ("SSH","TELNET","FTP","SMTP","MYSQL"):
            u = e.get("username",""); pw = e.get("password","")
            self.log_txt.insert(tk.END," user=","KEY")
            self.log_txt.insert(tk.END,f"{u:<16}")
            if pw:
                self.log_txt.insert(tk.END," pass=","KEY")
                self.log_txt.insert(tk.END,f"{pw[:24]}")
            if e.get("command"):
                self.log_txt.insert(tk.END,f" cmd={e['command'][:30]}","KEY")

        self.log_txt.insert(tk.END,"\n")
        self.log_txt.see(tk.END)
        self.log_txt.configure(state=tk.DISABLED)

    def set_filter(self, tag):
        self.current_filter = tag
        self.log_txt.configure(state=tk.NORMAL)
        self.log_txt.delete("1.0", tk.END)
        self.log_txt.configure(state=tk.DISABLED)
        for e in self.all_events:
            if tag == "ALL" or e.get("service") == tag:
                self._append_log(e)

    def clear_log(self):
        self.log_txt.configure(state=tk.NORMAL)
        self.log_txt.delete("1.0",tk.END)
        self.log_txt.configure(state=tk.DISABLED)

    def _update_stats(self, e):
        ip = e.get("ip","")
        self.stats["total"] += 1
        self.ip_counts[ip] += 1
        if e.get("decoy"):                    self.stats["decoy"] += 1
        if e.get("threat_score",0) > 50:     self.stats["threat"] += 1
        if CORE_OK: self.stats["banned"] = len(get_banned_ips())

        self.stat_w["total"].configure(text=str(self.stats["total"]))
        self.stat_w["uniq"].configure(text=str(len(self.ip_counts)))
        self.stat_w["banned"].configure(text=str(self.stats["banned"]))
        self.stat_w["decoy"].configure(text=str(self.stats["decoy"]))
        self.stat_w["threat"].configure(text=str(self.stats["threat"]))

        if hasattr(self,"live_counter"):
            self.live_counter.configure(text=f"⚡ {self.stats['total']} attacks")

        top = sorted(self.ip_counts.items(), key=lambda x:x[1], reverse=True)[:8]
        self.ip_board.configure(state=tk.NORMAL)
        self.ip_board.delete("1.0",tk.END)
        for i,(a,c) in enumerate(top,1):
            self.ip_board.insert(tk.END,f"{i:>2}. {a:<18} {c:>4}\n")
        self.ip_board.configure(state=tk.DISABLED)

        # Screenshot sirf HIGH threat pe (>=80 score)
        threat_score = e.get("threat_score",0)
        if self._ss_on_threat and threat_score >= 80:
            self.take_screenshot(reason=f"threat_{threat_score}")

        if self.stats["total"] % 20 == 0 and MPL_OK and hasattr(self,"wc_fig"):
            self.refresh_wordcloud()
        if self.stats["total"] % 10 == 0 and hasattr(self,"ml_tree"):
            self.refresh_ml_tab()

    # ── Export ────────────────────────────────────────────────────────────────
    def export(self, fmt):
        if not self.all_events: messagebox.showinfo("Export","No events yet."); return
        fn = f"honeypot_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.{fmt}"
        path = filedialog.asksaveasfilename(defaultextension=f".{fmt}", initialfile=fn)
        if not path: return
        try:
            if fmt == "json":
                with open(path,"w") as f: json.dump(self.all_events,f,indent=2)
            else:
                all_keys = sorted({k for e in self.all_events for k in e})
                with open(path,"w",newline="") as f:
                    w = csv.DictWriter(f,fieldnames=all_keys,extrasaction="ignore")
                    w.writeheader()
                    for e in self.all_events: w.writerow({k:e.get(k,"") for k in all_keys})
            self._status(f"Exported → {os.path.basename(path)}")
        except Exception as ex:
            messagebox.showerror("Export Error",str(ex))

    def export_pdf(self):
        if not PDF_OK: messagebox.showerror("Missing","pip install reportlab"); return
        if not self.all_events: messagebox.showinfo("PDF","No events yet."); return
        fn = f"honeypot_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        path = filedialog.asksaveasfilename(defaultextension=".pdf",initialfile=fn,
                                             filetypes=[("PDF","*.pdf")])
        if not path: return
        try:
            doc = SimpleDocTemplate(path, pagesize=A4)
            styles = getSampleStyleSheet(); story = []
            story.append(Paragraph("🍯 Honeypot Capture Report",styles["Title"]))
            story.append(Paragraph(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",styles["Normal"]))
            story.append(Spacer(1,12))
            data = [["Metric","Value"],
                    ["Total Events",str(len(self.all_events))],
                    ["Unique IPs",str(len(self.ip_counts))],
                    ["Tarpit Connections",str(TARPIT.total_connections)],
                    ["Time Wasted on Hackers",TARPIT.total_wasted_str()],
                    ["Fake Creds Captured",str(len(TARPIT.total_creds))]]
            t = Table(data, colWidths=[200,200])
            t.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,0),rl_colors.HexColor("#1e2230")),
                ("TEXTCOLOR",(0,0),(-1,0),rl_colors.white),
                ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
                ("GRID",(0,0),(-1,-1),0.5,rl_colors.grey),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[rl_colors.HexColor("#f0f0f0"),rl_colors.white]),
            ]))
            story.append(t); story.append(Spacer(1,20))
            story.append(Paragraph("Top 20 Events",styles["Heading2"]))
            story.append(Spacer(1,6))
            ev_data = [["Time","Service","IP","City","User","ML Score"]]
            for e in self.all_events[:20]:
                geo = e.get("geo",{}); city = geo.get("city","?")[:14]
                ev_data.append([e.get("timestamp","")[:16],e.get("service",""),
                                e.get("ip",""),city,e.get("username","")[:14],
                                str(e.get("ml_score",0))])
            et = Table(ev_data, colWidths=[80,60,100,80,80,60])
            et.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,0),rl_colors.HexColor("#89b4fa")),
                ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
                ("FONTSIZE",(0,0),(-1,-1),7),
                ("GRID",(0,0),(-1,-1),0.3,rl_colors.grey),
            ]))
            story.append(et); doc.build(story)
            messagebox.showinfo("PDF",f"Report saved:\n{path}")
        except Exception as ex:
            messagebox.showerror("PDF Error",str(ex))

    # ── Utilities ─────────────────────────────────────────────────────────────
    def _status(self, msg):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.status_lbl.configure(text=f"[{ts}] {msg}")

    def _tick_clock(self):
        self.clock_lbl.configure(text=datetime.datetime.now().strftime("%a %Y-%m-%d  %H:%M:%S"))
        self.after(1000, self._tick_clock)

    def quit_app(self):
        self.stop_all(); self.destroy(); sys.exit(0)


# ── Entry ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = App()
    # FIX: Koi test_attacks.inject_fake_attacks nahi — sirf real attacks dikhenge
    app.mainloop()