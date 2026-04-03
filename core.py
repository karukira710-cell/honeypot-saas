"""
core.py — Honeypot shared engine
Handles: GeoIP (ipwhois), Threat Intelligence, Auto-Ban, Discord/Telegram alerts, unified logging.
"""

import json
import os
import datetime
import threading
import time
import logging
import subprocess
import sys
import http.client
import urllib.parse
from collections import defaultdict

# ══════════════════════════════════════════════════════════════════════════════
#  CONFIG  — sirf yahan edit karo
# ══════════════════════════════════════════════════════════════════════════════
CONFIG = {
    # ── Auto-ban (Linux iptables only) ────────────────────────────────────────
    "auto_ban_enabled":  True,
    "auto_ban_threshold": 5,
    "auto_ban_duration":  3600,

    # ── GeoIP — ab ipwhois use hoga, koi DB nahi chahiye ─────────────────────
    "geoip_enabled":  True,
    "geoip_db_path":  "",   # ab zaroorat nahi, legacy ke liye rakha

    # ── Threat Intelligence — AbuseIPDB free API ──────────────────────────────
    "threat_intel_enabled": True,
    "abuseipdb_api_key":    "991331acd817884f0b1c28f9f2c529d9c4e1b01c45cd8b6a20c7fa0dc5d75a3d4801d62634982b70",

    # ── Discord webhook alert ─────────────────────────────────────────────────
    "discord_enabled": True,
    "discord_webhook": "https://discord.com/api/webhooks/1487676121934725181/OZIkQSjicLj2KbcSuDqJKkyje4GUIAhH8ih6KSMeco-APoiZI8Pd5zzfbBI2esciRwnv",

    # ── Telegram bot alert ────────────────────────────────────────────────────
    "telegram_enabled": False,
    "telegram_token":   "",
    "telegram_chat_id": "",

    # ── Alert cooldown (seconds) ──────────────────────────────────────────────
    "alert_cooldown": 5,

    # ── Decoy filenames ───────────────────────────────────────────────────────
    "decoy_files": [
        "passwords.txt", "config.php", ".env", "wp-config.php",
        "database_dump.sql", "backup_2024.tar.gz", "id_rsa",
        "credentials.txt", "secret.key",
    ],
}

DECOY_FILES = set(CONFIG["decoy_files"])

os.makedirs("logs", exist_ok=True)
MASTER_LOG = "logs/master.json"

# ══════════════════════════════════════════════════════════════════════════════
#  INTERNAL STATE
# ══════════════════════════════════════════════════════════════════════════════
_lock            = threading.Lock()
_attempt_counts  = defaultdict(int)
_banned_ips      = set()
_alert_cooldowns = {}
_geo_cache       = {}
_threat_cache    = {}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# ══════════════════════════════════════════════════════════════════════════════
#  COUNTRY COORDINATES — ISO code → (Latitude, Longitude)
# ══════════════════════════════════════════════════════════════════════════════
COUNTRY_COORDS = {
    "AF": (34.52, 69.17),   "AL": (41.33, 19.82),   "DZ": (36.73, 3.08),
    "AD": (42.50, 1.51),    "AO": (-8.83, 13.24),   "AR": (-34.61, -58.37),
    "AM": (40.18, 44.51),   "AU": (-35.28, 149.12),  "AT": (48.20, 16.37),
    "AZ": (40.40, 49.86),   "BS": (25.07, -77.34),   "BH": (26.21, 50.59),
    "BD": (23.72, 90.40),   "BY": (53.90, 27.57),    "BE": (50.85, 4.35),
    "BZ": (17.25, -88.77),  "BJ": (6.36, 2.42),      "BT": (27.47, 89.64),
    "BO": (-16.49, -68.12), "BA": (43.84, 18.36),    "BW": (-24.65, 25.91),
    "BR": (-15.78, -47.93), "BN": (4.94, 114.94),    "BG": (42.70, 23.32),
    "BF": (12.37, -1.52),   "BI": (-3.38, 29.36),    "CV": (14.93, -23.51),
    "KH": (11.56, 104.92),  "CM": (3.86, 11.52),     "CA": (45.42, -75.69),
    "CF": (4.36, 18.56),    "TD": (12.11, 15.04),    "CL": (-33.45, -70.67),
    "CN": (39.91, 116.39),  "CO": (4.71, -74.07),    "KM": (-11.70, 43.26),
    "CG": (-4.27, 15.28),   "CR": (9.93, -84.08),    "HR": (45.81, 15.98),
    "CU": (23.13, -82.38),  "CY": (35.17, 33.36),    "CZ": (50.08, 14.47),
    "DK": (55.68, 12.57),   "DJ": (11.59, 43.15),    "DO": (18.48, -69.90),
    "EC": (-0.22, -78.51),  "EG": (30.06, 31.25),    "SV": (13.70, -89.20),
    "GQ": (3.75, 8.78),     "ER": (15.33, 38.93),    "EE": (59.44, 24.75),
    "ET": (9.02, 38.74),    "FJ": (-18.14, 178.44),  "FI": (60.17, 24.94),
    "FR": (48.85, 2.35),    "GA": (0.39, 9.45),      "GM": (13.45, -16.57),
    "GE": (41.69, 44.83),   "DE": (52.52, 13.40),    "GH": (5.55, -0.20),
    "GR": (37.98, 23.73),   "GT": (14.64, -90.51),   "GN": (9.54, -13.68),
    "GW": (11.86, -15.60),  "GY": (6.80, -58.15),    "HT": (18.54, -72.34),
    "HN": (14.10, -87.22),  "HU": (47.50, 19.04),    "IS": (64.14, -21.94),
    "IN": (28.63, 77.22),   "ID": (-6.21, 106.85),   "IR": (35.69, 51.42),
    "IQ": (33.34, 44.40),   "IE": (53.33, -6.25),    "IL": (31.77, 35.23),
    "IT": (41.90, 12.48),   "JM": (17.99, -76.79),   "JP": (35.68, 139.69),
    "JO": (31.95, 35.93),   "KZ": (51.18, 71.45),    "KE": (-1.28, 36.82),
    "KI": (-0.88, 169.53),  "KW": (29.37, 47.98),    "KG": (42.87, 74.59),
    "LA": (17.97, 102.60),  "LV": (56.95, 24.11),    "LB": (33.87, 35.50),
    "LS": (-29.32, 27.48),  "LR": (6.30, -10.80),    "LY": (32.90, 13.18),
    "LI": (47.14, 9.52),    "LT": (54.69, 25.28),    "LU": (49.61, 6.13),
    "MG": (-18.91, 47.54),  "MW": (-13.97, 33.79),   "MY": (3.14, 101.69),
    "MV": (4.17, 73.51),    "ML": (12.65, -8.00),    "MT": (35.90, 14.51),
    "MR": (18.07, -15.97),  "MU": (-20.16, 57.49),   "MX": (19.43, -99.13),
    "MD": (47.01, 28.86),   "MC": (43.73, 7.42),     "MN": (47.91, 106.92),
    "ME": (42.44, 19.26),   "MA": (34.01, -6.83),    "MZ": (-25.97, 32.59),
    "MM": (19.76, 96.08),   "NA": (-22.56, 17.08),   "NP": (27.72, 85.32),
    "NL": (52.37, 4.90),    "NZ": (-41.29, 174.78),  "NI": (12.13, -86.28),
    "NE": (13.51, 2.12),    "NG": (9.07, 7.40),      "NO": (59.91, 10.75),
    "OM": (23.61, 58.59),   "PK": (33.72, 73.04),    "PW": (7.48, 134.62),
    "PA": (8.99, -79.52),   "PG": (-9.44, 147.18),   "PY": (-25.28, -57.64),
    "PE": (-12.04, -77.03), "PH": (14.60, 120.98),   "PL": (52.23, 21.01),
    "PT": (38.72, -9.13),   "QA": (25.29, 51.53),    "RO": (44.44, 26.10),
    "RU": (55.75, 37.62),   "RW": (-1.95, 30.06),    "SA": (24.69, 46.72),
    "SN": (14.73, -17.46),  "RS": (44.80, 20.47),    "SL": (8.49, -13.23),
    "SG": (1.28, 103.85),   "SK": (48.15, 17.11),    "SI": (46.05, 14.51),
    "SO": (2.05, 45.34),    "ZA": (-25.74, 28.19),   "SS": (4.85, 31.62),
    "ES": (40.42, -3.70),   "LK": (6.91, 79.86),     "SD": (15.55, 32.53),
    "SR": (5.87, -55.17),   "SE": (59.33, 18.07),    "CH": (46.95, 7.45),
    "SY": (33.51, 36.29),   "TW": (25.04, 121.56),   "TJ": (38.56, 68.77),
    "TZ": (-6.17, 35.74),   "TH": (13.75, 100.52),   "TL": (-8.56, 125.57),
    "TG": (6.14, 1.22),     "TO": (-21.13, -175.20), "TT": (10.65, -61.52),
    "TN": (36.82, 10.18),   "TR": (39.92, 32.85),    "TM": (37.95, 58.38),
    "UG": (0.32, 32.58),    "UA": (50.45, 30.52),    "AE": (24.47, 54.37),
    "GB": (51.50, -0.12),   "US": (38.89, -77.04),   "UY": (-34.86, -56.17),
    "UZ": (41.30, 69.27),   "VE": (10.48, -66.88),   "VN": (21.03, 105.85),
    "YE": (15.35, 44.21),   "ZM": (-15.42, 28.28),   "ZW": (-17.83, 31.05),
    "HK": (22.28, 114.16),  "MO": (22.20, 113.54),   "PS": (31.90, 35.20),
    "KP": (39.02, 125.75),  "KR": (37.57, 126.98),
}

COUNTRY_NAMES = {
    "US": "United States", "IN": "India",         "CN": "China",
    "RU": "Russia",        "GB": "United Kingdom","DE": "Germany",
    "FR": "France",        "JP": "Japan",          "BR": "Brazil",
    "AU": "Australia",     "CA": "Canada",         "KR": "South Korea",
    "SG": "Singapore",     "NL": "Netherlands",    "PK": "Pakistan",
    "BD": "Bangladesh",    "NG": "Nigeria",         "ZA": "South Africa",
    "EG": "Egypt",         "TR": "Turkey",          "SA": "Saudi Arabia",
    "AE": "UAE",           "ID": "Indonesia",       "MY": "Malaysia",
    "TH": "Thailand",      "VN": "Vietnam",         "PH": "Philippines",
    "UA": "Ukraine",       "IT": "Italy",           "ES": "Spain",
    "PL": "Poland",        "SE": "Sweden",          "NO": "Norway",
    "FI": "Finland",       "CH": "Switzerland",     "AT": "Austria",
    "BE": "Belgium",       "HK": "Hong Kong",       "TW": "Taiwan",
    "IR": "Iran",          "IQ": "Iraq",            "IL": "Israel",
    "MX": "Mexico",        "AR": "Argentina",       "CL": "Chile",
    "CO": "Colombia",      "RO": "Romania",         "CZ": "Czech Republic",
    "HU": "Hungary",       "GR": "Greece",          "PT": "Portugal",
    "DK": "Denmark",       "NZ": "New Zealand",     "ZA": "South Africa",
}

# ══════════════════════════════════════════════════════════════════════════════
#  GeoIP — ipwhois (No DB, No API Key!)
# ══════════════════════════════════════════════════════════════════════════════
def get_geo(ip: str) -> dict:
    if ip in _geo_cache:
        return _geo_cache[ip]

    # Local/private IPs skip karo
    private = ("127.", "192.168.", "10.", "172.16.", "172.17.",
               "172.18.", "172.19.", "172.20.", "169.254.", "::1", "0.")
    if any(ip.startswith(p) for p in private):
        result = {"country": "Local", "city": "Local",
                  "country_iso": "LO", "lat": 0.0, "lon": 0.0, "isp": "Local Network"}
        _geo_cache[ip] = result
        return result

    result = {"country": "Unknown", "city": "Unknown",
              "country_iso": "??", "lat": 0.0, "lon": 0.0, "isp": ""}
    try:
        from ipwhois import IPWhois
        obj  = IPWhois(ip)
        data = obj.lookup_rdap(depth=1)

        iso     = data.get("asn_country_code") or "??"
        isp     = data.get("asn_description")  or "Unknown"
        network = data.get("network", {})
        city    = network.get("name") or isp[:25]

        lat, lon = COUNTRY_COORDS.get(iso, (0.0, 0.0))
        country  = COUNTRY_NAMES.get(iso, iso)

        result = {
            "country":     country,
            "country_iso": iso,
            "city":        city,
            "lat":         lat,
            "lon":         lon,
            "isp":         isp,
        }
    except Exception as e:
        logging.debug(f"[GeoIP] ipwhois error for {ip}: {e}")

    _geo_cache[ip] = result
    return result

# ══════════════════════════════════════════════════════════════════════════════
#  Threat Intelligence
# ══════════════════════════════════════════════════════════════════════════════
def get_threat_score(ip: str) -> int:
    if ip in _threat_cache:
        return _threat_cache[ip]

    score = 0
    key = CONFIG.get("abuseipdb_api_key", "")
    if not CONFIG["threat_intel_enabled"] or not key:
        return score

    try:
        import urllib.request
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        req = urllib.request.Request(url, headers={
            "Key": key,
            "Accept": "application/json",
            "User-Agent": "HoneypotEngine/1.0",
        })
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            score = data.get("data", {}).get("abuseConfidenceScore", 0)
    except Exception as e:
        logging.debug(f"[ThreatIntel] Error for {ip}: {e}")

    _threat_cache[ip] = score
    return score

# ══════════════════════════════════════════════════════════════════════════════
#  Auto-Ban
# ══════════════════════════════════════════════════════════════════════════════
def ban_ip(ip: str) -> None:
    if ip in _banned_ips:
        return
    _banned_ips.add(ip)
    logging.warning(f"[AUTO-BAN] Blocking {ip}")

    if sys.platform.startswith("linux"):
        try:
            subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, timeout=5,
            )
            duration = CONFIG["auto_ban_duration"]
            if duration > 0:
                def _unban():
                    time.sleep(duration)
                    subprocess.run(
                        ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                        capture_output=True, timeout=5,
                    )
                    _banned_ips.discard(ip)
                    logging.info(f"[AUTO-BAN] Unblocked {ip} after {duration}s")
                threading.Thread(target=_unban, daemon=True).start()
        except Exception as e:
            logging.debug(f"[AUTO-BAN] iptables error: {e}")


def is_banned(ip: str) -> bool:
    return ip in _banned_ips


def record_attempt(ip: str) -> int:
    with _lock:
        _attempt_counts[ip] += 1
        count = _attempt_counts[ip]
    if CONFIG["auto_ban_enabled"] and count >= CONFIG["auto_ban_threshold"]:
        ban_ip(ip)
    return count


def get_attempt_count(ip: str) -> int:
    return _attempt_counts.get(ip, 0)

# ══════════════════════════════════════════════════════════════════════════════
#  DISCORD
# ══════════════════════════════════════════════════════════════════════════════
def _send_discord(message: str) -> None:
    webhook_url = CONFIG.get("discord_webhook", "").strip()
    if not CONFIG.get("discord_enabled") or not webhook_url:
        return

    try:
        parsed  = urllib.parse.urlparse(webhook_url)
        host    = parsed.netloc
        path    = parsed.path
        payload = json.dumps({"content": message, "username": "Spidy Bot"}).encode("utf-8")

        conn = http.client.HTTPSConnection(host, timeout=10)
        conn.request("POST", path, body=payload, headers={
            "Content-Type":   "application/json",
            "Content-Length": str(len(payload)),
            "User-Agent":     "Spidy Bot/1.0 (Discord Webhook)",
        })
        response = conn.getresponse()
        status   = response.status
        conn.close()

        if status in (200, 204):
            logging.debug(f"[Discord] Sent ✅ (HTTP {status})")
        elif status == 429:
            logging.warning("[Discord] Rate limited (429)")
        elif status == 403:
            logging.error("[Discord] 403 Forbidden — webhook URL check karo")
        else:
            body = response.read().decode("utf-8", errors="replace")
            logging.warning(f"[Discord] Status {status}: {body[:200]}")
    except Exception as e:
        logging.error(f"[Discord] Send error: {e}")

# ══════════════════════════════════════════════════════════════════════════════
#  TELEGRAM
# ══════════════════════════════════════════════════════════════════════════════
def _send_telegram(message: str) -> None:
    if not CONFIG.get("telegram_enabled") or not CONFIG.get("telegram_token"):
        return
    try:
        token   = CONFIG["telegram_token"]
        chat_id = CONFIG["telegram_chat_id"]
        payload = json.dumps({
            "chat_id": chat_id, "text": message, "parse_mode": "Markdown",
        }).encode("utf-8")

        conn = http.client.HTTPSConnection("api.telegram.org", timeout=10)
        conn.request("POST", f"/bot{token}/sendMessage", body=payload, headers={
            "Content-Type":   "application/json",
            "Content-Length": str(len(payload)),
            "User-Agent":     "HoneypotBot/1.0",
        })
        resp = conn.getresponse()
        conn.close()
        logging.debug(f"[Telegram] Status: {resp.status}")
    except Exception as e:
        logging.error(f"[Telegram] Send error: {e}")

# ══════════════════════════════════════════════════════════════════════════════
#  ALERT BUILDER
# ══════════════════════════════════════════════════════════════════════════════
def _should_alert(ip: str) -> bool:
    now  = time.time()
    last = _alert_cooldowns.get(ip, 0)
    if now - last > CONFIG["alert_cooldown"]:
        _alert_cooldowns[ip] = now
        return True
    return False


def send_alert(entry: dict) -> None:
    ip     = entry.get("ip", "?")
    svc    = entry.get("service", "?")
    ts     = entry.get("timestamp", "")
    geo    = entry.get("geo", {})
    loc    = f"{geo.get('city','?')}, {geo.get('country','?')}" if geo else "Unknown"
    threat = entry.get("threat_score", 0)
    decoy  = entry.get("decoy")
    count  = entry.get("attempts", 0)

    if not _should_alert(ip):
        return

    lines = [
        "🍯 **Honeypot Alert**",
        f"Service  : `{svc}`",
        f"IP       : `{ip}`  ({loc})",
        f"Time     : {ts}",
        f"Attempts : {count}",
    ]
    if entry.get("username"):
        lines.append(f"User     : `{entry['username']}`")
    if entry.get("password"):
        lines.append(f"Pass     : `{entry.get('password','')}`")
    if threat and threat > 0:
        lines.append(f"⚠️ Abuse Score : {threat}/100")
    if decoy:
        lines.append(f"🎣 DECOY FILE  : `{decoy}`")
    if entry.get("banned"):
        lines.append("🔨 IP AUTO-BANNED")

    msg = "\n".join(lines)
    threading.Thread(target=_send_discord,  args=(msg,), daemon=True).start()
    threading.Thread(target=_send_telegram, args=(msg,), daemon=True).start()

# ══════════════════════════════════════════════════════════════════════════════
#  UNIFIED LOG_EVENT
# ══════════════════════════════════════════════════════════════════════════════
def log_event(service: str, ip: str, port: int, **kwargs) -> dict:
    ts  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    geo = get_geo(ip)

    threat_score = _threat_cache.get(ip, 0)
    if CONFIG["threat_intel_enabled"] and ip not in _threat_cache:
        threading.Thread(target=get_threat_score, args=(ip,), daemon=True).start()

    entry = {
        "timestamp":    ts,
        "service":      service,
        "ip":           ip,
        "port":         port,
        "geo":          geo,
        "threat_score": threat_score,
        "attempts":     get_attempt_count(ip),
        "banned":       ip in _banned_ips,
        **kwargs,
    }

    with _lock:
        with open(MASTER_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    threading.Thread(target=send_alert, args=(entry,), daemon=True).start()
    return entry

# ══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def get_banned_ips() -> list:
    return list(_banned_ips)

def get_all_attempts() -> dict:
    return dict(_attempt_counts)

# ══════════════════════════════════════════════════════════════════════════════
#  QUICK TEST  — python core.py
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":

    print("=" * 60)
    print("  Discord + GeoIP Full Test")
    print("=" * 60)

    # ── Discord Test ──────────────────────────────────────────────────────────
    print("\n📡 Discord Test...")
    webhook = CONFIG.get("discord_webhook", "").strip()
    if not webhook:
        print("❌ discord_webhook URL nahi dali CONFIG mein!")
        sys.exit(1)

    print(f"   URL : {webhook[:55]}...")
    _send_discord(
        "✅ **Honeypot Core Test**\n"
        "Discord + GeoIP working hai!\n"
        "IP: `127.0.0.1` | Service: `test`"
    )
    time.sleep(2)
    print("   Done ✅ — Discord check karo")

    # ── GeoIP Test ────────────────────────────────────────────────────────────
    print("\n🌍 GeoIP Test (ipwhois)...")
    print("-" * 60)

    test_ips = {
        "8.8.8.8":         "Google DNS — USA",
        "1.1.1.1":         "Cloudflare",
        "49.36.0.1":       "Airtel — India",
        "157.240.22.35":   "Facebook — USA",
        "20.205.243.166":  "Microsoft",
        "185.220.101.1":   "TOR Node — Germany",
        "5.188.206.0":     "Russia",
    }

    for ip, label in test_ips.items():
        r = get_geo(ip)
        print(
            f"  ✅ {ip:<20} → "
            f"{r['country_iso']:<4} {r['country']:<20} | "
            f"Lat:{r['lat']:<8} Lon:{r['lon']:<8} | "
            f"ISP: {r['isp'][:28]}  ({label})"
        )

    print("\n" + "=" * 60)
    print("  Sab theek hai! core.py ready hai 🚀")
    print("=" * 60)