"""
Advanced HTTP Honeypot — HTTP.py
FIXED: Tarpit events ab Tarpit Monitor mein dikhenge.
"""

import socket, threading, logging, os, time, re
from core import log_event, is_banned, record_attempt
from honeypot_connector import send_to_api, make_event

LOG_FILE = "logs/http.log"
HOST     = "0.0.0.0"
PORT     = 8080

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [HTTP] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)

_callbacks    = []
BAN_THRESHOLD = 5
TARPIT_DELAY  = 5   # seconds

_attempt_counts = {}
_attempt_lock   = threading.Lock()

# Decoy paths — lures
DECOY_PATHS = [
    "/admin", "/admin.php", "/login", "/login.php",
    "/wp-admin", "/wp-login.php", "/phpmyadmin",
    "/.env", "/config.php", "/backup.zip",
    "/shell.php", "/cmd.php", "/passwd",
    "/manager/html", "/console", "/actuator",
]

FAKE_RESPONSE = b"""\
HTTP/1.1 200 OK\r\n\
Server: Apache/2.4.54 (Ubuntu)\r\n\
Content-Type: text/html\r\n\
Connection: close\r\n\
\r\n\
<html><body><h1>Apache2 Ubuntu Default Page</h1></body></html>"""

FAKE_LOGIN_PAGE = b"""\
HTTP/1.1 200 OK\r\n\
Server: Apache/2.4.54 (Ubuntu)\r\n\
Content-Type: text/html\r\n\
Connection: close\r\n\
\r\n\
<html><body>
<form method='POST'>
Username: <input name='username'><br>
Password: <input name='password' type='password'><br>
<input type='submit' value='Login'>
</form></body></html>"""

FAKE_404 = b"""\
HTTP/1.1 404 Not Found\r\n\
Server: Apache/2.4.54 (Ubuntu)\r\n\
Content-Type: text/html\r\n\
Connection: close\r\n\
\r\n\
<html><body><h1>404 Not Found</h1></body></html>"""


def _get_geo(ip):
    try:
        import urllib.request, json
        url = f"http://ip-api.com/json/{ip}?fields=status,city,country"
        with urllib.request.urlopen(url, timeout=3) as r:
            d = json.loads(r.read())
        if d.get("status") == "success":
            return d.get("city", "Unknown"), d.get("country", "??")
    except Exception:
        pass
    return "Unknown", "??"


def _fire(entry):
    for cb in _callbacks:
        try: cb(entry)
        except: pass


def _tarpit_event(ip, status, city="Unknown", country="??",
                  username="", password="", lure=None,
                  bytes_sent=0, attempts=0):
    event = {
        "source":     "tarpit",
        "ip":         ip,
        "trap":       "HTTP",
        "status":     status,
        "city":       city,
        "country":    country,
        "bytes_sent": bytes_sent,
        "attempts":   attempts,
    }
    if username or password:
        event["username"] = username
        event["password"] = password
    if lure:
        event["lure"] = lure
    for cb in _callbacks:
        try: cb(event)
        except: pass


def _check_local_ban(ip) -> bool:
    with _attempt_lock:
        _attempt_counts[ip] = _attempt_counts.get(ip, 0) + 1
        if _attempt_counts[ip] >= BAN_THRESHOLD:
            logging.warning(f"[BAN] {ip} banned after {_attempt_counts[ip]} attempts")
            return True
    return False


def _parse_request(data: bytes):
    try:
        text    = data.decode("utf-8", errors="replace")
        lines   = text.split("\r\n")
        parts   = lines[0].split(" ")
        method  = parts[0] if len(parts) > 0 else "?"
        path    = parts[1] if len(parts) > 1 else "/"
        ua      = ""
        for line in lines:
            if line.lower().startswith("user-agent:"):
                ua = line.split(":", 1)[1].strip()
        body = text.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in text else ""
        # POST credentials parse
        username = re.search(r"username=([^&\s]+)", body)
        password = re.search(r"password=([^&\s]+)", body)
        return method, path, ua, \
               username.group(1) if username else "", \
               password.group(1) if password else ""
    except Exception:
        return "?", "/", "", "", ""


def handle_client(conn, addr):
    ip, port = addr
    city, country = "Unknown", "??"
    try:
        city, country = _get_geo(ip)
    except Exception:
        pass

    _tarpit_event(ip, "connected", city, country)

    try:
        conn.settimeout(10)
        data = conn.recv(4096)
        if not data:
            return

        method, path, ua, username, password = _parse_request(data)

        record_attempt(ip)
        entry = log_event("HTTP", ip, port,
                          method=method, path=path,
                          user_agent=ua,
                          username=username,
                          password=password,
                          response="200")
        _fire(entry)
        send_to_api(entry)

        # Decoy lure check
        is_decoy = any(path.startswith(d) for d in DECOY_PATHS)
        if is_decoy:
            _tarpit_event(ip, "lure", city, country, lure=path)
            logging.info(f"[LURE] {ip} hit decoy path: {path}")

        # Credential capture
        if username or password:
            _tarpit_event(ip, "cred", city, country,
                          username=username, password=password)

        # Tarpit delay on suspicious paths
        if is_decoy:
            time.sleep(TARPIT_DELAY)
            if path in ("/login", "/login.php", "/wp-login.php"):
                conn.sendall(FAKE_LOGIN_PAGE)
            else:
                conn.sendall(FAKE_RESPONSE)
        else:
            conn.sendall(FAKE_RESPONSE)

    except Exception as e:
        logging.debug(f"HTTP error {ip}: {e}")
    finally:
        _tarpit_event(ip, "disconnected", city, country)
        try: conn.close()
        except: pass


def start_http_honeypot(host=HOST, port=PORT, callback=None):
    if callback:
        _callbacks.append(callback)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(100)
    logging.info(f"HTTP Honeypot → {host}:{port} | Tarpit delay: {TARPIT_DELAY}s | Ban after: {BAN_THRESHOLD}")
    srv.settimeout(1.0)

    while True:
        try:
            conn, addr = srv.accept()
            ip = addr[0]
            if is_banned(ip):
                conn.close(); continue
            if _check_local_ban(ip):
                conn.close(); continue
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
        except socket.timeout:
            continue
        except OSError:
            break
    srv.close()