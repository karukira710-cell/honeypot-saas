"""
Advanced MYSQL Honeypot — MYSQL.py
FIXED: Tarpit events ab Tarpit Monitor mein dikhenge.
"""

import socket, threading, logging, os, time, struct, hashlib, os as _os
from core import log_event, is_banned, record_attempt
from honeypot_connector import send_to_api, make_event

LOG_FILE = "logs/mysql.log"
HOST     = "0.0.0.0"
PORT     = 3306

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [MYSQL] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)

_callbacks    = []
BAN_THRESHOLD = 5
TARPIT_DELAY  = 5

_attempt_counts = {}
_attempt_lock   = threading.Lock()


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
        "trap":       "MYSQL",
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


def _make_handshake():
    """Fake MySQL server handshake packet."""
    scramble   = _os.urandom(20)
    server_ver = b"8.0.32\x00"
    conn_id    = struct.pack("<I", 1)
    caps       = struct.pack("<H", 0xF7FF)
    charset    = b"\x21"
    status     = struct.pack("<H", 0x0002)
    caps2      = struct.pack("<H", 0x8000)
    auth_len   = b"\x15"
    reserved   = b"\x00" * 10

    payload = (
        b"\x0a" + server_ver + conn_id +
        scramble[:8] + b"\x00" + caps + charset +
        status + caps2 + auth_len + reserved +
        scramble[8:] + b"\x00"
    )
    length  = struct.pack("<I", len(payload))[:3]
    seq     = b"\x00"
    return length + seq + payload


def _make_auth_failed():
    """MySQL auth failed error packet."""
    msg     = b"Access denied for user 'root'@'localhost'"
    payload = b"\xff" + struct.pack("<H", 1045) + b"#28000" + msg
    length  = struct.pack("<I", len(payload))[:3]
    return length + b"\x02" + payload


def _parse_auth(data: bytes):
    """MySQL auth packet se username parse karo."""
    try:
        if len(data) < 36:
            return "", ""
        # Skip: length(3) + seq(1) + caps(4) + maxpkt(4) + charset(1) + reserved(23)
        offset   = 4 + 4 + 4 + 1 + 23
        username = b""
        while offset < len(data) and data[offset:offset+1] != b"\x00":
            username += data[offset:offset+1]
            offset += 1
        return username.decode("utf-8", errors="replace"), ""
    except Exception:
        return "", ""


def handle_client(conn, addr):
    ip, port = addr
    city, country = "Unknown", "??"
    try:
        city, country = _get_geo(ip)
    except Exception:
        pass

    _tarpit_event(ip, "connected", city, country)
    attempts = 0

    try:
        # Send fake handshake
        conn.sendall(_make_handshake())

        while True:
            conn.settimeout(15)
            try:
                data = conn.recv(4096)
            except socket.timeout:
                break
            if not data:
                break

            username, password = _parse_auth(data)
            attempts += 1
            record_attempt(ip)

            logging.info(f"[MYSQL] {ip} → user={username}")

            entry = log_event("MYSQL", ip, port,
                              username=username, password="[HASHED]")
            _fire(entry)
            send_to_api(entry)

            _tarpit_event(ip, "cred", city, country,
                          username=username, password="[MYSQL-AUTH]",
                          attempts=attempts)

            # Tarpit delay
            time.sleep(TARPIT_DELAY)
            conn.sendall(_make_auth_failed())

            if attempts >= BAN_THRESHOLD:
                break

    except Exception as e:
        logging.debug(f"MYSQL error {ip}: {e}")
    finally:
        _tarpit_event(ip, "disconnected", city, country)
        try: conn.close()
        except: pass


def start_mysql_honeypot(host=HOST, port=PORT, callback=None):
    if callback:
        _callbacks.append(callback)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(100)
    logging.info(f"MYSQL Honeypot → {host}:{port} | Tarpit delay: {TARPIT_DELAY}s | Ban after: {BAN_THRESHOLD}")
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