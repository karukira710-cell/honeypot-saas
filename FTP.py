"""
Advanced FTP Honeypot — FTP.py
FIXED: Tarpit events ab Tarpit Monitor mein dikhenge.
"""

import socket, threading, logging, os, time
from core import log_event, is_banned, record_attempt
from honeypot_connector import send_to_api, make_event 

LOG_FILE = "logs/ftp.log"
HOST     = "0.0.0.0"
PORT     = 2121

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [FTP] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)

_callbacks    = []
BAN_THRESHOLD = 5
TARPIT_DELAY  = 6

_attempt_counts = {}
_attempt_lock   = threading.Lock()

DECOY_FILES = [
    "passwords.txt", "backup.zip", "database.sql",
    "config.php", "id_rsa", "credentials.txt",
    "users.csv", "dump.sql", "secret.key",
]


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
        "trap":       "FTP",
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


def handle_client(conn, addr):
    ip, port = addr
    city, country = "Unknown", "??"
    try:
        city, country = _get_geo(ip)
    except Exception:
        pass

    _tarpit_event(ip, "connected", city, country)

    username = ""
    password = ""
    attempts = 0

    try:
        conn.sendall(b"220 FTP server ready (vsftpd 3.0.5)\r\n")

        while True:
            conn.settimeout(30)
            try:
                data = conn.recv(1024)
            except socket.timeout:
                break
            if not data:
                break

            cmd = data.decode("utf-8", errors="replace").strip()
            upper = cmd.upper()
            logging.info(f"[FTP] {ip} → {cmd}")

            if upper.startswith("USER"):
                username = cmd[5:].strip()
                conn.sendall(b"331 Password required\r\n")

            elif upper.startswith("PASS"):
                password = cmd[5:].strip()
                attempts += 1
                record_attempt(ip)

                entry = log_event("FTP", ip, port,
                                  username=username, password=password)
                _fire(entry)
                send_to_api(entry)

                _tarpit_event(ip, "cred", city, country,
                              username=username, password=password,
                              attempts=attempts)

                # Tarpit delay
                time.sleep(TARPIT_DELAY)
                conn.sendall(b"530 Login incorrect.\r\n")

                if attempts >= BAN_THRESHOLD:
                    break

            elif upper.startswith("LIST") or upper.startswith("NLST"):
                # Decoy file list dikhao — lure
                _tarpit_event(ip, "lure", city, country, lure="DIR_LIST")
                file_list = "\r\n".join(
                    [f"-rw-r--r-- 1 root root 4096 Jan 13 08:22 {f}"
                     for f in DECOY_FILES]
                )
                conn.sendall(b"150 Here comes the directory listing.\r\n")
                conn.sendall(f"226 {file_list}\r\n".encode())

            elif upper.startswith("RETR"):
                fname = cmd[5:].strip()
                _tarpit_event(ip, "lure", city, country, lure=f"RETR:{fname}")
                # Fake slow transfer
                conn.sendall(b"150 Opening data connection.\r\n")
                time.sleep(3)
                conn.sendall(b"226 Transfer complete.\r\n")

            elif upper.startswith("QUIT"):
                conn.sendall(b"221 Goodbye.\r\n")
                break

            else:
                conn.sendall(b"500 Unknown command.\r\n")

    except Exception as e:
        logging.debug(f"FTP error {ip}: {e}")
    finally:
        _tarpit_event(ip, "disconnected", city, country)
        try: conn.close()
        except: pass


def start_ftp_honeypot(host=HOST, port=PORT, callback=None):
    if callback:
        _callbacks.append(callback)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(100)
    logging.info(f"FTP Honeypot → {host}:{port} | Tarpit delay: {TARPIT_DELAY}s | Ban after: {BAN_THRESHOLD}")
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