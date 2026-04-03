"""
Advanced SMTP Honeypot — SMTP.py
FIXED: Tarpit events ab Tarpit Monitor mein dikhenge.
"""

import socket, threading, logging, os, time, base64
from core import log_event, is_banned, record_attempt
from honeypot_connector import send_to_api, make_event    # ← ADD

LOG_FILE = "logs/smtp.log"
HOST     = "0.0.0.0"
PORT     = 2525

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SMTP] %(message)s",
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
        "trap":       "SMTP",
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
        conn.sendall(b"220 mail.company.com ESMTP Postfix\r\n")

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
            logging.info(f"[SMTP] {ip} → {cmd[:80]}")

            if upper.startswith("EHLO") or upper.startswith("HELO"):
                _tarpit_event(ip, "lure", city, country, lure=f"EHLO:{cmd[5:20]}")
                conn.sendall(
                    b"250-mail.company.com\r\n"
                    b"250-SIZE 52428800\r\n"
                    b"250-AUTH LOGIN PLAIN\r\n"
                    b"250 STARTTLS\r\n"
                )

            elif upper.startswith("AUTH LOGIN"):
                conn.sendall(b"334 VXNlcm5hbWU6\r\n")  # Username:
                try:
                    u_data = conn.recv(256).strip()
                    username = base64.b64decode(u_data).decode("utf-8", errors="replace")
                except Exception:
                    username = u_data.decode("utf-8", errors="replace") if isinstance(u_data, bytes) else ""

                conn.sendall(b"334 UGFzc3dvcmQ6\r\n")  # Password:
                try:
                    p_data = conn.recv(256).strip()
                    password = base64.b64decode(p_data).decode("utf-8", errors="replace")
                except Exception:
                    password = p_data.decode("utf-8", errors="replace") if isinstance(p_data, bytes) else ""

                attempts += 1
                record_attempt(ip)
                entry = log_event("SMTP", ip, port,
                                  username=username, password=password)
                _fire(entry)
                send_to_api(entry) 
                _tarpit_event(ip, "cred", city, country,
                              username=username, password=password,
                              attempts=attempts)

                time.sleep(TARPIT_DELAY)
                conn.sendall(b"535 Authentication credentials invalid\r\n")

            elif upper.startswith("AUTH PLAIN"):
                try:
                    parts = cmd.split(" ", 2)
                    if len(parts) == 3:
                        decoded = base64.b64decode(parts[2]).decode("utf-8", errors="replace")
                        creds   = decoded.split("\x00")
                        username = creds[1] if len(creds) > 1 else ""
                        password = creds[2] if len(creds) > 2 else ""
                except Exception:
                    username, password = "", ""

                attempts += 1
                record_attempt(ip)
                entry = log_event("SMTP", ip, port,
                                  username=username, password=password)
                _fire(entry)
                send_to_api(entry) 
                _tarpit_event(ip, "cred", city, country,
                              username=username, password=password,
                              attempts=attempts)

                time.sleep(TARPIT_DELAY)
                conn.sendall(b"535 Authentication credentials invalid\r\n")

            elif upper.startswith("MAIL FROM"):
                _tarpit_event(ip, "lure", city, country, lure=f"MAIL:{cmd[10:40]}")
                conn.sendall(b"250 Ok\r\n")

            elif upper.startswith("RCPT TO"):
                _tarpit_event(ip, "lure", city, country, lure=f"RCPT:{cmd[8:40]}")
                conn.sendall(b"250 Ok\r\n")

            elif upper == "DATA":
                conn.sendall(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                mail_data = b""
                while True:
                    chunk = conn.recv(4096)
                    mail_data += chunk
                    if b"\r\n.\r\n" in mail_data:
                        break
                _tarpit_event(ip, "lure", city, country,
                              lure=f"DATA:{len(mail_data)}bytes",
                              bytes_sent=len(mail_data))
                time.sleep(2)
                conn.sendall(b"250 Ok: queued\r\n")

            elif upper == "QUIT":
                conn.sendall(b"221 Bye\r\n")
                break

            else:
                conn.sendall(b"500 Unrecognized command\r\n")

            if attempts >= BAN_THRESHOLD:
                break

    except Exception as e:
        logging.debug(f"SMTP error {ip}: {e}")
    finally:
        _tarpit_event(ip, "disconnected", city, country)
        try: conn.close()
        except: pass


def start_smtp_honeypot(host=HOST, port=PORT, callback=None):
    if callback:
        _callbacks.append(callback)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(100)
    logging.info(f"SMTP Honeypot → {host}:{port} | Tarpit delay: {TARPIT_DELAY}s | Ban after: {BAN_THRESHOLD}")
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