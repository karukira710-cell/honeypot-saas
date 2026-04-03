"""
Advanced TELNET Honeypot — TELNET.py
FIXED: Tarpit events ab Tarpit Monitor mein dikhenge.
"""

import socket, threading, logging, os, time
from core import log_event, is_banned, record_attempt
from honeypot_connector import send_to_api, make_event 

LOG_FILE = "logs/telnet.log"
HOST     = "0.0.0.0"
PORT     = 2323

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [TELNET] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)

_callbacks    = []
BAN_THRESHOLD = 5
TARPIT_DELAY  = 6

_attempt_counts = {}
_attempt_lock   = threading.Lock()

BANNER = (
    b"\r\nUbuntu 22.04.2 LTS\r\n"
    b"Kernel 5.15.0-91-generic\r\n\r\n"
    b"login: "
)

FAKE_CMDS = {
    "whoami": b"root\r\n",
    "id":     b"uid=0(root) gid=0(root) groups=0(root)\r\n",
    "ls":     b"bin  boot  dev  etc  home  lib  lost+found  media  mnt  opt  proc  root  run  srv  sys  tmp  usr  var\r\n",
    "pwd":    b"/root\r\n",
    "uname -a": b"Linux ubuntu 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\r\n",
    "cat /etc/passwd": b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n",
}


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
        "trap":       "TELNET",
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
    attempts = 0

    try:
        conn.sendall(BANNER)

        while True:
            conn.settimeout(30)

            # Username
            try:
                user_data = b""
                while True:
                    ch = conn.recv(1)
                    if not ch or ch in (b"\r", b"\n"):
                        break
                    user_data += ch
                username = user_data.decode("utf-8", errors="replace").strip()
            except socket.timeout:
                break

            if not username:
                break

            conn.sendall(b"Password: ")

            # Password
            try:
                pass_data = b""
                while True:
                    ch = conn.recv(1)
                    if not ch or ch in (b"\r", b"\n"):
                        break
                    pass_data += ch
                password = pass_data.decode("utf-8", errors="replace").strip()
            except socket.timeout:
                break

            attempts += 1
            record_attempt(ip)

            entry = log_event("TELNET", ip, port,
                              username=username, password=password)
            _fire(entry)
            send_to_api(entry) 

            _tarpit_event(ip, "cred", city, country,
                          username=username, password=password,
                          attempts=attempts)

            # Tarpit delay
            time.sleep(TARPIT_DELAY)

            if attempts >= 3:
                conn.sendall(b"\r\nLogin incorrect\r\n\r\n")
                break

            # Fake shell — lure
            _tarpit_event(ip, "lure", city, country, lure="fake_shell")
            conn.sendall(b"\r\n$ ")

            # Command loop
            while True:
                try:
                    cmd_data = b""
                    while True:
                        ch = conn.recv(1)
                        if not ch or ch in (b"\r", b"\n"):
                            break
                        cmd_data += ch
                    cmd = cmd_data.decode("utf-8", errors="replace").strip()
                except socket.timeout:
                    break

                if not cmd:
                    conn.sendall(b"$ ")
                    continue

                logging.info(f"[TELNET] {ip} cmd: {cmd}")
                _tarpit_event(ip, "lure", city, country, lure=f"CMD:{cmd[:30]}")

                entry = log_event("TELNET", ip, port,
                                  username=username, command=cmd)
                _fire(entry)
                send_to_api(entry)

                response = FAKE_CMDS.get(cmd.lower(),
                           b"bash: command not found\r\n")
                conn.sendall(response)
                conn.sendall(b"$ ")

                if cmd.lower() in ("exit", "logout", "quit"):
                    break

            break

    except Exception as e:
        logging.debug(f"TELNET error {ip}: {e}")
    finally:
        _tarpit_event(ip, "disconnected", city, country)
        try: conn.close()
        except: pass


def start_telnet_honeypot(host=HOST, port=PORT, callback=None):
    if callback:
        _callbacks.append(callback)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(100)
    logging.info(f"TELNET Honeypot → {host}:{port} | Tarpit delay: {TARPIT_DELAY}s | Ban after: {BAN_THRESHOLD}")
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