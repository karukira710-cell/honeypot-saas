"""
Advanced SSH Honeypot — SSH.py
Captures credentials, public keys, commands.
FIXED: Tarpit events ab main.py ke Tarpit Monitor mein dikhenge.
"""

import socket, threading, logging, os, time
from core import log_event, is_banned, record_attempt
from honeypot_connector import send_to_api, make_event

LOG_FILE = "logs/ssh.log"
HOST     = "0.0.0.0"
PORT     = 2222

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SSH] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)

_callbacks = []

try:
    import paramiko
    PARAMIKO_OK = True
except ImportError:
    PARAMIKO_OK = False


def _host_key():
    kp = "logs/ssh_host_key"
    if PARAMIKO_OK:
        if os.path.exists(kp):
            return paramiko.RSAKey(filename=kp)
        k = paramiko.RSAKey.generate(2048)
        k.write_private_key_file(kp)
        return k
    return None


def _fire(entry):
    """Normal callback — Dashboard mein dikhne ke liye."""
    for cb in _callbacks:
        try: cb(entry)
        except: pass


def _tarpit_event(ip, trap, status, city="Unknown", country="??",
                  username="", password="", lure=None,
                  bytes_sent=0, attempts=0):
    """
    Tarpit event bhejo — main.py ka Tarpit Monitor tab
    sirf yeh events sunta hai (source == 'tarpit').
    """
    event = {
        "source":     "tarpit",
        "ip":         ip,
        "trap":       trap,
        "status":     status,   # connected / activity / lure / cred / disconnected
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


# ── GeoIP helper (agar main.py ka GEO available nahi toh basic fallback) ──────
def _get_geo(ip):
    """Basic geo lookup — city/country tarpit events ke liye."""
    try:
        import urllib.request, json
        url = f"http://ip-api.com/json/{ip}?fields=status,city,country,countryCode"
        with urllib.request.urlopen(url, timeout=3) as r:
            d = json.loads(r.read())
        if d.get("status") == "success":
            return d.get("city", "Unknown"), d.get("country", "??")
    except Exception:
        pass
    return "Unknown", "??"


# ── SSH Tarpit Delay ───────────────────────────────────────────────────────────
TARPIT_DELAY = 8      # seconds tak connection rok ke rakho (hacker ka time waste)
BAN_THRESHOLD = 5     # itni attempts ke baad local ban


if PARAMIKO_OK:
    class FakeSSH(paramiko.ServerInterface):
        def __init__(self, ip, port):
            self.ip       = ip
            self.port     = port
            self.username = ""
            self.attempts = 0
            self.event    = threading.Event()
            self._city    = "Unknown"
            self._country = "??"

        def check_channel_request(self, kind, chanid):
            if kind == "session":
                return paramiko.OPEN_SUCCEEDED
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

        def check_auth_password(self, username, password):
            self.username  = username
            self.attempts += 1

            # Normal dashboard event
            entry = log_event("SSH", self.ip, self.port,
                              username=username, password=password,
                              auth_type="password")
            record_attempt(self.ip)
            _fire(entry)
            send_to_api(entry)

            # Tarpit: credential captured event
            _tarpit_event(
                ip       = self.ip,
                trap     = "SSH",
                status   = "cred",
                city     = self._city,
                country  = self._country,
                username = username,
                password = password,
                attempts = self.attempts,
            )

            # Tarpit delay — hacker ka time waste karo
            logging.info(f"[TARPIT] {self.ip} — SSH cred captured, delaying {TARPIT_DELAY}s")
            time.sleep(TARPIT_DELAY)

            return paramiko.AUTH_FAILED

        def check_auth_publickey(self, username, key):
            fp = key.get_fingerprint().hex() if hasattr(key, "get_fingerprint") else "unknown"
            entry = log_event("SSH", self.ip, self.port,
                              username=username,
                              password=f"[PUBKEY:{fp[:20]}]",
                              auth_type="publickey")
            record_attempt(self.ip)
            _fire(entry)
            send_to_api(entry)

            _tarpit_event(
                ip       = self.ip,
                trap     = "SSH",
                status   = "cred",
                city     = self._city,
                country  = self._country,
                username = username,
                password = f"[PUBKEY:{fp[:20]}]",
                attempts = self.attempts,
            )
            return paramiko.AUTH_FAILED

        def get_allowed_auths(self, username):
            return "password,publickey"

        def check_channel_shell_request(self, ch):
            self.event.set()
            return True

        def check_channel_pty_request(self, ch, *a):
            return True

        def check_channel_exec_request(self, channel, command):
            cmd = command.decode("utf-8", errors="replace")
            entry = log_event("SSH", self.ip, self.port,
                              username=self.username, command=cmd)
            _fire(entry)
            send_to_api(entry)

            # Command = lure event (hacker ne command try kiya)
            _tarpit_event(
                ip      = self.ip,
                trap    = "SSH",
                status  = "lure",
                city    = self._city,
                country = self._country,
                lure    = cmd[:40],
            )
            channel.send_exit_status(0)
            return True


def handle_paramiko(conn, addr, hkey):
    ip, port = addr

    # Geo lookup background mein
    city, country = "Unknown", "??"
    try:
        city, country = _get_geo(ip)
    except Exception:
        pass

    transport = None
    try:
        transport = paramiko.Transport(conn)
        transport.add_server_key(hkey)
        transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"

        srv = FakeSSH(ip, port)
        srv._city    = city
        srv._country = country

        # Tarpit: connected event
        _tarpit_event(ip=ip, trap="SSH", status="connected",
                      city=city, country=country)

        transport.start_server(server=srv)
        chan = transport.accept(20)

        if chan:
            srv.event.wait(10)
            # Lure: fake shell prompt bhejo
            _tarpit_event(ip=ip, trap="SSH", status="lure",
                          city=city, country=country,
                          lure="shell_prompt")
            chan.send(
                b"\r\nWelcome to Ubuntu 22.04.2 LTS\r\n"
                b"Last login: Fri Jan 13 08:22:01 2025 from 10.0.0.1\r\n$ "
            )
            # Hacker ka time aur waste karo
            time.sleep(TARPIT_DELAY)
            chan.close()

    except Exception as e:
        logging.debug(f"SSH paramiko error {ip}: {e}")
    finally:
        # Tarpit: disconnected event — duration calculate hoga main.py mein
        _tarpit_event(ip=ip, trap="SSH", status="disconnected",
                      city=city, country=country)
        if transport:
            try: transport.close()
            except: pass
        conn.close()
        logging.info(f"[TARPIT] {ip} disconnected from SSH trap")


def handle_raw(conn, addr):
    """Paramiko nahi hai toh raw socket se handle karo."""
    ip, port = addr
    city, country = "Unknown", "??"
    try:
        city, country = _get_geo(ip)
    except Exception:
        pass

    _tarpit_event(ip=ip, trap="SSH-RAW", status="connected",
                  city=city, country=country)
    try:
        conn.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n")
        data = conn.recv(256)
        raw  = data.decode("utf-8", errors="replace").strip()

        entry = log_event("SSH", ip, port,
                          username="[banner-grab]", password=raw[:80])
        record_attempt(ip)
        _fire(entry)
        send_to_api(entry)

        _tarpit_event(ip=ip, trap="SSH-RAW", status="cred",
                      city=city, country=country,
                      username="[banner-grab]", password=raw[:80])

        time.sleep(TARPIT_DELAY)   # delay
    except Exception:
        pass
    finally:
        _tarpit_event(ip=ip, trap="SSH-RAW", status="disconnected",
                      city=city, country=country)
        conn.close()


# ── IP attempt counter for local ban ─────────────────────────────────────────
_attempt_counts = {}
_attempt_lock   = threading.Lock()


def _check_local_ban(ip) -> bool:
    """5+ attempts = local ban, connection drop karo."""
    with _attempt_lock:
        _attempt_counts[ip] = _attempt_counts.get(ip, 0) + 1
        if _attempt_counts[ip] >= BAN_THRESHOLD:
            logging.warning(f"[BAN] {ip} banned after {_attempt_counts[ip]} attempts")
            return True
    return False


def start_ssh_honeypot(host=HOST, port=PORT, callback=None):
    if callback:
        _callbacks.append(callback)

    hkey = _host_key()
    srv  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(100)

    mode = "paramiko" if PARAMIKO_OK else "raw"
    logging.info(f"SSH Honeypot → {host}:{port} [{mode}] | Tarpit delay: {TARPIT_DELAY}s | Ban after: {BAN_THRESHOLD} attempts")

    srv.settimeout(1.0)
    while True:
        try:
            conn, addr = srv.accept()
            ip = addr[0]

            # core.py ban check
            if is_banned(ip):
                logging.info(f"[BANNED] {ip} — connection rejected")
                conn.close()
                continue

            # Local 5-attempt ban check
            if _check_local_ban(ip):
                conn.close()
                continue

            fn   = handle_paramiko if PARAMIKO_OK else handle_raw
            args = (conn, addr, hkey) if PARAMIKO_OK else (conn, addr)
            threading.Thread(target=fn, args=args, daemon=True).start()

        except socket.timeout:
            continue
        except OSError:
            break

    srv.close()