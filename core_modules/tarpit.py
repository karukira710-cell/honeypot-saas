import time, datetime, threading
from collections import defaultdict

class TarpitSession:
    def __init__(self, ip, trap_name, city="Unknown", country="??"):
        self.ip             = ip
        self.trap_name      = trap_name
        self.city           = city
        self.country        = country
        self.start_time     = time.time()
        self.last_seen      = time.time()
        self.bytes_sent     = 0
        self.attempts       = 0
        self.lures_taken    = []
        self.creds_captured = []
        self.alive          = True

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

    def process_event(self, e: dict):
        ip      = e.get("ip", "unknown")
        trap    = e.get("trap", "unknown")
        status  = e.get("status", "activity")
        city    = e.get("city", "Unknown")
        country = e.get("country", "??")

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
                    self.total_creds.append({
                        "ip": ip, "user": u, "pass": p,
                        "time": datetime.datetime.now().isoformat()
                    })

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


# Global instance
TARPIT = TarpitMonitor()
