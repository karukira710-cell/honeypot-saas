import os, threading
import os as _os

class GeoResolver:
    MMDB_SEARCH = [
        "GeoLite2-City.mmdb",
        _os.path.expanduser("~/GeoLite2-City.mmdb"),
        "/usr/share/GeoIP/GeoLite2-City.mmdb",
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


# Global instance
GEO = GeoResolver(mmdb_path=None)