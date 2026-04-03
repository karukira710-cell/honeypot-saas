import datetime, json, threading, urllib.request

DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1487676121934725181/OZIkQSjicLj2KbcSuDqJKkyje4GUIAhH8ih6KSMeco-APoiZI8Pd5zzfbBI2esciRwnv"

def send_discord_alert(event: dict, geo: dict, ml_score: int, ml_label: str):
    if not DISCORD_WEBHOOK_URL or not DISCORD_WEBHOOK_URL.startswith("https://"):
        return
    if ml_label == "SAFE":
        return

    def _send():
        try:
            svc     = event.get("service", "?")
            ip      = event.get("ip", "?")
            ts      = event.get("timestamp", "")[:19]
            city    = geo.get("city", "Unknown")
            country = geo.get("country", "??")
            user    = event.get("username", "")
            pwd     = event.get("password", "")
            path    = event.get("path", event.get("command", ""))[:60]
            emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "SUSPICIOUS": "🟡"}.get(ml_label, "⚪")
            embed = {
                "title": f"{emoji} Honeypot Alert — {ml_label}",
                "color": {"CRITICAL": 0xf38ba8, "HIGH": 0xfab387,
                           "SUSPICIOUS": 0xf9e2af}.get(ml_label, 0xaaaaaa),
                "fields": [
                    {"name": "🕐 Time",     "value": ts,                "inline": True},
                    {"name": "🌐 Service",  "value": svc,               "inline": True},
                    {"name": "🤖 ML Score", "value": f"{ml_score}/100", "inline": True},
                    {"name": "🖥️ IP",       "value": f"`{ip}`",         "inline": True},
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
                pass
        except Exception as ex:
            print(f"[Discord] Alert failed: {ex}")

    threading.Thread(target=_send, daemon=True).start()
