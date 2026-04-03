"""
Honeypot → API Connector
Jab bhi attack aaye, API ko data bhejo
"""

import requests
import datetime
import threading

API_URL = "http://127.0.0.1:8000"

def send_to_api(event: dict):
    """
    Kisi bhi event ko API mein save karo
    Background thread mein chalega — honeypot slow nahi hoga
    """
    def _send():
        try:
            # Timestamp add karo
            if "timestamp" not in event:
                event["timestamp"] = datetime.datetime.now().isoformat()

            response = requests.post(
                f"{API_URL}/event",
                json=event,
                timeout=3
            )
            if response.status_code == 200:
                print(f"[API] ✅ Event saved: {event.get('service')} from {event.get('ip')}")
            else:
                print(f"[API] ❌ Failed: {response.status_code}")
        except Exception as ex:
            print(f"[API] ❌ Error: {ex}")

    threading.Thread(target=_send, daemon=True).start()


def make_event(service, ip, **kwargs) -> dict:
    """
    Standard event format banao
    """
    event = {
        "service":   service,
        "ip":        ip,
        "timestamp": datetime.datetime.now().isoformat(),
    }
    event.update(kwargs)
    return event
