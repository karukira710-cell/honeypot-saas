from fastapi import APIRouter
from db.database import save_event, get_events, get_stats
import datetime

router = APIRouter()

# ── Saare attacks ─────────────────────────────────
@router.get("/attacks")
def get_attacks():
    events = get_events()
    return {
        "total": len(events),
        "attacks": events
    }

# ── Latest 10 attacks ─────────────────────────────
@router.get("/live")
def get_live():
    events = get_events()
    return {
        "total": len(events),
        "latest": events[-10:] if len(events) >= 10 else events
    }

# ── Stats ──────────────────────────────────────────
@router.get("/stats")
def get_stats_route():
    return get_stats()

# ── Honeypot se event receive karo ────────────────
@router.post("/event")
def post_event(event: dict):
    event["received_at"] = datetime.datetime.now().isoformat()
    save_event(event)
    # ObjectId wali cheez mat return karo
    event.pop("_id", None)
    return {"status": "saved"}
# ── Health check ───────────────────────────────────
@router.get("/health")
def health():
    return {"status": "ok"}
