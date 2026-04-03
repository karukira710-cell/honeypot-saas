from pymongo import MongoClient
from collections import defaultdict
import datetime,os

# ── MongoDB Connection ─────────────────────────────
MONGO_URL = os.environ.get("MONGO_URL", "mongodb://localhost:27017/")
client = MongoClient(
    MONGO_URL,
    tls=True,
    tlsAllowInvalidCertificates=True
)
db     = client["honeypot"]
events_collection = db["events"]

print(f"[DB] MongoDB connected: {MONGO_URL}")

# ── Save Event ─────────────────────────────────────
def save_event(event: dict):
    try:
        event.pop("_id", None)
        result = events_collection.insert_one(event)
        # _id remove karo response se
        event.pop("_id", None)
    except Exception as ex:
        print(f"[DB] Save error: {ex}")
# ── Get Events ─────────────────────────────────────
def get_events(limit: int = 500) -> list:
    try:
        events = list(
            events_collection.find(
                {}, {"_id": 0}  # _id hide karo
            ).sort("_id", -1).limit(limit)
        )
        return events
    except Exception as ex:
        print(f"[DB] Fetch error: {ex}")
        return []

# ── Get Stats ──────────────────────────────────────
def get_stats() -> dict:
    try:
        total      = events_collection.count_documents({})
        unique_ips = len(events_collection.distinct("ip"))

        # Service wise count
        pipeline_svc = [
            {"$group": {"_id": "$service", "count": {"$sum": 1}}}
        ]
        svc_result = list(events_collection.aggregate(pipeline_svc))
        by_service = {r["_id"]: r["count"] for r in svc_result if r["_id"]}

        # Top attackers
        pipeline_ip = [
            {"$group": {"_id": "$ip", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]
        ip_result     = list(events_collection.aggregate(pipeline_ip))
        top_attackers = [{"ip": r["_id"], "count": r["count"]} for r in ip_result]

        # ML threat counts
        pipeline_ml = [
            {"$group": {"_id": "$ml_label", "count": {"$sum": 1}}}
        ]
        ml_result  = list(events_collection.aggregate(pipeline_ml))
        by_threat  = {r["_id"]: r["count"] for r in ml_result if r["_id"]}

        return {
            "total":         total,
            "unique_ips":    unique_ips,
            "by_service":    by_service,
            "top_attackers": top_attackers,
            "by_threat":     by_threat,
        }
    except Exception as ex:
        print(f"[DB] Stats error: {ex}")
        return {"total": 0, "unique_ips": 0}
