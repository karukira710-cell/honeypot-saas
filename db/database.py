from pymongo import MongoClient
from collections import defaultdict
import datetime, os, certifi

# MongoDB URL
MONGO_URL = os.environ.get("MONGO_URL", "mongodb://localhost:27017/")

# Connect
client = MongoClient(
    MONGO_URL,
    tlsCAFile=certifi.where()
)

db = client["honeypot"]
events_collection = db["events"]

print(f"[DB] MongoDB connected: {MONGO_URL[:30]}...")

def save_event(event: dict):
    try:
        event.pop("_id", None)
        events_collection.insert_one(event)
        event.pop("_id", None)
    except Exception as ex:
        print(f"[DB] Save error: {ex}")

def get_events(limit: int = 500) -> list:
    try:
        events = list(
            events_collection.find(
                {}, {"_id": 0}
            ).sort("_id", -1).limit(limit)
        )
        return events
    except Exception as ex:
        print(f"[DB] Fetch error: {ex}")
        return []

def get_stats() -> dict:
    try:
        total = events_collection.count_documents({})
        unique_ips = len(events_collection.distinct("ip"))

        pipeline_svc = [
            {"$group": {"_id": "$service", "count": {"$sum": 1}}}
        ]
        svc_result = list(events_collection.aggregate(pipeline_svc))
        by_service = {r["_id"]: r["count"] for r in svc_result if r["_id"]}

        pipeline_ip = [
            {"$group": {"_id": "$ip", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]
        ip_result = list(events_collection.aggregate(pipeline_ip))
        top_attackers = [{"ip": r["_id"], "count": r["count"]} for r in ip_result]

        pipeline_ml = [
            {"$group": {"_id": "$ml_label", "count": {"$sum": 1}}}
        ]
        ml_result = list(events_collection.aggregate(pipeline_ml))
        by_threat = {r["_id"]: r["count"] for r in ml_result if r["_id"]}

        return {
            "total": total,
            "unique_ips": unique_ips,
            "by_service": by_service,
            "top_attackers": top_attackers,
            "by_threat": by_threat,
        }
    except Exception as ex:
        print(f"[DB] Stats error: {ex}")
        return {"total": 0, "unique_ips": 0}
