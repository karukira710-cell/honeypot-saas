from pymongo import MongoClient
import os

# ==============================
# ENV CONFIG (IMPORTANT)
# ==============================
MONGO_URL = os.environ.get("MONGO_URL")

if not MONGO_URL:
    raise Exception("❌ MONGO_URL not set in environment variables")

# ==============================
# CONNECT TO MONGODB
# ==============================
try:
    client = MongoClient(
        MONGO_URL,
        tls=True,
        tlsAllowInvalidCertificates=True,
        serverSelectionTimeoutMS=5000
    )

    # Test connection
    client.admin.command('ping')
    print("✅ MongoDB Connected Successfully")

except Exception as e:
    print("❌ MongoDB Connection Failed:", e)
    raise e

# ==============================
# DATABASE SETUP
# ==============================
db = client["honeypot"]
events_collection = db["events"]

# ==============================
# SAVE EVENT
# ==============================
def save_event(event: dict):
    try:
        event.pop("_id", None)
        events_collection.insert_one(event)
    except Exception as ex:
        print(f"[DB] Save error: {ex}")

# ==============================
# GET EVENTS
# ==============================
def get_events(limit: int = 500) -> list:
    try:
        return list(
            events_collection.find({}, {"_id": 0})
            .sort("_id", -1)
            .limit(limit)
        )
    except Exception as ex:
        print(f"[DB] Fetch error: {ex}")
        return []

# ==============================
# GET STATS
# ==============================
def get_stats() -> dict:
    try:
        total = events_collection.count_documents({})
        unique_ips = len(events_collection.distinct("ip"))

        # By Service
        by_service = {
            r["_id"]: r["count"]
            for r in events_collection.aggregate([
                {"$group": {"_id": "$service", "count": {"$sum": 1}}}
            ]) if r["_id"]
        }

        # Top Attackers
        top_attackers = [
            {"ip": r["_id"], "count": r["count"]}
            for r in events_collection.aggregate([
                {"$group": {"_id": "$ip", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
                {"$limit": 10}
            ])
        ]

        # By Threat (ML)
        by_threat = {
            r["_id"]: r["count"]
            for r in events_collection.aggregate([
                {"$group": {"_id": "$ml_label", "count": {"$sum": 1}}}
            ]) if r["_id"]
        }

        return {
            "total": total,
            "unique_ips": unique_ips,
            "by_service": by_service,
            "top_attackers": top_attackers,
            "by_threat": by_threat,
        }

    except Exception as ex:
        print(f"[DB] Stats error: {ex}")
        return {
            "total": 0,
            "unique_ips": 0,
            "by_service": {},
            "top_attackers": [],
            "by_threat": {}
        }
