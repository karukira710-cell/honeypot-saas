from pymongo import MongoClient
import os, certifi

MONGO_URL = os.environ.get("MONGO_URL")
if not MONGO_URL:
    raise Exception("MONGO_URL not set")

# ========== FIX SSL ==========
client = MongoClient(
    MONGO_URL,
    tls=True,
    tlsAllowInvalidCertificates=True,
    tlsInsecure=True,            # yeh SSL internal error fix karega
    serverSelectionTimeoutMS=30000
)

# Test connection
try:
    client.admin.command('ping')
    print("✅ MongoDB Connected")
except Exception as e:
    print("❌ MongoDB error:", e)
    raise e

db = client["honeypot"]
events_collection = db["events"]

def save_event(event: dict):
    event.pop("_id", None)
    events_collection.insert_one(event)

def get_events(limit=500):
    return list(events_collection.find({}, {"_id":0}).sort("_id", -1).limit(limit))

def get_stats():
    total = events_collection.count_documents({})
    unique_ips = len(events_collection.distinct("ip"))
    by_service = {r["_id"]: r["count"] for r in events_collection.aggregate([{"$group": {"_id":"$service","count":{"$sum":1}}}]) if r["_id"]}
    top_attackers = [{"ip":r["_id"],"count":r["count"]} for r in events_collection.aggregate([{"$group":{"_id":"$ip","count":{"$sum":1}}},{"$sort":{"count":-1}},{"$limit":10}])]
    by_threat = {r["_id"]: r["count"] for r in events_collection.aggregate([{"$group":{"_id":"$ml_label","count":{"$sum":1}}}]) if r["_id"]}
    return {"total":total, "unique_ips":unique_ips, "by_service":by_service, "top_attackers":top_attackers, "by_threat":by_threat}

