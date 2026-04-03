from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from api.routes import router
import datetime

app = FastAPI(
    title="Honeypot API",
    description="Live honeypot data API",
    version="2.0"
)

# CORS — browser se access karne ke liye
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)

@app.get("/")
def home():
    return {
        "status": "running",
        "message": "Honeypot API v2 is live!",
        "time": datetime.datetime.now().isoformat(),
        "endpoints": ["/attacks", "/stats", "/live", "/event"]
    }

@app.get("/dashboard")
def dashboard():
    return FileResponse("dashboard.html")