"""
FastAPI Server Entry Point

AI-Powered Phishing & Threat Detection System Backend
"""

import os
import sys
import datetime
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Ensure workspace root is on sys.path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from backend.routes.analyze import router as analyze_router
from backend.database.database import init_db
from backend.services.url_analyzer import load_model_artifact

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context manager."""
    init_db()
    load_model_artifact()
    yield

app = FastAPI(
    title="AI-Powered Phishing & Threat Detection API",
    description="Defensive URL Threat Intelligence and Machine Learning Analysis API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# CORS Middleware Configuration
origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "*"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Router
app.include_router(analyze_router)


@app.get("/api/health", summary="Health Check Endpoint")
def health_check():
    artifact = load_model_artifact()
    model_loaded = artifact is not None and "model" in artifact
    
    return {
        "status": "ok",
        "service": "AI-Powered Phishing & Threat Detection System",
        "version": "1.0.0",
        "model_loaded": model_loaded,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app:app", host="0.0.0.0", port=8000, reload=True)
