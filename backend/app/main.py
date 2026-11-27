
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.core.database import create_tables
from backend.app.api.evidence import router as evidence_router
from backend.app.api.incidents import router as incidents_router
from backend.app.api.sources import router as sources_router
from backend.app.api.correlations import router as correlations_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    create_tables()
    yield


app = FastAPI(
    title="AEGIS-X",
    description="Unified AI Cybersecurity Intelligence Platform",
    version="0.3.0",
    lifespan=lifespan
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500"
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Content-Type", "Accept"]
)


app.include_router(evidence_router)
app.include_router(incidents_router)
app.include_router(sources_router)
app.include_router(correlations_router)


@app.get("/")
def home():
    return {
        "project": "AEGIS-X",
        "message": "Cybersecurity Intelligence Platform is running",
        "version": "0.3.0"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "AEGIS-X Backend",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
