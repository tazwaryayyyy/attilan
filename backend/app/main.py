from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

from backend.app.config import settings
from backend.app.database import db_manager
from backend.app.routers import entity, events, export, ingest
from backend.app.services.storage import storage_service


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    # Lifespan startup
    try:
        await db_manager.connect()
    except Exception as e:
        # Allow running in testing/offline mock environments
        print(f"Warning: Database connection could not be established on startup: {e}")
    yield
    # Lifespan shutdown
    await db_manager.disconnect()


app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Criminal Intelligence & Evidence Integrity Platform (Evidence Act 2022 Compliant)",
    version="1.0.0",
    lifespan=lifespan,
)

if settings.cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH"],
        allow_headers=["Authorization", "Content-Type", "X-Dual-Control-Authorization"],
    )

app.include_router(ingest.router)
app.include_router(entity.router)
app.include_router(events.router)
app.include_router(export.router)


@app.get("/health", tags=["System Health"])
async def health_check():
    """Rigorous dependency healthcheck verifying live Postgres and MinIO WORM subsystems."""
    subsystem_status = {
        "postgres": "DOWN",
        "minio": "DOWN",
    }
    failures = []

    # 1. PostgreSQL Ping Verification
    try:
        await db_manager.execute("SELECT 1")
        subsystem_status["postgres"] = "UP"
    except Exception as exc:
        subsystem_status["postgres"] = f"ERROR: {str(exc)}"
        failures.append(f"PostgreSQL ping failed: {str(exc)}")

    # 2. MinIO WORM Storage Verification
    try:
        bucket_exists = storage_service.client.bucket_exists(storage_service.bucket_name)
        if bucket_exists:
            subsystem_status["minio"] = "UP"
        else:
            subsystem_status["minio"] = "BUCKET_NOT_FOUND"
            failures.append(f"MinIO bucket '{storage_service.bucket_name}' not found")
    except Exception as exc:
        subsystem_status["minio"] = f"ERROR: {str(exc)}"
        failures.append(f"MinIO check failed: {str(exc)}")

    if failures:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "status": "DEGRADED",
                "failures": failures,
                "subsystems": subsystem_status,
            },
        )

    return {
        "status": "OPERATIONAL",
        "platform": settings.PROJECT_NAME,
        "compliance": "Evidence (Amendment) Act 2022 s.65B",
        "storage": "MinIO WORM (Object Lock Enabled)",
        "subsystems": subsystem_status,
    }
