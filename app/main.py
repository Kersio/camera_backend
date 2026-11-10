
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, status
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.core.config import settings
from app.core.database import engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await engine.dispose()


app = FastAPI(
    title=settings.app_name,
    description="Backend for intelligent video surveillance system",
    version="0.1.0",
    debug=settings.debug,
    lifespan=lifespan,
)


@app.get("/health", tags=["Health"])
async def health_check() -> dict[str, str]:
    return {
        "status": "ok",
        "application": settings.app_name,
    }


@app.get("/health/db", tags=["Health"])
async def database_health_check() -> dict[str, str]:
    try:
        async with engine.connect() as connection:
            await connection.execute(text("SELECT 1"))

        return {"status": "ok", "database": "connected"}

    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database connection failed",
        ) from exc
