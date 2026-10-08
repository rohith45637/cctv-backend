from fastapi import APIRouter, status, Response
from src.config.settings import settings
from src.database.session import check_database_health

router = APIRouter(tags=["Health & Status"])


@router.get("/health", status_code=status.HTTP_200_OK)
async def health_check(response: Response):
    """
    Comprehensive system health check.
    Validates database connectivity and service environment.
    """
    db_ok = check_database_health()
    if not db_ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "healthy" if db_ok else "degraded",
        "service": settings.PROJECT_NAME,
        "version": settings.PROJECT_VERSION,
        "environment": settings.APP_ENV,
        "database": "connected" if db_ok else "disconnected",
        "demo_mode": settings.DEMO_MODE,
    }


@router.get("/health/live", status_code=status.HTTP_200_OK)
async def liveness():
    """
    Kubernetes / Docker liveness probe: returns 200 if process is running.
    """
    return {"status": "alive"}


@router.get("/health/ready", status_code=status.HTTP_200_OK)
async def readiness(response: Response):
    """
    Kubernetes / Docker readiness probe: verifies dependencies are ready for traffic.
    """
    db_ok = check_database_health()
    if not db_ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"ready": False, "reason": "Database unavailable"}
    return {"ready": True}
