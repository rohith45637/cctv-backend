import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from src.config.settings import settings
from src.database.init_db import initialize_database
from src.api.routes import health, api_v1, auth, events, threats_incidents, evidence, memory, investigations, ai_video, copilot, audit

# Configure logging
logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("backend.security_core")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifecycle manager: initializes database, applies schema,
    and runs initial seed before handling traffic.
    """
    logger.info(f"Starting {settings.PROJECT_NAME} v{settings.PROJECT_VERSION} in [{settings.APP_ENV}] mode...")
    
    # 1. Initialize database (migrations & optional demo seed)
    initialize_database()
    logger.info("Database and core models successfully initialized.")
    
    yield
    
    logger.info(f"Shutting down {settings.PROJECT_NAME}...")


app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Physical & Surveillance AI Backend Security Core. Handles cameras, zones, events, evidence, policies, threats, and investigations.",
    version=settings.PROJECT_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", tags=["Root"])
async def root():
    """
    Service landing metadata.
    """
    return {
        "service": settings.PROJECT_NAME,
        "version": settings.PROJECT_VERSION,
        "environment": settings.APP_ENV,
        "status": "online",
        "docs": "/docs",
        "health": "/health",
        "auth": "/api/auth",
        "events": "/api/events",
        "evidence": "/api/evidence",
        "memory": "/api/memory",
        "investigations": "/api/investigations",
        "ai_video": "/api/integrations/ai-video",
        "threats": "/api/threats",
        "incidents": "/api/incidents",
        "copilot": "/api/copilot",
        "audit": "/api/audit",
        "api_v1": "/api/v1",
    }


# Include Routers
app.include_router(health.router)
app.include_router(auth.router)
app.include_router(events.router)
app.include_router(evidence.router)
app.include_router(threats_incidents.threats_router)
app.include_router(threats_incidents.incidents_router)
app.include_router(memory.router)
app.include_router(investigations.router)
app.include_router(ai_video.router)
app.include_router(copilot.router)
app.include_router(audit.router)
app.include_router(api_v1.router)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception on {request.method} {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error occurred.", "path": str(request.url.path)},
    )
