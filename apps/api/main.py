from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI

from apps.api.routers.attack_surface import router as attack_surface_router
from apps.api.routers.enterprise import router as enterprise_router
from apps.api.routers.network import router as network_router
from apps.api.routers.phase6 import router as phase6_router
from apps.api.routers.projects import router as projects_router
from apps.api.routers.scans import router as scans_router
from apps.api.routers.system import router as system_router
from apps.api.routers.web_inventory import router as web_inventory_router
from scopegraph.application.errors import install_exception_handlers
from scopegraph.application.health import router as health_router
from scopegraph.infrastructure.config import get_settings
from scopegraph.infrastructure.database import dispose_engine
from scopegraph.infrastructure.logging import configure_logging
from scopegraph.infrastructure.middleware import ApiKeyMiddleware, RequestContextMiddleware


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging(settings.log_level)
    structlog.get_logger().info(
        "application_started",
        application=settings.app_name,
        environment=settings.environment,
    )
    yield
    await dispose_engine()
    structlog.get_logger().info("application_stopped")


def create_app() -> FastAPI:
    settings = get_settings()
    application = FastAPI(
        title=settings.app_name,
        version="1.0.0",
        description="ScopeGraph local API",
        lifespan=lifespan,
        docs_url="/docs" if settings.environment != "production" else None,
        redoc_url=None,
    )
    application.add_middleware(RequestContextMiddleware)
    if settings.public_bind:
        if settings.api_key is None:
            raise RuntimeError("SCOPEGRAPH_API_KEY is required when public_bind is enabled")
        application.add_middleware(ApiKeyMiddleware, api_key=settings.api_key.get_secret_value())
    install_exception_handlers(application)
    application.include_router(health_router)
    application.include_router(projects_router)
    application.include_router(scans_router)
    application.include_router(network_router)
    application.include_router(attack_surface_router)
    application.include_router(web_inventory_router)
    application.include_router(enterprise_router)
    application.include_router(phase6_router)
    application.include_router(system_router)
    return application


app = create_app()
