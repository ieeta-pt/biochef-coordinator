"""The FastAPI application.

Run it with:

    uv run uvicorn coordinator.main:app --reload
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from importlib.metadata import version

from fastapi import FastAPI
from sqlalchemy.ext.asyncio import create_async_engine

from coordinator import health, problems, researcher
from coordinator.config import Settings


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Settings are read when the app starts, not on import, so exporting the
    # OpenAPI document needs no configuration. pool_pre_ping replaces a
    # connection the database dropped (after a restart, say) before it is used.
    app.state.engine = create_async_engine(Settings().database_url, pool_pre_ping=True)
    yield
    await app.state.engine.dispose()


app = FastAPI(
    title="BioChef Coordination Hub",
    summary="Studies, per-node approvals and jobs that BioChef agents fetch by polling.",
    version=version("biochef-coordinator"),
    lifespan=lifespan,
)
problems.install(app)
app.include_router(health.router)
app.include_router(researcher.router)
