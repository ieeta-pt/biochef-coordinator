"""GET /healthz: whether the service is up and can reach its database."""

import asyncio
import logging
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

PING_TIMEOUT_S = 2

logger = logging.getLogger(__name__)

router = APIRouter(tags=["operations"])


class Health(BaseModel):
    status: Literal["ok"]
    database: Literal["ok"]


@router.get(
    "/healthz",
    summary="Whether the service is up and can reach its database",
    responses={503: {"description": "The database does not answer."}},
)
async def healthz(request: Request) -> Health:
    try:
        # Bounded, so a database that hangs makes the check fail rather than
        # hang along with it.
        async with asyncio.timeout(PING_TIMEOUT_S), request.app.state.engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except (OSError, SQLAlchemyError, TimeoutError) as exc:
        logger.warning("health check: database unreachable: %s", exc)
        raise HTTPException(503, "The database does not answer.") from exc
    return Health(status="ok", database="ok")
