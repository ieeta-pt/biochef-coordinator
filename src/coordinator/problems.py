"""Errors as RFC 9457 problem details (application/problem+json).

The spec requires this format for every error (section 3), including the ones
FastAPI produces itself: unknown routes, wrong methods and invalid requests.
"""

import logging
from http import HTTPStatus
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

PROBLEM_JSON = "application/problem+json"

logger = logging.getLogger(__name__)


def problem(
    status: int,
    detail: str | None = None,
    headers: dict[str, str] | None = None,
    **extensions: Any,
) -> JSONResponse:
    """A problem details response with no specific problem type."""
    try:
        title = HTTPStatus(status).phrase
    except ValueError:
        title = "Error"
    body: dict[str, Any] = {"type": "about:blank", "title": title, "status": status}
    if detail and detail != title:
        body["detail"] = detail
    body.update(extensions)
    return JSONResponse(body, status_code=status, headers=headers, media_type=PROBLEM_JSON)


async def _http_error(request: Request, exc: HTTPException) -> JSONResponse:
    # Keep the headers: a 405 needs Allow, and a 401 needs WWW-Authenticate.
    detail = exc.detail if isinstance(exc.detail, str) else None
    return problem(exc.status_code, detail, headers=exc.headers)


async def _invalid_request(request: Request, exc: RequestValidationError) -> JSONResponse:
    # Where and why, but never the input: a request can carry ciphertext or
    # signed documents, and echoing them back serves nobody.
    errors = [
        {"loc": list(error["loc"]), "msg": error["msg"], "type": error["type"]}
        for error in exc.errors()
    ]
    return problem(422, "The request is not valid.", errors=errors)


async def _unexpected_error(request: Request, exc: Exception) -> JSONResponse:
    # The traceback goes to the log, not to the caller.
    logger.exception("unhandled error on %s %s", request.method, request.url.path)
    return problem(500)


def install(app: FastAPI) -> None:
    """Make every error the app returns a problem details response."""
    app.add_exception_handler(HTTPException, _http_error)
    app.add_exception_handler(RequestValidationError, _invalid_request)
    app.add_exception_handler(Exception, _unexpected_error)
