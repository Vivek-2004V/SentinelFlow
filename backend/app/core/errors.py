"""
Standardized API Error Handlers.

Adheres to Backend Architect Contract Governance (RFC 7807 inspired envelope):
- Consistent, predictable error JSON format across all endpoints
- Preserves backwards compatibility with legacy `detail` assertions
- Binds unique `request_id` to every error for SOC log correlation
"""
from __future__ import annotations

import http
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException


def _get_request_id(request: Request) -> str:
    return getattr(request.state, "request_id", None) or str(uuid.uuid4())


async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    request_id = _get_request_id(request)
    status_phrase = http.HTTPStatus(exc.status_code).name

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.detail,
            "error": {
                "code": status_phrase,
                "message": exc.detail if isinstance(exc.detail, str) else str(exc.detail),
                "request_id": request_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        },
        headers={
            "X-Request-ID": request_id,
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        },
    )


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    request_id = _get_request_id(request)
    errors = exc.errors()

    return JSONResponse(
        status_code=422,
        content={
            "detail": errors,
            "error": {
                "code": "UNPROCESSABLE_ENTITY",
                "message": "Input validation failed against the schema contract.",
                "details": errors,
                "request_id": request_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        },
        headers={
            "X-Request-ID": request_id,
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        },
    )
