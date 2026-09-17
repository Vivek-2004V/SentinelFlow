"""
SentinelFlow Architecture Middleware Suite.

Engineered to Senior Backend Architect Standards:
1. Distributed Request Tracing (X-Request-ID, X-Correlation-ID, X-Response-Time-Ms)
2. Defense-in-Depth Security Headers (nosniff, DENY, XSS-Protection, Referrer & Permissions Policy)
3. Pure ASGI Architecture: Zero-overhead, 100% Streaming-Safe (SSE / WebSockets compatible)
   Eliminates Starlette BaseHTTPMiddleware concurrency stalls and memory buffering.
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Callable

logger = logging.getLogger("sentinelflow.backend_architect")


class RequestTracingAndSecurityMiddleware:
    """
    Pure ASGI Middleware for distributed correlation tracing,
    high-precision latency metrics, and defense-in-depth security response headers.
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        start_time = time.perf_counter()

        # 1. Resolve or generate correlation request ID from headers
        headers_dict = dict(scope.get("headers", []))
        req_id_bytes = (
            headers_dict.get(b"x-request-id")
            or headers_dict.get(b"x-correlation-id")
        )
        request_id = req_id_bytes.decode("latin-1") if req_id_bytes else str(uuid.uuid4())

        # Store in scope state for downstream route handlers / error wrappers
        if "state" not in scope:
            scope["state"] = {}
        scope["state"]["request_id"] = request_id

        client = scope.get("client")
        client_ip = client[0] if client else "unknown"
        path = scope.get("path", "")
        method = scope.get("method", "")

        response_status = 200

        async def send_wrapper(message: dict) -> None:
            nonlocal response_status
            if message["type"] == "http.response.start":
                response_status = message.get("status", 200)
                duration_ms = (time.perf_counter() - start_time) * 1000.0

                existing_headers = list(message.get("headers", []))
                security_and_trace_headers = [
                    (b"x-request-id", request_id.encode("latin-1")),
                    (b"x-response-time-ms", f"{duration_ms:.2f}".encode("latin-1")),
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"x-xss-protection", b"1; mode=block"),
                    (b"referrer-policy", b"strict-origin-when-cross-origin"),
                    (
                        b"permissions-policy",
                        b"accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
                        b"magnetometer=(), microphone=(), payment=(), usb=()",
                    ),
                ]
                existing_headers.extend(security_and_trace_headers)
                message["headers"] = existing_headers

                # Structured log on response start
                if not path.startswith("/health"):
                    logger.info(
                        "method=%s path=%s status=%d duration_ms=%.2f request_id=%s ip=%s",
                        method,
                        path,
                        response_status,
                        duration_ms,
                        request_id,
                        client_ip,
                    )

            await send(message)

        await self.app(scope, receive, send_wrapper)
