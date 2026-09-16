from __future__ import annotations

import logging
import os
from typing import Optional

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import settings

logger = logging.getLogger("sentinelflow.auth")

api_key_header = APIKeyHeader(
    name="X-API-Key",
    auto_error=False,
)
http_bearer = HTTPBearer(auto_error=False)

# Read directly from environment variable
API_KEY = os.getenv("SENTINELFLOW_API_KEY", "sentinelflow-soc-dev-key")
ENFORCE_AUTH = os.getenv("ENFORCE_API_KEY", "false").lower() in ("true", "1", "yes")


async def verify_api_key(
    api_key: Optional[str] = Security(api_key_header),
    bearer_creds: Optional[HTTPAuthorizationCredentials] = Security(http_bearer),
) -> str:
    """
    Verifies the provided X-API-Key header or Authorization: Bearer token against SENTINELFLOW_API_KEY.
    """
    provided_key = None
    if api_key:
        provided_key = api_key.strip()
    elif bearer_creds and bearer_creds.credentials:
        provided_key = bearer_creds.credentials.strip()

    configured_key = (os.getenv("SENTINELFLOW_API_KEY") or getattr(settings, "api_key", API_KEY) or "").strip()

    if provided_key:
        if provided_key != configured_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API Key",
                headers={"WWW-Authenticate": "ApiKey"},
            )
        return provided_key

    # In production or if enforce_api_key is True, missing key is rejected
    is_enforced = (
        getattr(settings, "enforce_api_key", False)
        or os.getenv("ENFORCE_API_KEY", "false").lower() in ("true", "1", "yes")
        or os.getenv("ENV", getattr(settings, "environment", "development")).lower() == "production"
    )

    if is_enforced:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Provide 'X-API-Key' header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    return "development-bypass"
