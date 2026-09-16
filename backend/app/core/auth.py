from __future__ import annotations

import logging
from typing import Optional

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import settings

logger = logging.getLogger("sentinelflow.auth")

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
http_bearer = HTTPBearer(auto_error=False)


async def verify_api_key(
    header_key: Optional[str] = Security(api_key_header),
    bearer_creds: Optional[HTTPAuthorizationCredentials] = Security(http_bearer),
) -> str:
    """
    Validates API authentication via:
      1. 'X-API-Key' custom header, or
      2. 'Authorization: Bearer <token>' standard HTTP header.

    In development, if no key is supplied and enforce_api_key is False,
    the request is permitted. If an invalid key is supplied, or if authentication
    is enforced, it raises 401 UNAUTHORIZED.
    """
    provided_key: Optional[str] = None
    if header_key:
        provided_key = header_key.strip()
    elif bearer_creds and bearer_creds.credentials:
        provided_key = bearer_creds.credentials.strip()

    expected_key = (settings.api_key or "").strip()

    # If key is provided, validate strictly
    if provided_key:
        if provided_key != expected_key:
            logger.warning("Authentication failure: invalid API key or bearer token provided")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API Key or Bearer Token.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return provided_key

    # If no key is provided, check if authentication is enforced
    if settings.enforce_api_key or settings.environment.lower() == "production":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Provide 'X-API-Key' header or 'Authorization: Bearer <token>'.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return "development-bypass"
