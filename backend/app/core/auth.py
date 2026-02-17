"""API key authentication and role-based authorization for protecting endpoints."""
import logging
from fastapi import Header, HTTPException
from app.core.config import settings, is_api_auth_active

logger = logging.getLogger("cybersentinel")


async def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """Require X-API-Key header when API auth is fully active."""
    if not is_api_auth_active():
        if settings.api_auth_enabled and not settings.api_key:
            logger.warning("API_AUTH_ENABLED=true but API_KEY is missing; auth checks are bypassed in non-production")
        return
    if x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="Unauthorized")


async def require_admin_key(x_api_key: str | None = Header(default=None)) -> None:
    """
    Require admin-level API key for sensitive write operations.
    This is used for settings updates, configuration changes, and other 
    security-critical operations that should have additional protection.
    """
    # Check if auth is disabled entirely
    if not is_api_auth_active():
        if settings.api_auth_enabled and not settings.api_key:
            logger.warning("API_AUTH_ENABLED=true but API_KEY is missing; auth checks are bypassed in non-production")
        return
    
    # If we have admin key configured, require it for admin operations
    if settings.admin_api_key:
        if x_api_key != settings.admin_api_key:
            logger.warning(f"Admin operation attempted with non-admin key")
            raise HTTPException(
                status_code=403, 
                detail="Forbidden: Admin privileges required for this operation"
            )
    else:
        # If no separate admin key is configured, check standard API key
        if x_api_key != settings.api_key:
            raise HTTPException(status_code=401, detail="Unauthorized")
        # Log this as it's less secure
        logger.info("Admin operation allowed with standard API key (no separate admin key configured)")
