import html
import re
import hashlib
import hmac
import os
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError

from app.core.config import settings

ALGORITHM = "HS256"
bearer = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 120_000)
    return salt.hex() + "$" + dk.hex()


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, dk_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 120_000)
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


def create_access_token(username: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=settings.TOKEN_EXPIRE_MINUTES)
    return jwt.encode({"sub": username, "exp": exp}, settings.SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> Optional[str]:
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM]).get("sub")
    except JWTError:
        return None


def get_current_admin(creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer)) -> str:
    """FastAPI dependency: every dashboard API route needs a valid admin token."""
    user = decode_token(creds.credentials) if creds else None
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Login required")
    return user



def sanitize_evidence_text(text: str) -> str:
    """
    Sanitize text evidence to prevent XSS and injection attacks.
    Escapes HTML entities and strips non-printable control characters.
    """
    if not isinstance(text, str):
        return str(text)
    
    # Strip dangerous null bytes and raw control characters
    cleaned = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', text)
    # HTML escape
    return html.escape(cleaned, quote=True)


def mask_sensitive_token(token: str) -> str:
    """
    Safely mask honeytokens or sensitive secrets before returning in API or logs.
    Shows only the first 4 and last 3 characters if length > 8.
    """
    if not token or len(token) <= 8:
        return "[REDACTED_SECRET]"
    return f"{token[:4]}...{token[-3:]}"


def sanitize_dict_evidence(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively sanitize dictionary values for safe frontend rendering.
    """
    sanitized = {}
    for k, v in data.items():
        if isinstance(v, str):
            sanitized[k] = sanitize_evidence_text(v)
        elif isinstance(v, dict):
            sanitized[k] = sanitize_dict_evidence(v)
        elif isinstance(v, list):
            sanitized[k] = [
                sanitize_evidence_text(item) if isinstance(item, str)
                else (sanitize_dict_evidence(item) if isinstance(item, dict) else item)
                for item in v
            ]
        else:
            sanitized[k] = v
    return sanitized
