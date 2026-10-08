import time
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

import bcrypt
from jose import JWTError, jwt
from src.config.settings import settings


# In-memory sliding window tracker for failed login attempts
# Format: {identifier_or_ip: [timestamp1, timestamp2, ...]}
_FAILED_ATTEMPTS: Dict[str, list] = defaultdict(list)
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_WINDOW_SECONDS = 60


def hash_password(password: str) -> str:
    """
    Hash a plaintext password securely using bcrypt.
    Safely truncates at 72 bytes per bcrypt standard.
    """
    pwd_bytes = password.encode("utf-8")[:72]
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plaintext password against a stored bcrypt hash.
    Safely returns False on malformed or mismatched inputs.
    """
    if not plain_password or not hashed_password:
        return False
    try:
        pwd_bytes = plain_password.encode("utf-8")[:72]
        hash_bytes = hashed_password.encode("utf-8")
        return bcrypt.checkpw(pwd_bytes, hash_bytes)
    except Exception:
        return False


def create_access_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Generate a cryptographically signed JWT access token.
    Enforces 'access' token type, expiry, and unique jti.
    """
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": str(uuid.uuid4()),
        "type": "access",
    })
    return jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None,
) -> Tuple[str, str, datetime]:
    """
    Generate a cryptographically signed JWT refresh token.
    Returns (token_string, jti, expire_datetime).
    """
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(days=7)

    token_jti = str(uuid.uuid4())
    to_encode.update({
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": token_jti,
        "type": "refresh",
    })
    token = jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return token, token_jti, expire


def decode_token(token: str) -> Dict[str, Any]:
    """
    Decode and validate a JWT token against application secrets.
    Raises JWTError if expired, signature invalid, or malformed.
    """
    return jwt.decode(
        token,
        settings.JWT_SECRET,
        algorithms=[settings.JWT_ALGORITHM],
        options={"verify_exp": True},
    )


def is_rate_limited(key: str) -> bool:
    """
    Check if a given client key (IP or username) is currently rate limited
    due to excessive failed login attempts.
    """
    now = time.time()
    attempts = _FAILED_ATTEMPTS[key]
    # Prune attempts outside lockout window
    _FAILED_ATTEMPTS[key] = [t for t in attempts if now - t < LOCKOUT_WINDOW_SECONDS]
    return len(_FAILED_ATTEMPTS[key]) >= MAX_FAILED_ATTEMPTS


def record_failed_attempt(key: str) -> None:
    """Record a failed login attempt for rate-limiting purposes."""
    now = time.time()
    _FAILED_ATTEMPTS[key].append(now)


def reset_rate_limit(key: str) -> None:
    """Reset failed login attempts upon successful authentication."""
    if key in _FAILED_ATTEMPTS:
        _FAILED_ATTEMPTS.pop(key, None)
