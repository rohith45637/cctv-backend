from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, Boolean
from src.database.session import Base


def utc_now():
    return datetime.now(timezone.utc)


class TimestampMixin:
    """Provides created_at and updated_at UTC timestamps."""
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)


class SoftDeleteMixin:
    """Provides soft-deletion flag and deleted_at timestamp."""
    is_deleted = Column(Boolean, default=False, nullable=False, index=True)
    deleted_at = Column(DateTime(timezone=True), nullable=True)
