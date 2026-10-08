import logging
from datetime import datetime
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session

from src.database.models import AuditLog, User
from src.database.models.base import utc_now

logger = logging.getLogger("backend.audit")

SENSITIVE_FIELD_NAMES = {
    "password", "hashed_password", "token", "access_token", "refresh_token",
    "secret", "jwt_secret_key", "authorization", "bearer", "cookie",
    "credential", "credentials", "api_key", "private_key"
}


def sanitize_audit_details(data: Any) -> Any:
    """
    Recursively sanitize metadata dictionary or list to ensure credentials,
    hashes, secrets, and auth tokens are never persisted in plain audit trails.
    """
    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            k_lower = str(k).lower()
            if any(term in k_lower for term in SENSITIVE_FIELD_NAMES):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = sanitize_audit_details(v)
        return sanitized
    elif isinstance(data, list):
        return [sanitize_audit_details(item) for item in data]
    return data


class AuditService:
    """
    Authoritative service for immutable audit logging, lifecycle event recording,
    and granular compliance log inspection.
    """

    @staticmethod
    def record_action(
        db: Session,
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        user_id: Optional[int] = None,
        user_identifier: Optional[str] = None,
        ip_address: Optional[str] = None,
        status: str = "SUCCESS",
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditLog:
        """
        Record an authoritative security audit log event with automatic redaction.
        """
        # Resolve integer user_id if string user_identifier or username was passed
        if user_id is None and user_identifier:
            u = db.query(User).filter(
                (User.user_id == user_identifier) | (User.username == user_identifier)
            ).first()
            if u:
                user_id = u.id

        sanitized_details = sanitize_audit_details(details) if details else None

        entry = AuditLog(
            user_id=user_id,
            action=action.strip().upper(),
            resource_type=resource_type.strip().lower(),
            resource_id=str(resource_id) if resource_id is not None else None,
            ip_address=ip_address,
            status=status.strip().upper(),
            details_json=sanitized_details,
            created_at=utc_now(),
        )
        db.add(entry)
        db.commit()
        db.refresh(entry)
        logger.info(f"Audit event recorded: [{entry.action}] on {entry.resource_type}:{entry.resource_id} status={entry.status}")
        return entry

    @staticmethod
    def list_logs(
        db: Session,
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        status: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> List[AuditLog]:
        """
        Query immutable audit trail records with granular security filters.
        """
        query = db.query(AuditLog)

        if user_id is not None:
            if str(user_id).isdigit():
                query = query.filter(AuditLog.user_id == int(user_id))
            else:
                u = db.query(User).filter(
                    (User.user_id == user_id) | (User.username == user_id)
                ).first()
                if u:
                    query = query.filter(AuditLog.user_id == u.id)
                else:
                    return []

        if action:
            query = query.filter(AuditLog.action == action.strip().upper())
        if resource_type:
            query = query.filter(AuditLog.resource_type == resource_type.strip().lower())
        if resource_id:
            query = query.filter(AuditLog.resource_id == resource_id.strip())
        if status:
            query = query.filter(AuditLog.status == status.strip().upper())
        if start_time:
            query = query.filter(AuditLog.created_at >= start_time)
        if end_time:
            query = query.filter(AuditLog.created_at <= end_time)

        return query.order_by(AuditLog.created_at.desc()).offset(skip).limit(limit).all()
