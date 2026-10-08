import logging
from typing import List, Optional, Dict, Any
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from src.database.models import Evidence, EvidenceVerification, Camera, Event
from src.database.models.base import utc_now
from src.schemas.evidence import EvidenceCreate
from src.utils.identifiers import generate_identifier
from src.audit.service import AuditService

logger = logging.getLogger("backend.evidence")

VALID_VERIFICATION_STATUSES = {"VERIFIED", "REJECTED", "INSUFFICIENT_EVIDENCE"}


class EvidenceService:
    """
    Authoritative service managing physical surveillance evidence lifecycle,
    verification audit trails, and strict provenance tracking.
    """

    @staticmethod
    def create_evidence(
        db: Session,
        evidence_in: EvidenceCreate,
        current_user_id: Optional[str] = None,
    ) -> Evidence:
        """
        Register a new authoritative evidence item.
        Always initializes in UNVERIFIED state.
        Verifies camera and event relationships, and stores origin provenance.
        """
        # 1. Validate Camera existence
        camera = db.query(Camera).filter(
            Camera.camera_id == evidence_in.camera_id,
            Camera.is_deleted == False,
        ).first()
        if not camera:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Camera '{evidence_in.camera_id}' not found",
            )

        # 2. Validate Event existence if linked
        event = None
        if evidence_in.event_id:
            event = db.query(Event).filter(Event.event_id == evidence_in.event_id).first()
            if not event:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Linked Event '{evidence_in.event_id}' not found",
                )

        # 3. Determine evidence ID
        evidence_id = evidence_in.evidence_id or generate_identifier("evidence_id")
        existing = db.query(Evidence).filter(Evidence.evidence_id == evidence_id).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Evidence with identifier '{evidence_id}' already exists",
            )

        now = utc_now()
        # 4. Construct authoritative provenance trail
        provenance = {
            "source_type": evidence_in.source_type,
            "source_reference": evidence_in.source_reference,
            "camera_id": evidence_in.camera_id,
            "event_id": evidence_in.event_id,
            "created_at": now.isoformat(),
        }

        # 5. Persist evidence record
        evidence = Evidence(
            evidence_id=evidence_id,
            camera_id=evidence_in.camera_id,
            event_id=evidence_in.event_id,
            timestamp_start=evidence_in.timestamp_start,
            timestamp_end=evidence_in.timestamp_end,
            source_reference=evidence_in.source_reference,
            clip_reference=evidence_in.clip_reference,
            confidence=evidence_in.confidence,
            verification_status="UNVERIFIED",
            source_type=evidence_in.source_type,
            provenance_json=provenance,
            schema_version=evidence_in.schema_version,
            storage_url=evidence_in.storage_url,
            hash_sha256=evidence_in.hash_sha256,
            metadata_json=evidence_in.metadata_json,
        )
        db.add(evidence)
        db.flush()

        # 6. Bi-directionally associate with event if applicable
        if event and not event.evidence_id:
            event.evidence_id = evidence_id

        db.commit()
        db.refresh(evidence)
        logger.info(f"Registered authoritative evidence {evidence.evidence_id} for camera {evidence.camera_id}")
        return evidence

    @staticmethod
    def get_evidence(db: Session, evidence_id: str) -> Optional[Evidence]:
        """Retrieve evidence item by unique evidence_id."""
        return db.query(Evidence).filter(
            Evidence.evidence_id == evidence_id,
            Evidence.is_deleted == False,
        ).first()

    @staticmethod
    def list_evidence(
        db: Session,
        skip: int = 0,
        limit: int = 50,
        camera_id: Optional[str] = None,
        event_id: Optional[str] = None,
        verification_status: Optional[str] = None,
        source_type: Optional[str] = None,
    ) -> List[Evidence]:
        """List evidence with granular surveillance filters."""
        query = db.query(Evidence).filter(Evidence.is_deleted == False)

        if camera_id:
            query = query.filter(Evidence.camera_id == camera_id)
        if event_id:
            query = query.filter(Evidence.event_id == event_id)
        if verification_status:
            query = query.filter(Evidence.verification_status == verification_status)
        if source_type:
            query = query.filter(Evidence.source_type == source_type)

        return query.order_by(Evidence.created_at.desc()).offset(skip).limit(limit).all()

    @staticmethod
    def verify_evidence(
        db: Session,
        evidence_id: str,
        target_status: str,
        verified_by_user_id: str,
        notes: Optional[str] = None,
    ) -> Evidence:
        """
        Explicitly verify, reject, or mark evidence as insufficient.
        Maintains an immutable verification audit log with provenance snapshot.
        """
        evidence = EvidenceService.get_evidence(db, evidence_id)
        if not evidence:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Evidence '{evidence_id}' not found",
            )

        status_norm = target_status.upper()
        if status_norm not in VALID_VERIFICATION_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid verification status '{target_status}'. Must be one of: {', '.join(sorted(VALID_VERIFICATION_STATUSES))}",
            )

        # Capture provenance snapshot
        snapshot = evidence.provenance

        verification_entry = EvidenceVerification(
            evidence_id=evidence.evidence_id,
            verified_by_user_id=verified_by_user_id,
            status=status_norm,
            notes=notes,
            provenance_snapshot_json=snapshot,
            verified_at=utc_now(),
        )
        db.add(verification_entry)

        # Update evidence status
        evidence.verification_status = status_norm
        evidence.updated_at = utc_now()

        db.commit()
        db.refresh(evidence)

        # Record audit log
        audit_act = "VERIFY_EVIDENCE" if status_norm == "VERIFIED" else ("REJECT_EVIDENCE" if status_norm == "REJECTED" else "INSUFFICIENT_EVIDENCE")
        AuditService.record_action(
            db=db,
            action=audit_act,
            resource_type="evidence",
            resource_id=evidence.evidence_id,
            user_identifier=verified_by_user_id,
            status="SUCCESS",
            details={"notes": notes, "status": status_norm},
        )

        logger.info(
            f"Evidence {evidence.evidence_id} updated to {status_norm} by user {verified_by_user_id}"
        )
        return evidence

    @staticmethod
    def get_provenance(db: Session, evidence_id: str) -> Dict[str, Any]:
        """Retrieve complete provenance audit data for an evidence item."""
        evidence = EvidenceService.get_evidence(db, evidence_id)
        if not evidence:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Evidence '{evidence_id}' not found",
            )

        return {
            "evidence_id": evidence.evidence_id,
            "provenance": evidence.provenance,
            "verification_status": evidence.verification_status,
            "verifications_count": len(evidence.verifications),
            "created_at": evidence.created_at,
        }
