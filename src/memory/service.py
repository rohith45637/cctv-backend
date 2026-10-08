import logging
from typing import List, Optional
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import or_

from src.database.models import SecurityMemory, Camera, Zone, Event, Incident
from src.database.models.base import utc_now
from src.schemas.security_memory import SecurityMemoryCreate, SecurityMemoryUpdate
from src.utils.identifiers import generate_identifier

logger = logging.getLogger("backend.memory")


class SecurityMemoryService:
    """
    Authoritative service managing persistent Security Context Memory records.
    Provides structured context storage for surveillance operations,
    investigation dossiers, entity profiles, and anomaly baselines.
    """

    @staticmethod
    def create_memory(db: Session, memory_in: SecurityMemoryCreate) -> SecurityMemory:
        """
        Create a new authoritative security context memory record.
        Validates referential integrity against cameras, zones, events, and incidents.
        """
        # 1. Validate Camera reference if provided
        if memory_in.camera_id:
            camera = db.query(Camera).filter(
                Camera.camera_id == memory_in.camera_id,
                Camera.is_deleted == False,
            ).first()
            if not camera:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Camera '{memory_in.camera_id}' not found",
                )

        # 2. Validate Zone reference if provided
        if memory_in.zone_id:
            zone = db.query(Zone).filter(
                Zone.zone_id == memory_in.zone_id,
                Zone.is_deleted == False,
            ).first()
            if not zone:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Zone '{memory_in.zone_id}' not found",
                )

        # 3. Validate Event reference if provided
        if memory_in.event_id:
            event = db.query(Event).filter(Event.event_id == memory_in.event_id).first()
            if not event:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Event '{memory_in.event_id}' not found",
                )

        # 4. Validate Incident reference if provided
        if memory_in.incident_id:
            incident = db.query(Incident).filter(
                Incident.incident_id == memory_in.incident_id,
                Incident.is_deleted == False,
            ).first()
            if not incident:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Incident '{memory_in.incident_id}' not found",
                )

        # 5. Determine canonical memory_id
        memory_id = memory_in.memory_id or generate_identifier("memory_id")
        existing = db.query(SecurityMemory).filter(SecurityMemory.memory_id == memory_id).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Security memory with identifier '{memory_id}' already exists",
            )

        now = utc_now()
        # 6. Instantiate and persist SecurityMemory
        memory = SecurityMemory(
            memory_id=memory_id,
            memory_type=memory_in.memory_type.upper(),
            entity_id=memory_in.entity_id,
            camera_id=memory_in.camera_id,
            zone_id=memory_in.zone_id,
            event_id=memory_in.event_id,
            incident_id=memory_in.incident_id,
            content=memory_in.content,
            description=memory_in.description,
            confidence=memory_in.confidence,
            source_reference=memory_in.source_reference,
            identifier_value=memory_in.identifier_value,
            observations_count=memory_in.observations_count,
            last_seen_at=memory_in.last_seen_at or now,
            expires_at=memory_in.expires_at,
            schema_version=memory_in.schema_version,
            metadata_json=memory_in.metadata_json,
        )
        db.add(memory)
        db.commit()
        db.refresh(memory)

        logger.info(f"Created authoritative security memory {memory.memory_id} of type {memory.memory_type}")
        return memory

    @staticmethod
    def get_memory(db: Session, memory_id: str) -> Optional[SecurityMemory]:
        """Retrieve security memory item by memory_id."""
        return db.query(SecurityMemory).filter(
            SecurityMemory.memory_id == memory_id,
            SecurityMemory.is_deleted == False,
        ).first()

    @staticmethod
    def list_memories(
        db: Session,
        skip: int = 0,
        limit: int = 50,
        memory_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        camera_id: Optional[str] = None,
        zone_id: Optional[str] = None,
        event_id: Optional[str] = None,
        incident_id: Optional[str] = None,
        active_only: bool = False,
    ) -> List[SecurityMemory]:
        """List security memory entries with contextual filtering."""
        query = db.query(SecurityMemory).filter(SecurityMemory.is_deleted == False)

        if memory_type:
            query = query.filter(SecurityMemory.memory_type == memory_type.upper())
        if entity_id:
            query = query.filter(SecurityMemory.entity_id == entity_id)
        if camera_id:
            query = query.filter(SecurityMemory.camera_id == camera_id)
        if zone_id:
            query = query.filter(SecurityMemory.zone_id == zone_id)
        if event_id:
            query = query.filter(SecurityMemory.event_id == event_id)
        if incident_id:
            query = query.filter(SecurityMemory.incident_id == incident_id)

        if active_only:
            now = utc_now()
            query = query.filter(
                or_(
                    SecurityMemory.expires_at == None,
                    SecurityMemory.expires_at > now,
                )
            )

        return query.order_by(SecurityMemory.created_at.desc()).offset(skip).limit(limit).all()

    @staticmethod
    def update_memory(
        db: Session,
        memory_id: str,
        update_in: SecurityMemoryUpdate,
    ) -> SecurityMemory:
        """Update context content, confidence, expiration, or metadata for an existing memory."""
        memory = SecurityMemoryService.get_memory(db, memory_id)
        if not memory:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Security memory '{memory_id}' not found",
            )

        if update_in.content is not None:
            memory.content = update_in.content
        if update_in.description is not None:
            memory.description = update_in.description
        if update_in.confidence is not None:
            memory.confidence = update_in.confidence
        if update_in.source_reference is not None:
            memory.source_reference = update_in.source_reference
        if update_in.expires_at is not None:
            memory.expires_at = update_in.expires_at
        if update_in.metadata_json is not None:
            memory.metadata_json = update_in.metadata_json

        memory.updated_at = utc_now()
        db.commit()
        db.refresh(memory)
        return memory

    @staticmethod
    def delete_memory(db: Session, memory_id: str) -> bool:
        """Soft-delete security memory item."""
        memory = SecurityMemoryService.get_memory(db, memory_id)
        if not memory:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Security memory '{memory_id}' not found",
            )

        memory.is_deleted = True
        memory.deleted_at = utc_now()
        db.commit()
        return True
