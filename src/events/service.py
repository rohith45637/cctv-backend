import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from src.database.models import Camera, Event as EventModel, EventEntity, Zone
from src.schemas.event import Event as EventSchema

logger = logging.getLogger("backend.events.service")


class EventService:
    """
    Authoritative ingestion, relational storage, and deduplication engine
    for events arriving from AI Video Intelligence.
    """

    @staticmethod
    def ingest_event(
        db: Session,
        event_data: EventSchema,
        dedup_window_seconds: int = 10,
    ) -> Tuple[EventModel, bool, str]:
        """
        Ingest structured event with primary identity and temporal deduplication.
        Returns: (event_model, is_deduplicated, status_message)
        """
        # 1. Primary Identity Deduplication by event_id
        existing_by_id = (
            db.query(EventModel)
            .filter(EventModel.event_id == event_data.event_id)
            .first()
        )
        if existing_by_id:
            logger.info(f"Duplicate event_id detected: {event_data.event_id}")
            return existing_by_id, True, "Duplicate event_id detected. Returning existing record."

        # 2. Configurable Temporal Deduplication
        # Checks if identical event was already emitted on same camera/zone/entity in recent window
        if dedup_window_seconds > 0 and event_data.timestamp:
            event_ts = event_data.timestamp
            if event_ts.tzinfo is None:
                event_ts = event_ts.replace(tzinfo=timezone.utc)
            window_start = event_ts - timedelta(seconds=dedup_window_seconds)
            window_end = event_ts + timedelta(seconds=dedup_window_seconds)

            temporal_query = (
                db.query(EventModel)
                .filter(
                    EventModel.camera_id == event_data.camera_id,
                    EventModel.event_type == event_data.event_type,
                    EventModel.timestamp >= window_start,
                    EventModel.timestamp <= window_end,
                )
            )
            if event_data.entity_id:
                temporal_query = temporal_query.filter(EventModel.entity_id == event_data.entity_id)
            if event_data.zone_id:
                temporal_query = temporal_query.filter(EventModel.zone_id == event_data.zone_id)

            temporal_match = temporal_query.first()
            if temporal_match:
                logger.info(
                    f"Temporal duplicate event detected for camera {event_data.camera_id} "
                    f"type {event_data.event_type} matching {temporal_match.event_id}"
                )
                return temporal_match, True, "Temporal duplicate detected within window. Returning existing record."

        # 3. Relational Foreign Key Validation
        camera = (
            db.query(Camera)
            .filter(Camera.camera_id == event_data.camera_id, Camera.is_deleted == False)
            .first()
        )
        if not camera:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Camera with id '{event_data.camera_id}' does not exist in registry",
            )

        if event_data.zone_id:
            zone = (
                db.query(Zone)
                .filter(Zone.zone_id == event_data.zone_id, Zone.is_deleted == False)
                .first()
            )
            if not zone:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Zone with id '{event_data.zone_id}' does not exist in registry",
                )

        # 4. Atomic Database Transaction: Event + Entity
        try:
            event_model = EventModel(
                event_id=event_data.event_id,
                camera_id=event_data.camera_id,
                timestamp=event_data.timestamp,
                event_type=event_data.event_type,
                entity_id=event_data.entity_id,
                zone_id=event_data.zone_id,
                confidence=event_data.confidence,
                evidence_id=event_data.evidence_id,
                source=event_data.source,
                status=event_data.status,
                schema_version=event_data.schema_version,
                metadata_json=event_data.metadata_json,
            )
            db.add(event_model)

            # Link entity if present
            if event_data.entity_id:
                entity_type_guess = "OBJECT"
                if "PERSON" in event_data.event_type:
                    entity_type_guess = "PERSON"
                elif "VEHICLE" in event_data.event_type:
                    entity_type_guess = "VEHICLE"

                entity_model = EventEntity(
                    event_id=event_data.event_id,
                    entity_id=event_data.entity_id,
                    entity_type=entity_type_guess,
                    confidence=event_data.confidence,
                    bounding_box_json=event_data.metadata_json.get("bounding_box") if event_data.metadata_json else None,
                )
                db.add(entity_model)

            db.commit()
            db.refresh(event_model)
            logger.info(f"Successfully ingested event {event_model.event_id} ({event_model.event_type})")
            return event_model, False, "Event ingested successfully"
        except Exception as exc:
            db.rollback()
            logger.error(f"Failed to ingest event {event_data.event_id}: {exc}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to ingest event transactionally: {str(exc)}",
            )

    @staticmethod
    def get_event(db: Session, event_id: str) -> Optional[EventModel]:
        """Retrieve authoritative event by event_id."""
        return db.query(EventModel).filter(EventModel.event_id == event_id).first()

    @staticmethod
    def list_events(
        db: Session,
        skip: int = 0,
        limit: int = 50,
        camera_id: Optional[str] = None,
        event_type: Optional[str] = None,
        zone_id: Optional[str] = None,
    ) -> List[EventModel]:
        """Query events with filtering and pagination."""
        query = db.query(EventModel)
        if camera_id:
            query = query.filter(EventModel.camera_id == camera_id)
        if event_type:
            query = query.filter(EventModel.event_type == event_type)
        if zone_id:
            query = query.filter(EventModel.zone_id == zone_id)

        return query.order_by(EventModel.timestamp.desc()).offset(skip).limit(limit).all()
