from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from src.database.session import get_db
from src.database.models import Camera, Zone, SecurityPolicy, Event, Evidence, Threat, Incident
from src.schemas import (
    Camera as CameraSchema,
    Zone as ZoneSchema,
    SecurityPolicy as PolicySchema,
    Event as EventSchema,
    Evidence as EvidenceSchema,
    Threat as ThreatSchema,
    Incident as IncidentSchema,
)

router = APIRouter(prefix="/api/v1")


@router.get("/cameras", response_model=List[CameraSchema], tags=["Cameras"])
def list_cameras(skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    """List registered cameras."""
    return db.query(Camera).filter(Camera.is_deleted == False).offset(skip).limit(limit).all()


@router.get("/cameras/{camera_id}", response_model=CameraSchema, tags=["Cameras"])
def get_camera(camera_id: str, db: Session = Depends(get_db)):
    """Retrieve camera by camera_id."""
    camera = db.query(Camera).filter(Camera.camera_id == camera_id, Camera.is_deleted == False).first()
    if not camera:
        raise HTTPException(status_code=404, detail=f"Camera '{camera_id}' not found")
    return camera


@router.get("/zones", response_model=List[ZoneSchema], tags=["Zones"])
def list_zones(skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    """List registered zones."""
    return db.query(Zone).filter(Zone.is_deleted == False).offset(skip).limit(limit).all()


@router.get("/zones/{zone_id}", response_model=ZoneSchema, tags=["Zones"])
def get_zone(zone_id: str, db: Session = Depends(get_db)):
    """Retrieve zone by zone_id."""
    zone = db.query(Zone).filter(Zone.zone_id == zone_id, Zone.is_deleted == False).first()
    if not zone:
        raise HTTPException(status_code=404, detail=f"Zone '{zone_id}' not found")
    return zone


@router.get("/policies", response_model=List[PolicySchema], tags=["Policies"])
def list_policies(skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    """List registered security policies."""
    return db.query(SecurityPolicy).filter(SecurityPolicy.is_deleted == False).offset(skip).limit(limit).all()


@router.get("/events", response_model=List[EventSchema], tags=["Events"])
def list_events(skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    """List recent security events."""
    return db.query(Event).order_by(Event.timestamp.desc()).offset(skip).limit(limit).all()


@router.get("/evidence", response_model=List[EvidenceSchema], tags=["Evidence"])
def list_evidence(skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    """List registered evidence items."""
    return db.query(Evidence).filter(Evidence.is_deleted == False).offset(skip).limit(limit).all()


@router.get("/threats", response_model=List[ThreatSchema], tags=["Threats"])
def list_threats(skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    """List detected security threats."""
    return db.query(Threat).filter(Threat.is_deleted == False).order_by(Threat.detected_at.desc()).offset(skip).limit(limit).all()


@router.get("/incidents", response_model=List[IncidentSchema], tags=["Incidents"])
def list_incidents(skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    """List security incidents."""
    return db.query(Incident).filter(Incident.is_deleted == False).order_by(Incident.opened_at.desc()).offset(skip).limit(limit).all()
