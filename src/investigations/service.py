import logging
from typing import List, Optional, Dict, Any, Set
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from src.database.models import (
    Investigation,
    Incident,
    Event,
    Threat,
    User,
    Evidence,
    SecurityMemory,
    Camera,
    Zone,
    SecurityPolicy,
    EventEntity,
    ZoneCameraMapping,
)
from src.database.models.base import utc_now
from src.schemas.investigation import (
    InvestigationCreate,
    InvestigationUpdate,
    InvestigationExecutionResult,
    ObservedFact,
    Inference,
    UnknownInformation,
    InvestigationExecuteRequest,
)
from src.schemas.ai_agent import (
    AIAgentInvestigationRequest,
    AIAgentInvestigationResponse,
    AIAgentValidationResult,
)
from src.utils.identifiers import generate_identifier
from src.audit.service import AuditService

logger = logging.getLogger("backend.investigations")

# Authoritative controlled state transition table
VALID_INVESTIGATION_TRANSITIONS: Dict[str, Set[str]] = {
    "PENDING": {"ACTIVE", "CANCELLED"},
    "ACTIVE": {"PAUSED", "COMPLETED", "FAILED", "CANCELLED"},
    "PAUSED": {"ACTIVE", "CANCELLED"},
    "COMPLETED": set(),
    "FAILED": set(),
    "CANCELLED": set(),
    # Graceful support for legacy state strings
    "OPEN": {"ACTIVE", "IN_PROGRESS", "CLOSED", "CANCELLED"},
    "IN_PROGRESS": {"ACTIVE", "PAUSED", "COMPLETED", "CLOSED", "FAILED", "CANCELLED"},
    "CLOSED": set(),
}


class InvestigationService:
    """
    Authoritative service managing security investigation lifecycle,
    evidence dossiers, and AI Investigation Agent contract validation.
    """

    @staticmethod
    def create_investigation(
        db: Session,
        data: InvestigationCreate,
        current_user_id: Optional[str] = None,
    ) -> Investigation:
        """
        Create a new authoritative investigation dossier.
        Validates referential integrity against Incidents, Events, Threats, and Users.
        """
        # 1. Validate Incident if provided
        inc_id = data.trigger_incident_id or data.incident_id
        if inc_id:
            incident = db.query(Incident).filter(
                Incident.incident_id == inc_id,
                Incident.is_deleted == False,
            ).first()
            if not incident:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Target Incident '{inc_id}' not found",
                )

        # 2. Validate Event if provided
        if data.trigger_event_id:
            event = db.query(Event).filter(Event.event_id == data.trigger_event_id).first()
            if not event:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Triggering Event '{data.trigger_event_id}' not found",
                )

        # 3. Validate Threat if provided
        if data.trigger_threat_id:
            threat = db.query(Threat).filter(
                Threat.threat_id == data.trigger_threat_id,
                Threat.is_deleted == False,
            ).first()
            if not threat:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Triggering Threat '{data.trigger_threat_id}' not found",
                )

        # 4. Validate Assigned User if provided
        assigned_user = data.assigned_user_id or data.investigator_id or current_user_id
        if assigned_user:
            user = db.query(User).filter(
                User.user_id == assigned_user,
                User.is_deleted == False,
            ).first()
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Assigned User '{assigned_user}' not found",
                )

        # 5. Identifier check
        inv_id = data.investigation_id or generate_identifier("investigation_id")
        existing = db.query(Investigation).filter(Investigation.investigation_id == inv_id).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Investigation with identifier '{inv_id}' already exists",
            )

        now = utc_now()
        initial_status = data.status.upper() if data.status else "PENDING"

        investigation = Investigation(
            investigation_id=inv_id,
            incident_id=inc_id,
            trigger_incident_id=inc_id,
            trigger_event_id=data.trigger_event_id,
            trigger_threat_id=data.trigger_threat_id,
            assigned_user_id=assigned_user,
            title=data.title,
            description=data.description,
            status=initial_status,
            priority=data.priority.upper(),
            findings=data.findings,
            started_at=now,
            completed_at=None,
            schema_version=data.schema_version,
            metadata_json=data.metadata_json or {},
        )
        db.add(investigation)
        db.commit()
        db.refresh(investigation)

        AuditService.record_action(
            db=db,
            action="CREATE_INVESTIGATION",
            resource_type="investigation",
            resource_id=investigation.investigation_id,
            user_identifier=current_user_id,
            status="SUCCESS",
            details={"title": investigation.title, "priority": investigation.priority, "status": investigation.status},
        )

        logger.info(f"Created authoritative investigation dossier {investigation.investigation_id}")
        return investigation

    @staticmethod
    def get_investigation(db: Session, investigation_id: str) -> Optional[Investigation]:
        """Retrieve investigation by authoritative identifier."""
        return db.query(Investigation).filter(
            Investigation.investigation_id == investigation_id,
            Investigation.is_deleted == False,
        ).first()

    @staticmethod
    def list_investigations(
        db: Session,
        skip: int = 0,
        limit: int = 50,
        status: Optional[str] = None,
        priority: Optional[str] = None,
        assigned_user_id: Optional[str] = None,
        incident_id: Optional[str] = None,
    ) -> List[Investigation]:
        """List investigations with lifecycle and assignment filters."""
        query = db.query(Investigation).filter(Investigation.is_deleted == False)

        if status:
            query = query.filter(Investigation.status == status.upper())
        if priority:
            query = query.filter(Investigation.priority == priority.upper())
        if assigned_user_id:
            query = query.filter(Investigation.assigned_user_id == assigned_user_id)
        if incident_id:
            query = query.filter(
                (Investigation.incident_id == incident_id)
                | (Investigation.trigger_incident_id == incident_id)
            )

        return query.order_by(Investigation.created_at.desc()).offset(skip).limit(limit).all()

    @staticmethod
    def update_investigation(
        db: Session,
        investigation_id: str,
        update_in: InvestigationUpdate,
    ) -> Investigation:
        """
        Update investigation attributes and execute controlled lifecycle state transitions.
        Strictly rejects invalid lifecycle transitions.
        """
        inv = InvestigationService.get_investigation(db, investigation_id)
        if not inv:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Investigation '{investigation_id}' not found",
            )

        # 1. Validate state transition if status update requested
        if update_in.status is not None:
            new_status = update_in.status.upper()
            curr_status = inv.status.upper()

            if new_status != curr_status:
                allowed = VALID_INVESTIGATION_TRANSITIONS.get(curr_status, set())
                if new_status not in allowed:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=(
                            f"Invalid state transition from '{curr_status}' to '{new_status}'. "
                            f"Allowed transitions from '{curr_status}': {sorted(list(allowed))}"
                        ),
                    )

                # Update lifecycle timestamps based on authoritative transition
                now = utc_now()
                if curr_status == "PENDING" and new_status == "ACTIVE":
                    inv.started_at = now
                elif new_status in {"COMPLETED", "FAILED", "CANCELLED"}:
                    inv.completed_at = now

                inv.status = new_status

        # 2. Update priority
        if update_in.priority is not None:
            inv.priority = update_in.priority.upper()

        # 3. Update assigned investigator
        if update_in.assigned_user_id is not None:
            user = db.query(User).filter(
                User.user_id == update_in.assigned_user_id,
                User.is_deleted == False,
            ).first()
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"User '{update_in.assigned_user_id}' not found",
                )
            inv.assigned_user_id = update_in.assigned_user_id

        # 4. Update basic metadata
        if update_in.title is not None:
            inv.title = update_in.title
        if update_in.description is not None:
            inv.description = update_in.description
        if update_in.findings is not None:
            inv.findings = update_in.findings
        if update_in.metadata_json is not None:
            meta = inv.metadata_json or {}
            meta.update(update_in.metadata_json)
            inv.metadata_json = meta

        inv.updated_at = utc_now()
        db.commit()
        db.refresh(inv)

        AuditService.record_action(
            db=db,
            action="UPDATE_INVESTIGATION",
            resource_type="investigation",
            resource_id=inv.investigation_id,
            user_identifier=inv.assigned_user_id,
            status="SUCCESS",
            details={"title": inv.title, "status": inv.status, "priority": inv.priority},
        )

        logger.info(f"Updated investigation {inv.investigation_id} (Status: {inv.status})")
        return inv

    @staticmethod
    def build_agent_request(
        db: Session,
        investigation_id: str,
        requested_action: str = "ANALYZE_INCIDENT",
    ) -> AIAgentInvestigationRequest:
        """
        Build an authoritative, validated data packet for external AI Investigation Agent analysis.
        Gathers referenced evidence IDs, incident data, and context memory IDs.
        """
        inv = InvestigationService.get_investigation(db, investigation_id)
        if not inv:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Investigation '{investigation_id}' not found",
            )

        # Collect evidence IDs linked with incident/events
        evidence_ids = []
        if inv.trigger_event_id:
            evts = db.query(Event).filter(Event.event_id == inv.trigger_event_id).all()
            for e in evts:
                if e.evidence_id:
                    evidence_ids.append(e.evidence_id)

        # Also collect evidence directly associated with incident camera/events
        if inv.incident:
            for evd in db.query(Evidence).filter(
                Evidence.camera_id == inv.incident.primary_camera_id,
                Evidence.is_deleted == False,
            ).limit(10).all():
                evidence_ids.append(evd.evidence_id)

        evidence_ids = list(set(evidence_ids))

        # Collect context memories
        memory_ids = [
            m.memory_id
            for m in db.query(SecurityMemory).filter(
                SecurityMemory.is_deleted == False,
                (SecurityMemory.event_id == inv.trigger_event_id)
                | (SecurityMemory.incident_id == inv.incident_id),
            ).limit(10).all()
        ]

        camera_id = inv.incident.primary_camera_id if inv.incident else None
        zone_id = inv.incident.zone_id if inv.incident else None

        return AIAgentInvestigationRequest(
            investigation_id=inv.investigation_id,
            event_id=inv.trigger_event_id,
            threat_id=inv.trigger_threat_id,
            incident_id=inv.incident_id,
            camera_id=camera_id,
            zone_id=zone_id,
            evidence_ids=evidence_ids,
            memory_ids=memory_ids,
            requested_action=requested_action,
            schema_version="1.0",
        )

    @staticmethod
    def validate_and_apply_agent_response(
        db: Session,
        agent_response: AIAgentInvestigationResponse,
    ) -> AIAgentValidationResult:
        """
        Authoritative backend validation of an external AI Investigation Agent response.
        Enforces strict safety:
        - Rejects fabricated evidence IDs.
        - Validates confidence range.
        - Flags INSUFFICIENT_EVIDENCE when confidence is low or evidence is lacking.
        - Preserves human-in-the-loop: does NOT automatically transition to COMPLETED or treat AI suggestions as confirmed facts.
        """
        # 1. Validate target investigation exists
        inv = InvestigationService.get_investigation(db, agent_response.investigation_id)
        if not inv:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Referenced Investigation '{agent_response.investigation_id}' does not exist in authoritative backend",
            )

        # 2. Check every referenced evidence ID
        validated_evd_ids = []
        rejected_evd_ids = []

        for evd_id in agent_response.evidence_references:
            evd_model = db.query(Evidence).filter(
                Evidence.evidence_id == evd_id,
                Evidence.is_deleted == False,
            ).first()
            if not evd_model:
                rejected_evd_ids.append(evd_id)
            else:
                validated_evd_ids.append(evd_id)

        # Reject immediately if fabricated / nonexistent evidence was cited
        if rejected_evd_ids:
            logger.warning(
                f"AI Agent submitted nonexistent evidence references for {inv.investigation_id}: {rejected_evd_ids}"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"Fabricated or nonexistent evidence reference(s) rejected by Backend Security Core: "
                    f"{rejected_evd_ids}. AI Agent suggestions must only cite authoritative evidence."
                ),
            )

        # 3. Evaluate evidence sufficiency
        # Low confidence (< 0.5) or zero validated evidence when confidence < 0.8 flags INSUFFICIENT_EVIDENCE
        if agent_response.confidence < 0.5 or (not validated_evd_ids and agent_response.confidence < 0.8):
            status_outcome = "INSUFFICIENT_EVIDENCE"
            notes = (
                f"AI analysis submitted with insufficient evidence/confidence ({agent_response.confidence:.2f}). "
                f"Findings require additional forensic review."
            )
        else:
            status_outcome = "ACCEPTED"
            notes = "AI analysis successfully validated against authoritative backend evidence registry."

        # 4. Safely store the untrusted report in metadata without overriding confirmed facts
        meta = inv.metadata_json or {}
        agent_reports = meta.get("ai_agent_reports", [])
        report_entry = {
            "submitted_at": utc_now().isoformat(),
            "status": status_outcome,
            "confidence": agent_response.confidence,
            "analysis": agent_response.analysis,
            "findings": agent_response.findings,
            "validated_evidence_ids": validated_evd_ids,
            "recommended_actions": agent_response.recommended_actions,
        }
        agent_reports.append(report_entry)
        meta["ai_agent_reports"] = agent_reports
        inv.metadata_json = meta

        # Append labeled unverified finding note to findings log
        unverified_tag = f"\n\n[AI Agent Report ({status_outcome}) - Confidence: {agent_response.confidence:.2f}]\n{agent_response.analysis}"
        if inv.findings:
            inv.findings += unverified_tag
        else:
            inv.findings = unverified_tag.strip()

        inv.updated_at = utc_now()
        db.commit()
        db.refresh(inv)

        return AIAgentValidationResult(
            investigation_id=inv.investigation_id,
            is_valid=(status_outcome == "ACCEPTED"),
            status=status_outcome,
            confidence=agent_response.confidence,
            validated_evidence_ids=validated_evd_ids,
            rejected_evidence_ids=[],
            recommended_actions=agent_response.recommended_actions,
            findings=agent_response.findings,
            notes=notes,
            schema_version="1.0",
        )

    @staticmethod
    def execute_autonomous_investigation(
        db: Session,
        request: InvestigationExecuteRequest,
        current_user_id: Optional[str] = None,
    ) -> InvestigationExecutionResult:
        """
        Execute autonomous security investigation following the mandatory flow:
        Incident
        → Find relevant cameras
        → Find detected entities
        → Cross-camera search/tracking
        → Check relevant zones
        → Check security policies
        → Build incident timeline
        → Collect evidence
        → Cross-check evidence
        → Calculate confidence
        → Generate explanation
        → Return investigation result

        The result MUST clearly separate:
        1. OBSERVED FACTS
        2. INFERENCES
        3. UNKNOWN INFORMATION

        Every investigation result must be evidence-grounded.
        Never invent: camera IDs, timestamps, people, objects, locations, events, movements, evidence, conclusions.
        If evidence is insufficient, return: "I don't know — insufficient evidence."
        """
        # 1. Validate investigation exists
        inv = InvestigationService.get_investigation(db, request.investigation_id)
        if not inv:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Investigation '{request.investigation_id}' not found",
            )

        # Determine the incident to investigate
        incident_id = request.incident_id or inv.incident_id or inv.trigger_incident_id
        trigger_event_id = request.trigger_event_id or inv.trigger_event_id

        incident = None
        if incident_id:
            incident = db.query(Incident).filter(
                Incident.incident_id == incident_id,
                Incident.is_deleted == False,
            ).first()

        trigger_event = None
        if trigger_event_id:
            trigger_event = db.query(Event).filter(Event.event_id == trigger_event_id).first()

        # Initialize result containers
        observed_facts: List[ObservedFact] = []
        inferences: List[Inference] = []
        unknown_info: List[UnknownInformation] = []
        cameras_analyzed: List[str] = []
        zones_analyzed: List[str] = []
        policies_checked: List[str] = []
        evidence_collected: List[str] = []
        cross_camera_tracks: List[Dict[str, Any]] = []
        timeline_events: List[Dict[str, Any]] = []

        fact_counter = 0
        inference_counter = 0
        unknown_counter = 0

        def next_fact_id() -> str:
            nonlocal fact_counter
            fact_counter += 1
            return f"FACT-{request.investigation_id}-{fact_counter:03d}"

        def next_inference_id() -> str:
            nonlocal inference_counter
            inference_counter += 1
            return f"INF-{request.investigation_id}-{inference_counter:03d}"

        def next_unknown_id() -> str:
            nonlocal unknown_counter
            unknown_counter += 1
            return f"UNK-{request.investigation_id}-{unknown_counter:03d}"

        # 2. Find relevant cameras
        relevant_camera_ids: List[str] = []
        if incident and incident.primary_camera_id:
            relevant_camera_ids.append(incident.primary_camera_id)
            cameras_analyzed.append(incident.primary_camera_id)
        if trigger_event and trigger_event.camera_id:
            if trigger_event.camera_id not in relevant_camera_ids:
                relevant_camera_ids.append(trigger_event.camera_id)
                cameras_analyzed.append(trigger_event.camera_id)

        # Add cameras from zone mappings if zone is known
        zone_ids: List[str] = []
        if incident and incident.zone_id:
            zone_ids.append(incident.zone_id)
            zones_analyzed.append(incident.zone_id)
        if trigger_event and trigger_event.zone_id:
            if trigger_event.zone_id not in zone_ids:
                zone_ids.append(trigger_event.zone_id)
                zones_analyzed.append(trigger_event.zone_id)

        # Find cameras mapping to relevant zones
        if zone_ids:
            for zone_id in zone_ids:
                zone_cameras = db.query(ZoneCameraMapping).filter(
                    ZoneCameraMapping.zone_id == zone_id
                ).all()
                for zc in zone_cameras:
                    if zc.camera_id not in relevant_camera_ids:
                        relevant_camera_ids.append(zc.camera_id)
                        cameras_analyzed.append(zc.camera_id)

        # If no cameras found, record as unknown
        if not relevant_camera_ids:
            unknown_info.append(UnknownInformation(
                unknown_id=next_unknown_id(),
                description="No relevant cameras identified for investigation scope",
                reason="No incident primary camera, trigger event camera, or zone camera mappings found",
                impact="CRITICAL",
                potential_sources=["Incident configuration", "Zone camera mappings", "Event camera metadata"],
            ))

        # 3. Define time window
        lookback_start = utc_now() - timedelta(hours=request.lookback_hours)
        lookback_end = utc_now()

        # 4. Find detected entities and events in time window
        relevant_events: List[Event] = []
        for cam_id in relevant_camera_ids:
            cam_events = db.query(Event).filter(
                Event.camera_id == cam_id,
                Event.timestamp >= lookback_start,
                Event.timestamp <= lookback_end,
            ).order_by(Event.timestamp).all()
            relevant_events.extend(cam_events)

        # Deduplicate events by event_id
        seen_event_ids = set()
        unique_events = []
        for evt in relevant_events:
            if evt.event_id not in seen_event_ids:
                seen_event_ids.add(evt.event_id)
                unique_events.append(evt)

        relevant_events = unique_events

        # 5. Cross-camera search/tracking (if enabled)
        if request.cross_camera:
            # First, search for events with matching entity_ids from all cameras
            # This enables cross-camera tracking even when zone-camera mappings are limited
            entity_ids_in_events = set(evt.entity_id for evt in relevant_events if evt.entity_id)
            if entity_ids_in_events:
                for entity_id in entity_ids_in_events:
                    matching_events = db.query(Event).filter(
                        Event.entity_id == entity_id,
                        Event.timestamp >= lookback_start,
                        Event.timestamp <= lookback_end,
                    ).all()
                    for evt in matching_events:
                        if evt.event_id not in seen_event_ids:
                            relevant_events.append(evt)
                            seen_event_ids.add(evt.event_id)
                            if evt.camera_id not in relevant_camera_ids:
                                relevant_camera_ids.append(evt.camera_id)
                            if evt.camera_id not in cameras_analyzed:
                                cameras_analyzed.append(evt.camera_id)

            # Also search for events from other cameras in the same zone
            if zone_ids:
                for zone_id in zone_ids:
                    zone_cam_ids = [zc.camera_id for zc in db.query(ZoneCameraMapping).filter(
                        ZoneCameraMapping.zone_id == zone_id
                    ).all()]
                    for cam_id in zone_cam_ids:
                        if cam_id not in relevant_camera_ids:
                            cam_events = db.query(Event).filter(
                                Event.camera_id == cam_id,
                                Event.timestamp >= lookback_start,
                                Event.timestamp <= lookback_end,
                            ).order_by(Event.timestamp).all()
                            relevant_events.extend(cam_events)
                            if cam_id not in cameras_analyzed:
                                cameras_analyzed.append(cam_id)
                            relevant_camera_ids.append(cam_id)

            # Deduplicate events again after cross-camera search
            seen_event_ids = set()
            unique_events = []
            for evt in relevant_events:
                if evt.event_id not in seen_event_ids:
                    seen_event_ids.add(evt.event_id)
                    unique_events.append(evt)
            relevant_events = unique_events

            # Group events by entity_id and tracking_id to find cross-camera tracks
            entity_tracks: Dict[str, List[Event]] = {}
            for evt in relevant_events:
                track_key = evt.entity_id or (evt.metadata_json.get("tracking_id") if evt.metadata_json else None)
                if track_key:
                    if track_key not in entity_tracks:
                        entity_tracks[track_key] = []
                    entity_tracks[track_key].append(evt)

            # Find entities seen across multiple cameras
            for track_id, track_events in entity_tracks.items():
                cameras_in_track = list(set(e.camera_id for e in track_events))
                if len(cameras_in_track) > 1:
                    cross_camera_tracks.append({
                        "tracking_id": track_id,
                        "cameras": cameras_in_track,
                        "event_count": len(track_events),
                        "first_seen": min(e.timestamp for e in track_events).isoformat(),
                        "last_seen": max(e.timestamp for e in track_events).isoformat(),
                        "event_ids": [e.event_id for e in track_events],
                    })
                    # Record as observed fact
                    observed_facts.append(ObservedFact(
                        fact_id=next_fact_id(),
                        description=f"Entity {track_id} tracked across {len(cameras_in_track)} cameras: {', '.join(cameras_in_track)}",
                        evidence_references=[],
                        event_references=[e.event_id for e in track_events],
                        camera_id=cameras_in_track[0] if cameras_in_track else None,
                        timestamp=min(e.timestamp for e in track_events),
                        confidence=0.8,
                        verification_status="UNVERIFIED",
                    ))

        # 6. Check relevant zones and security policies
        relevant_policies: List[SecurityPolicy] = []
        for zone_id in zone_ids:
            zone_policies = db.query(SecurityPolicy).filter(
                SecurityPolicy.zone_id == zone_id,
                SecurityPolicy.is_active == True,
            ).all()
            for pol in zone_policies:
                relevant_policies.append(pol)
                policies_checked.append(pol.policy_id)

        # 7. Build incident timeline from relevant events
        for evt in relevant_events:
            timeline_events.append({
                "event_id": evt.event_id,
                "camera_id": evt.camera_id,
                "timestamp": evt.timestamp.isoformat(),
                "event_type": evt.event_type,
                "entity_id": evt.entity_id,
                "zone_id": evt.zone_id,
                "confidence": evt.confidence,
                "evidence_id": evt.evidence_id,
            })

            # Create observed facts for high-confidence events
            if evt.confidence >= request.min_confidence:
                evd_refs = [evt.evidence_id] if evt.evidence_id else []
                observed_facts.append(ObservedFact(
                    fact_id=next_fact_id(),
                    description=f"{evt.event_type} detected on camera {evt.camera_id}",
                    evidence_references=evd_refs,
                    event_references=[evt.event_id],
                    camera_id=evt.camera_id,
                    timestamp=evt.timestamp,
                    confidence=evt.confidence,
                    verification_status="UNVERIFIED",
                ))

        # 8. Collect evidence
        collected_evidence: List[Evidence] = []
        if request.include_evidence:
            for cam_id in relevant_camera_ids:
                cam_evidence = db.query(Evidence).filter(
                    Evidence.camera_id == cam_id,
                    Evidence.timestamp_start >= lookback_start,
                    Evidence.timestamp_end <= lookback_end,
                    Evidence.is_deleted == False,
                ).all()
                for evd in cam_evidence:
                    collected_evidence.append(evd)
                    evidence_collected.append(evd.evidence_id)

            # Also collect evidence linked to relevant events
            for evt in relevant_events:
                if evt.evidence_id:
                    evd = db.query(Evidence).filter(
                        Evidence.evidence_id == evt.evidence_id,
                        Evidence.is_deleted == False,
                    ).first()
                    if evd and evd.evidence_id not in evidence_collected:
                        collected_evidence.append(evd)
                        evidence_collected.append(evd.evidence_id)

        # 9. Cross-check evidence
        # Verify evidence consistency and corroboration
        evidence_by_camera: Dict[str, List[Evidence]] = {}
        for evd in collected_evidence:
            if evd.camera_id not in evidence_by_camera:
                evidence_by_camera[evd.camera_id] = []
            evidence_by_camera[evd.camera_id].append(evd)

        # Check for corroborating evidence across cameras for same time window
        for track in cross_camera_tracks:
            track_start = datetime.fromisoformat(track["first_seen"].replace("Z", "+00:00"))
            track_end = datetime.fromisoformat(track["last_seen"].replace("Z", "+00:00"))
            
            corroborating_evidence = []
            for cam_id in track["cameras"]:
                for evd in evidence_by_camera.get(cam_id, []):
                    if evd.timestamp_start <= track_end and evd.timestamp_end >= track_start:
                        corroborating_evidence.append(evd.evidence_id)

            if len(corroborating_evidence) >= 2:
                inferences.append(Inference(
                    inference_id=next_inference_id(),
                    description=f"Cross-camera corroboration for entity {track['tracking_id']}: {len(corroborating_evidence)} evidence items span the tracking window",
                    supported_by_facts=[f.fact_id for f in observed_facts if any(eid in f.event_references for eid in track["event_ids"])],
                    reasoning="Multiple cameras captured evidence within the entity tracking time window, supporting cross-camera presence",
                    confidence=0.75,
                    inference_type="CORRELATIONAL",
                ))

        # 10. Check policy violations and create inferences
        for pol in relevant_policies:
            # Check if any relevant event matches policy type
            matching_events = []
            for evt in relevant_events:
                if pol.policy_type.upper() in evt.event_type.upper() or pol.policy_type.upper() in (evt.metadata_json or {}).get("policy_types", []):
                    matching_events.append(evt)

            if matching_events:
                # Create observed fact for policy trigger
                observed_facts.append(ObservedFact(
                    fact_id=next_fact_id(),
                    description=f"Security policy '{pol.name}' ({pol.policy_id}) triggered by {len(matching_events)} event(s)",
                    evidence_references=[e.evidence_id for e in matching_events if e.evidence_id],
                    event_references=[e.event_id for e in matching_events],
                    camera_id=matching_events[0].camera_id if matching_events else None,
                    timestamp=matching_events[0].timestamp if matching_events else None,
                    confidence=0.9,
                    verification_status="UNVERIFIED",
                ))
                policies_checked.append(pol.policy_id)

                # Create inference about policy violation
                inferences.append(Inference(
                    inference_id=next_inference_id(),
                    description=f"Policy violation inferred: {pol.name} ({pol.severity} severity)",
                    supported_by_facts=[f.fact_id for f in observed_facts if pol.name in f.description][-1:],
                    reasoning=f"Events matching policy type '{pol.policy_type}' detected in zone with active {pol.severity} policy",
                    confidence=0.8,
                    inference_type="LOGICAL",
                ))

        # 11. Identify unknown information
        # Check for cameras without evidence
        for cam_id in relevant_camera_ids:
            cam_evidence = evidence_by_camera.get(cam_id, [])
            if not cam_evidence:
                unknown_info.append(UnknownInformation(
                    unknown_id=next_unknown_id(),
                    description=f"No evidence collected from camera {cam_id} during investigation window",
                    reason="Camera may be offline, evidence not retained, or outside retention window",
                    impact="MEDIUM",
                    potential_sources=[f"Camera {cam_id} status history", "Storage retention policies", "Evidence ingestion logs"],
                ))

        # Check for zones without policies
        for zone_id in zone_ids:
            zone_policies = [p for p in relevant_policies if p.zone_id == zone_id]
            if not zone_policies:
                unknown_info.append(UnknownInformation(
                    unknown_id=next_unknown_id(),
                    description=f"No active security policies defined for zone {zone_id}",
                    reason="Zone may not have policies configured or policies are inactive",
                    impact="MEDIUM",
                    potential_sources=["Zone configuration", "Policy management interface"],
                ))

        # Check for entities without cross-camera tracking
        if request.cross_camera:
            single_camera_entities = set()
            for evt in relevant_events:
                if evt.entity_id:
                    track_key = evt.entity_id
                    cam_ids = {e.camera_id for e in relevant_events if e.entity_id == track_key}
                    if len(cam_ids) == 1:
                        single_camera_entities.add(track_key)

            for entity_id in single_camera_entities:
                unknown_info.append(UnknownInformation(
                    unknown_id=next_unknown_id(),
                    description=f"Entity {entity_id} only observed on single camera; cross-camera path unknown",
                    reason="Insufficient camera coverage or entity not tracked across camera boundaries",
                    impact="LOW",
                    potential_sources=["Additional camera feeds", "Extended tracking window", "Manual review"],
                ))

        # 12. Calculate overall confidence
        if observed_facts:
            fact_confidences = [f.confidence for f in observed_facts if f.confidence > 0]
            evidence_confidences = [e.confidence for e in collected_evidence if e.confidence > 0]
            all_confidences = fact_confidences + evidence_confidences
            overall_confidence = sum(all_confidences) / len(all_confidences) if all_confidences else 0.0
        else:
            overall_confidence = 0.0

        # 13. Determine evidence sufficiency and conclusion
        verified_evidence = [e for e in collected_evidence if e.verification_status == "VERIFIED"]
        unverified_evidence = [e for e in collected_evidence if e.verification_status == "UNVERIFIED"]

        if not observed_facts and not collected_evidence:
            evidence_sufficiency = "INSUFFICIENT"
            conclusion = "I don't know - insufficient evidence."
        elif len(verified_evidence) == 0 and len(unverified_evidence) == 0:
            evidence_sufficiency = "INSUFFICIENT"
            conclusion = "I don't know - insufficient evidence."
        elif len(verified_evidence) >= 2 and overall_confidence >= 0.7:
            evidence_sufficiency = "SUFFICIENT"
            conclusion = f"Investigation completed with {len(observed_facts)} observed facts and {len(inferences)} inferences. Evidence corroborates timeline across {len(cameras_analyzed)} cameras."
        elif len(collected_evidence) > 0 and overall_confidence >= 0.5:
            evidence_sufficiency = "PARTIAL"
            conclusion = f"Investigation partially complete. {len(observed_facts)} observed facts with {len(verified_evidence)} verified and {len(unverified_evidence)} unverified evidence items. Some inferences require additional verification."
        else:
            evidence_sufficiency = "INSUFFICIENT"
            conclusion = "I don't know - insufficient evidence."

        # 14. Store result in investigation metadata
        inv.status = "COMPLETED"
        inv.completed_at = utc_now()
        inv.findings = conclusion
        meta = inv.metadata_json or {}
        meta["autonomous_investigation_result"] = {
            "executed_at": utc_now().isoformat(),
            "executed_by": current_user_id or "AUTONOMOUS_INVESTIGATION_ENGINE",
            "observed_facts_count": len(observed_facts),
            "inferences_count": len(inferences),
            "unknown_information_count": len(unknown_info),
            "overall_confidence": overall_confidence,
            "evidence_sufficiency": evidence_sufficiency,
            "cameras_analyzed": cameras_analyzed,
            "zones_analyzed": zones_analyzed,
            "policies_checked": policies_checked,
            "evidence_collected": evidence_collected,
        }
        inv.metadata_json = meta
        inv.updated_at = utc_now()
        db.commit()
        db.refresh(inv)

        AuditService.record_action(
            db=db,
            action="EXECUTE_AUTONOMOUS_INVESTIGATION",
            resource_type="investigation",
            resource_id=inv.investigation_id,
            user_identifier=current_user_id,
            status="SUCCESS",
            details={
                "observed_facts": len(observed_facts),
                "inferences": len(inferences),
                "unknown_information": len(unknown_info),
                "confidence": overall_confidence,
                "evidence_sufficiency": evidence_sufficiency,
            },
        )

        logger.info(f"Autonomous investigation {inv.investigation_id} completed: {len(observed_facts)} facts, {len(inferences)} inferences, {len(unknown_info)} unknowns, confidence={overall_confidence:.2f}")

        return InvestigationExecutionResult(
            investigation_id=inv.investigation_id,
            incident_id=incident_id,
            trigger_event_id=trigger_event_id,
            executed_at=utc_now(),
            executed_by=current_user_id or "AUTONOMOUS_INVESTIGATION_ENGINE",
            observed_facts=observed_facts,
            inferences=inferences,
            unknown_information=unknown_info,
            overall_confidence=round(overall_confidence, 2),
            conclusion=conclusion,
            evidence_sufficiency=evidence_sufficiency,
            cameras_analyzed=cameras_analyzed,
            zones_analyzed=zones_analyzed,
            policies_checked=policies_checked,
            evidence_collected=evidence_collected,
            cross_camera_tracks=cross_camera_tracks,
            timeline_events=timeline_events,
            schema_version="1.0",
        )
