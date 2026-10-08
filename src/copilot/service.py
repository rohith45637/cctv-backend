import re
import logging
from typing import List, Optional, Set, Dict, Any
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import or_

from src.database.models import (
    Camera,
    Zone,
    Event,
    Threat,
    Incident,
    Investigation,
    Evidence,
    SecurityMemory,
    User,
)
from src.schemas.copilot import CopilotQueryRequest, CopilotQueryResponse
from src.auth.rbac.permissions import PermissionCode
from src.audit.service import AuditService

logger = logging.getLogger("backend.copilot")

STOPWORDS = {
    "a", "an", "the", "in", "on", "at", "for", "to", "of", "and", "or", "is",
    "are", "was", "were", "what", "who", "where", "which", "how", "tell", "me",
    "about", "show", "get", "status", "any", "with", "from", "by", "this", "that"
}


class CopilotService:
    """
    Authoritative service executing AI Security Copilot queries.
    Enforces strict backend ground-truth retrieval, RBAC permission filters,
    and bounded responses without external generative LLM hallucination.
    """

    @staticmethod
    def query(
        db: Session,
        request: CopilotQueryRequest,
        current_user: User,
    ) -> CopilotQueryResponse:
        """
        Execute an authoritative bounded query against Backend Security Core data.
        """
        # 1. Authoritative Validation of explicit context IDs
        matched_camera: Optional[Camera] = None
        matched_zone: Optional[Zone] = None
        matched_event: Optional[Event] = None
        matched_threat: Optional[Threat] = None
        matched_incident: Optional[Incident] = None
        matched_investigation: Optional[Investigation] = None

        if request.camera_id:
            if not current_user.has_permission(PermissionCode.CAMERA_READ.value):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied: required permission '{PermissionCode.CAMERA_READ.value}'",
                )
            matched_camera = (
                db.query(Camera)
                .filter(Camera.camera_id == request.camera_id, Camera.is_deleted == False)
                .first()
            )
            if not matched_camera:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Camera '{request.camera_id}' not found",
                )

        if request.zone_id:
            if not current_user.has_permission(PermissionCode.ZONE_READ.value):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied: required permission '{PermissionCode.ZONE_READ.value}'",
                )
            matched_zone = (
                db.query(Zone)
                .filter(Zone.zone_id == request.zone_id, Zone.is_deleted == False)
                .first()
            )
            if not matched_zone:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Zone '{request.zone_id}' not found",
                )

        if request.event_id:
            if not current_user.has_permission(PermissionCode.EVENT_READ.value):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied: required permission '{PermissionCode.EVENT_READ.value}'",
                )
            matched_event = (
                db.query(Event)
                .filter(Event.event_id == request.event_id)
                .first()
            )
            if not matched_event:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Event '{request.event_id}' not found",
                )

        if request.threat_id:
            if not current_user.has_permission(PermissionCode.THREAT_READ.value):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied: required permission '{PermissionCode.THREAT_READ.value}'",
                )
            matched_threat = (
                db.query(Threat)
                .filter(Threat.threat_id == request.threat_id, Threat.is_deleted == False)
                .first()
            )
            if not matched_threat:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Threat '{request.threat_id}' not found",
                )

        if request.incident_id:
            if not current_user.has_permission(PermissionCode.INCIDENT_READ.value):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied: required permission '{PermissionCode.INCIDENT_READ.value}'",
                )
            matched_incident = (
                db.query(Incident)
                .filter(Incident.incident_id == request.incident_id, Incident.is_deleted == False)
                .first()
            )
            if not matched_incident:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Incident '{request.incident_id}' not found",
                )

        if request.investigation_id:
            if not current_user.has_permission(PermissionCode.INVESTIGATION_READ.value):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied: required permission '{PermissionCode.INVESTIGATION_READ.value}'",
                )
            matched_investigation = (
                db.query(Investigation)
                .filter(Investigation.investigation_id == request.investigation_id, Investigation.is_deleted == False)
                .first()
            )
            if not matched_investigation:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Investigation '{request.investigation_id}' not found",
                )

        # 2. Extract potential ID patterns and keywords from free text query
        query_text = request.query.strip()
        tokens = set(re.findall(r"[A-Za-z0-9_-]+", query_text))
        keywords = {t.lower() for t in tokens if len(t) > 2 and t.lower() not in STOPWORDS}

        # Sets to hold authoritative entity instances
        events: Dict[str, Event] = {}
        threats: Dict[str, Threat] = {}
        incidents: Dict[str, Incident] = {}
        investigations: Dict[str, Investigation] = {}
        evidence_items: Dict[str, Evidence] = {}
        memories: Dict[str, SecurityMemory] = {}

        if matched_event:
            events[matched_event.event_id] = matched_event
        if matched_threat:
            threats[matched_threat.threat_id] = matched_threat
        if matched_incident:
            incidents[matched_incident.incident_id] = matched_incident
        if matched_investigation:
            investigations[matched_investigation.investigation_id] = matched_investigation

        # 3. Discover relevant records based on explicit context and query keywords
        # Events
        if current_user.has_permission(PermissionCode.EVENT_READ.value):
            evt_query = db.query(Event)
            if request.camera_id:
                evt_query = evt_query.filter(Event.camera_id == request.camera_id)
            if request.zone_id:
                evt_query = evt_query.filter(Event.zone_id == request.zone_id)
            
            # Text matching for events
            or_conditions = []
            for token in tokens:
                if token.startswith("EVT-"):
                    or_conditions.append(Event.event_id == token)
            for kw in keywords:
                or_conditions.append(Event.event_type.ilike(f"%{kw}%"))
                or_conditions.append(Event.entity_id.ilike(f"%{kw}%"))
            
            if or_conditions:
                matching_evts = evt_query.filter(or_(*or_conditions)).limit(20).all()
                for e in matching_evts:
                    events[e.event_id] = e
            elif matched_camera or matched_zone:
                # If camera or zone specified, fetch latest events
                for e in evt_query.order_by(Event.timestamp.desc()).limit(10).all():
                    events[e.event_id] = e

        # Threats
        if current_user.has_permission(PermissionCode.THREAT_READ.value):
            thr_query = db.query(Threat).filter(Threat.is_deleted == False)
            if request.camera_id:
                thr_query = thr_query.filter(Threat.camera_id == request.camera_id)
            if request.zone_id:
                thr_query = thr_query.filter(Threat.zone_id == request.zone_id)
            
            or_conditions = []
            for token in tokens:
                if token.startswith("THR-"):
                    or_conditions.append(Threat.threat_id == token)
            for kw in keywords:
                or_conditions.append(Threat.title.ilike(f"%{kw}%"))
                or_conditions.append(Threat.description.ilike(f"%{kw}%"))
                or_conditions.append(Threat.reason.ilike(f"%{kw}%"))
            
            if or_conditions:
                matching_thrs = thr_query.filter(or_(*or_conditions)).limit(20).all()
                for t in matching_thrs:
                    threats[t.threat_id] = t
            elif (matched_camera or matched_zone) and not events:
                for t in thr_query.order_by(Threat.detected_at.desc()).limit(10).all():
                    threats[t.threat_id] = t

        # Incidents
        if current_user.has_permission(PermissionCode.INCIDENT_READ.value):
            inc_query = db.query(Incident).filter(Incident.is_deleted == False)
            if request.zone_id:
                inc_query = inc_query.filter(Incident.zone_id == request.zone_id)
            if request.camera_id:
                inc_query = inc_query.filter(Incident.primary_camera_id == request.camera_id)
                
            or_conditions = []
            for token in tokens:
                if token.startswith("INC-"):
                    or_conditions.append(Incident.incident_id == token)
            for kw in keywords:
                or_conditions.append(Incident.title.ilike(f"%{kw}%"))
                or_conditions.append(Incident.description.ilike(f"%{kw}%"))
            
            if or_conditions:
                matching_incs = inc_query.filter(or_(*or_conditions)).limit(20).all()
                for inc in matching_incs:
                    incidents[inc.incident_id] = inc

        # Investigations
        if current_user.has_permission(PermissionCode.INVESTIGATION_READ.value):
            inv_query = db.query(Investigation).filter(Investigation.is_deleted == False)
            or_conditions = []
            for token in tokens:
                if token.startswith("INV-"):
                    or_conditions.append(Investigation.investigation_id == token)
            for kw in keywords:
                or_conditions.append(Investigation.title.ilike(f"%{kw}%"))
                or_conditions.append(Investigation.description.ilike(f"%{kw}%"))
                or_conditions.append(Investigation.findings.ilike(f"%{kw}%"))
            
            if or_conditions:
                matching_invs = inv_query.filter(or_(*or_conditions)).limit(20).all()
                for inv in matching_invs:
                    investigations[inv.investigation_id] = inv

        # Correlate linked entities across discovered records
        # From threats -> link events & incidents
        for t in list(threats.values()):
            if t.event_id and t.event_id not in events and current_user.has_permission(PermissionCode.EVENT_READ.value):
                linked_e = db.query(Event).filter(Event.event_id == t.event_id).first()
                if linked_e:
                    events[linked_e.event_id] = linked_e
            if t.incident_id and t.incident_id not in incidents and current_user.has_permission(PermissionCode.INCIDENT_READ.value):
                linked_inc = db.query(Incident).filter(Incident.incident_id == t.incident_id, Incident.is_deleted == False).first()
                if linked_inc:
                    incidents[linked_inc.incident_id] = linked_inc

        # From incidents -> link threats, events, investigations
        for inc in list(incidents.values()):
            if inc.threat_id and inc.threat_id not in threats and current_user.has_permission(PermissionCode.THREAT_READ.value):
                linked_t = db.query(Threat).filter(Threat.threat_id == inc.threat_id, Threat.is_deleted == False).first()
                if linked_t:
                    threats[linked_t.threat_id] = linked_t
            if inc.related_event_ids and current_user.has_permission(PermissionCode.EVENT_READ.value):
                for eid in inc.related_event_ids:
                    if eid not in events:
                        linked_e = db.query(Event).filter(Event.event_id == eid).first()
                        if linked_e:
                            events[linked_e.event_id] = linked_e

        # From investigations -> link incident, trigger event/threat, event links
        for inv in list(investigations.values()):
            if inv.incident_id and inv.incident_id not in incidents and current_user.has_permission(PermissionCode.INCIDENT_READ.value):
                linked_inc = db.query(Incident).filter(Incident.incident_id == inv.incident_id, Incident.is_deleted == False).first()
                if linked_inc:
                    incidents[linked_inc.incident_id] = linked_inc
            if inv.trigger_event_id and inv.trigger_event_id not in events and current_user.has_permission(PermissionCode.EVENT_READ.value):
                linked_e = db.query(Event).filter(Event.event_id == inv.trigger_event_id).first()
                if linked_e:
                    events[linked_e.event_id] = linked_e
            if inv.trigger_threat_id and inv.trigger_threat_id not in threats and current_user.has_permission(PermissionCode.THREAT_READ.value):
                linked_t = db.query(Threat).filter(Threat.threat_id == inv.trigger_threat_id, Threat.is_deleted == False).first()
                if linked_t:
                    threats[linked_t.threat_id] = linked_t
            if inv.event_links and current_user.has_permission(PermissionCode.EVENT_READ.value):
                for elink in inv.event_links:
                    if elink.event_id not in events:
                        linked_e = db.query(Event).filter(Event.event_id == elink.event_id).first()
                        if linked_e:
                            events[linked_e.event_id] = linked_e

        # Discover Evidence for all collected events or explicitly referenced evidence
        if current_user.has_permission(PermissionCode.EVIDENCE_READ.value):
            # Check explicit tokens
            for token in tokens:
                if token.startswith("EVD-"):
                    ev_item = db.query(Evidence).filter(Evidence.evidence_id == token, Evidence.is_deleted == False).first()
                    if ev_item:
                        evidence_items[ev_item.evidence_id] = ev_item
            
            # Check evidence referenced by events
            for e in events.values():
                if e.evidence_id and e.evidence_id not in evidence_items:
                    ev_item = db.query(Evidence).filter(Evidence.evidence_id == e.evidence_id, Evidence.is_deleted == False).first()
                    if ev_item:
                        evidence_items[ev_item.evidence_id] = ev_item
                # Also query evidence by event_id
                for ev_match in db.query(Evidence).filter(Evidence.event_id == e.event_id, Evidence.is_deleted == False).all():
                    evidence_items[ev_match.evidence_id] = ev_match

        # Discover Security Memory
        if current_user.has_permission(PermissionCode.MEMORY_READ.value):
            mem_query = db.query(SecurityMemory).filter(SecurityMemory.is_deleted == False)
            or_conditions = []
            for token in tokens:
                if token.startswith("MEM-"):
                    or_conditions.append(SecurityMemory.memory_id == token)
            for kw in keywords:
                or_conditions.append(SecurityMemory.content.ilike(f"%{kw}%"))
                or_conditions.append(SecurityMemory.identifier_value.ilike(f"%{kw}%"))
            for e in events.values():
                if e.entity_id:
                    or_conditions.append(SecurityMemory.entity_id == e.entity_id)
            
            if or_conditions:
                matching_mems = mem_query.filter(or_(*or_conditions)).limit(10).all()
                for m in matching_mems:
                    memories[m.memory_id] = m

        # 4. Check for unverified evidence, compute confidence, status, and limitations
        limitations: List[str] = [
            "Grounded strictly in authoritative backend security records without external generative hallucination."
        ]

        has_unverified_evidence = False
        has_rejected_evidence = False
        has_insufficient_evidence_status = False

        for ev in evidence_items.values():
            if ev.verification_status == "UNVERIFIED":
                has_unverified_evidence = True
                limitations.append(f"Evidence '{ev.evidence_id}' is UNVERIFIED; forensic verification required for definitive conclusions.")
            elif ev.verification_status == "REJECTED":
                has_rejected_evidence = True
                limitations.append(f"Evidence '{ev.evidence_id}' was REJECTED during forensic verification.")
            elif ev.verification_status == "INSUFFICIENT_EVIDENCE":
                has_insufficient_evidence_status = True
                limitations.append(f"Evidence '{ev.evidence_id}' has verification status INSUFFICIENT_EVIDENCE.")

        # Determine overall records found
        total_records = (
            len(events)
            + len(threats)
            + len(incidents)
            + len(investigations)
            + len(evidence_items)
            + len(memories)
            + (1 if matched_camera else 0)
            + (1 if matched_zone else 0)
        )

        if total_records == 0:
            AuditService.record_action(
                db=db,
                action="COPILOT_QUERY",
                resource_type="copilot",
                user_id=current_user.id,
                status="SUCCESS",
                details={"query": request.query, "copilot_status": "UNKNOWN", "confidence": 0.0},
            )
            return CopilotQueryResponse(
                query=request.query,
                answer="No authoritative security records found matching inquiry.",
                confidence=0.0,
                status="UNKNOWN",
                evidence_references=[],
                event_references=[],
                threat_references=[],
                incident_references=[],
                investigation_references=[],
                memory_references=[],
                limitations=["No matching records in authoritative security registry."],
                schema_version="1.0",
            )

        # Collect confidence scores across records
        confidence_samples: List[float] = []
        for e in events.values():
            if e.confidence is not None:
                confidence_samples.append(e.confidence)
        for t in threats.values():
            if t.confidence is not None and t.confidence > 0:
                confidence_samples.append(t.confidence)
        for ev in evidence_items.values():
            if ev.confidence is not None:
                confidence_samples.append(ev.confidence)
        for m in memories.values():
            if m.confidence is not None:
                confidence_samples.append(m.confidence)

        if confidence_samples:
            avg_conf = sum(confidence_samples) / len(confidence_samples)
        else:
            avg_conf = 0.85

        # Status and confidence semantics
        if has_unverified_evidence or has_rejected_evidence or has_insufficient_evidence_status:
            status_val = "INSUFFICIENT_EVIDENCE"
            confidence_val = round(min(avg_conf, 0.65), 2)
        elif avg_conf < 0.70:
            status_val = "INSUFFICIENT_EVIDENCE"
            confidence_val = round(avg_conf, 2)
        else:
            status_val = "CONFIRMED"
            confidence_val = round(min(1.0, max(0.70, avg_conf)), 2)

        # 5. Synthesize Fact-Based Authoritative Answer
        answer_parts: List[str] = []

        if matched_camera:
            answer_parts.append(f"Camera '{matched_camera.camera_id}' ({matched_camera.name}) status: {matched_camera.status}.")
        if matched_zone:
            answer_parts.append(f"Zone '{matched_zone.zone_id}' ({matched_zone.name}) risk level: {matched_zone.risk_level}.")

        if investigations:
            inv_summaries = [
                f"Investigation {inv.investigation_id} ('{inv.title}', priority {inv.priority}, status {inv.status})"
                + (f" with findings: '{inv.findings}'" if inv.findings else "")
                for inv in investigations.values()
            ]
            answer_parts.append("Investigations: " + "; ".join(inv_summaries) + ".")

        if incidents:
            inc_summaries = [
                f"Incident {inc.incident_id} ('{inc.title}', severity {inc.severity}, status {inc.status})"
                for inc in incidents.values()
            ]
            answer_parts.append("Incidents: " + "; ".join(inc_summaries) + ".")

        if threats:
            thr_summaries = [
                f"Threat {t.threat_id} ('{t.title}', severity {t.severity}, risk score {t.risk_score}, status {t.status})"
                for t in threats.values()
            ]
            answer_parts.append("Threats: " + "; ".join(thr_summaries) + ".")

        if events:
            evt_summaries = [
                f"Event {e.event_id} ({e.event_type} on camera {e.camera_id} at {e.timestamp.isoformat() if e.timestamp else 'unknown'}, status {e.status})"
                for e in list(events.values())[:5]
            ]
            answer_parts.append("Events: " + "; ".join(evt_summaries) + ".")

        if evidence_items:
            ev_summaries = [
                f"Evidence {ev.evidence_id} (status {ev.verification_status}, source {ev.source_type})"
                for ev in list(evidence_items.values())[:5]
            ]
            answer_parts.append("Evidence items: " + "; ".join(ev_summaries) + ".")

        if memories:
            mem_summaries = [
                f"Memory {m.memory_id} ({m.memory_type}: {m.content or m.description or m.identifier_value})"
                for m in list(memories.values())[:3]
            ]
            answer_parts.append("Security memory: " + "; ".join(mem_summaries) + ".")

        if not answer_parts:
            answer_parts.append("Authoritative backend security records identified for context.")

        answer_text = " ".join(answer_parts)

        # 6. Build References with strict RBAC filtering
        event_refs = sorted(list(events.keys())) if current_user.has_permission(PermissionCode.EVENT_READ.value) else []
        threat_refs = sorted(list(threats.keys())) if current_user.has_permission(PermissionCode.THREAT_READ.value) else []
        incident_refs = sorted(list(incidents.keys())) if current_user.has_permission(PermissionCode.INCIDENT_READ.value) else []
        investigation_refs = sorted(list(investigations.keys())) if current_user.has_permission(PermissionCode.INVESTIGATION_READ.value) else []
        evidence_refs = sorted(list(evidence_items.keys())) if current_user.has_permission(PermissionCode.EVIDENCE_READ.value) else []
        memory_refs = sorted(list(memories.keys())) if current_user.has_permission(PermissionCode.MEMORY_READ.value) else []

        AuditService.record_action(
            db=db,
            action="COPILOT_QUERY",
            resource_type="copilot",
            user_id=current_user.id,
            status="SUCCESS",
            details={"query": request.query, "copilot_status": status_val, "confidence": confidence_val},
        )

        return CopilotQueryResponse(
            query=request.query,
            answer=answer_text,
            confidence=confidence_val,
            status=status_val,
            evidence_references=evidence_refs,
            event_references=event_refs,
            threat_references=threat_refs,
            incident_references=incident_refs,
            investigation_references=investigation_refs,
            memory_references=memory_refs,
            limitations=limitations,
            schema_version="1.0",
        )
