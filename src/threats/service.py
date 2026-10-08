import logging
from typing import List, Optional
from datetime import datetime, timezone
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from src.database.models import (
    Camera,
    Event,
    Incident,
    SecurityPolicy,
    Threat,
    Zone,
    Evidence,
    EventEntity,
)
from src.database.models.base import utc_now
from src.threats.risk_engine import RiskEngine, RiskEvaluationResult
from src.utils.identifiers import generate_identifier
from src.audit.service import AuditService
from src.schemas.threat import (
    RiskReasoningResult,
    RiskReasoningObservation,
    RiskReasoningContext,
    RiskReasoningPolicy,
    RiskReasoningEvidence,
    RiskReasoningExecuteRequest,
)

logger = logging.getLogger("backend.threats.service")


class ThreatService:
    """Core domain service for threat analysis, risk evaluation, and incident management."""

    @staticmethod
    def evaluate_and_create_threat(
        db: Session,
        event_id: str,
        force_escalate: bool = False,
    ) -> Optional[Threat]:
        """
        Evaluate an ingested event and authoritatively create a Threat
        if observation + context + policy + evidence warrant escalation.
        """
        event = db.query(Event).filter(Event.event_id == event_id).first()
        if not event:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Event '{event_id}' not found for threat evaluation",
            )

        # Check if threat already exists for this event
        existing_threat = db.query(Threat).filter(Threat.event_id == event_id).first()
        if existing_threat:
            return existing_threat

        zone = db.query(Zone).filter(Zone.zone_id == event.zone_id).first() if event.zone_id else None
        camera = db.query(Camera).filter(Camera.camera_id == event.camera_id).first() if event.camera_id else None
        policies = []
        if event.zone_id:
            policies = (
                db.query(SecurityPolicy)
                .filter(SecurityPolicy.zone_id == event.zone_id, SecurityPolicy.is_active == True)
                .all()
            )

        evaluation = RiskEngine.evaluate(event=event, zone=zone, camera=camera, policies=policies)

        if not evaluation.is_threat and not force_escalate:
            logger.info(f"Event {event_id} evaluated with risk score {evaluation.risk_score}: below threat threshold.")
            return None

        # Transactional creation of threat
        try:
            threat_id = generate_identifier("threat_id")
            title = f"{evaluation.severity} Threat: {event.event_type}"
            if zone:
                title += f" in {zone.name}"

            threat = Threat(
                threat_id=threat_id,
                title=title,
                description=f"Risk Score: {evaluation.risk_score} | " + "; ".join(evaluation.reasons),
                severity=evaluation.severity,
                risk_score=evaluation.risk_score,
                reason="; ".join(evaluation.reasons),
                status="NEW",
                camera_id=event.camera_id,
                zone_id=event.zone_id,
                event_id=event.event_id,
                confidence=event.confidence,
                schema_version="1.0",
                detected_at=event.timestamp or utc_now(),
                metadata_json={"evaluation_reasons": evaluation.reasons},
            )
            db.add(threat)
            db.commit()
            db.refresh(threat)

            AuditService.record_action(
                db=db,
                action="THREAT_CREATED",
                resource_type="threat",
                resource_id=threat.threat_id,
                status="SUCCESS",
                details={"title": threat.title, "severity": threat.severity, "risk_score": threat.risk_score, "event_id": event_id},
            )

            logger.info(f"Created authoritative threat {threat.threat_id} for event {event_id} (Score: {evaluation.risk_score})")
            return threat
        except Exception as exc:
            db.rollback()
            logger.error(f"Failed to create threat for event {event_id}: {exc}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to create threat: {str(exc)}",
            )

    @staticmethod
    def get_threat(db: Session, threat_id: str) -> Optional[Threat]:
        return db.query(Threat).filter(Threat.threat_id == threat_id, Threat.is_deleted == False).first()

    @staticmethod
    def list_threats(
        db: Session,
        skip: int = 0,
        limit: int = 50,
        status_filter: Optional[str] = None,
        severity_filter: Optional[str] = None,
    ) -> List[Threat]:
        query = db.query(Threat).filter(Threat.is_deleted == False)
        if status_filter:
            query = query.filter(Threat.status == status_filter.upper())
        if severity_filter:
            query = query.filter(Threat.severity == severity_filter.upper())
        return query.order_by(Threat.detected_at.desc()).offset(skip).limit(limit).all()

    @staticmethod
    def update_threat(
        db: Session,
        threat_id: str,
        status: Optional[str] = None,
        incident_id: Optional[str] = None,
    ) -> Threat:
        threat = ThreatService.get_threat(db, threat_id)
        if not threat:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Threat '{threat_id}' not found")

        valid_statuses = {"NEW", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED", "DISMISSED"}
        if status:
            norm_status = status.strip().upper()
            if norm_status not in valid_statuses:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Invalid status '{status}'. Must be one of {list(valid_statuses)}",
                )
            threat.status = norm_status

        if incident_id:
            threat.incident_id = incident_id

        db.commit()
        db.refresh(threat)
        return threat

    # ===============================
    # Incident Management Operations
    # ===============================

    @staticmethod
    def create_incident(
        db: Session,
        title: str,
        description: Optional[str] = None,
        severity: str = "P2",
        zone_id: Optional[str] = None,
        primary_camera_id: Optional[str] = None,
        related_threat_ids: Optional[List[str]] = None,
        related_event_ids: Optional[List[str]] = None,
    ) -> Incident:
        """Atomically create security incident and link originating threats."""
        threat_ids = related_threat_ids or []
        event_ids = related_event_ids or []

        try:
            incident_id = generate_identifier("incident_id")
            incident = Incident(
                incident_id=incident_id,
                title=title,
                description=description,
                severity=severity.upper(),
                status="OPEN",
                zone_id=zone_id,
                primary_camera_id=primary_camera_id,
                threat_id=threat_ids[0] if threat_ids else None,
                related_threat_ids=threat_ids,
                related_event_ids=event_ids,
                opened_at=utc_now(),
                schema_version="1.0",
            )
            db.add(incident)
            db.flush()

            # Link threats to this incident
            if threat_ids:
                for t_id in threat_ids:
                    t = db.query(Threat).filter(Threat.threat_id == t_id).first()
                    if t:
                        t.incident_id = incident.incident_id
                        if t.status == "NEW":
                            t.status = "INVESTIGATING"

            db.commit()
            db.refresh(incident)

            AuditService.record_action(
                db=db,
                action="INCIDENT_CREATED",
                resource_type="incident",
                resource_id=incident.incident_id,
                status="SUCCESS",
                details={"title": incident.title, "severity": incident.severity, "threat_count": len(threat_ids)},
            )

            logger.info(f"Created incident {incident.incident_id} ({incident.title}) with {len(threat_ids)} threats")
            return incident
        except Exception as exc:
            db.rollback()
            logger.error(f"Failed to create incident: {exc}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to create incident transactionally: {str(exc)}",
            )

    @staticmethod
    def get_incident(db: Session, incident_id: str) -> Optional[Incident]:
        return db.query(Incident).filter(Incident.incident_id == incident_id, Incident.is_deleted == False).first()

    @staticmethod
    def list_incidents(
        db: Session,
        skip: int = 0,
        limit: int = 50,
        status_filter: Optional[str] = None,
    ) -> List[Incident]:
        query = db.query(Incident).filter(Incident.is_deleted == False)
        if status_filter:
            query = query.filter(Incident.status == status_filter.upper())
        return query.order_by(Incident.opened_at.desc()).offset(skip).limit(limit).all()

    @staticmethod
    def update_incident(
        db: Session,
        incident_id: str,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        description: Optional[str] = None,
    ) -> Incident:
        incident = ThreatService.get_incident(db, incident_id)
        if not incident:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident '{incident_id}' not found")

        valid_statuses = {"OPEN", "INVESTIGATING", "RESOLVED", "CLOSED"}
        if status:
            norm_status = status.strip().upper()
            if norm_status not in valid_statuses:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Invalid status '{status}'. Must be one of {list(valid_statuses)}",
                )
            incident.status = norm_status
            if norm_status in ("RESOLVED", "CLOSED") and not incident.resolved_at:
                incident.resolved_at = utc_now()

        if severity:
            incident.severity = severity.strip().upper()

        if description is not None:
            incident.description = description

        db.commit()
        db.refresh(incident)
        return incident

    # ===============================
    # Evidence-Grounded Risk Reasoning (Step 14)
    # ===============================

    @staticmethod
    def execute_evidence_grounded_risk_reasoning(
        db: Session,
        request: RiskReasoningExecuteRequest,
        current_user_id: Optional[str] = None,
    ) -> RiskReasoningResult:
        """
        Execute evidence-grounded risk reasoning following the chain:
        Observation -> Event -> Context -> Security Policy -> Risk -> Evidence -> Confidence

        Every high-risk result must have explainable inputs.
        Risk scores must NOT be generated from unexplained/random values.

        Evidence references must point to real existing evidence records.
        NEVER create fake evidence IDs, timestamps, camera references or video references.
        """
        from src.utils.identifiers import generate_identifier as _gen_id
        reasoning_id = _gen_id("investigation_id")

        # 1. Validate and retrieve the event (Observation)
        event = db.query(Event).filter(Event.event_id == request.event_id).first()
        if not event:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Event '{request.event_id}' not found for risk reasoning",
            )

        # 2. Retrieve Context (camera, zone)
        camera = db.query(Camera).filter(
            Camera.camera_id == event.camera_id,
            Camera.is_deleted == False,
        ).first() if event.camera_id else None

        zone = db.query(Zone).filter(
            Zone.zone_id == event.zone_id,
            Zone.is_deleted == False,
        ).first() if event.zone_id else None

        # 3. Retrieve Security Policy (Context -> Policy)
        active_policies = db.query(SecurityPolicy).filter(
            SecurityPolicy.is_active == True,
            SecurityPolicy.is_deleted == False,
        ).all() if event.zone_id else []

        if event.zone_id:
            zone_policies = [p for p in active_policies if p.zone_id == event.zone_id]
        else:
            zone_policies = []

        # 4. Retrieve Evidence (Risk -> Evidence -> Confidence)
        collected_evidence: List[Evidence] = []
        if request.include_evidence:
            # Evidence directly linked to event
            if event.evidence_id:
                evd = db.query(Evidence).filter(
                    Evidence.evidence_id == event.evidence_id,
                    Evidence.is_deleted == False,
                ).first()
                if evd:
                    collected_evidence.append(evd)

            # Evidence from same camera in temporal proximity
            if camera:
                time_window_start = event.timestamp
                from datetime import timedelta
                time_window_end = event.timestamp + timedelta(hours=1)
                cam_evidence = db.query(Evidence).filter(
                    Evidence.camera_id == camera.camera_id,
                    Evidence.timestamp_start >= time_window_start,
                    Evidence.timestamp_end <= time_window_end,
                    Evidence.is_deleted == False,
                ).all()
                for evd in cam_evidence:
                    if evd.evidence_id not in [e.evidence_id for e in collected_evidence]:
                        collected_evidence.append(evd)

        # 5. Build Observation
        observation = RiskReasoningObservation(
            observation_id=f"OBS-{reasoning_id}",
            event_id=event.event_id,
            camera_id=event.camera_id,
            timestamp=event.timestamp,
            description=f"{event.event_type} detected with confidence {event.confidence:.2f} on camera {event.camera_id}",
            entity_type="PERSON" if "PERSON" in event.event_type else ("VEHICLE" if "VEHICLE" in event.event_type else None),
            entity_id=event.entity_id,
            confidence=event.confidence,
            source=event.source,
        )

        # 6. Build Context
        time_str = event.timestamp.strftime("%H:%M") if event.timestamp else "unknown"
        try:
            time_hour = event.timestamp.hour
            time_of_day = "after_hours" if (time_hour < 6 or time_hour > 22) else "business_hours"
        except (AttributeError, ValueError):
            time_of_day = "unknown"

        context = RiskReasoningContext(
            zone_id=event.zone_id,
            zone_risk_level=(zone.risk_level if zone else None),
            zone_name=(zone.name if zone else None),
            camera_id=event.camera_id,
            camera_location=(camera.location_description if camera else None),
            time_of_day=time_of_day,
            active_policies=[p.policy_id for p in zone_policies],
            historical_baseline=f"Event type {event.event_type} baseline in zone {event.zone_id or 'unzoned'}",
        )

        # 7. Build Applicable Policies
        policy_results: List[RiskReasoningPolicy] = []
        triggered_policies = []
        for pol in zone_policies:
            triggered = False
            trigger_details = ""

            # Heuristic: check if event type matches policy type
            if pol.policy_type and pol.policy_type.upper() in event.event_type.upper():
                triggered = True
                trigger_details = f"Event type {event.event_type} matches policy type {pol.policy_type}"

            # Check rules if present
            if pol.rules_json and not triggered:
                rules = pol.rules_json if isinstance(pol.rules_json, dict) else {}
                event_types = rules.get("event_types", [])
                if event.event_type in event_types:
                    triggered = True
                    trigger_details = f"Event type {event.event_type} listed in policy rules"

            policy_results.append(RiskReasoningPolicy(
                policy_id=pol.policy_id,
                name=pol.name,
                policy_type=pol.policy_type,
                severity=(pol.severity or "MEDIUM").upper(),
                description=pol.description,
                triggered=triggered,
                trigger_details=trigger_details if triggered else None,
            ))

            if triggered:
                triggered_policies.append(pol)

        # 8. Build Evidence References
        evidence_refs: List[RiskReasoningEvidence] = []
        for evd in collected_evidence:
            relevance = "Direct event evidence" if evd.evidence_id == event.evidence_id else f"Temporal corroboration within {time_window_start if event.timestamp else 'time'} window"
            evidence_refs.append(RiskReasoningEvidence(
                evidence_id=evd.evidence_id,
                camera_id=evd.camera_id,
                timestamp_start=evd.timestamp_start,
                timestamp_end=evd.timestamp_end,
                verification_status=evd.verification_status,
                confidence=evd.confidence,
                source_type=evd.source_type,
                relevance=relevance,
            ))

        # 9. Calculate Risk Score (using existing RiskEngine for explainability)
        risk_eval = RiskEngine.evaluate(
            event=event,
            zone=zone,
            camera=camera,
            policies=zone_policies,
        )

        # 10. Determine Risk Level
        if risk_eval.risk_score >= 85:
            risk_level = "CRITICAL"
        elif risk_eval.risk_score >= 75:
            risk_level = "HIGH"
        elif risk_eval.risk_score >= 50:
            risk_level = "MEDIUM"
        elif risk_eval.risk_score >= 25:
            risk_level = "LOW"
        else:
            risk_level = "UNKNOWN"

        # 11. Calculate Confidence from evidence and detection
        if evidence_refs:
            evidence_confidences = [e.confidence for e in evidence_refs if e.confidence > 0]
            evidence_verification = [e.verification_status for e in evidence_refs]
            avg_evidence_confidence = sum(evidence_confidences) / len(evidence_confidences) if evidence_confidences else 0.0
            verified_count = sum(1 for s in evidence_verification if s == "VERIFIED")
            evidence_confidence_factor = verified_count / len(evidence_refs) if evidence_refs else 0.0
            # Blend detection confidence and evidence confidence
            confidence = (event.confidence * 0.3) + (avg_evidence_confidence * 0.4) + (evidence_confidence_factor * 0.3)
            confidence = min(confidence, 1.0)
        else:
            confidence = event.confidence

        # 12. Determine verification status
        if evidence_refs and all(e.verification_status == "VERIFIED" for e in evidence_refs):
            evidence_verification_status = "VERIFIED"
        elif evidence_refs and any(e.verification_status == "VERIFIED" for e in evidence_refs):
            evidence_verification_status = "PARTIAL"
        elif evidence_refs:
            evidence_verification_status = "UNVERIFIED"
        else:
            evidence_verification_status = "NO_EVIDENCE"

        # 13. Build reasoning
        reasons_text = "; ".join(risk_eval.reasons) if risk_eval.reasons else "No specific risks identified"
        reasoning_parts = [
            f"OBSERVATION: {observation.description}",
            f"CONTEXT: Zone '{context.zone_name}' (risk level: {context.zone_risk_level or 'unknown'}), camera location: {context.camera_location or 'unknown'}, time: {context.time_of_day}",
            f"POLICIES: {len(zone_policies)} active policy/policies in zone, {len(triggered_policies)} triggered",
            f"EVIDENCE: {len(evidence_refs)} evidence item(s) referenced, verification status: {evidence_verification_status}",
            f"RISK EVALUATION: Risk score {risk_eval.risk_score:.1f}/100, severity {risk_eval.severity}",
            f"CONFIDENCE: {confidence:.2f} (blended from detection confidence and evidence verification)",
            f"FACTORS: {reasons_text}",
        ]
        reasoning = "\n".join(reasoning_parts)

        # 14. Determine recommended actions
        recommended_actions = []
        if risk_eval.is_threat:
            recommended_actions.append("Escalate to security team for immediate review")
        if evidence_verification_status in ("UNVERIFIED", "PARTIAL"):
            recommended_actions.append("Collect and verify additional evidence from related cameras")
        if risk_level in ("CRITICAL", "HIGH"):
            recommended_actions.append("Initiate incident response protocol")
        if not evidence_refs:
            recommended_actions.append("No evidence found - request manual review of footage")
        if not recommended_actions:
            recommended_actions.append("Continue monitoring, no immediate action required")

        # 15. Determine escalation
        escalation_warranted = risk_eval.is_threat or risk_level in ("CRITICAL", "HIGH")

        # 16. Check for existing threat on this event
        existing_threat = db.query(Threat).filter(
            Threat.event_id == event.event_id,
            Threat.is_deleted == False,
        ).first()

        result = RiskReasoningResult(
            reasoning_id=reasoning_id,
            event_id=event.event_id,
            threat_id=existing_threat.threat_id if existing_threat else None,
            incident_id=(existing_threat.incident_id if existing_threat and existing_threat.incident_id else None),
            executed_at=utc_now(),
            executed_by=current_user_id or "RISK_REASONING_ENGINE",
            observation=observation,
            context=context,
            applicable_policies=policy_results,
            evidence_references=evidence_refs,
            risk_score=risk_eval.risk_score,
            risk_level=risk_level,
            confidence=round(confidence, 2),
            reasoning=reasoning,
            evidence_verification_status=evidence_verification_status,
            verification_notes=f"Reviewed {len(evidence_refs)} evidence item(s) for event {event.event_id}",
            recommended_actions=recommended_actions,
            escalation_warranted=escalation_warranted,
            schema_version="1.0",
        )

        AuditService.record_action(
            db=db,
            action="RISK_REASONING_EXECUTED",
            resource_type="threat",
            resource_id=existing_threat.threat_id if existing_threat else None,
            user_identifier=current_user_id,
            status="SUCCESS",
            details={
                "event_id": event.event_id,
                "risk_score": risk_eval.risk_score,
                "risk_level": risk_level,
                "confidence": round(confidence, 2),
                "evidence_count": len(evidence_refs),
                "verification_status": evidence_verification_status,
                "policy_count": len(zone_policies),
                "triggered_policies": len(triggered_policies),
            },
        )

        logger.info(f"Risk reasoning executed for event {event.event_id}: score={risk_eval.risk_score:.1f}, level={risk_level}, confidence={confidence:.2f}")

        return result
