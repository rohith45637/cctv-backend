from dataclasses import dataclass
from typing import List, Optional
from src.database.models import Camera, Event, SecurityPolicy, Zone


@dataclass
class RiskEvaluationResult:
    risk_score: float
    severity: str  # HIGH, MEDIUM, LOW, UNKNOWN, INSUFFICIENT_EVIDENCE
    reasons: List[str]
    is_threat: bool


class RiskEngine:
    """
    Transparent, explainable risk evaluation engine.
    Computes risk based on: OBSERVATION + CONTEXT + POLICY + EVIDENCE.
    Never fabricates mathematical certainty or produces unexplained scores.
    """

    @staticmethod
    def evaluate(
        event: Event,
        zone: Optional[Zone] = None,
        camera: Optional[Camera] = None,
        policies: Optional[List[SecurityPolicy]] = None,
    ) -> RiskEvaluationResult:
        reasons: List[str] = []

        # 1. Observation Validation
        confidence = float(event.confidence or 0.0)
        if confidence < 0.4:
            return RiskEvaluationResult(
                risk_score=0.0,
                severity="UNKNOWN",
                reasons=["Insufficient detection confidence (< 40%) - threat unverified"],
                is_threat=False,
            )

        # 2. Raw benign detection check (Do not create threats from raw detection alone)
        raw_benign_types = {"OBJECT_DETECTED", "BLINDSPOT_DETECTED", "CAMERA_STATUS_CHANGED"}
        matching_policies = policies or []
        if event.event_type in raw_benign_types and not matching_policies:
            return RiskEvaluationResult(
                risk_score=15.0,
                severity="LOW",
                reasons=[f"Routine {event.event_type} without active policy violation or restricted context"],
                is_threat=False,
            )

        score = 0.0

        # Event type base weight
        event_type = event.event_type.upper()
        if event_type in ("INTRUSION", "TAILGATING"):
            score += 35.0
            reasons.append(f"High-risk perimeter event type: {event_type}")
        elif event_type in ("SUSPICIOUS_ACTIVITY", "LOITERING"):
            score += 25.0
            reasons.append(f"Suspicious activity event type: {event_type}")
        elif event_type in ("ZONE_ENTRY", "LINE_CROSSING"):
            score += 20.0
            reasons.append(f"Zone boundary crossing detected: {event_type}")
        elif event_type in ("PERSON_DETECTED", "VEHICLE_DETECTED"):
            score += 15.0
            reasons.append(f"Entity presence detected: {event_type}")
        else:
            score += 10.0
            reasons.append(f"Observational event: {event_type}")

        # Zone Context
        if zone:
            zone_risk = (zone.risk_level or "MEDIUM").upper()
            if zone_risk == "CRITICAL":
                score += 30.0
                reasons.append(f"Restricted critical zone: '{zone.name}'")
            elif zone_risk == "HIGH":
                score += 20.0
                reasons.append(f"High-security zone boundary: '{zone.name}'")
            elif zone_risk == "MEDIUM":
                score += 10.0
                reasons.append(f"Standard interior zone: '{zone.name}'")
            else:
                reasons.append(f"Low-risk zone: '{zone.name}'")
        else:
            reasons.append("Unzoned location context")

        # Policy Breaches
        if matching_policies:
            for pol in matching_policies:
                pol_sev = (pol.severity or "MEDIUM").upper()
                if pol_sev == "CRITICAL":
                    score += 25.0
                    reasons.append(f"Triggered CRITICAL security policy: '{pol.name}'")
                elif pol_sev == "HIGH":
                    score += 15.0
                    reasons.append(f"Triggered HIGH security policy: '{pol.name}'")
                else:
                    score += 10.0
                    reasons.append(f"Triggered security policy: '{pol.name}'")

        # Evidence Context
        if event.evidence_id:
            score += 10.0
            reasons.append(f"Forensic evidence artifact linked: {event.evidence_id}")
        else:
            # If a critical policy was breached but evidence is missing
            if any(p.severity == "CRITICAL" for p in matching_policies):
                reasons.append("INSUFFICIENT_EVIDENCE: Required video clip evidence not yet attached")

        # Detection Confidence factor
        if confidence >= 0.85:
            score += 10.0
            reasons.append(f"High AI detection confidence ({int(confidence * 100)}%)")
        elif confidence >= 0.60:
            reasons.append(f"Moderate AI detection confidence ({int(confidence * 100)}%)")

        # Normalize score
        final_score = min(max(score, 0.0), 100.0)

        # Severity Classification
        if final_score >= 75.0:
            severity = "HIGH"
        elif final_score >= 50.0:
            severity = "MEDIUM"
        elif final_score >= 25.0:
            severity = "LOW"
        else:
            severity = "UNKNOWN"

        is_threat = (final_score >= 50.0) or (severity == "HIGH")

        return RiskEvaluationResult(
            risk_score=round(final_score, 1),
            severity=severity,
            reasons=reasons,
            is_threat=is_threat,
        )
