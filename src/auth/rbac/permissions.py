from enum import Enum
from typing import Dict, List


class SystemRole(str, Enum):
    """Authoritative system roles for Backend Security Core."""
    ADMIN = "ADMIN"
    SECURITY_OPERATOR = "SECURITY_OPERATOR"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    INVESTIGATOR = "INVESTIGATOR"
    AUDITOR = "AUDITOR"
    VIEWER = "VIEWER"


class PermissionCode(str, Enum):
    """Authoritative granular permissions for surveillance and security operations."""
    # Cameras
    CAMERA_READ = "camera.read"
    CAMERA_MANAGE = "camera.manage"

    # Zones
    ZONE_READ = "zone.read"
    ZONE_MANAGE = "zone.manage"

    # Events
    EVENT_READ = "event.read"

    # Threats
    THREAT_READ = "threat.read"
    THREAT_MANAGE = "threat.manage"

    # Incidents
    INCIDENT_READ = "incident.read"
    INCIDENT_MANAGE = "incident.manage"

    # Investigations
    INVESTIGATION_READ = "investigation.read"
    INVESTIGATION_CREATE = "investigation.create"

    # Evidence
    EVIDENCE_READ = "evidence.read"
    EVIDENCE_VERIFY = "evidence.verify"

    # Security Memory
    MEMORY_READ = "memory.read"
    MEMORY_MANAGE = "memory.manage"

    # Audit
    AUDIT_READ = "audit.read"

    # User & Identity Management
    USER_READ = "user.read"
    USER_MANAGE = "user.manage"

    # Role & Permission Management
    ROLE_READ = "role.read"
    ROLE_MANAGE = "role.manage"


# Baseline role-permission mappings as specified by Module 2 Security Core specification
ROLE_PERMISSIONS_MAPPING: Dict[str, List[str]] = {
    SystemRole.ADMIN.value: [
        PermissionCode.CAMERA_READ.value,
        PermissionCode.CAMERA_MANAGE.value,
        PermissionCode.ZONE_READ.value,
        PermissionCode.ZONE_MANAGE.value,
        PermissionCode.EVENT_READ.value,
        PermissionCode.THREAT_READ.value,
        PermissionCode.THREAT_MANAGE.value,
        PermissionCode.INCIDENT_READ.value,
        PermissionCode.INCIDENT_MANAGE.value,
        PermissionCode.INVESTIGATION_READ.value,
        PermissionCode.INVESTIGATION_CREATE.value,
        PermissionCode.EVIDENCE_READ.value,
        PermissionCode.EVIDENCE_VERIFY.value,
        PermissionCode.MEMORY_READ.value,
        PermissionCode.MEMORY_MANAGE.value,
        PermissionCode.AUDIT_READ.value,
        PermissionCode.USER_READ.value,
        PermissionCode.USER_MANAGE.value,
        PermissionCode.ROLE_READ.value,
        PermissionCode.ROLE_MANAGE.value,
    ],
    SystemRole.SECURITY_OPERATOR.value: [
        PermissionCode.CAMERA_READ.value,
        PermissionCode.EVENT_READ.value,
        PermissionCode.THREAT_READ.value,
        PermissionCode.THREAT_MANAGE.value,
        PermissionCode.INCIDENT_READ.value,
        PermissionCode.INCIDENT_MANAGE.value,
        PermissionCode.INVESTIGATION_READ.value,
        PermissionCode.INVESTIGATION_CREATE.value,
        PermissionCode.EVIDENCE_READ.value,
        PermissionCode.EVIDENCE_VERIFY.value,
        PermissionCode.MEMORY_READ.value,
    ],
    SystemRole.SECURITY_ANALYST.value: [
        PermissionCode.EVENT_READ.value,
        PermissionCode.THREAT_READ.value,
        PermissionCode.INCIDENT_READ.value,
        PermissionCode.INVESTIGATION_READ.value,
        PermissionCode.INVESTIGATION_CREATE.value,
        PermissionCode.EVIDENCE_READ.value,
        PermissionCode.MEMORY_READ.value,
    ],
    SystemRole.INVESTIGATOR.value: [
        PermissionCode.EVENT_READ.value,
        PermissionCode.THREAT_READ.value,
        PermissionCode.INCIDENT_READ.value,
        PermissionCode.INVESTIGATION_READ.value,
        PermissionCode.INVESTIGATION_CREATE.value,
        PermissionCode.EVIDENCE_READ.value,
        PermissionCode.EVIDENCE_VERIFY.value,
        PermissionCode.MEMORY_READ.value,
    ],
    SystemRole.AUDITOR.value: [
        PermissionCode.AUDIT_READ.value,
        PermissionCode.EVIDENCE_READ.value,
        PermissionCode.INVESTIGATION_READ.value,
        PermissionCode.EVENT_READ.value,
        PermissionCode.THREAT_READ.value,
        PermissionCode.INCIDENT_READ.value,
    ],
    SystemRole.VIEWER.value: [
        PermissionCode.CAMERA_READ.value,
        PermissionCode.EVENT_READ.value,
        PermissionCode.THREAT_READ.value,
        PermissionCode.INCIDENT_READ.value,
        PermissionCode.INVESTIGATION_READ.value,
        PermissionCode.EVIDENCE_READ.value,
        PermissionCode.MEMORY_READ.value,
    ],
}

# Role descriptions for seeding
ROLE_DESCRIPTIONS: Dict[str, str] = {
    SystemRole.ADMIN.value: "Full administrative control over backend security core, users, roles, and policies",
    SystemRole.SECURITY_OPERATOR.value: "Surveillance monitoring, camera review, threat and incident operations",
    SystemRole.SECURITY_ANALYST.value: "Triage security events, analyze incident patterns, and author investigations",
    SystemRole.INVESTIGATOR.value: "Forensic evidence verification, comprehensive incident investigations",
    SystemRole.AUDITOR.value: "Compliance inspection, audit logs, and evidence verification review",
    SystemRole.VIEWER.value: "Read-only surveillance view of cameras, events, and evidence",
}

# Permission display names & descriptions for seeding
PERMISSION_METADATA: Dict[str, Dict[str, str]] = {
    PermissionCode.CAMERA_READ.value: {"name": "Read Cameras", "description": "View camera details, stream links, and statuses"},
    PermissionCode.CAMERA_MANAGE.value: {"name": "Manage Cameras", "description": "Register, configure, update, or remove cameras"},
    PermissionCode.ZONE_READ.value: {"name": "Read Zones", "description": "View perimeter and interior security zones"},
    PermissionCode.ZONE_MANAGE.value: {"name": "Manage Zones", "description": "Create, configure, and reassign camera zones"},
    PermissionCode.EVENT_READ.value: {"name": "Read Events", "description": "Access surveillance motion and detection events"},
    PermissionCode.THREAT_READ.value: {"name": "Read Threats", "description": "Inspect detected potential threats and alarms"},
    PermissionCode.THREAT_MANAGE.value: {"name": "Manage Threats", "description": "Acknowledge, escalate, and resolve threats"},
    PermissionCode.INCIDENT_READ.value: {"name": "Read Incidents", "description": "View security incidents and dossiers"},
    PermissionCode.INCIDENT_MANAGE.value: {"name": "Manage Incidents", "description": "Open, update severity, and close security incidents"},
    PermissionCode.INVESTIGATION_READ.value: {"name": "Read Investigations", "description": "Inspect investigation cases and timelines"},
    PermissionCode.INVESTIGATION_CREATE.value: {"name": "Create Investigations", "description": "Initiate forensic security investigations"},
    PermissionCode.EVIDENCE_READ.value: {"name": "Read Evidence", "description": "View evidentiary video clips and snapshots"},
    PermissionCode.EVIDENCE_VERIFY.value: {"name": "Verify Evidence", "description": "Cryptographically verify and sign forensic evidence"},
    PermissionCode.MEMORY_READ.value: {"name": "Read Security Memory", "description": "Query behavioral baselines and known entities"},
    PermissionCode.MEMORY_MANAGE.value: {"name": "Manage Security Memory", "description": "Update security baselines and memory profiles"},
    PermissionCode.AUDIT_READ.value: {"name": "Read Audit Logs", "description": "Inspect immutable system audit log records"},
    PermissionCode.USER_READ.value: {"name": "Read Users", "description": "View system operators and user accounts"},
    PermissionCode.USER_MANAGE.value: {"name": "Manage Users", "description": "Create, update, suspend, and configure users"},
    PermissionCode.ROLE_READ.value: {"name": "Read Roles", "description": "View roles and assigned permission matrices"},
    PermissionCode.ROLE_MANAGE.value: {"name": "Manage Roles", "description": "Create custom roles and alter permission sets"},
}


def get_permissions_for_role(role_name: str) -> List[str]:
    """Retrieve list of permission codes mapped to a given role name (case-insensitive)."""
    normalized = role_name.strip().upper()
    return ROLE_PERMISSIONS_MAPPING.get(normalized, [])
