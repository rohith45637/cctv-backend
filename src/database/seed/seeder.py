import logging
from sqlalchemy.orm import Session
from src.database.models import (
    User,
    Role,
    Permission,
    Camera,
    CameraStatusHistory,
    Zone,
    ZoneCameraMapping,
    SecurityPolicy,
    SystemSetting,
)
from src.auth.rbac.permissions import (
    SystemRole,
    PermissionCode,
    ROLE_PERMISSIONS_MAPPING,
    ROLE_DESCRIPTIONS,
    PERMISSION_METADATA,
)
from src.auth.security import hash_password

logger = logging.getLogger("backend.seed")

# Deterministic demo password for development & test environments
DEMO_PASSWORD_DEFAULT = "AdminSecure!2026"


def seed_database(db: Session, force: bool = False) -> None:
    """
    Idempotent database seeder.
    Provides verified demo foundation clearly labeled with is_demo=True.
    Seeds granular permissions, authoritative roles, role-permission links,
    and demo security staff accounts.
    """
    logger.info("Checking database seed status...")

    # 1. Seed Permissions
    created_permissions = {}
    for perm_enum in PermissionCode:
        code_val = perm_enum.value
        meta = PERMISSION_METADATA.get(code_val, {"name": code_val, "description": code_val})
        perm = db.query(Permission).filter(Permission.code == code_val).first()
        if not perm:
            perm = Permission(
                code=code_val,
                name=meta["name"],
                description=meta["description"],
            )
            db.add(perm)
            db.flush()
        created_permissions[code_val] = perm

    # 2. Seed Roles and map permissions
    created_roles = {}
    for role_enum in SystemRole:
        role_name = role_enum.value
        desc = ROLE_DESCRIPTIONS.get(role_name, f"{role_name} security role")
        role = db.query(Role).filter(Role.name == role_name).first()
        if not role:
            role = Role(name=role_name, description=desc, is_system_role=True)
            db.add(role)
            db.flush()
        
        # Link permissions to role
        target_perm_codes = ROLE_PERMISSIONS_MAPPING.get(role_name, [])
        current_perm_codes = {p.code for p in role.permissions}
        for p_code in target_perm_codes:
            if p_code in created_permissions and p_code not in current_perm_codes:
                role.permissions.append(created_permissions[p_code])
        db.flush()
        created_roles[role_name] = role

    # Also ensure legacy lowercase role names exist for backward compatibility
    legacy_aliases = {
        "admin": SystemRole.ADMIN.value,
        "analyst": SystemRole.SECURITY_ANALYST.value,
        "operator": SystemRole.SECURITY_OPERATOR.value,
        "viewer": SystemRole.VIEWER.value,
    }
    for leg_name, target_role_name in legacy_aliases.items():
        leg_role = db.query(Role).filter(Role.name == leg_name).first()
        if not leg_role:
            leg_role = Role(
                name=leg_name,
                description=f"Legacy alias for {target_role_name}",
                is_system_role=True,
            )
            db.add(leg_role)
            db.flush()
            # Copy target permissions
            for p_code in ROLE_PERMISSIONS_MAPPING.get(target_role_name, []):
                if p_code in created_permissions and p_code not in {p.code for p in leg_role.permissions}:
                    leg_role.permissions.append(created_permissions[p_code])
            db.flush()
        created_roles[leg_name] = leg_role

    # 3. Seed Demo Users (Explicitly flagged as demo, with bcrypt hashed passwords)
    demo_password_hash = hash_password(DEMO_PASSWORD_DEFAULT)
    demo_users = [
        {
            "user_id": "USR-ADMIN01",
            "username": "admin",
            "email": "admin@security-core.internal",
            "hashed_password": demo_password_hash,
            "full_name": "[DEMO] Lead Security Administrator",
            "display_name": "Lead Admin",
            "status": "ACTIVE",
            "is_active": True,
            "is_demo": True,
            "roles": ["ADMIN", "admin"],
        },
        {
            "user_id": "USR-OPERATOR01",
            "username": "operator",
            "email": "operator@security-core.internal",
            "hashed_password": demo_password_hash,
            "full_name": "[DEMO] Central Security Operator",
            "display_name": "Security Operator",
            "status": "ACTIVE",
            "is_active": True,
            "is_demo": True,
            "roles": ["SECURITY_OPERATOR", "operator"],
        },
        {
            "user_id": "USR-ANALYST01",
            "username": "analyst",
            "email": "analyst@security-core.internal",
            "hashed_password": demo_password_hash,
            "full_name": "[DEMO] Senior Security Analyst",
            "display_name": "Security Analyst",
            "status": "ACTIVE",
            "is_active": True,
            "is_demo": True,
            "roles": ["SECURITY_ANALYST", "analyst"],
        },
        {
            "user_id": "USR-INVESTIGATOR01",
            "username": "investigator",
            "email": "investigator@security-core.internal",
            "hashed_password": demo_password_hash,
            "full_name": "[DEMO] Lead Forensic Investigator",
            "display_name": "Forensic Investigator",
            "status": "ACTIVE",
            "is_active": True,
            "is_demo": True,
            "roles": ["INVESTIGATOR"],
        },
        {
            "user_id": "USR-AUDITOR01",
            "username": "auditor",
            "email": "auditor@security-core.internal",
            "hashed_password": demo_password_hash,
            "full_name": "[DEMO] Compliance Auditor",
            "display_name": "Compliance Auditor",
            "status": "ACTIVE",
            "is_active": True,
            "is_demo": True,
            "roles": ["AUDITOR"],
        },
        {
            "user_id": "USR-VIEWER01",
            "username": "viewer",
            "email": "viewer@security-core.internal",
            "hashed_password": demo_password_hash,
            "full_name": "[DEMO] Read-Only Viewer",
            "display_name": "Read-Only Viewer",
            "status": "ACTIVE",
            "is_active": True,
            "is_demo": True,
            "roles": ["VIEWER", "viewer"],
        },
    ]

    for u_data in demo_users:
        roles_to_assign = u_data.pop("roles")
        user = db.query(User).filter(User.user_id == u_data["user_id"]).first()
        if not user:
            user = User(**u_data)
            for r_name in roles_to_assign:
                if r_name in created_roles:
                    user.roles.append(created_roles[r_name])
            db.add(user)
        else:
            # Update password hash and display name to ensure valid login
            user.hashed_password = demo_password_hash
            if not user.display_name:
                user.display_name = u_data.get("display_name")
            current_user_roles = {r.name for r in user.roles}
            for r_name in roles_to_assign:
                if r_name in created_roles and r_name not in current_user_roles:
                    user.roles.append(created_roles[r_name])
    db.flush()

    # 4. Seed Demo Cameras
    demo_cameras = [
        {
            "camera_id": "CAM-01",
            "name": "[DEMO] CAM-01 Main Gate",
            "stream_url": "rtsp://demo-mock.internal:8554/cam-01",
            "ip_address": "192.168.10.101",
            "location_description": "Perimeter checkpoint - Main Vehicle & Pedestrian Entrance",
            "status": "ONLINE",
            "is_active": True,
            "is_demo": True,
            "schema_version": "1.0",
            "metadata_json": {"fps": 30, "resolution": "1920x1080", "fov": "95deg"},
        },
        {
            "camera_id": "CAM-02",
            "name": "[DEMO] CAM-02 North Corridor",
            "stream_url": "rtsp://demo-mock.internal:8554/cam-02",
            "ip_address": "192.168.10.102",
            "location_description": "Internal Sector B - Ground Floor North Hallway",
            "status": "ONLINE",
            "is_active": True,
            "is_demo": True,
            "schema_version": "1.0",
            "metadata_json": {"fps": 25, "resolution": "1920x1080", "fov": "85deg"},
        },
        {
            "camera_id": "CAM-03",
            "name": "[DEMO] CAM-03 Warehouse",
            "stream_url": "rtsp://demo-mock.internal:8554/cam-03",
            "ip_address": "192.168.10.103",
            "location_description": "High Value Storage & Loading Bay A",
            "status": "ONLINE",
            "is_active": True,
            "is_demo": True,
            "schema_version": "1.0",
            "metadata_json": {"fps": 30, "resolution": "2560x1440", "fov": "110deg"},
        },
    ]
    for c_data in demo_cameras:
        cam = db.query(Camera).filter(Camera.camera_id == c_data["camera_id"]).first()
        if not cam:
            cam = Camera(**c_data)
            db.add(cam)
            # Add initial status record
            status_entry = CameraStatusHistory(
                camera_id=c_data["camera_id"],
                status="ONLINE",
                reason="Initial seed synchronization",
            )
            db.add(status_entry)

    # 5. Seed Demo Zones
    demo_zones = [
        {
            "zone_id": "ZONE-01",
            "name": "[DEMO] Perimeter - Main Gate",
            "description": "Outer perimeter barrier, security barrier gate, and badge reader zone",
            "risk_level": "HIGH",
            "is_active": True,
            "is_demo": True,
            "schema_version": "1.0",
            "camera_id": "CAM-01",
        },
        {
            "zone_id": "ZONE-02",
            "name": "[DEMO] Internal - North Corridor",
            "description": "Circulation corridor between office wings and server rooms",
            "risk_level": "MEDIUM",
            "is_active": True,
            "is_demo": True,
            "schema_version": "1.0",
            "camera_id": "CAM-02",
        },
        {
            "zone_id": "ZONE-03",
            "name": "[DEMO] Logistics - Warehouse Bay",
            "description": "Secure storage bay for logistics, inventory, and loading dock",
            "risk_level": "HIGH",
            "is_active": True,
            "is_demo": True,
            "schema_version": "1.0",
            "camera_id": "CAM-03",
        },
    ]
    for z_data in demo_zones:
        target_cam_id = z_data.pop("camera_id")
        zone = db.query(Zone).filter(Zone.zone_id == z_data["zone_id"]).first()
        if not zone:
            zone = Zone(**z_data)
            db.add(zone)
            db.flush()
            # Map zone to primary camera
            mapping = ZoneCameraMapping(
                zone_id=zone.zone_id,
                camera_id=target_cam_id,
                primary_camera=True,
            )
            db.add(mapping)

    # 6. Seed Baseline Security Policies
    demo_policies = [
        {
            "policy_id": "POL-01",
            "name": "[DEMO] Perimeter Intrusion Detection",
            "description": "Trigger alert if person or vehicle crosses perimeter fence line outside gate opening hours",
            "zone_id": "ZONE-01",
            "policy_type": "INTRUSION",
            "severity": "CRITICAL",
            "rules_json": {"after_hours_only": True, "cooldown_seconds": 60, "min_confidence": 0.8},
            "is_active": True,
            "is_demo": True,
            "schema_version": "1.0",
        },
        {
            "policy_id": "POL-02",
            "name": "[DEMO] Corridor Loitering Policy",
            "description": "Detect stationary presence exceeding 180 seconds in restricted corridor",
            "zone_id": "ZONE-02",
            "policy_type": "LOITERING",
            "severity": "MEDIUM",
            "rules_json": {"max_dwell_seconds": 180, "target_entity": "PERSON"},
            "is_active": True,
            "is_demo": True,
            "schema_version": "1.0",
        },
        {
            "policy_id": "POL-03",
            "name": "[DEMO] Warehouse Tailgating Policy",
            "description": "Detect multiple individuals entering secure bay on single badge scan",
            "zone_id": "ZONE-03",
            "policy_type": "TAILGATING",
            "severity": "HIGH",
            "rules_json": {"distance_threshold_meters": 1.5, "badge_window_seconds": 5},
            "is_active": True,
            "is_demo": True,
            "schema_version": "1.0",
        },
    ]
    for p_data in demo_policies:
        pol = db.query(SecurityPolicy).filter(SecurityPolicy.policy_id == p_data["policy_id"]).first()
        if not pol:
            pol = SecurityPolicy(**p_data)
            db.add(pol)

    # 7. Seed System Settings
    settings_data = [
        {"key": "retention_days", "value": "30", "description": "Storage retention duration for metadata in days"},
        {"key": "default_confidence_threshold", "value": "0.75", "description": "Minimum AI confidence threshold"},
        {"key": "alert_sound_enabled", "value": "true", "description": "Audible alert playback on critical threats"},
    ]
    for s_data in settings_data:
        setting = db.query(SystemSetting).filter(SystemSetting.key == s_data["key"]).first()
        if not setting:
            setting = SystemSetting(**s_data)
            db.add(setting)

    db.commit()
    logger.info("Database seeding completed successfully.")
