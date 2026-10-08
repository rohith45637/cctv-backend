from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Table, Index
from sqlalchemy.orm import relationship, synonym
from src.database.session import Base
from src.database.models.base import TimestampMixin, SoftDeleteMixin, utc_now

# Association table: user_roles
user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", Integer, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
)

# Association table: role_permissions
role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column("role_id", Integer, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
    Column("permission_id", Integer, ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True),
)


class User(Base, TimestampMixin, SoftDeleteMixin):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String(64), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    display_name = Column(String(255), nullable=True)
    status = Column(String(32), default="ACTIVE", nullable=False, index=True)
    is_active = Column(Boolean, default=True, nullable=False)
    is_demo = Column(Boolean, default=False, nullable=False)
    last_login_at = Column(DateTime(timezone=True), nullable=True)

    # Synonym for password_hash
    password_hash = synonym("hashed_password")

    # Relational mappings
    roles = relationship("Role", secondary=user_roles, back_populates="users", lazy="joined")
    audit_logs = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")
    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")

    @property
    def effective_display_name(self) -> str:
        return self.display_name or self.full_name or self.username

    @property
    def permission_codes(self) -> set:
        """Aggregated set of permission code strings from all roles."""
        perms = set()
        for role in self.roles:
            for p in role.permissions:
                perms.add(p.code)
        return perms

    @property
    def role_names(self) -> set:
        """Set of assigned role names in uppercase."""
        return {r.name.upper() for r in self.roles}

    def has_permission(self, permission_code: str) -> bool:
        """Check if user holds the specified permission code."""
        # Admins hold all permissions implicitly or explicitly
        if "ADMIN" in self.role_names or "admin" in {r.name for r in self.roles}:
            return True
        return permission_code in self.permission_codes

    def has_role(self, role_name: str) -> bool:
        """Check if user has a specific role."""
        return role_name.upper() in self.role_names


class Role(Base, TimestampMixin):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(64), unique=True, index=True, nullable=False)
    description = Column(String(255), nullable=True)
    is_system_role = Column(Boolean, default=False, nullable=False)

    users = relationship("User", secondary=user_roles, back_populates="roles")
    permissions = relationship("Permission", secondary=role_permissions, back_populates="roles", lazy="joined")


class Permission(Base):
    __tablename__ = "permissions"

    id = Column(Integer, primary_key=True, index=True)
    code = Column(String(100), unique=True, index=True, nullable=False)
    name = Column(String(100), nullable=False)
    description = Column(String(255), nullable=True)

    roles = relationship("Role", secondary=role_permissions, back_populates="permissions")


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String(500), unique=True, index=True, nullable=False)
    jti = Column(String(64), unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    is_revoked = Column(Boolean, default=False, nullable=False, index=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    user = relationship("User", back_populates="refresh_tokens")

    __table_args__ = (
        Index("ix_refresh_tokens_user_revoked", "user_id", "is_revoked"),
    )
