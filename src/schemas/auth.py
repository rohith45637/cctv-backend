from datetime import datetime
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field, EmailStr, ConfigDict


class UserStatus(str, Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    SUSPENDED = "SUSPENDED"


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=255, description="Username or email address")
    password: str = Field(..., min_length=1, max_length=128, description="User password")


class RefreshTokenRequest(BaseModel):
    refresh_token: str = Field(..., min_length=10, description="Valid JWT refresh token")


class LogoutRequest(BaseModel):
    refresh_token: Optional[str] = Field(None, description="Optional refresh token to revoke")


class PermissionOut(BaseModel):
    id: Optional[int] = None
    code: str
    name: str
    description: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class RoleOut(BaseModel):
    id: Optional[int] = None
    name: str
    description: Optional[str] = None
    permissions: List[str] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class UserOut(BaseModel):
    user_id: str = Field(..., description="Unique alphanumeric user identifier")
    username: str = Field(..., description="Unique username")
    email: str = Field(..., description="User email address")
    display_name: Optional[str] = Field(None, description="Preferred public display name")
    full_name: Optional[str] = Field(None, description="Full real name")
    status: str = Field(default="ACTIVE", description="Account status: ACTIVE, INACTIVE, SUSPENDED")
    is_active: bool = Field(default=True, description="Account active flag")
    roles: List[str] = Field(default_factory=list, description="Assigned role names")
    permissions: List[str] = Field(default_factory=list, description="Aggregated effective permissions")
    created_at: datetime
    updated_at: datetime
    last_login_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    access_token: str = Field(..., description="JWT Bearer access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(default="bearer", description="Token authentication scheme")
    expires_in: int = Field(..., description="Access token lifetime in seconds")
    user: UserOut = Field(..., description="Authenticated user safe profile")


class TokenRefreshResponse(BaseModel):
    access_token: str = Field(..., description="New JWT Bearer access token")
    refresh_token: str = Field(..., description="Current or rotated refresh token")
    token_type: str = Field(default="bearer", description="Token authentication scheme")
    expires_in: int = Field(..., description="Access token lifetime in seconds")


class LogoutResponse(BaseModel):
    message: str = Field(default="Successfully logged out")
