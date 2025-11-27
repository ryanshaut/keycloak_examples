"""
Pydantic models for Keycloak API responses and requests.

These models provide type safety and automatic validation for data
exchanged with the Keycloak API.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, ConfigDict


class BaseKeycloakModel(BaseModel):
    """Base model for all Keycloak API models."""
    
    model_config = ConfigDict(
        # Allow extra fields that Keycloak might return
        extra='allow',
        # Use enum values instead of enum objects
        use_enum_values=True,
        # Populate by name (allows both snake_case and camelCase)
        populate_by_name=True,
    )


# =========================================================================
# Token-related Models
# =========================================================================

class TokenResponse(BaseKeycloakModel):
    """
    Response from Keycloak token endpoints.
    
    This model represents the standard OAuth2/OpenID Connect token response
    from endpoints like /protocol/openid-connect/token.
    """
    
    access_token: str = Field(
        description="The access token for API calls"
    )
    
    token_type: str = Field(
        default="Bearer",
        description="The type of token (usually 'Bearer')"
    )
    
    expires_in: Optional[int] = Field(
        default=None,
        description="Access token lifetime in seconds"
    )
    
    refresh_token: Optional[str] = Field(
        default=None,
        description="Refresh token for obtaining new access tokens"
    )
    
    refresh_expires_in: Optional[int] = Field(
        default=None,
        description="Refresh token lifetime in seconds"
    )
    
    id_token: Optional[str] = Field(
        default=None,
        description="OpenID Connect ID token (JWT)"
    )
    
    scope: Optional[str] = Field(
        default=None,
        description="Granted scopes (space-separated string)"
    )
    
    session_state: Optional[str] = Field(
        default=None,
        description="Keycloak session state for logout"
    )
    
    not_before_policy: Optional[int] = Field(
        default=None,
        alias="not-before-policy",
        description="Not-before policy timestamp"
    )
    
    @property
    def scopes_list(self) -> List[str]:
        """Convert scope string to list of individual scopes."""
        if not self.scope:
            return []
        return self.scope.split()
    
    @property
    def is_expired(self) -> bool:
        """
        Check if the access token is likely expired.
        
        Note: This is a rough estimate since we don't track when 
        the token was issued. For accurate expiration checking,
        use token introspection.
        """
        if not self.expires_in:
            return False
        # This is a simplified check - in practice you'd want to
        # store the issued_at timestamp
        return False  # Placeholder - implement with actual timing logic


class TokenIntrospectionResponse(BaseKeycloakModel):
    """
    Response from Keycloak token introspection endpoint.
    
    Based on RFC 7662 - OAuth 2.0 Token Introspection.
    """
    
    active: bool = Field(
        description="Whether the token is active and valid"
    )
    
    scope: Optional[str] = Field(
        default=None,
        description="Space-separated list of scopes"
    )
    
    client_id: Optional[str] = Field(
        default=None,
        description="Client identifier for the token"
    )
    
    username: Optional[str] = Field(
        default=None,
        description="Username of the token owner"
    )
    
    token_type: Optional[str] = Field(
        default=None,
        description="Type of the token"
    )
    
    exp: Optional[int] = Field(
        default=None,
        description="Token expiration timestamp"
    )
    
    iat: Optional[int] = Field(
        default=None,
        description="Token issued at timestamp"
    )
    
    nbf: Optional[int] = Field(
        default=None,
        description="Token not valid before timestamp"
    )
    
    sub: Optional[str] = Field(
        default=None,
        description="Subject identifier (usually user ID)"
    )
    
    aud: Optional[Union[str, List[str]]] = Field(
        default=None,
        description="Intended audience(s) for the token"
    )
    
    iss: Optional[str] = Field(
        default=None,
        description="Token issuer"
    )
    
    jti: Optional[str] = Field(
        default=None,
        description="Unique token identifier"
    )
    
    # Keycloak-specific fields
    realm_access: Optional[Dict[str, List[str]]] = Field(
        default=None,
        description="Realm-level role assignments"
    )
    
    resource_access: Optional[Dict[str, Dict[str, List[str]]]] = Field(
        default=None,
        description="Resource/client-level role assignments"
    )
    
    preferred_username: Optional[str] = Field(
        default=None,
        description="Preferred username for display"
    )
    
    email: Optional[str] = Field(
        default=None,
        description="User's email address"
    )
    
    email_verified: Optional[bool] = Field(
        default=None,
        description="Whether the email is verified"
    )
    
    name: Optional[str] = Field(
        default=None,
        description="User's full name"
    )
    
    given_name: Optional[str] = Field(
        default=None,
        description="User's given name"
    )
    
    family_name: Optional[str] = Field(
        default=None,
        description="User's family name"
    )
    
    @property
    def scopes_list(self) -> List[str]:
        """Convert scope string to list of individual scopes."""
        if not self.scope:
            return []
        return self.scope.split()
    
    @property
    def is_expired(self) -> bool:
        """Check if token is expired based on exp claim."""
        if not self.exp:
            return not self.active
        return datetime.utcnow().timestamp() >= self.exp
    
    def has_scope(self, scope: str) -> bool:
        """Check if token has a specific scope."""
        return scope in self.scopes_list
    
    def has_realm_role(self, role: str) -> bool:
        """Check if token has a specific realm role."""
        if not self.realm_access or 'roles' not in self.realm_access:
            return False
        return role in self.realm_access['roles']
    
    def has_client_role(self, client: str, role: str) -> bool:
        """Check if token has a specific client role."""
        if not self.resource_access or client not in self.resource_access:
            return False
        client_access = self.resource_access[client]
        if 'roles' not in client_access:
            return False
        return role in client_access['roles']


class UserInfoResponse(BaseKeycloakModel):
    """
    Response from Keycloak UserInfo endpoint.
    
    Based on OpenID Connect Core specification.
    """
    
    sub: str = Field(
        description="Subject identifier (user ID)"
    )
    
    preferred_username: Optional[str] = Field(
        default=None,
        description="Preferred username for display"
    )
    
    name: Optional[str] = Field(
        default=None,
        description="User's full name"
    )
    
    given_name: Optional[str] = Field(
        default=None,
        description="User's given name"
    )
    
    family_name: Optional[str] = Field(
        default=None,
        description="User's family name"
    )
    
    middle_name: Optional[str] = Field(
        default=None,
        description="User's middle name"
    )
    
    nickname: Optional[str] = Field(
        default=None,
        description="User's nickname"
    )
    
    profile: Optional[str] = Field(
        default=None,
        description="URL of user's profile page"
    )
    
    picture: Optional[str] = Field(
        default=None,
        description="URL of user's profile picture"
    )
    
    website: Optional[str] = Field(
        default=None,
        description="URL of user's website"
    )
    
    email: Optional[str] = Field(
        default=None,
        description="User's email address"
    )
    
    email_verified: Optional[bool] = Field(
        default=None,
        description="Whether the email is verified"
    )
    
    gender: Optional[str] = Field(
        default=None,
        description="User's gender"
    )
    
    birthdate: Optional[str] = Field(
        default=None,
        description="User's birth date (YYYY-MM-DD format)"
    )
    
    zoneinfo: Optional[str] = Field(
        default=None,
        description="User's time zone"
    )
    
    locale: Optional[str] = Field(
        default=None,
        description="User's locale"
    )
    
    phone_number: Optional[str] = Field(
        default=None,
        description="User's phone number"
    )
    
    phone_number_verified: Optional[bool] = Field(
        default=None,
        description="Whether the phone number is verified"
    )
    
    address: Optional[Dict[str, Any]] = Field(
        default=None,
        description="User's address information"
    )
    
    updated_at: Optional[int] = Field(
        default=None,
        description="Time when user info was last updated"
    )


# =========================================================================
# Error Models
# =========================================================================

class KeycloakError(BaseKeycloakModel):
    """
    Standard Keycloak error response.
    
    Used for OAuth2/OpenID Connect error responses and general API errors.
    """
    
    error: str = Field(
        description="Error code (e.g., 'invalid_grant', 'invalid_client')"
    )
    
    error_description: Optional[str] = Field(
        default=None,
        description="Human-readable error description"
    )
    
    error_uri: Optional[str] = Field(
        default=None,
        description="URI with more information about the error"
    )
    
    # Additional Keycloak-specific fields
    message: Optional[str] = Field(
        default=None,
        description="Additional error message from Keycloak"
    )
    
    details: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Additional error details"
    )


# =========================================================================
# Request Models
# =========================================================================

class TokenRequest(BaseKeycloakModel):
    """Base class for token requests."""
    
    grant_type: str = Field(
        description="OAuth2 grant type"
    )
    
    client_id: Optional[str] = Field(
        default=None,
        description="Client identifier"
    )
    
    client_secret: Optional[str] = Field(
        default=None,
        description="Client secret (for confidential clients)"
    )
    
    scope: Optional[str] = Field(
        default=None,
        description="Requested scopes (space-separated)"
    )


class ClientCredentialsRequest(TokenRequest):
    """Client credentials grant request."""
    
    grant_type: str = Field(
        default="client_credentials",
        description="Must be 'client_credentials'"
    )


class AuthorizationCodeRequest(TokenRequest):
    """Authorization code grant request."""
    
    grant_type: str = Field(
        default="authorization_code",
        description="Must be 'authorization_code'"
    )
    
    code: str = Field(
        description="Authorization code from authorization server"
    )
    
    redirect_uri: str = Field(
        description="Redirect URI used in authorization request"
    )
    
    code_verifier: Optional[str] = Field(
        default=None,
        description="PKCE code verifier"
    )


class RefreshTokenRequest(TokenRequest):
    """Refresh token grant request."""
    
    grant_type: str = Field(
        default="refresh_token",
        description="Must be 'refresh_token'"
    )
    
    refresh_token: str = Field(
        description="Refresh token"
    )


class PasswordRequest(TokenRequest):
    """Resource owner password credentials grant request."""
    
    grant_type: str = Field(
        default="password",
        description="Must be 'password'"
    )
    
    username: str = Field(
        description="Resource owner username"
    )
    
    password: str = Field(
        description="Resource owner password"
    )


class TokenIntrospectionRequest(BaseKeycloakModel):
    """Token introspection request."""
    
    token: str = Field(
        description="Token to introspect"
    )
    
    token_type_hint: Optional[str] = Field(
        default=None,
        description="Hint about the token type"
    )
    
    client_id: Optional[str] = Field(
        default=None,
        description="Client identifier"
    )
    
    client_secret: Optional[str] = Field(
        default=None,
        description="Client secret"
    )


# =========================================================================
# Admin API Models
# =========================================================================

class User(BaseKeycloakModel):
    """Keycloak user representation."""
    
    id: Optional[str] = Field(
        default=None,
        description="User ID"
    )
    
    username: Optional[str] = Field(
        default=None,
        description="Username"
    )
    
    email: Optional[str] = Field(
        default=None,
        description="Email address"
    )
    
    email_verified: Optional[bool] = Field(
        default=None,
        alias="emailVerified",
        description="Whether email is verified"
    )
    
    first_name: Optional[str] = Field(
        default=None,
        alias="firstName",
        description="First name"
    )
    
    last_name: Optional[str] = Field(
        default=None,
        alias="lastName", 
        description="Last name"
    )
    
    enabled: Optional[bool] = Field(
        default=None,
        description="Whether user is enabled"
    )
    
    created_timestamp: Optional[int] = Field(
        default=None,
        alias="createdTimestamp",
        description="User creation timestamp"
    )
    
    attributes: Optional[Dict[str, List[str]]] = Field(
        default=None,
        description="User attributes"
    )
    
    credentials: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="User credentials"
    )
    
    required_actions: Optional[List[str]] = Field(
        default=None,
        alias="requiredActions",
        description="Required actions for the user"
    )


class Role(BaseKeycloakModel):
    """Keycloak role representation."""
    
    id: Optional[str] = Field(
        default=None,
        description="Role ID"
    )
    
    name: Optional[str] = Field(
        default=None,
        description="Role name"
    )
    
    description: Optional[str] = Field(
        default=None,
        description="Role description"
    )
    
    composite: Optional[bool] = Field(
        default=None,
        description="Whether this is a composite role"
    )
    
    client_role: Optional[bool] = Field(
        default=None,
        alias="clientRole",
        description="Whether this is a client role"
    )
    
    container_id: Optional[str] = Field(
        default=None,
        alias="containerId",
        description="Container ID (realm or client)"
    )


class Client(BaseKeycloakModel):
    """Keycloak client representation."""
    
    id: Optional[str] = Field(
        default=None,
        description="Client ID"
    )
    
    client_id: Optional[str] = Field(
        default=None,
        alias="clientId",
        description="Client identifier"
    )
    
    name: Optional[str] = Field(
        default=None,
        description="Client name"
    )
    
    description: Optional[str] = Field(
        default=None,
        description="Client description"
    )
    
    enabled: Optional[bool] = Field(
        default=None,
        description="Whether client is enabled"
    )
    
    client_authenticator_type: Optional[str] = Field(
        default=None,
        alias="clientAuthenticatorType",
        description="Client authenticator type"
    )
    
    redirect_uris: Optional[List[str]] = Field(
        default=None,
        alias="redirectUris",
        description="Valid redirect URIs"
    )
    
    web_origins: Optional[List[str]] = Field(
        default=None,
        alias="webOrigins",
        description="Valid web origins"
    )
    
    public_client: Optional[bool] = Field(
        default=None,
        alias="publicClient",
        description="Whether this is a public client"
    )
    
    protocol: Optional[str] = Field(
        default=None,
        description="Client protocol"
    )
    
    attributes: Optional[Dict[str, str]] = Field(
        default=None,
        description="Client attributes"
    )