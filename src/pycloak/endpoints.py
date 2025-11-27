"""
Keycloak API endpoints.

This module centralizes all Keycloak REST API endpoint URLs and paths.
All endpoints are defined as constants to provide transparency and
allow users to see exactly which Keycloak APIs are being called.
"""

from dataclasses import dataclass
from typing import Dict, Any
from urllib.parse import urljoin


@dataclass
class KeycloakEndpoints:
    """
    Centralized Keycloak API endpoints.
    
    This class provides all the endpoint URLs used by the Keycloak API client.
    All endpoints are based on the official Keycloak REST API documentation.
    """
    
    # Base server configuration
    server_url: str
    realm: str
    
    def __post_init__(self):
        """Ensure server_url ends with a slash for proper URL joining."""
        if not self.server_url.endswith('/'):
            self.server_url += '/'
    
    @property
    def realm_base_url(self) -> str:
        """Base URL for all realm-specific endpoints."""
        return urljoin(self.server_url, f"realms/{self.realm}/")
    
    @property
    def admin_base_url(self) -> str:
        """Base URL for admin API endpoints."""
        return urljoin(self.server_url, f"admin/realms/{self.realm}/")
    
    # =========================================================================
    # Authentication & Token Endpoints
    # =========================================================================
    
    @property
    def token_endpoint(self) -> str:
        """
        OAuth2/OpenID Connect token endpoint.
        Used for:
        - Authorization code flow token exchange
        - Client credentials flow
        - Resource owner password flow
        - Refresh token flow
        """
        return urljoin(self.realm_base_url, "protocol/openid-connect/token")
    
    @property
    def token_introspect_endpoint(self) -> str:
        """
        OAuth2 token introspection endpoint (RFC 7662).
        Used to validate and get metadata about access tokens.
        """
        return urljoin(self.realm_base_url, "protocol/openid-connect/token/introspect")
    
    @property
    def userinfo_endpoint(self) -> str:
        """
        OpenID Connect UserInfo endpoint.
        Returns claims about the authenticated user.
        """
        return urljoin(self.realm_base_url, "protocol/openid-connect/userinfo")
    
    @property
    def logout_endpoint(self) -> str:
        """
        OpenID Connect logout endpoint.
        Used to invalidate tokens and end user sessions.
        """
        return urljoin(self.realm_base_url, "protocol/openid-connect/logout")
    
    @property
    def revoke_endpoint(self) -> str:
        """
        OAuth2 token revocation endpoint (RFC 7009).
        Used to revoke access or refresh tokens.
        """
        return urljoin(self.realm_base_url, "protocol/openid-connect/revoke")
    
    # =========================================================================
    # Authorization & Discovery Endpoints  
    # =========================================================================
    
    @property
    def auth_endpoint(self) -> str:
        """
        OAuth2/OpenID Connect authorization endpoint.
        Used for authorization code flow redirects.
        """
        return urljoin(self.realm_base_url, "protocol/openid-connect/auth")
    
    @property
    def well_known_endpoint(self) -> str:
        """
        OpenID Connect Discovery endpoint.
        Returns metadata about the OpenID Connect provider.
        """
        return urljoin(self.realm_base_url, ".well-known/openid-configuration")
    
    @property
    def certs_endpoint(self) -> str:
        """
        JSON Web Key Set (JWKS) endpoint.
        Returns public keys for token signature verification.
        """
        return urljoin(self.realm_base_url, "protocol/openid-connect/certs")
    
    # =========================================================================
    # User Management Endpoints (Admin API)
    # =========================================================================
    
    @property
    def users_endpoint(self) -> str:
        """
        Admin API users endpoint.
        Used for user CRUD operations.
        """
        return urljoin(self.admin_base_url, "users")
    
    def user_endpoint(self, user_id: str) -> str:
        """
        Specific user endpoint for admin operations.
        
        Args:
            user_id: The Keycloak user ID
            
        Returns:
            URL for the specific user endpoint
        """
        return urljoin(self.users_endpoint + "/", user_id)
    
    def user_sessions_endpoint(self, user_id: str) -> str:
        """
        User sessions endpoint for admin operations.
        
        Args:
            user_id: The Keycloak user ID
            
        Returns:
            URL for the user's sessions endpoint
        """
        return urljoin(self.user_endpoint(user_id) + "/", "sessions")
    
    # =========================================================================
    # Client Management Endpoints (Admin API)
    # =========================================================================
    
    @property
    def clients_endpoint(self) -> str:
        """
        Admin API clients endpoint.
        Used for client CRUD operations.
        """
        return urljoin(self.admin_base_url, "clients")
    
    def client_endpoint(self, client_id: str) -> str:
        """
        Specific client endpoint for admin operations.
        
        Args:
            client_id: The Keycloak client ID
            
        Returns:
            URL for the specific client endpoint
        """
        return urljoin(self.clients_endpoint + "/", client_id)
    
    def client_secret_endpoint(self, client_id: str) -> str:
        """
        Client secret endpoint for admin operations.
        
        Args:
            client_id: The Keycloak client ID
            
        Returns:
            URL for the client's secret endpoint
        """
        return urljoin(self.client_endpoint(client_id) + "/", "client-secret")
    
    # =========================================================================
    # Role Management Endpoints (Admin API)
    # =========================================================================
    
    @property
    def roles_endpoint(self) -> str:
        """
        Admin API realm roles endpoint.
        Used for realm role CRUD operations.
        """
        return urljoin(self.admin_base_url, "roles")
    
    def role_endpoint(self, role_name: str) -> str:
        """
        Specific realm role endpoint for admin operations.
        
        Args:
            role_name: The role name
            
        Returns:
            URL for the specific role endpoint
        """
        return urljoin(self.roles_endpoint + "/", role_name)
    
    def client_roles_endpoint(self, client_id: str) -> str:
        """
        Client roles endpoint for admin operations.
        
        Args:
            client_id: The Keycloak client ID
            
        Returns:
            URL for the client's roles endpoint
        """
        return urljoin(self.client_endpoint(client_id) + "/", "roles")
    
    def client_role_endpoint(self, client_id: str, role_name: str) -> str:
        """
        Specific client role endpoint for admin operations.
        
        Args:
            client_id: The Keycloak client ID
            role_name: The role name
            
        Returns:
            URL for the specific client role endpoint
        """
        return urljoin(self.client_roles_endpoint(client_id) + "/", role_name)
    
    # =========================================================================
    # Group Management Endpoints (Admin API)
    # =========================================================================
    
    @property
    def groups_endpoint(self) -> str:
        """
        Admin API groups endpoint.
        Used for group CRUD operations.
        """
        return urljoin(self.admin_base_url, "groups")
    
    def group_endpoint(self, group_id: str) -> str:
        """
        Specific group endpoint for admin operations.
        
        Args:
            group_id: The Keycloak group ID
            
        Returns:
            URL for the specific group endpoint
        """
        return urljoin(self.groups_endpoint + "/", group_id)
    
    # =========================================================================
    # Session Management Endpoints (Admin API)
    # =========================================================================
    
    @property
    def sessions_endpoint(self) -> str:
        """
        Admin API sessions endpoint.
        Used for session management operations.
        """
        return urljoin(self.admin_base_url, "sessions")
    
    def session_endpoint(self, session_id: str) -> str:
        """
        Specific session endpoint for admin operations.
        
        Args:
            session_id: The Keycloak session ID
            
        Returns:
            URL for the specific session endpoint
        """
        return urljoin(self.sessions_endpoint + "/", session_id)
    
    # =========================================================================
    # Utility Methods
    # =========================================================================
    
    def build_url(self, path: str, base_url: str = None) -> str:
        """
        Build a complete URL from a path and base URL.
        
        Args:
            path: The API path
            base_url: Base URL to use (defaults to realm_base_url)
            
        Returns:
            Complete URL
        """
        if base_url is None:
            base_url = self.realm_base_url
        return urljoin(base_url, path)
    
    def get_all_endpoints(self) -> Dict[str, str]:
        """
        Get a dictionary of all available endpoints.
        
        Useful for debugging and documentation purposes.
        
        Returns:
            Dictionary mapping endpoint names to URLs
        """
        endpoints = {}
        
        # Get all properties that end with '_endpoint'
        for attr_name in dir(self):
            if attr_name.endswith('_endpoint') and not attr_name.startswith('_'):
                try:
                    attr_value = getattr(self, attr_name)
                    if isinstance(attr_value, str):
                        endpoints[attr_name] = attr_value
                except Exception:
                    # Skip properties that might fail (like methods requiring parameters)
                    continue
        
        return endpoints


# =========================================================================
# Constants for common parameter names and values
# =========================================================================

class GrantTypes:
    """OAuth2 grant type constants."""
    AUTHORIZATION_CODE = "authorization_code"
    CLIENT_CREDENTIALS = "client_credentials"
    PASSWORD = "password"
    REFRESH_TOKEN = "refresh_token"
    JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
    TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"


class ResponseTypes:
    """OAuth2 response type constants."""
    CODE = "code"
    TOKEN = "token"
    ID_TOKEN = "id_token"


class Scopes:
    """Common OAuth2/OpenID Connect scopes."""
    OPENID = "openid"
    PROFILE = "profile"
    EMAIL = "email"
    ADDRESS = "address"
    PHONE = "phone"
    OFFLINE_ACCESS = "offline_access"


class TokenTypes:
    """Token type constants."""
    BEARER = "Bearer"
    ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
    REFRESH_TOKEN = "urn:ietf:params:oauth:token-type:refresh_token"
    ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token"


class ClientAuthMethods:
    """Client authentication method constants."""
    CLIENT_SECRET_POST = "client_secret_post"
    CLIENT_SECRET_BASIC = "client_secret_basic"
    CLIENT_SECRET_JWT = "client_secret_jwt"
    PRIVATE_KEY_JWT = "private_key_jwt"
    NONE = "none"