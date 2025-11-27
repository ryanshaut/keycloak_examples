"""
PyCloak - A Keycloak HTTP API client library.

This library provides both synchronous and asynchronous interfaces
for interacting with Keycloak's REST API using raw HTTP calls.
"""

from .client import KeycloakClient, AsyncKeycloakClient, create_client_from_env
from .endpoints import KeycloakEndpoints, GrantTypes, Scopes, TokenTypes, ResponseTypes
from .models import (
    TokenResponse,
    TokenIntrospectionResponse,
    UserInfoResponse,
    KeycloakError,
    User,
    Role,
    Client,
    ClientCredentialsRequest,
    AuthorizationCodeRequest,
    RefreshTokenRequest,
    PasswordRequest,
)
from .exceptions import (
    KeycloakException,
    AuthenticationError,
    AuthorizationError,
    TokenExpiredError,
    InvalidTokenError,
    InvalidGrantError,
    InvalidClientError,
    ServerError,
    NetworkError,
    ConfigurationError,
)

__version__ = "0.1.0"

__all__ = [
    # Client classes
    "KeycloakClient",
    "AsyncKeycloakClient", 
    "create_client_from_env",
    
    # Endpoints and constants
    "KeycloakEndpoints",
    "GrantTypes",
    "Scopes", 
    "TokenTypes",
    "ResponseTypes",
    
    # Response models
    "TokenResponse",
    "TokenIntrospectionResponse", 
    "UserInfoResponse",
    "KeycloakError",
    
    # Admin models
    "User",
    "Role", 
    "Client",
    
    # Request models
    "ClientCredentialsRequest",
    "AuthorizationCodeRequest",
    "RefreshTokenRequest", 
    "PasswordRequest",
    
    # Exception classes
    "KeycloakException",
    "AuthenticationError",
    "AuthorizationError", 
    "TokenExpiredError",
    "InvalidTokenError",
    "InvalidGrantError",
    "InvalidClientError",
    "ServerError",
    "NetworkError",
    "ConfigurationError",
]