"""Test configuration and fixtures."""

import pytest
import httpx
from typing import Generator, Dict, Any
from unittest.mock import Mock, patch

from pycloak import KeycloakClient, AsyncKeycloakClient
from pycloak.endpoints import KeycloakEndpoints


# Test configuration constants
TEST_SERVER_URL = "https://keycloak.example.com"
TEST_REALM = "test-realm"
TEST_CLIENT_ID = "test-client"
TEST_CLIENT_SECRET = "test-secret"


@pytest.fixture
def keycloak_endpoints() -> KeycloakEndpoints:
    """Create a test KeycloakEndpoints instance."""
    return KeycloakEndpoints(
        server_url=TEST_SERVER_URL,
        realm=TEST_REALM,
    )


@pytest.fixture
def mock_http_client() -> Generator[Mock, None, None]:
    """Create a mock HTTP client for testing."""
    mock_client = Mock(spec=httpx.Client)
    yield mock_client


@pytest.fixture  
def mock_async_http_client() -> Generator[Mock, None, None]:
    """Create a mock async HTTP client for testing."""
    mock_client = Mock(spec=httpx.AsyncClient)
    yield mock_client


@pytest.fixture
def keycloak_client(mock_http_client: Mock) -> Generator[KeycloakClient, None, None]:
    """Create a test KeycloakClient with mocked HTTP client."""
    client = KeycloakClient(
        server_url=TEST_SERVER_URL,
        realm=TEST_REALM,
        client_id=TEST_CLIENT_ID,
        client_secret=TEST_CLIENT_SECRET,
        http_client=mock_http_client,
    )
    yield client


@pytest.fixture
def async_keycloak_client(mock_async_http_client: Mock) -> Generator[AsyncKeycloakClient, None, None]:
    """Create a test AsyncKeycloakClient with mocked HTTP client."""
    client = AsyncKeycloakClient(
        server_url=TEST_SERVER_URL,
        realm=TEST_REALM,
        client_id=TEST_CLIENT_ID,
        client_secret=TEST_CLIENT_SECRET,
        http_client=mock_async_http_client,
    )
    yield client


@pytest.fixture
def sample_token_response() -> Dict[str, Any]:
    """Sample token response data."""
    return {
        "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJyWmJZSFNVU1M4Y09WODE5NlJEd21oOVJtN1l2bVhRTHVPOWY0aXY0clNRIn0...",
        "expires_in": 300,
        "refresh_expires_in": 1800,
        "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI5YzFkMjEyMC0zYjY5LTQ2ZTgtOTllOS1jNTJhZTY4M2VkMmEifQ...",
        "token_type": "Bearer",
        "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJyWmJZSFNVU1M4Y09WODE5NlJEd21oOVJtN1l2bVhRTHVPOWY0aXY0clNRIn0...",
        "not-before-policy": 0,
        "session_state": "b0f5a0ad-8b4a-4e6e-9e8f-4c4a6e5d7c8b",
        "scope": "openid profile email"
    }


@pytest.fixture
def sample_introspection_response() -> Dict[str, Any]:
    """Sample token introspection response data."""
    return {
        "active": True,
        "scope": "openid profile email",
        "client_id": "test-client",
        "username": "testuser",
        "token_type": "Bearer",
        "exp": 1700000000,
        "iat": 1699999700,
        "sub": "123e4567-e89b-12d3-a456-426614174000",
        "aud": ["test-client"],
        "iss": f"{TEST_SERVER_URL}/realms/{TEST_REALM}",
        "jti": "abcd1234-5678-90ef-ghij-klmnopqrstuv",
        "preferred_username": "testuser",
        "email": "testuser@example.com",
        "email_verified": True,
        "name": "Test User",
        "given_name": "Test",
        "family_name": "User",
        "realm_access": {
            "roles": ["offline_access", "uma_authorization", "user"]
        },
        "resource_access": {
            "test-client": {
                "roles": ["client-role-1", "client-role-2"]
            }
        }
    }


@pytest.fixture
def sample_userinfo_response() -> Dict[str, Any]:
    """Sample userinfo response data."""
    return {
        "sub": "123e4567-e89b-12d3-a456-426614174000",
        "preferred_username": "testuser",
        "name": "Test User",
        "given_name": "Test",
        "family_name": "User",
        "email": "testuser@example.com",
        "email_verified": True,
        "picture": "https://example.com/avatar.jpg",
        "updated_at": 1699999700
    }


@pytest.fixture
def sample_well_known_response() -> Dict[str, Any]:
    """Sample OpenID Connect discovery document."""
    return {
        "issuer": f"{TEST_SERVER_URL}/realms/{TEST_REALM}",
        "authorization_endpoint": f"{TEST_SERVER_URL}/realms/{TEST_REALM}/protocol/openid-connect/auth",
        "token_endpoint": f"{TEST_SERVER_URL}/realms/{TEST_REALM}/protocol/openid-connect/token",
        "userinfo_endpoint": f"{TEST_SERVER_URL}/realms/{TEST_REALM}/protocol/openid-connect/userinfo",
        "introspection_endpoint": f"{TEST_SERVER_URL}/realms/{TEST_REALM}/protocol/openid-connect/token/introspect",
        "end_session_endpoint": f"{TEST_SERVER_URL}/realms/{TEST_REALM}/protocol/openid-connect/logout",
        "revocation_endpoint": f"{TEST_SERVER_URL}/realms/{TEST_REALM}/protocol/openid-connect/revoke",
        "jwks_uri": f"{TEST_SERVER_URL}/realms/{TEST_REALM}/protocol/openid-connect/certs",
        "response_types_supported": ["code", "token", "id_token"],
        "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token", "password"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email", "offline_access"]
    }


@pytest.fixture
def sample_error_response() -> Dict[str, Any]:
    """Sample error response data."""
    return {
        "error": "invalid_grant",
        "error_description": "Invalid authorization code"
    }


def create_mock_response(
    status_code: int = 200,
    json_data: Dict[str, Any] = None,
    headers: Dict[str, str] = None,
) -> Mock:
    """
    Create a mock HTTP response.
    
    Args:
        status_code: HTTP status code
        json_data: JSON response data
        headers: Response headers
        
    Returns:
        Mock response object
    """
    mock_response = Mock(spec=httpx.Response)
    mock_response.status_code = status_code
    mock_response.headers = headers or {"content-type": "application/json"}
    mock_response.is_success = 200 <= status_code < 300
    
    if json_data is not None:
        mock_response.json.return_value = json_data
    else:
        mock_response.json.side_effect = ValueError("No JSON object could be decoded")
    
    return mock_response