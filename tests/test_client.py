"""Tests for KeycloakClient."""

import base64
from unittest.mock import Mock, patch
import httpx
import pytest

from pycloak.client import KeycloakClient, AsyncKeycloakClient, create_client_from_env
from pycloak.models import TokenResponse, TokenIntrospectionResponse, UserInfoResponse
from pycloak.exceptions import (
    KeycloakException,
    AuthenticationError,
    NetworkError,
    ConfigurationError,
)
from tests.conftest import create_mock_response


class TestKeycloakClientInit:
    """Test KeycloakClient initialization."""
    
    def test_basic_init(self):
        """Test basic client initialization."""
        client = KeycloakClient(
            server_url="https://keycloak.example.com",
            realm="test-realm",
            client_id="test-client",
            client_secret="test-secret",
        )
        
        assert client.server_url == "https://keycloak.example.com"
        assert client.realm == "test-realm"
        assert client.client_id == "test-client"
        assert client.client_secret == "test-secret"
        assert client.timeout == 30.0
        assert client.verify_ssl is True
    
    def test_init_normalizes_server_url(self):
        """Test that server URL is normalized."""
        client = KeycloakClient(
            server_url="https://keycloak.example.com/",
            realm="test-realm",
        )
        
        assert client.server_url == "https://keycloak.example.com"
    
    def test_init_missing_server_url(self):
        """Test initialization with missing server URL."""
        with pytest.raises(ConfigurationError, match="server_url is required"):
            KeycloakClient(server_url="", realm="test-realm")
    
    def test_init_missing_realm(self):
        """Test initialization with missing realm."""
        with pytest.raises(ConfigurationError, match="realm is required"):
            KeycloakClient(
                server_url="https://keycloak.example.com",
                realm="",
            )
    
    def test_init_with_custom_http_client(self):
        """Test initialization with custom HTTP client."""
        custom_client = Mock(spec=httpx.Client)
        
        client = KeycloakClient(
            server_url="https://keycloak.example.com",
            realm="test-realm",
            http_client=custom_client,
        )
        
        assert client.http_client == custom_client
        assert client._owns_client is False
    
    def test_context_manager(self, mock_http_client):
        """Test client as context manager."""
        with KeycloakClient(
            server_url="https://keycloak.example.com",
            realm="test-realm",
            http_client=mock_http_client,
        ) as client:
            assert client is not None
        
        # Should not close the client we don't own
        mock_http_client.close.assert_not_called()


class TestKeycloakClientAuth:
    """Test client authentication methods."""
    
    def test_get_client_auth_header(self, keycloak_client):
        """Test client authentication header generation."""
        header = keycloak_client._get_client_auth_header()
        
        # Decode the Basic auth header
        auth_header = header["Authorization"]
        assert auth_header.startswith("Basic ")
        
        encoded_creds = auth_header.split(" ", 1)[1]
        decoded_creds = base64.b64decode(encoded_creds).decode()
        assert decoded_creds == "test-client:test-secret"
    
    def test_get_client_auth_header_custom_creds(self, keycloak_client):
        """Test client auth header with custom credentials."""
        header = keycloak_client._get_client_auth_header("other-client", "other-secret")
        
        encoded_creds = header["Authorization"].split(" ", 1)[1]
        decoded_creds = base64.b64decode(encoded_creds).decode()
        assert decoded_creds == "other-client:other-secret"
    
    def test_get_client_auth_header_missing_creds(self):
        """Test client auth header with missing credentials."""
        client = KeycloakClient(
            server_url="https://keycloak.example.com",
            realm="test-realm",
        )
        
        with pytest.raises(ConfigurationError, match="Client ID and secret are required"):
            client._get_client_auth_header()
    
    def test_get_bearer_auth_header(self, keycloak_client):
        """Test bearer token header generation."""
        header = keycloak_client._get_bearer_auth_header("test-access-token")
        
        assert header["Authorization"] == "Bearer test-access-token"
    
    def test_prepare_headers(self, keycloak_client):
        """Test header preparation."""
        headers = keycloak_client._prepare_headers()
        
        assert headers["Content-Type"] == "application/x-www-form-urlencoded"
        assert headers["User-Agent"] == "pycloak/0.1.0"
    
    def test_prepare_headers_with_additional(self, keycloak_client):
        """Test header preparation with additional headers."""
        additional = {"X-Custom": "value", "Content-Type": "application/json"}
        headers = keycloak_client._prepare_headers(additional)
        
        assert headers["Content-Type"] == "application/json"  # Should override
        assert headers["X-Custom"] == "value"
        assert headers["User-Agent"] == "pycloak/0.1.0"


class TestKeycloakClientTokenOperations:
    """Test token-related operations."""
    
    def test_get_token_client_credentials(self, keycloak_client, sample_token_response):
        """Test client credentials token request."""
        mock_response = create_mock_response(200, sample_token_response)
        keycloak_client.http_client.post.return_value = mock_response
        
        token_response = keycloak_client.get_token_client_credentials(scope="openid profile")
        
        assert isinstance(token_response, TokenResponse)
        assert token_response.access_token.startswith("eyJ")
        assert token_response.token_type == "Bearer"
        
        # Verify the request was made correctly
        keycloak_client.http_client.post.assert_called_once()
        call_args = keycloak_client.http_client.post.call_args
        
        # Check endpoint
        assert call_args[0][0].endswith("/protocol/openid-connect/token")
        
        # Check data
        data = call_args[1]["data"]
        assert data["grant_type"] == "client_credentials"
        assert data["scope"] == "openid profile"
        
        # Check headers
        headers = call_args[1]["headers"]
        assert "Authorization" in headers
        assert headers["Authorization"].startswith("Basic ")
    
    def test_get_token_authorization_code(self, keycloak_client, sample_token_response):
        """Test authorization code token request."""
        mock_response = create_mock_response(200, sample_token_response)
        keycloak_client.http_client.post.return_value = mock_response
        
        token_response = keycloak_client.get_token_authorization_code(
            code="auth-code-123",
            redirect_uri="https://app.example.com/callback",
            code_verifier="pkce-verifier"
        )
        
        assert isinstance(token_response, TokenResponse)
        
        # Verify the request
        call_args = keycloak_client.http_client.post.call_args
        data = call_args[1]["data"]
        
        assert data["grant_type"] == "authorization_code"
        assert data["code"] == "auth-code-123"
        assert data["redirect_uri"] == "https://app.example.com/callback"
        assert data["code_verifier"] == "pkce-verifier"
    
    def test_get_token_password(self, keycloak_client, sample_token_response):
        """Test password grant token request."""
        mock_response = create_mock_response(200, sample_token_response)
        keycloak_client.http_client.post.return_value = mock_response
        
        token_response = keycloak_client.get_token_password(
            username="testuser",
            password="testpass",
            scope="openid profile"
        )
        
        assert isinstance(token_response, TokenResponse)
        
        # Verify the request
        call_args = keycloak_client.http_client.post.call_args
        data = call_args[1]["data"]
        
        assert data["grant_type"] == "password"
        assert data["username"] == "testuser"
        assert data["password"] == "testpass"
        assert data["scope"] == "openid profile"
    
    def test_refresh_token(self, keycloak_client, sample_token_response):
        """Test refresh token request."""
        mock_response = create_mock_response(200, sample_token_response)
        keycloak_client.http_client.post.return_value = mock_response
        
        token_response = keycloak_client.refresh_token(
            refresh_token="refresh-token-123",
            scope="openid profile"
        )
        
        assert isinstance(token_response, TokenResponse)
        
        # Verify the request
        call_args = keycloak_client.http_client.post.call_args
        data = call_args[1]["data"]
        
        assert data["grant_type"] == "refresh_token"
        assert data["refresh_token"] == "refresh-token-123"
        assert data["scope"] == "openid profile"
    
    def test_introspect_token(self, keycloak_client, sample_introspection_response):
        """Test token introspection."""
        mock_response = create_mock_response(200, sample_introspection_response)
        keycloak_client.http_client.post.return_value = mock_response
        
        introspection_response = keycloak_client.introspect_token(
            token="token-to-introspect",
            token_type_hint="access_token"
        )
        
        assert isinstance(introspection_response, TokenIntrospectionResponse)
        assert introspection_response.active is True
        assert introspection_response.client_id == "test-client"
        
        # Verify the request
        call_args = keycloak_client.http_client.post.call_args
        assert call_args[0][0].endswith("/token/introspect")
        
        data = call_args[1]["data"]
        assert data["token"] == "token-to-introspect"
        assert data["token_type_hint"] == "access_token"
    
    def test_get_userinfo(self, keycloak_client, sample_userinfo_response):
        """Test get user info."""
        mock_response = create_mock_response(200, sample_userinfo_response)
        keycloak_client.http_client.get.return_value = mock_response
        
        userinfo_response = keycloak_client.get_userinfo("access-token-123")
        
        assert isinstance(userinfo_response, UserInfoResponse)
        assert userinfo_response.sub == "123e4567-e89b-12d3-a456-426614174000"
        assert userinfo_response.preferred_username == "testuser"
        
        # Verify the request
        call_args = keycloak_client.http_client.get.call_args
        assert call_args[0][0].endswith("/userinfo")
        
        headers = call_args[1]["headers"]
        assert headers["Authorization"] == "Bearer access-token-123"
        assert headers["Accept"] == "application/json"
    
    def test_logout(self, keycloak_client):
        """Test logout."""
        mock_response = create_mock_response(204, {})
        keycloak_client.http_client.post.return_value = mock_response
        
        keycloak_client.logout("refresh-token-123")
        
        # Verify the request
        call_args = keycloak_client.http_client.post.call_args
        assert call_args[0][0].endswith("/logout")
        
        data = call_args[1]["data"]
        assert data["refresh_token"] == "refresh-token-123"
        assert data["client_id"] == "test-client"
    
    def test_revoke_token(self, keycloak_client):
        """Test token revocation."""
        mock_response = create_mock_response(200, {})
        keycloak_client.http_client.post.return_value = mock_response
        
        keycloak_client.revoke_token(
            token="token-to-revoke",
            token_type_hint="access_token"
        )
        
        # Verify the request
        call_args = keycloak_client.http_client.post.call_args
        assert call_args[0][0].endswith("/revoke")
        
        data = call_args[1]["data"]
        assert data["token"] == "token-to-revoke"
        assert data["token_type_hint"] == "access_token"


class TestKeycloakClientDiscovery:
    """Test discovery operations."""
    
    def test_get_well_known_config(self, keycloak_client, sample_well_known_response):
        """Test get well-known configuration."""
        mock_response = create_mock_response(200, sample_well_known_response)
        keycloak_client.http_client.get.return_value = mock_response
        
        well_known = keycloak_client.get_well_known_config()
        
        assert well_known["issuer"].endswith("/realms/test-realm")
        assert "authorization_endpoint" in well_known
        assert "token_endpoint" in well_known
        
        # Verify the request
        call_args = keycloak_client.http_client.get.call_args
        assert call_args[0][0].endswith("/.well-known/openid-configuration")
    
    def test_get_certs(self, keycloak_client):
        """Test get JWKS certificates."""
        jwks_response = {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "test-key-id",
                    "use": "sig",
                    "n": "test-modulus",
                    "e": "AQAB"
                }
            ]
        }
        
        mock_response = create_mock_response(200, jwks_response)
        keycloak_client.http_client.get.return_value = mock_response
        
        certs = keycloak_client.get_certs()
        
        assert "keys" in certs
        assert len(certs["keys"]) == 1
        assert certs["keys"][0]["kid"] == "test-key-id"
        
        # Verify the request
        call_args = keycloak_client.http_client.get.call_args
        assert call_args[0][0].endswith("/certs")


class TestKeycloakClientErrorHandling:
    """Test error handling."""
    
    def test_handle_401_error(self, keycloak_client):
        """Test handling 401 authentication error."""
        error_response = {"error": "invalid_token", "error_description": "Token expired"}
        mock_response = create_mock_response(401, error_response)
        keycloak_client.http_client.post.return_value = mock_response
        
        with pytest.raises(AuthenticationError) as exc_info:
            keycloak_client.get_token_client_credentials()
        
        assert exc_info.value.status_code == 401
        assert exc_info.value.error_code == "invalid_token"
    
    def test_handle_network_error(self, keycloak_client):
        """Test handling network errors."""
        keycloak_client.http_client.post.side_effect = httpx.ConnectError("Connection failed")
        
        with pytest.raises(NetworkError) as exc_info:
            keycloak_client.get_token_client_credentials()
        
        assert "Failed to connect" in str(exc_info.value)
        assert isinstance(exc_info.value.original_exception, httpx.ConnectError)
    
    def test_handle_invalid_json_response(self, keycloak_client):
        """Test handling invalid JSON response."""
        mock_response = create_mock_response(200, None)
        mock_response.json.side_effect = ValueError("Invalid JSON")
        keycloak_client.http_client.post.return_value = mock_response
        
        with pytest.raises(KeycloakException, match="Failed to parse token response"):
            keycloak_client.get_token_client_credentials()


class TestAsyncKeycloakClient:
    """Test AsyncKeycloakClient."""
    
    @pytest.mark.asyncio
    async def test_async_client_credentials(self, async_keycloak_client, sample_token_response):
        """Test async client credentials token request."""
        mock_response = create_mock_response(200, sample_token_response)
        async_keycloak_client.http_client.post.return_value = mock_response
        
        token_response = await async_keycloak_client.get_token_client_credentials(scope="openid")
        
        assert isinstance(token_response, TokenResponse)
        assert token_response.access_token.startswith("eyJ")
        
        # Verify the request
        async_keycloak_client.http_client.post.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_async_introspect_token(self, async_keycloak_client, sample_introspection_response):
        """Test async token introspection."""
        mock_response = create_mock_response(200, sample_introspection_response)
        async_keycloak_client.http_client.post.return_value = mock_response
        
        introspection_response = await async_keycloak_client.introspect_token("test-token")
        
        assert isinstance(introspection_response, TokenIntrospectionResponse)
        assert introspection_response.active is True
    
    @pytest.mark.asyncio
    async def test_async_get_userinfo(self, async_keycloak_client, sample_userinfo_response):
        """Test async get user info."""
        mock_response = create_mock_response(200, sample_userinfo_response)
        async_keycloak_client.http_client.get.return_value = mock_response
        
        userinfo_response = await async_keycloak_client.get_userinfo("access-token")
        
        assert isinstance(userinfo_response, UserInfoResponse)
        assert userinfo_response.preferred_username == "testuser"
    
    @pytest.mark.asyncio
    async def test_async_get_well_known_config(self, async_keycloak_client, sample_well_known_response):
        """Test async get well-known configuration."""
        mock_response = create_mock_response(200, sample_well_known_response)
        async_keycloak_client.http_client.get.return_value = mock_response
        
        well_known = await async_keycloak_client.get_well_known_config()
        
        assert "issuer" in well_known
        assert "token_endpoint" in well_known
    
    @pytest.mark.asyncio
    async def test_async_context_manager(self, mock_async_http_client):
        """Test async client as context manager."""
        async with AsyncKeycloakClient(
            server_url="https://keycloak.example.com",
            realm="test-realm",
            http_client=mock_async_http_client,
        ) as client:
            assert client is not None
        
        # Should not close the client we don't own
        mock_async_http_client.aclose.assert_not_called()


class TestClientUtilities:
    """Test client utility functions."""
    
    @patch.dict("os.environ", {
        "KEYCLOAK_SERVER_URL": "https://keycloak.example.com",
        "KEYCLOAK_REALM": "test-realm",
        "KEYCLOAK_CLIENT_ID": "env-client",
        "KEYCLOAK_CLIENT_SECRET": "env-secret"
    })
    def test_create_client_from_env(self):
        """Test creating client from environment variables."""
        client = create_client_from_env()
        
        assert isinstance(client, KeycloakClient)
        assert client.server_url == "https://keycloak.example.com"
        assert client.realm == "test-realm"
        assert client.client_id == "env-client"
        assert client.client_secret == "env-secret"
    
    @patch.dict("os.environ", {
        "KEYCLOAK_SERVER_URL": "https://keycloak.example.com",
        "KEYCLOAK_REALM": "test-realm",
    })
    def test_create_async_client_from_env(self):
        """Test creating async client from environment variables."""
        client = create_client_from_env(async_client=True)
        
        assert isinstance(client, AsyncKeycloakClient)
        assert client.server_url == "https://keycloak.example.com"
        assert client.realm == "test-realm"
    
    def test_create_client_from_env_missing_server_url(self):
        """Test creating client with missing server URL in env."""
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(ConfigurationError, match="KEYCLOAK_SERVER_URL environment variable is required"):
                create_client_from_env()
    
    def test_create_client_from_env_missing_realm(self):
        """Test creating client with missing realm in env."""
        with patch.dict("os.environ", {"KEYCLOAK_SERVER_URL": "https://keycloak.example.com"}, clear=True):
            with pytest.raises(ConfigurationError, match="KEYCLOAK_REALM environment variable is required"):
                create_client_from_env()