"""Tests for admin API functionality."""

import pytest
from unittest.mock import Mock
from pycloak.client import KeycloakClient, AsyncKeycloakClient
from pycloak.models import TokenResponse
from pycloak.exceptions import KeycloakException, AuthenticationError
from tests.conftest import create_mock_response


class TestKeycloakAdminOperations:
    """Test admin operations for KeycloakClient."""
    
    def test_get_admin_token(self, keycloak_client, sample_token_response):
        """Test getting admin token."""
        mock_response = create_mock_response(200, sample_token_response)
        keycloak_client.http_client.post.return_value = mock_response
        
        token_response = keycloak_client.get_admin_token("admin", "password")
        
        assert isinstance(token_response, TokenResponse)
        
        # Verify the request was made correctly
        call_args = keycloak_client.http_client.post.call_args
        data = call_args[1]["data"]
        
        assert data["grant_type"] == "password"
        assert data["username"] == "admin"
        assert data["password"] == "password"
        assert data["client_id"] == "admin-cli"
    
    def test_create_user(self, keycloak_client):
        """Test creating a user."""
        mock_response = create_mock_response(
            201, 
            {},
            headers={"Location": "https://keycloak.example.com/admin/realms/test/users/12345"}
        )
        keycloak_client.http_client.post.return_value = mock_response
        
        user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "firstName": "Test",
            "lastName": "User"
        }
        
        user_id = keycloak_client.create_user(
            "admin-token",
            user_data,
            temporary_password="temp123"
        )
        
        assert user_id == "12345"
        
        # Verify the request
        call_args = keycloak_client.http_client.post.call_args
        assert call_args[0][0].endswith("/users")
        
        headers = call_args[1]["headers"]
        assert headers["Authorization"] == "Bearer admin-token"
        assert headers["Content-Type"] == "application/json"
        
        payload = call_args[1]["json"]
        assert payload["username"] == "testuser"
        assert payload["enabled"] is True
        assert len(payload["credentials"]) == 1
        assert payload["credentials"][0]["value"] == "temp123"
        assert payload["credentials"][0]["temporary"] is True
    
    def test_create_user_no_location_header(self, keycloak_client):
        """Test creating user when no Location header is returned."""
        mock_response = create_mock_response(201, {})
        keycloak_client.http_client.post.return_value = mock_response
        
        with pytest.raises(KeycloakException, match="User created but no Location header found"):
            keycloak_client.create_user("admin-token", {"username": "test"})
    
    def test_get_user_by_username(self, keycloak_client):
        """Test getting user by username."""
        user_data = {
            "id": "user-123",
            "username": "testuser",
            "email": "test@example.com",
            "firstName": "Test",
            "lastName": "User"
        }
        mock_response = create_mock_response(200, [user_data])
        keycloak_client.http_client.get.return_value = mock_response
        
        result = keycloak_client.get_user_by_username("admin-token", "testuser")
        
        assert result == user_data
        
        # Verify the request
        call_args = keycloak_client.http_client.get.call_args
        params = call_args[1]["params"]
        assert params["username"] == "testuser"
        assert params["exact"] == "true"
    
    def test_get_user_by_username_not_found(self, keycloak_client):
        """Test getting user by username when user doesn't exist."""
        mock_response = create_mock_response(200, [])
        keycloak_client.http_client.get.return_value = mock_response
        
        result = keycloak_client.get_user_by_username("admin-token", "nonexistent")
        
        assert result is None
    
    def test_create_client(self, keycloak_client):
        """Test creating a client."""
        mock_response = create_mock_response(
            201,
            {},
            headers={"Location": "https://keycloak.example.com/admin/realms/test/clients/client-123"}
        )
        keycloak_client.http_client.post.return_value = mock_response
        
        client_data = {
            "clientId": "my-app",
            "name": "My Application",
            "enabled": True,
            "publicClient": False,
            "redirectUris": ["https://app.example.com/*"]
        }
        
        client_id = keycloak_client.create_client("admin-token", client_data)
        
        assert client_id == "client-123"
        
        # Verify the request
        call_args = keycloak_client.http_client.post.call_args
        assert call_args[0][0].endswith("/clients")
        assert call_args[1]["json"] == client_data
    
    def test_get_client_by_client_id(self, keycloak_client):
        """Test getting client by clientId."""
        client_data = {
            "id": "internal-123",
            "clientId": "my-app",
            "name": "My Application",
            "enabled": True
        }
        mock_response = create_mock_response(200, [client_data])
        keycloak_client.http_client.get.return_value = mock_response
        
        result = keycloak_client.get_client_by_client_id("admin-token", "my-app")
        
        assert result == client_data
        
        # Verify the request
        call_args = keycloak_client.http_client.get.call_args
        params = call_args[1]["params"]
        assert params["clientId"] == "my-app"
    
    def test_get_client_secret(self, keycloak_client):
        """Test getting client secret."""
        secret_data = {"value": "super-secret-123"}
        mock_response = create_mock_response(200, secret_data)
        keycloak_client.http_client.get.return_value = mock_response
        
        secret = keycloak_client.get_client_secret("admin-token", "internal-123")
        
        assert secret == "super-secret-123"
        
        # Verify the request
        call_args = keycloak_client.http_client.get.call_args
        assert "internal-123/client-secret" in call_args[0][0]
    
    def test_create_realm_role(self, keycloak_client):
        """Test creating a realm role."""
        mock_response = create_mock_response(201, {})
        keycloak_client.http_client.post.return_value = mock_response
        
        keycloak_client.create_realm_role("admin-token", "test-role", "Test role description")
        
        # Verify the request
        call_args = keycloak_client.http_client.post.call_args
        assert call_args[0][0].endswith("/roles")
        
        payload = call_args[1]["json"]
        assert payload["name"] == "test-role"
        assert payload["description"] == "Test role description"
    
    def test_assign_realm_role_to_user(self, keycloak_client):
        """Test assigning realm role to user."""
        role_data = {
            "id": "role-123",
            "name": "test-role",
            "description": "Test role"
        }
        
        # Mock the role retrieval
        role_response = create_mock_response(200, role_data)
        assign_response = create_mock_response(204, {})
        
        keycloak_client.http_client.get.return_value = role_response
        keycloak_client.http_client.post.return_value = assign_response
        
        keycloak_client.assign_realm_role_to_user("admin-token", "user-123", "test-role")
        
        # Verify role was fetched
        get_call = keycloak_client.http_client.get.call_args
        assert "roles/test-role" in get_call[0][0]
        
        # Verify role assignment
        post_call = keycloak_client.http_client.post.call_args
        assert "user-123/role-mappings/realm" in post_call[0][0]
        assert post_call[1]["json"] == [role_data]


class TestAsyncKeycloakAdminOperations:
    """Test async admin operations for AsyncKeycloakClient."""
    
    @pytest.mark.asyncio
    async def test_async_get_admin_token(self, async_keycloak_client, sample_token_response):
        """Test async admin token acquisition."""
        mock_response = create_mock_response(200, sample_token_response)
        async_keycloak_client.http_client.post.return_value = mock_response
        
        token_response = await async_keycloak_client.get_admin_token("admin", "password")
        
        assert isinstance(token_response, TokenResponse)
    
    @pytest.mark.asyncio
    async def test_async_create_user(self, async_keycloak_client):
        """Test async user creation."""
        mock_response = create_mock_response(
            201,
            {},
            headers={"Location": "https://keycloak.example.com/admin/realms/test/users/async-123"}
        )
        async_keycloak_client.http_client.post.return_value = mock_response
        
        user_data = {"username": "asyncuser", "email": "async@example.com"}
        
        user_id = await async_keycloak_client.create_user("admin-token", user_data)
        
        assert user_id == "async-123"
    
    @pytest.mark.asyncio
    async def test_async_get_user_by_username(self, async_keycloak_client):
        """Test async user retrieval."""
        user_data = {"id": "async-user-123", "username": "asyncuser"}
        mock_response = create_mock_response(200, [user_data])
        async_keycloak_client.http_client.get.return_value = mock_response
        
        result = await async_keycloak_client.get_user_by_username("admin-token", "asyncuser")
        
        assert result == user_data
    
    @pytest.mark.asyncio
    async def test_async_create_client(self, async_keycloak_client):
        """Test async client creation."""
        mock_response = create_mock_response(
            201,
            {},
            headers={"Location": "https://keycloak.example.com/admin/realms/test/clients/async-client-123"}
        )
        async_keycloak_client.http_client.post.return_value = mock_response
        
        client_data = {"clientId": "async-app", "name": "Async App"}
        
        client_id = await async_keycloak_client.create_client("admin-token", client_data)
        
        assert client_id == "async-client-123"


class TestAdminHeaders:
    """Test admin header generation."""
    
    def test_get_admin_headers(self, keycloak_client):
        """Test admin headers generation."""
        headers = keycloak_client._get_admin_headers("test-admin-token")
        
        assert headers["Authorization"] == "Bearer test-admin-token"
        assert headers["Content-Type"] == "application/json"
        assert headers["Accept"] == "application/json"
        assert headers["User-Agent"] == "pycloak/0.1.0"