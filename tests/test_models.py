"""Tests for Pydantic models."""

from datetime import datetime
from pycloak.models import (
    TokenResponse,
    TokenIntrospectionResponse,
    UserInfoResponse,
    KeycloakError,
    ClientCredentialsRequest,
    AuthorizationCodeRequest,
    RefreshTokenRequest,
    PasswordRequest,
    TokenIntrospectionRequest,
    User,
    Role,
    Client,
)


class TestTokenResponse:
    """Test TokenResponse model."""
    
    def test_minimal_token_response(self):
        """Test token response with minimal required fields."""
        data = {
            "access_token": "test-access-token",
        }
        
        response = TokenResponse.model_validate(data)
        assert response.access_token == "test-access-token"
        assert response.token_type == "Bearer"  # default value
        assert response.expires_in is None
        assert response.refresh_token is None
    
    def test_complete_token_response(self, sample_token_response):
        """Test token response with all fields."""
        response = TokenResponse.model_validate(sample_token_response)
        
        assert response.access_token.startswith("eyJ")
        assert response.token_type == "Bearer"
        assert response.expires_in == 300
        assert response.refresh_expires_in == 1800
        assert response.refresh_token.startswith("eyJ")
        assert response.id_token.startswith("eyJ")
        assert response.session_state == "b0f5a0ad-8b4a-4e6e-9e8f-4c4a6e5d7c8b"
        assert response.scope == "openid profile email"
        assert response.not_before_policy == 0
    
    def test_scopes_list_property(self):
        """Test scopes_list property."""
        data = {
            "access_token": "test-token",
            "scope": "openid profile email"
        }
        
        response = TokenResponse.model_validate(data)
        assert response.scopes_list == ["openid", "profile", "email"]
        
        # Test empty scope
        data_no_scope = {"access_token": "test-token"}
        response_no_scope = TokenResponse.model_validate(data_no_scope)
        assert response_no_scope.scopes_list == []
    
    def test_not_before_policy_alias(self):
        """Test not-before-policy field alias."""
        data = {
            "access_token": "test-token",
            "not-before-policy": 1234567890
        }
        
        response = TokenResponse.model_validate(data)
        assert response.not_before_policy == 1234567890


class TestTokenIntrospectionResponse:
    """Test TokenIntrospectionResponse model."""
    
    def test_inactive_token(self):
        """Test inactive token response."""
        data = {"active": False}
        
        response = TokenIntrospectionResponse.model_validate(data)
        assert response.active is False
        assert response.scope is None
        assert response.client_id is None
    
    def test_complete_introspection_response(self, sample_introspection_response):
        """Test complete introspection response."""
        response = TokenIntrospectionResponse.model_validate(sample_introspection_response)
        
        assert response.active is True
        assert response.scope == "openid profile email"
        assert response.client_id == "test-client"
        assert response.username == "testuser"
        assert response.token_type == "Bearer"
        assert response.exp == 1700000000
        assert response.iat == 1699999700
        assert response.sub == "123e4567-e89b-12d3-a456-426614174000"
        assert response.preferred_username == "testuser"
        assert response.email == "testuser@example.com"
        assert response.email_verified is True
        assert response.name == "Test User"
        assert response.given_name == "Test"
        assert response.family_name == "User"
    
    def test_scopes_list_property(self):
        """Test scopes_list property."""
        data = {
            "active": True,
            "scope": "openid profile email"
        }
        
        response = TokenIntrospectionResponse.model_validate(data)
        assert response.scopes_list == ["openid", "profile", "email"]
    
    def test_has_scope_method(self):
        """Test has_scope method."""
        data = {
            "active": True,
            "scope": "openid profile email"
        }
        
        response = TokenIntrospectionResponse.model_validate(data)
        assert response.has_scope("openid") is True
        assert response.has_scope("profile") is True
        assert response.has_scope("admin") is False
    
    def test_has_realm_role_method(self, sample_introspection_response):
        """Test has_realm_role method."""
        response = TokenIntrospectionResponse.model_validate(sample_introspection_response)
        
        assert response.has_realm_role("user") is True
        assert response.has_realm_role("offline_access") is True
        assert response.has_realm_role("admin") is False
    
    def test_has_client_role_method(self, sample_introspection_response):
        """Test has_client_role method."""
        response = TokenIntrospectionResponse.model_validate(sample_introspection_response)
        
        assert response.has_client_role("test-client", "client-role-1") is True
        assert response.has_client_role("test-client", "client-role-2") is True
        assert response.has_client_role("test-client", "non-existent") is False
        assert response.has_client_role("other-client", "client-role-1") is False
    
    def test_is_expired_property(self):
        """Test is_expired property."""
        # Create response with expiration in the past
        past_timestamp = int(datetime(2020, 1, 1).timestamp())
        data = {
            "active": True,
            "exp": past_timestamp
        }
        
        response = TokenIntrospectionResponse.model_validate(data)
        assert response.is_expired is True
        
        # Create response with expiration in the future
        future_timestamp = int(datetime(2030, 1, 1).timestamp())
        data_future = {
            "active": True,
            "exp": future_timestamp
        }
        
        response_future = TokenIntrospectionResponse.model_validate(data_future)
        assert response_future.is_expired is False


class TestUserInfoResponse:
    """Test UserInfoResponse model."""
    
    def test_minimal_userinfo(self):
        """Test userinfo with only required sub field."""
        data = {"sub": "123e4567-e89b-12d3-a456-426614174000"}
        
        response = UserInfoResponse.model_validate(data)
        assert response.sub == "123e4567-e89b-12d3-a456-426614174000"
        assert response.preferred_username is None
        assert response.email is None
    
    def test_complete_userinfo(self, sample_userinfo_response):
        """Test complete userinfo response."""
        response = UserInfoResponse.model_validate(sample_userinfo_response)
        
        assert response.sub == "123e4567-e89b-12d3-a456-426614174000"
        assert response.preferred_username == "testuser"
        assert response.name == "Test User"
        assert response.given_name == "Test"
        assert response.family_name == "User"
        assert response.email == "testuser@example.com"
        assert response.email_verified is True
        assert response.picture == "https://example.com/avatar.jpg"
        assert response.updated_at == 1699999700


class TestKeycloakError:
    """Test KeycloakError model."""
    
    def test_minimal_error(self):
        """Test error with only required field."""
        data = {"error": "invalid_grant"}
        
        error = KeycloakError.model_validate(data)
        assert error.error == "invalid_grant"
        assert error.error_description is None
        assert error.error_uri is None
    
    def test_complete_error(self, sample_error_response):
        """Test complete error response."""
        error = KeycloakError.model_validate(sample_error_response)
        
        assert error.error == "invalid_grant"
        assert error.error_description == "Invalid authorization code"


class TestRequestModels:
    """Test request models."""
    
    def test_client_credentials_request(self):
        """Test ClientCredentialsRequest model."""
        request = ClientCredentialsRequest(
            client_id="test-client",
            client_secret="test-secret",
            scope="openid profile"
        )
        
        assert request.grant_type == "client_credentials"
        assert request.client_id == "test-client"
        assert request.client_secret == "test-secret"
        assert request.scope == "openid profile"
    
    def test_authorization_code_request(self):
        """Test AuthorizationCodeRequest model."""
        request = AuthorizationCodeRequest(
            code="auth-code-123",
            redirect_uri="https://app.example.com/callback",
            client_id="test-client",
            client_secret="test-secret",
            code_verifier="pkce-verifier"
        )
        
        assert request.grant_type == "authorization_code"
        assert request.code == "auth-code-123"
        assert request.redirect_uri == "https://app.example.com/callback"
        assert request.client_id == "test-client"
        assert request.client_secret == "test-secret"
        assert request.code_verifier == "pkce-verifier"
    
    def test_refresh_token_request(self):
        """Test RefreshTokenRequest model."""
        request = RefreshTokenRequest(
            refresh_token="refresh-token-123",
            client_id="test-client",
            scope="openid profile"
        )
        
        assert request.grant_type == "refresh_token"
        assert request.refresh_token == "refresh-token-123"
        assert request.client_id == "test-client"
        assert request.scope == "openid profile"
    
    def test_password_request(self):
        """Test PasswordRequest model."""
        request = PasswordRequest(
            username="testuser",
            password="testpass",
            client_id="test-client",
            scope="openid profile"
        )
        
        assert request.grant_type == "password"
        assert request.username == "testuser"
        assert request.password == "testpass"
        assert request.client_id == "test-client"
        assert request.scope == "openid profile"
    
    def test_token_introspection_request(self):
        """Test TokenIntrospectionRequest model."""
        request = TokenIntrospectionRequest(
            token="token-to-introspect",
            token_type_hint="access_token",
            client_id="test-client",
            client_secret="test-secret"
        )
        
        assert request.token == "token-to-introspect"
        assert request.token_type_hint == "access_token"
        assert request.client_id == "test-client"
        assert request.client_secret == "test-secret"


class TestAdminModels:
    """Test admin API models."""
    
    def test_user_model(self):
        """Test User model."""
        user_data = {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "username": "testuser",
            "email": "testuser@example.com",
            "emailVerified": True,
            "firstName": "Test",
            "lastName": "User",
            "enabled": True,
            "createdTimestamp": 1699999700,
            "attributes": {
                "customAttribute": ["value1", "value2"]
            },
            "requiredActions": ["UPDATE_PASSWORD"]
        }
        
        user = User.model_validate(user_data)
        
        assert user.id == "123e4567-e89b-12d3-a456-426614174000"
        assert user.username == "testuser"
        assert user.email == "testuser@example.com"
        assert user.email_verified is True
        assert user.first_name == "Test"
        assert user.last_name == "User"
        assert user.enabled is True
        assert user.created_timestamp == 1699999700
        assert user.attributes["customAttribute"] == ["value1", "value2"]
        assert user.required_actions == ["UPDATE_PASSWORD"]
    
    def test_role_model(self):
        """Test Role model."""
        role_data = {
            "id": "role-uuid",
            "name": "test-role",
            "description": "A test role",
            "composite": False,
            "clientRole": False,
            "containerId": "realm-id"
        }
        
        role = Role.model_validate(role_data)
        
        assert role.id == "role-uuid"
        assert role.name == "test-role"
        assert role.description == "A test role"
        assert role.composite is False
        assert role.client_role is False
        assert role.container_id == "realm-id"
    
    def test_client_model(self):
        """Test Client model."""
        client_data = {
            "id": "client-uuid",
            "clientId": "test-client",
            "name": "Test Client",
            "description": "A test client",
            "enabled": True,
            "clientAuthenticatorType": "client-secret",
            "redirectUris": ["https://app.example.com/callback"],
            "webOrigins": ["https://app.example.com"],
            "publicClient": False,
            "protocol": "openid-connect",
            "attributes": {
                "custom.attribute": "value"
            }
        }
        
        client = Client.model_validate(client_data)
        
        assert client.id == "client-uuid"
        assert client.client_id == "test-client"
        assert client.name == "Test Client"
        assert client.description == "A test client"
        assert client.enabled is True
        assert client.client_authenticator_type == "client-secret"
        assert client.redirect_uris == ["https://app.example.com/callback"]
        assert client.web_origins == ["https://app.example.com"]
        assert client.public_client is False
        assert client.protocol == "openid-connect"
        assert client.attributes["custom.attribute"] == "value"


class TestModelValidation:
    """Test model validation and error handling."""
    
    def test_extra_fields_allowed(self):
        """Test that extra fields are allowed in models."""
        data = {
            "access_token": "test-token",
            "custom_field": "custom_value",
            "another_field": {"nested": "value"}
        }
        
        response = TokenResponse.model_validate(data)
        assert response.access_token == "test-token"
        # Extra fields should be accessible via model_extra
        assert hasattr(response, 'custom_field')
    
    def test_field_aliases(self):
        """Test that field aliases work correctly."""
        data = {
            "access_token": "test-token",
            "not-before-policy": 1234567890
        }
        
        response = TokenResponse.model_validate(data)
        assert response.not_before_policy == 1234567890
        
        # Test admin model aliases
        user_data = {
            "sub": "user-id",
            "emailVerified": True,
            "firstName": "Test",
            "lastName": "User"
        }
        
        user = User.model_validate(user_data)
        assert user.email_verified is True
        assert user.first_name == "Test"
        assert user.last_name == "User"