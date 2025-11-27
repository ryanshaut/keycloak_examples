"""Tests for Keycloak exception classes."""

import httpx
from unittest.mock import Mock

from pycloak.exceptions import (
    KeycloakException,
    AuthenticationError,
    AuthorizationError,
    TokenExpiredError,
    InvalidTokenError,
    InvalidGrantError,
    InvalidClientError,
    InvalidScopeError,
    ServerError,
    NetworkError,
    ConfigurationError,
    create_exception_from_response,
    create_network_exception,
)


class TestKeycloakException:
    """Test base KeycloakException class."""
    
    def test_basic_exception(self):
        """Test basic exception creation."""
        exc = KeycloakException("Test error")
        
        assert str(exc) == "Test error"
        assert exc.message == "Test error"
        assert exc.response is None
        assert exc.error_details == {}
        assert exc.status_code is None
        assert exc.headers == {}
    
    def test_exception_with_response(self, sample_error_response):
        """Test exception with HTTP response."""
        mock_response = Mock(spec=httpx.Response)
        mock_response.status_code = 400
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = sample_error_response
        
        exc = KeycloakException("Test error", response=mock_response)
        
        assert str(exc) == "Test error (HTTP 400)"
        assert exc.status_code == 400
        assert exc.headers == {"content-type": "application/json"}
        assert exc.error_details == sample_error_response
        assert exc.error_code == "invalid_grant"
        assert exc.error_description == "Invalid authorization code"
    
    def test_exception_with_non_json_response(self):
        """Test exception with non-JSON response."""
        mock_response = Mock(spec=httpx.Response)
        mock_response.status_code = 500
        mock_response.headers = {"content-type": "text/html"}
        mock_response.json.side_effect = ValueError("No JSON")
        
        exc = KeycloakException("Server error", response=mock_response)
        
        assert str(exc) == "Server error (HTTP 500)"
        assert exc.status_code == 500
        assert exc.error_details == {}
    
    def test_exception_repr(self):
        """Test exception string representation."""
        exc = KeycloakException(
            "Test error",
            error_details={"error": "test_error"}
        )
        
        repr_str = repr(exc)
        assert "KeycloakException" in repr_str
        assert "Test error" in repr_str
        assert "test_error" in repr_str


class TestSpecificExceptions:
    """Test specific exception types."""
    
    def test_authentication_error(self):
        """Test AuthenticationError."""
        exc = AuthenticationError("Auth failed")
        
        assert isinstance(exc, KeycloakException)
        assert str(exc) == "Auth failed"
    
    def test_authorization_error(self):
        """Test AuthorizationError."""
        exc = AuthorizationError("Access denied")
        
        assert isinstance(exc, KeycloakException)
        assert str(exc) == "Access denied"
    
    def test_token_expired_error(self):
        """Test TokenExpiredError."""
        exc = TokenExpiredError("Token expired")
        
        assert isinstance(exc, AuthenticationError)
        assert isinstance(exc, KeycloakException)
        assert str(exc) == "Token expired"
    
    def test_invalid_token_error(self):
        """Test InvalidTokenError."""
        exc = InvalidTokenError("Invalid token")
        
        assert isinstance(exc, AuthenticationError)
        assert str(exc) == "Invalid token"
    
    def test_invalid_grant_error(self):
        """Test InvalidGrantError."""
        exc = InvalidGrantError("Invalid grant")
        
        assert isinstance(exc, AuthenticationError)
        assert str(exc) == "Invalid grant"
    
    def test_invalid_client_error(self):
        """Test InvalidClientError."""
        exc = InvalidClientError("Invalid client")
        
        assert isinstance(exc, AuthenticationError)
        assert str(exc) == "Invalid client"
    
    def test_invalid_scope_error(self):
        """Test InvalidScopeError."""
        exc = InvalidScopeError("Invalid scope")
        
        assert isinstance(exc, AuthenticationError)
        assert str(exc) == "Invalid scope"
    
    def test_server_error(self):
        """Test ServerError."""
        exc = ServerError("Server error")
        
        assert isinstance(exc, KeycloakException)
        assert str(exc) == "Server error"
    
    def test_network_error(self):
        """Test NetworkError."""
        original_exc = ConnectionError("Connection failed")
        exc = NetworkError("Network error", original_exc)
        
        assert isinstance(exc, KeycloakException)
        assert str(exc) == "Network error"
        assert exc.original_exception == original_exc
    
    def test_configuration_error(self):
        """Test ConfigurationError."""
        exc = ConfigurationError("Config error")
        
        assert isinstance(exc, KeycloakException)
        assert str(exc) == "Config error"


class TestExceptionCreation:
    """Test exception creation utilities."""
    
    def test_create_exception_from_401_response(self):
        """Test creating exception from 401 response."""
        mock_response = Mock(spec=httpx.Response)
        mock_response.status_code = 401
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {"error": "invalid_token", "error_description": "Token invalid"}
        
        exc = create_exception_from_response(mock_response)
        
        assert isinstance(exc, InvalidTokenError)
        assert exc.status_code == 401
        assert exc.error_code == "invalid_token"
        assert exc.error_description == "Token invalid"
    
    def test_create_exception_from_401_expired_token(self):
        """Test creating TokenExpiredError from 401 response."""
        mock_response = Mock(spec=httpx.Response)
        mock_response.status_code = 401
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {"error": "token_expired", "error_description": "Token has expired"}
        
        exc = create_exception_from_response(mock_response)
        
        assert isinstance(exc, TokenExpiredError)
        assert "expired" in exc.error_description.lower()
    
    def test_create_exception_from_403_response(self):
        """Test creating exception from 403 response."""
        mock_response = Mock(spec=httpx.Response)
        mock_response.status_code = 403
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {"error": "insufficient_scope", "error_description": "Insufficient permissions"}
        
        exc = create_exception_from_response(mock_response)
        
        assert isinstance(exc, AuthorizationError)
        assert exc.status_code == 403
    
    def test_create_exception_from_invalid_grant(self):
        """Test creating InvalidGrantError from response."""
        mock_response = Mock(spec=httpx.Response)
        mock_response.status_code = 400
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {"error": "invalid_grant", "error_description": "Authorization code invalid"}
        
        exc = create_exception_from_response(mock_response)
        
        assert isinstance(exc, InvalidGrantError)
        assert exc.error_code == "invalid_grant"
    
    def test_create_exception_from_invalid_client(self):
        """Test creating InvalidClientError from response."""
        mock_response = Mock(spec=httpx.Response)
        mock_response.status_code = 401
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {"error": "invalid_client", "error_description": "Client authentication failed"}
        
        exc = create_exception_from_response(mock_response)
        
        assert isinstance(exc, InvalidClientError)
        assert exc.error_code == "invalid_client"
    
    def test_create_exception_from_invalid_scope(self):
        """Test creating InvalidScopeError from response."""
        mock_response = Mock(spec=httpx.Response)
        mock_response.status_code = 400
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {"error": "invalid_scope", "error_description": "Requested scope invalid"}
        
        exc = create_exception_from_response(mock_response)
        
        assert isinstance(exc, InvalidScopeError)
        assert exc.error_code == "invalid_scope"
    
    def test_create_exception_from_500_response(self):
        """Test creating ServerError from 500 response."""
        mock_response = Mock(spec=httpx.Response)
        mock_response.status_code = 500
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {"error": "server_error", "error_description": "Internal server error"}
        
        exc = create_exception_from_response(mock_response)
        
        assert isinstance(exc, ServerError)
        assert exc.status_code == 500
    
    def test_create_exception_from_generic_error(self):
        """Test creating generic exception from unspecified error."""
        mock_response = Mock(spec=httpx.Response)
        mock_response.status_code = 422
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {"error": "validation_error", "error_description": "Request validation failed"}
        
        exc = create_exception_from_response(mock_response)
        
        assert isinstance(exc, AuthenticationError)
        assert exc.status_code == 422
    
    def test_create_exception_with_no_json(self):
        """Test creating exception when response has no JSON."""
        mock_response = Mock(spec=httpx.Response)
        mock_response.status_code = 400
        mock_response.headers = {"content-type": "text/html"}
        mock_response.json.side_effect = ValueError("No JSON")
        
        exc = create_exception_from_response(mock_response)
        
        assert isinstance(exc, AuthenticationError)
        assert exc.status_code == 400
        assert "Bad request" in str(exc)


class TestNetworkExceptionCreation:
    """Test network exception creation."""
    
    def test_create_network_exception_timeout(self):
        """Test creating NetworkError from timeout."""
        original_exc = httpx.TimeoutException("Request timed out")
        
        exc = create_network_exception(original_exc)
        
        assert isinstance(exc, NetworkError)
        assert "Timeout communicating" in str(exc)
        assert exc.original_exception == original_exc
    
    def test_create_network_exception_connect_error(self):
        """Test creating NetworkError from connection error."""
        original_exc = httpx.ConnectError("Connection refused")
        
        exc = create_network_exception(original_exc)
        
        assert isinstance(exc, NetworkError)
        assert "Failed to connect" in str(exc)
        assert exc.original_exception == original_exc
    
    def test_create_network_exception_request_error(self):
        """Test creating NetworkError from generic request error."""
        original_exc = httpx.RequestError("Request failed")
        
        exc = create_network_exception(original_exc)
        
        assert isinstance(exc, NetworkError)
        assert "Request error" in str(exc)
        assert exc.original_exception == original_exc
    
    def test_create_network_exception_generic(self):
        """Test creating NetworkError from generic exception."""
        original_exc = Exception("Generic error")
        
        exc = create_network_exception(original_exc)
        
        assert isinstance(exc, NetworkError)
        assert "Network error" in str(exc)
        assert exc.original_exception == original_exc