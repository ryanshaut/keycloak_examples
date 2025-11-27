"""
Exception classes for PyCloak Keycloak client.

This module defines custom exceptions for different types of errors
that can occur when interacting with Keycloak APIs.
"""

from typing import Any, Dict, Optional
import httpx


class KeycloakException(Exception):
    """
    Base exception for all Keycloak-related errors.
    
    This is the parent class for all custom Keycloak exceptions.
    It provides common functionality for handling HTTP responses
    and error details.
    """
    
    def __init__(
        self, 
        message: str, 
        response: Optional[httpx.Response] = None,
        error_details: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize a Keycloak exception.
        
        Args:
            message: Human-readable error message
            response: HTTP response that caused the error (if any)
            error_details: Additional error details from Keycloak
        """
        super().__init__(message)
        self.message = message
        self.response = response
        self.error_details = error_details or {}
        
        # Extract additional info from response if available
        if response is not None:
            self.status_code = response.status_code
            self.headers = dict(response.headers)
            
            # Try to extract error details from response body
            try:
                if response.headers.get('content-type', '').startswith('application/json'):
                    response_data = response.json()
                    if isinstance(response_data, dict):
                        self.error_details.update(response_data)
            except Exception:
                # If we can't parse the response, that's okay
                pass
        else:
            self.status_code = None
            self.headers = {}
    
    def __str__(self) -> str:
        """Return string representation of the exception."""
        if self.status_code:
            return f"{self.message} (HTTP {self.status_code})"
        return self.message
    
    def __repr__(self) -> str:
        """Return detailed representation of the exception."""
        return (
            f"{self.__class__.__name__}("
            f"message='{self.message}', "
            f"status_code={self.status_code}, "
            f"error_details={self.error_details})"
        )
    
    @property
    def error_code(self) -> Optional[str]:
        """Get the Keycloak error code from error details."""
        return self.error_details.get('error')
    
    @property
    def error_description(self) -> Optional[str]:
        """Get the Keycloak error description from error details."""
        return self.error_details.get('error_description') or self.error_details.get('message')


class AuthenticationError(KeycloakException):
    """
    Raised when authentication with Keycloak fails.
    
    This includes scenarios like:
    - Invalid client credentials
    - Invalid username/password
    - Invalid authorization codes
    - Missing or malformed authentication headers
    """
    
    def __init__(
        self, 
        message: str = "Authentication failed",
        response: Optional[httpx.Response] = None,
        error_details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message, response, error_details)


class AuthorizationError(KeycloakException):
    """
    Raised when authorization fails (insufficient permissions).
    
    This includes scenarios like:
    - Missing required scopes
    - Insufficient role permissions
    - Access to forbidden resources
    - Invalid or expired tokens (when used for authorization)
    """
    
    def __init__(
        self, 
        message: str = "Authorization failed - insufficient permissions",
        response: Optional[httpx.Response] = None,
        error_details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message, response, error_details)


class TokenExpiredError(AuthenticationError):
    """
    Raised when a token has expired.
    
    This is a specific type of authentication error that indicates
    the token was valid at some point but has now expired.
    """
    
    def __init__(
        self, 
        message: str = "Token has expired",
        response: Optional[httpx.Response] = None,
        error_details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message, response, error_details)


class InvalidTokenError(AuthenticationError):
    """
    Raised when a token is invalid or malformed.
    
    This includes scenarios like:
    - Malformed JWT tokens
    - Tokens for the wrong audience
    - Tampered tokens
    - Tokens from unknown issuers
    """
    
    def __init__(
        self, 
        message: str = "Token is invalid or malformed",
        response: Optional[httpx.Response] = None,
        error_details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message, response, error_details)


class InvalidGrantError(AuthenticationError):
    """
    Raised when an OAuth2 grant is invalid.
    
    This includes scenarios like:
    - Invalid authorization codes
    - Invalid refresh tokens
    - Expired authorization codes
    - Grant type not supported
    """
    
    def __init__(
        self, 
        message: str = "Invalid grant",
        response: Optional[httpx.Response] = None,
        error_details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message, response, error_details)


class InvalidClientError(AuthenticationError):
    """
    Raised when client authentication fails.
    
    This includes scenarios like:
    - Unknown client ID
    - Invalid client secret
    - Client not authorized for the requested operation
    - Disabled client
    """
    
    def __init__(
        self, 
        message: str = "Invalid client credentials",
        response: Optional[httpx.Response] = None,
        error_details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message, response, error_details)


class InvalidScopeError(AuthenticationError):
    """
    Raised when requested scopes are invalid or unauthorized.
    
    This includes scenarios like:
    - Unknown scopes
    - Scopes not authorized for the client
    - Conflicting scope requests
    """
    
    def __init__(
        self, 
        message: str = "Invalid or unauthorized scope",
        response: Optional[httpx.Response] = None,
        error_details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message, response, error_details)


class ServerError(KeycloakException):
    """
    Raised when Keycloak server returns a server error (5xx).
    
    This indicates an internal server error or temporary unavailability.
    """
    
    def __init__(
        self, 
        message: str = "Keycloak server error",
        response: Optional[httpx.Response] = None,
        error_details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message, response, error_details)


class NetworkError(KeycloakException):
    """
    Raised when network-related errors occur.
    
    This includes scenarios like:
    - Connection timeouts
    - DNS resolution failures
    - SSL/TLS errors
    - Network unreachable
    """
    
    def __init__(
        self, 
        message: str = "Network error communicating with Keycloak",
        original_exception: Optional[Exception] = None
    ):
        super().__init__(message)
        self.original_exception = original_exception


class ConfigurationError(KeycloakException):
    """
    Raised when there are configuration errors.
    
    This includes scenarios like:
    - Missing required configuration
    - Invalid configuration values
    - Conflicting configuration options
    """
    
    def __init__(
        self, 
        message: str = "Keycloak client configuration error",
        error_details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message, error_details=error_details)


# =========================================================================
# Utility Functions for Exception Handling
# =========================================================================

def create_exception_from_response(response: httpx.Response) -> KeycloakException:
    """
    Create an appropriate exception from an HTTP response.
    
    This function analyzes the HTTP response and returns the most
    appropriate exception type based on the status code and error details.
    
    Args:
        response: HTTP response from Keycloak
        
    Returns:
        Appropriate KeycloakException subclass
    """
    status_code = response.status_code
    
    # Extract error details from response
    error_details = {}
    try:
        if response.headers.get('content-type', '').startswith('application/json'):
            error_details = response.json()
    except Exception:
        pass
    
    error_code = error_details.get('error', '').lower() if isinstance(error_details, dict) else ''
    error_message = error_details.get('error_description') or error_details.get('message', '')
    
    # Default message based on status code
    if not error_message:
        if status_code == 400:
            error_message = "Bad request"
        elif status_code == 401:
            error_message = "Unauthorized"
        elif status_code == 403:
            error_message = "Forbidden"
        elif status_code == 404:
            error_message = "Not found"
        elif status_code >= 500:
            error_message = "Server error"
        else:
            error_message = f"HTTP {status_code} error"
    
    # Choose exception type based on status code and error code
    if status_code == 401 or error_code in ['invalid_token', 'token_expired']:
        if error_code == 'token_expired' or 'expired' in error_message.lower():
            return TokenExpiredError(error_message, response, error_details)
        elif error_code == 'invalid_token':
            return InvalidTokenError(error_message, response, error_details)
        else:
            return AuthenticationError(error_message, response, error_details)
    
    elif status_code == 403:
        return AuthorizationError(error_message, response, error_details)
    
    elif error_code == 'invalid_grant':
        return InvalidGrantError(error_message, response, error_details)
    
    elif error_code == 'invalid_client':
        return InvalidClientError(error_message, response, error_details)
    
    elif error_code == 'invalid_scope':
        return InvalidScopeError(error_message, response, error_details)
    
    elif status_code >= 500:
        return ServerError(error_message, response, error_details)
    
    elif status_code >= 400:
        # Generic client error
        return AuthenticationError(error_message, response, error_details)
    
    else:
        # Fallback for other status codes
        return KeycloakException(error_message, response, error_details)


def create_network_exception(original_exception: Exception) -> NetworkError:
    """
    Create a NetworkError from an underlying network exception.
    
    Args:
        original_exception: Original exception that occurred
        
    Returns:
        NetworkError with appropriate message
    """
    if isinstance(original_exception, httpx.TimeoutException):
        message = "Timeout communicating with Keycloak server"
    elif isinstance(original_exception, httpx.ConnectError):
        message = "Failed to connect to Keycloak server"
    elif isinstance(original_exception, httpx.RequestError):
        message = f"Request error: {original_exception}"
    else:
        message = f"Network error: {original_exception}"
    
    return NetworkError(message, original_exception)