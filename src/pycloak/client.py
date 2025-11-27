"""
Keycloak HTTP API client implementations.

This module provides both synchronous and asynchronous clients for
interacting with Keycloak's REST API using raw HTTP calls.
"""

import base64
from typing import Any, Dict, Optional, Union
import httpx
from urllib.parse import urlencode

from .endpoints import KeycloakEndpoints, GrantTypes, Scopes
from .models import (
    TokenResponse,
    TokenIntrospectionResponse,
    UserInfoResponse,
    KeycloakError,
    ClientCredentialsRequest,
    AuthorizationCodeRequest,
    RefreshTokenRequest,
    PasswordRequest,
    TokenIntrospectionRequest,
)
from .exceptions import (
    KeycloakException,
    AuthenticationError,
    NetworkError,
    ConfigurationError,
    create_exception_from_response,
    create_network_exception,
)


class BaseKeycloakClient:
    """
    Base class for Keycloak clients.
    
    Contains common functionality shared between sync and async clients.
    """
    
    def __init__(
        self,
        server_url: str,
        realm: str,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        timeout: float = 30.0,
        verify_ssl: bool = True,
        headers: Optional[Dict[str, str]] = None,
    ):
        """
        Initialize the Keycloak client.
        
        Args:
            server_url: Keycloak server URL (e.g., 'https://keycloak.example.com')
            realm: Keycloak realm name
            client_id: Default client ID for requests
            client_secret: Default client secret for confidential clients
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
            headers: Additional headers to include in all requests
        """
        self.server_url = server_url.rstrip('/')
        self.realm = realm
        self.client_id = client_id
        self.client_secret = client_secret
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.default_headers = headers or {}
        
        # Initialize endpoints
        self.endpoints = KeycloakEndpoints(server_url=server_url, realm=realm)
        
        # Validate required configuration
        if not server_url:
            raise ConfigurationError("server_url is required")
        if not realm:
            raise ConfigurationError("realm is required")
    
    def _get_client_auth_header(
        self, 
        client_id: Optional[str] = None, 
        client_secret: Optional[str] = None
    ) -> Dict[str, str]:
        """
        Get HTTP Basic authentication header for client credentials.
        
        Args:
            client_id: Client ID (falls back to instance default)
            client_secret: Client secret (falls back to instance default)
            
        Returns:
            Dictionary with Authorization header
            
        Raises:
            ConfigurationError: If client credentials are missing
        """
        cid = client_id or self.client_id
        secret = client_secret or self.client_secret
        
        if not cid or not secret:
            raise ConfigurationError(
                "Client ID and secret are required for client authentication"
            )
        
        # Create Basic Auth header
        credentials = f"{cid}:{secret}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        
        return {"Authorization": f"Basic {encoded_credentials}"}
    
    def _get_bearer_auth_header(self, access_token: str) -> Dict[str, str]:
        """
        Get Bearer token authentication header.
        
        Args:
            access_token: Access token
            
        Returns:
            Dictionary with Authorization header
        """
        return {"Authorization": f"Bearer {access_token}"}
    
    def _prepare_headers(self, additional_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """
        Prepare headers for HTTP request.
        
        Args:
            additional_headers: Additional headers to include
            
        Returns:
            Combined headers dictionary
        """
        headers = self.default_headers.copy()
        
        # Add default content type for POST requests
        if 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        
        # Add User-Agent if not present
        if 'User-Agent' not in headers:
            headers['User-Agent'] = 'pycloak/0.1.0'
        
        # Merge additional headers
        if additional_headers:
            headers.update(additional_headers)
        
        return headers
    
    def _handle_response_error(self, response: httpx.Response) -> None:
        """
        Handle HTTP error responses by raising appropriate exceptions.
        
        Args:
            response: HTTP response object
            
        Raises:
            KeycloakException: Appropriate exception based on response
        """
        if response.is_success:
            return
        
        # Create and raise appropriate exception
        exception = create_exception_from_response(response)
        raise exception
    
    def _parse_token_response(self, response: httpx.Response) -> TokenResponse:
        """
        Parse token response from Keycloak.
        
        Args:
            response: HTTP response from token endpoint
            
        Returns:
            Parsed token response
            
        Raises:
            KeycloakException: If response is invalid
        """
        self._handle_response_error(response)
        
        try:
            data = response.json()
            return TokenResponse.model_validate(data)
        except Exception as e:
            raise KeycloakException(f"Failed to parse token response: {e}", response)


class KeycloakClient(BaseKeycloakClient):
    """
    Synchronous Keycloak HTTP API client.
    
    This client uses raw HTTP calls to interact with Keycloak's REST API,
    providing transparency into the underlying OAuth2/OpenID Connect flows.
    """
    
    def __init__(
        self,
        server_url: str,
        realm: str,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        timeout: float = 30.0,
        verify_ssl: bool = True,
        headers: Optional[Dict[str, str]] = None,
        http_client: Optional[httpx.Client] = None,
    ):
        """
        Initialize the synchronous Keycloak client.
        
        Args:
            server_url: Keycloak server URL
            realm: Keycloak realm name
            client_id: Default client ID
            client_secret: Default client secret
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
            headers: Additional headers for all requests
            http_client: Custom HTTP client instance (optional)
        """
        super().__init__(
            server_url=server_url,
            realm=realm,
            client_id=client_id,
            client_secret=client_secret,
            timeout=timeout,
            verify_ssl=verify_ssl,
            headers=headers,
        )
        
        # Initialize HTTP client
        if http_client is not None:
            self.http_client = http_client
            self._owns_client = False
        else:
            self.http_client = httpx.Client(
                timeout=self.timeout,
                verify=self.verify_ssl,
                headers=self.default_headers,
            )
            self._owns_client = True
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
    
    def close(self) -> None:
        """Close the HTTP client."""
        if self._owns_client and hasattr(self, 'http_client'):
            self.http_client.close()
    
    # =========================================================================
    # Token Operations
    # =========================================================================
    
    def get_token_client_credentials(
        self,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> TokenResponse:
        """
        Get access token using client credentials grant.
        
        This is used for app-to-app authentication where a service needs
        to authenticate itself to access APIs on its own behalf.
        
        Args:
            client_id: Client ID (falls back to instance default)
            client_secret: Client secret (falls back to instance default)
            scope: Requested scopes (space-separated string)
            
        Returns:
            Token response with access token
            
        Raises:
            AuthenticationError: If client authentication fails
            KeycloakException: If the request fails
        """
        headers = self._prepare_headers()
        headers.update(self._get_client_auth_header(client_id, client_secret))
        
        data = {
            'grant_type': GrantTypes.CLIENT_CREDENTIALS,
        }
        
        if scope:
            data['scope'] = scope
        
        try:
            response = self.http_client.post(
                self.endpoints.token_endpoint,
                headers=headers,
                data=data,
            )
            return self._parse_token_response(response)
        
        except httpx.RequestError as e:
            raise create_network_exception(e)
    
    def get_token_authorization_code(
        self,
        code: str,
        redirect_uri: str,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        code_verifier: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> TokenResponse:
        """
        Exchange authorization code for access token.
        
        This is part of the authorization code flow, typically used after
        redirecting the user back from Keycloak with an authorization code.
        
        Args:
            code: Authorization code from Keycloak
            redirect_uri: Redirect URI used in the authorization request
            client_id: Client ID (falls back to instance default)
            client_secret: Client secret (for confidential clients)
            code_verifier: PKCE code verifier (for PKCE flow)
            scope: Requested scopes
            
        Returns:
            Token response with access and potentially refresh token
            
        Raises:
            AuthenticationError: If authentication fails
            KeycloakException: If the request fails
        """
        headers = self._prepare_headers()
        
        data = {
            'grant_type': GrantTypes.AUTHORIZATION_CODE,
            'code': code,
            'redirect_uri': redirect_uri,
        }
        
        # Add client credentials
        cid = client_id or self.client_id
        if cid:
            data['client_id'] = cid
        
        # For confidential clients, use Basic auth
        if client_secret or self.client_secret:
            headers.update(self._get_client_auth_header(client_id, client_secret))
        elif cid and client_secret is None and self.client_secret is None:
            # Public client - include client_id in body
            pass
        
        if code_verifier:
            data['code_verifier'] = code_verifier
        
        if scope:
            data['scope'] = scope
        
        try:
            response = self.http_client.post(
                self.endpoints.token_endpoint,
                headers=headers,
                data=data,
            )
            return self._parse_token_response(response)
        
        except httpx.RequestError as e:
            raise create_network_exception(e)
    
    def get_token_password(
        self,
        username: str,
        password: str,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> TokenResponse:
        """
        Get access token using resource owner password credentials grant.
        
        ⚠️  WARNING: This grant type is generally discouraged for security reasons.
        Only use when other flows are not feasible (e.g., legacy systems).
        
        Args:
            username: Resource owner username
            password: Resource owner password
            client_id: Client ID (falls back to instance default)
            client_secret: Client secret (optional for public clients)
            scope: Requested scopes
            
        Returns:
            Token response with access token
            
        Raises:
            AuthenticationError: If authentication fails
            KeycloakException: If the request fails
        """
        headers = self._prepare_headers()
        
        data = {
            'grant_type': GrantTypes.PASSWORD,
            'username': username,
            'password': password,
        }
        
        # Add client credentials
        cid = client_id or self.client_id
        if cid:
            data['client_id'] = cid
        
        # For confidential clients, use Basic auth
        if client_secret or self.client_secret:
            headers.update(self._get_client_auth_header(client_id, client_secret))
        
        if scope:
            data['scope'] = scope
        
        try:
            response = self.http_client.post(
                self.endpoints.token_endpoint,
                headers=headers,
                data=data,
            )
            return self._parse_token_response(response)
        
        except httpx.RequestError as e:
            raise create_network_exception(e)
    
    def refresh_token(
        self,
        refresh_token: str,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> TokenResponse:
        """
        Get new access token using refresh token.
        
        Args:
            refresh_token: Valid refresh token
            client_id: Client ID (falls back to instance default)
            client_secret: Client secret (for confidential clients)
            scope: Requested scopes (should not exceed original scopes)
            
        Returns:
            Token response with new access token
            
        Raises:
            AuthenticationError: If refresh token is invalid
            KeycloakException: If the request fails
        """
        headers = self._prepare_headers()
        
        data = {
            'grant_type': GrantTypes.REFRESH_TOKEN,
            'refresh_token': refresh_token,
        }
        
        # Add client credentials
        cid = client_id or self.client_id
        if cid:
            data['client_id'] = cid
        
        # For confidential clients, use Basic auth
        if client_secret or self.client_secret:
            headers.update(self._get_client_auth_header(client_id, client_secret))
        
        if scope:
            data['scope'] = scope
        
        try:
            response = self.http_client.post(
                self.endpoints.token_endpoint,
                headers=headers,
                data=data,
            )
            return self._parse_token_response(response)
        
        except httpx.RequestError as e:
            raise create_network_exception(e)
    
    def introspect_token(
        self,
        token: str,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        token_type_hint: Optional[str] = None,
    ) -> TokenIntrospectionResponse:
        """
        Introspect a token to get its metadata and validate it.
        
        This endpoint returns information about the token including
        whether it's active, expiration time, scopes, and claims.
        
        Args:
            token: Token to introspect
            client_id: Client ID (falls back to instance default)
            client_secret: Client secret (falls back to instance default)
            token_type_hint: Hint about token type ('access_token' or 'refresh_token')
            
        Returns:
            Token introspection response
            
        Raises:
            AuthenticationError: If client authentication fails
            KeycloakException: If the request fails
        """
        headers = self._prepare_headers()
        headers.update(self._get_client_auth_header(client_id, client_secret))
        
        data = {
            'token': token,
        }
        
        if token_type_hint:
            data['token_type_hint'] = token_type_hint
        
        try:
            response = self.http_client.post(
                self.endpoints.token_introspect_endpoint,
                headers=headers,
                data=data,
            )
            
            self._handle_response_error(response)
            
            try:
                data = response.json()
                return TokenIntrospectionResponse.model_validate(data)
            except Exception as e:
                raise KeycloakException(f"Failed to parse introspection response: {e}", response)
        
        except httpx.RequestError as e:
            raise create_network_exception(e)
    
    def get_userinfo(self, access_token: str) -> UserInfoResponse:
        """
        Get user information using an access token.
        
        This endpoint returns claims about the authenticated user
        according to the OpenID Connect UserInfo specification.
        
        Args:
            access_token: Valid access token
            
        Returns:
            User information response
            
        Raises:
            AuthenticationError: If token is invalid or expired
            KeycloakException: If the request fails
        """
        headers = self._prepare_headers()
        headers.update(self._get_bearer_auth_header(access_token))
        # UserInfo endpoint expects application/json for some claims
        headers['Accept'] = 'application/json'
        
        try:
            response = self.http_client.get(
                self.endpoints.userinfo_endpoint,
                headers=headers,
            )
            
            self._handle_response_error(response)
            
            try:
                data = response.json()
                return UserInfoResponse.model_validate(data)
            except Exception as e:
                raise KeycloakException(f"Failed to parse userinfo response: {e}", response)
        
        except httpx.RequestError as e:
            raise create_network_exception(e)
    
    def logout(
        self,
        refresh_token: str,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
    ) -> None:
        """
        Logout user and invalidate tokens.
        
        This endpoint invalidates the refresh token and associated
        access tokens, effectively logging out the user.
        
        Args:
            refresh_token: Valid refresh token
            client_id: Client ID (falls back to instance default)
            client_secret: Client secret (for confidential clients)
            
        Raises:
            AuthenticationError: If authentication fails
            KeycloakException: If the request fails
        """
        headers = self._prepare_headers()
        
        data = {
            'refresh_token': refresh_token,
        }
        
        # Add client credentials
        cid = client_id or self.client_id
        if cid:
            data['client_id'] = cid
        
        # For confidential clients, use Basic auth
        if client_secret or self.client_secret:
            headers.update(self._get_client_auth_header(client_id, client_secret))
        
        try:
            response = self.http_client.post(
                self.endpoints.logout_endpoint,
                headers=headers,
                data=data,
            )
            
            self._handle_response_error(response)
        
        except httpx.RequestError as e:
            raise create_network_exception(e)
    
    def revoke_token(
        self,
        token: str,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        token_type_hint: Optional[str] = None,
    ) -> None:
        """
        Revoke an access or refresh token.
        
        This endpoint revokes the specified token according to RFC 7009.
        
        Args:
            token: Token to revoke
            client_id: Client ID (falls back to instance default)
            client_secret: Client secret (falls back to instance default)
            token_type_hint: Hint about token type
            
        Raises:
            AuthenticationError: If client authentication fails
            KeycloakException: If the request fails
        """
        headers = self._prepare_headers()
        headers.update(self._get_client_auth_header(client_id, client_secret))
        
        data = {
            'token': token,
        }
        
        if token_type_hint:
            data['token_type_hint'] = token_type_hint
        
        try:
            response = self.http_client.post(
                self.endpoints.revoke_endpoint,
                headers=headers,
                data=data,
            )
            
            self._handle_response_error(response)
        
        except httpx.RequestError as e:
            raise create_network_exception(e)
    
    # =========================================================================
    # Admin Operations
    # =========================================================================
    
    def _get_admin_headers(self, access_token: str) -> Dict[str, str]:
        """
        Get headers for admin API requests.
        
        Args:
            access_token: Admin access token
            
        Returns:
            Headers dictionary with authorization and content type
        """
        headers = self._prepare_headers()
        headers.update(self._get_bearer_auth_header(access_token))
        headers['Content-Type'] = 'application/json'
        headers['Accept'] = 'application/json'
        return headers
    
    def get_admin_token(
        self,
        username: str,
        password: str,
        client_id: str = "admin-cli"
    ) -> TokenResponse:
        """
        Get admin access token for management operations.
        
        This uses the password grant with the admin-cli client to obtain
        admin privileges. In production, consider using client credentials
        with a service account instead.
        
        Args:
            username: Admin username
            password: Admin password  
            client_id: Admin client ID (defaults to 'admin-cli')
            
        Returns:
            Token response with admin access token
            
        Raises:
            AuthenticationError: If admin authentication fails
            KeycloakException: If the request fails
        """
        return self.get_token_password(
            username=username,
            password=password,
            client_id=client_id,
            client_secret=None  # admin-cli is a public client
        )
    
    def create_user(
        self,
        admin_token: str,
        user_data: Dict[str, Any],
        temporary_password: Optional[str] = None
    ) -> str:
        """
        Create a new user in Keycloak.
        
        Args:
            admin_token: Admin access token
            user_data: User data dictionary (username, email, firstName, lastName, etc.)
            temporary_password: Optional temporary password for the user
            
        Returns:
            Created user's ID
            
        Raises:
            AuthenticationError: If admin token is invalid
            AuthorizationError: If insufficient permissions
            KeycloakException: If the request fails
        """
        headers = self._get_admin_headers(admin_token)
        
        # Prepare user payload
        payload = {
            "enabled": True,
            **user_data
        }
        
        # Add temporary password if provided
        if temporary_password:
            payload["credentials"] = [{
                "type": "password",
                "value": temporary_password,
                "temporary": True
            }]
        
        try:
            response = self.http_client.post(
                self.endpoints.users_endpoint,
                headers=headers,
                json=payload,
            )
            
            self._handle_response_error(response)
            
            # Extract user ID from Location header
            location = response.headers.get('Location', '')
            if location:
                return location.split('/')[-1]
            else:
                raise KeycloakException("User created but no Location header found", response)
        
        except httpx.RequestError as e:
            raise create_network_exception(e)
    
    def get_user_by_username(
        self,
        admin_token: str,
        username: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get user by username.
        
        Args:
            admin_token: Admin access token
            username: Username to search for
            
        Returns:
            User data dictionary or None if not found
            
        Raises:
            AuthenticationError: If admin token is invalid
            KeycloakException: If the request fails
        """
        headers = self._get_admin_headers(admin_token)
        
        try:
            response = self.http_client.get(
                self.endpoints.users_endpoint,
                headers=headers,
                params={"username": username, "exact": "true"}
            )
            
            self._handle_response_error(response)
            
            users = response.json()
            return users[0] if users else None
        
        except httpx.RequestError as e:
            raise create_network_exception(e)
    
    def create_client(
        self,
        admin_token: str,
        client_data: Dict[str, Any]
    ) -> str:
        """
        Create a new client in Keycloak.
        
        Args:
            admin_token: Admin access token
            client_data: Client configuration dictionary
            
        Returns:
            Created client's internal ID (not clientId)
            
        Raises:
            AuthenticationError: If admin token is invalid
            AuthorizationError: If insufficient permissions
            KeycloakException: If the request fails
        """
        headers = self._get_admin_headers(admin_token)
        
        try:
            response = self.http_client.post(
                self.endpoints.clients_endpoint,
                headers=headers,
                json=client_data,
            )
            
            self._handle_response_error(response)
            
            # Extract client ID from Location header
            location = response.headers.get('Location', '')
            if location:
                return location.split('/')[-1]
            else:
                raise KeycloakException("Client created but no Location header found", response)
        
        except httpx.RequestError as e:
            raise create_network_exception(e)
    
    def get_client_by_client_id(
        self,
        admin_token: str,
        client_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get client by clientId.
        
        Args:
            admin_token: Admin access token
            client_id: Client ID to search for
            
        Returns:
            Client data dictionary or None if not found
            
        Raises:
            AuthenticationError: If admin token is invalid
            KeycloakException: If the request fails
        """
        headers = self._get_admin_headers(admin_token)
        
        try:
            response = self.http_client.get(
                self.endpoints.clients_endpoint,
                headers=headers,
                params={"clientId": client_id}
            )
            
            self._handle_response_error(response)
            
            clients = response.json()
            return clients[0] if clients else None
        
        except httpx.RequestError as e:
            raise create_network_exception(e)
    
    def get_client_secret(
        self,
        admin_token: str,
        internal_client_id: str
    ) -> str:
        """
        Get client secret for a confidential client.
        
        Args:
            admin_token: Admin access token
            internal_client_id: Internal client ID (not clientId)
            
        Returns:
            Client secret
            
        Raises:
            AuthenticationError: If admin token is invalid
            KeycloakException: If the request fails
        """
        headers = self._get_admin_headers(admin_token)
        
        try:
            response = self.http_client.get(
                self.endpoints.client_secret_endpoint(internal_client_id),
                headers=headers,
            )
            
            self._handle_response_error(response)
            
            secret_data = response.json()
            return secret_data.get('value', '')
        
        except httpx.RequestError as e:
            raise create_network_exception(e)
    
    def create_realm_role(
        self,
        admin_token: str,
        role_name: str,
        role_description: Optional[str] = None
    ) -> None:
        """
        Create a realm role.
        
        Args:
            admin_token: Admin access token
            role_name: Name of the role to create
            role_description: Optional role description
            
        Raises:
            AuthenticationError: If admin token is invalid
            AuthorizationError: If insufficient permissions
            KeycloakException: If the request fails
        """
        headers = self._get_admin_headers(admin_token)
        
        payload = {
            "name": role_name,
            "description": role_description or f"Role: {role_name}"
        }
        
        try:
            response = self.http_client.post(
                self.endpoints.roles_endpoint,
                headers=headers,
                json=payload,
            )
            
            self._handle_response_error(response)
        
        except httpx.RequestError as e:
            raise create_network_exception(e)
    
    def assign_realm_role_to_user(
        self,
        admin_token: str,
        user_id: str,
        role_name: str
    ) -> None:
        """
        Assign a realm role to a user.
        
        Args:
            admin_token: Admin access token
            user_id: User's ID
            role_name: Name of the role to assign
            
        Raises:
            AuthenticationError: If admin token is invalid
            AuthorizationError: If insufficient permissions
            KeycloakException: If the request fails
        """
        headers = self._get_admin_headers(admin_token)
        
        # First get the role representation
        role_response = self.http_client.get(
            self.endpoints.role_endpoint(role_name),
            headers=headers,
        )
        self._handle_response_error(role_response)
        role_data = role_response.json()
        
        # Assign the role to the user
        user_roles_endpoint = f"{self.endpoints.user_endpoint(user_id)}/role-mappings/realm"
        
        try:
            response = self.http_client.post(
                user_roles_endpoint,
                headers=headers,
                json=[role_data],
            )
            
            self._handle_response_error(response)
        
        except httpx.RequestError as e:
            raise create_network_exception(e)

    # =========================================================================
    # Discovery Operations
    # =========================================================================
    
    def get_well_known_config(self) -> Dict[str, Any]:
        """
        Get OpenID Connect discovery document.
        
        This endpoint returns metadata about the OpenID Connect provider
        including supported endpoints, grant types, and capabilities.
        
        Returns:
            OpenID Connect discovery document
            
        Raises:
            KeycloakException: If the request fails
        """
        headers = self._prepare_headers()
        headers['Accept'] = 'application/json'
        
        try:
            response = self.http_client.get(
                self.endpoints.well_known_endpoint,
                headers=headers,
            )
            
            self._handle_response_error(response)
            
            return response.json()
        
        except httpx.RequestError as e:
            raise create_network_exception(e)
    
    def get_certs(self) -> Dict[str, Any]:
        """
        Get JSON Web Key Set (JWKS) for token verification.
        
        This endpoint returns the public keys used to verify
        JWT token signatures.
        
        Returns:
            JWKS document with public keys
            
        Raises:
            KeycloakException: If the request fails
        """
        headers = self._prepare_headers()
        headers['Accept'] = 'application/json'
        
        try:
            response = self.http_client.get(
                self.endpoints.certs_endpoint,
                headers=headers,
            )
            
            self._handle_response_error(response)
            
            return response.json()
        
        except httpx.RequestError as e:
            raise create_network_exception(e)


class AsyncKeycloakClient(BaseKeycloakClient):
    """
    Asynchronous Keycloak HTTP API client.
    
    This client provides the same functionality as KeycloakClient
    but with async/await support for non-blocking operations.
    """
    
    def __init__(
        self,
        server_url: str,
        realm: str,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        timeout: float = 30.0,
        verify_ssl: bool = True,
        headers: Optional[Dict[str, str]] = None,
        http_client: Optional[httpx.AsyncClient] = None,
    ):
        """
        Initialize the asynchronous Keycloak client.
        
        Args:
            server_url: Keycloak server URL
            realm: Keycloak realm name
            client_id: Default client ID
            client_secret: Default client secret
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
            headers: Additional headers for all requests
            http_client: Custom async HTTP client instance (optional)
        """
        super().__init__(
            server_url=server_url,
            realm=realm,
            client_id=client_id,
            client_secret=client_secret,
            timeout=timeout,
            verify_ssl=verify_ssl,
            headers=headers,
        )
        
        # Initialize async HTTP client
        if http_client is not None:
            self.http_client = http_client
            self._owns_client = False
        else:
            self.http_client = httpx.AsyncClient(
                timeout=self.timeout,
                verify=self.verify_ssl,
                headers=self.default_headers,
            )
            self._owns_client = True
    
    async def __aenter__(self):
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.aclose()
    
    async def aclose(self) -> None:
        """Close the async HTTP client."""
        if self._owns_client and hasattr(self, 'http_client'):
            await self.http_client.aclose()
    
    async def _parse_token_response_async(self, response: httpx.Response) -> TokenResponse:
        """
        Parse token response from Keycloak (async version).
        
        Args:
            response: HTTP response from token endpoint
            
        Returns:
            Parsed token response
            
        Raises:
            KeycloakException: If response is invalid
        """
        self._handle_response_error(response)
        
        try:
            data = response.json()
            return TokenResponse.model_validate(data)
        except Exception as e:
            raise KeycloakException(f"Failed to parse token response: {e}", response)
    
    # =========================================================================
    # Token Operations (Async)
    # =========================================================================
    
    async def get_token_client_credentials(
        self,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> TokenResponse:
        """
        Get access token using client credentials grant (async).
        
        Args:
            client_id: Client ID (falls back to instance default)
            client_secret: Client secret (falls back to instance default)
            scope: Requested scopes (space-separated string)
            
        Returns:
            Token response with access token
            
        Raises:
            AuthenticationError: If client authentication fails
            KeycloakException: If the request fails
        """
        headers = self._prepare_headers()
        headers.update(self._get_client_auth_header(client_id, client_secret))
        
        data = {
            'grant_type': GrantTypes.CLIENT_CREDENTIALS,
        }
        
        if scope:
            data['scope'] = scope
        
        try:
            response = await self.http_client.post(
                self.endpoints.token_endpoint,
                headers=headers,
                data=data,
            )
            return await self._parse_token_response_async(response)
        
        except httpx.RequestError as e:
            raise create_network_exception(e)
    
    async def get_token_password(
        self,
        username: str,
        password: str,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> TokenResponse:
        """
        Get access token using resource owner password credentials grant (async).
        
        Args:
            username: Resource owner username
            password: Resource owner password
            client_id: Client ID (falls back to instance default)
            client_secret: Client secret (optional for public clients)
            scope: Requested scopes
            
        Returns:
            Token response with access token
        """
        headers = self._prepare_headers()
        
        data = {
            'grant_type': GrantTypes.PASSWORD,
            'username': username,
            'password': password,
        }
        
        # Add client credentials
        cid = client_id or self.client_id
        if cid:
            data['client_id'] = cid
        
        # For confidential clients, use Basic auth
        if client_secret or self.client_secret:
            headers.update(self._get_client_auth_header(client_id, client_secret))
        
        if scope:
            data['scope'] = scope
        
        try:
            response = await self.http_client.post(
                self.endpoints.token_endpoint,
                headers=headers,
                data=data,
            )
            return await self._parse_token_response_async(response)
        
        except httpx.RequestError as e:
            raise create_network_exception(e)
    
    async def introspect_token(
        self,
        token: str,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        token_type_hint: Optional[str] = None,
    ) -> TokenIntrospectionResponse:
        """
        Introspect a token to get its metadata and validate it (async).
        
        Args:
            token: Token to introspect
            client_id: Client ID (falls back to instance default)
            client_secret: Client secret (falls back to instance default)
            token_type_hint: Hint about token type
            
        Returns:
            Token introspection response
            
        Raises:
            AuthenticationError: If client authentication fails
            KeycloakException: If the request fails
        """
        headers = self._prepare_headers()
        headers.update(self._get_client_auth_header(client_id, client_secret))
        
        data = {
            'token': token,
        }
        
        if token_type_hint:
            data['token_type_hint'] = token_type_hint
        
        try:
            response = await self.http_client.post(
                self.endpoints.token_introspect_endpoint,
                headers=headers,
                data=data,
            )
            
            self._handle_response_error(response)
            
            try:
                response_data = response.json()
                return TokenIntrospectionResponse.model_validate(response_data)
            except Exception as e:
                raise KeycloakException(f"Failed to parse introspection response: {e}", response)
        
        except httpx.RequestError as e:
            raise create_network_exception(e)
    
    async def get_userinfo(self, access_token: str) -> UserInfoResponse:
        """
        Get user information using an access token (async).
        
        Args:
            access_token: Valid access token
            
        Returns:
            User information response
            
        Raises:
            AuthenticationError: If token is invalid or expired
            KeycloakException: If the request fails
        """
        headers = self._prepare_headers()
        headers.update(self._get_bearer_auth_header(access_token))
        headers['Accept'] = 'application/json'
        
        try:
            response = await self.http_client.get(
                self.endpoints.userinfo_endpoint,
                headers=headers,
            )
            
            self._handle_response_error(response)
            
            try:
                data = response.json()
                return UserInfoResponse.model_validate(data)
            except Exception as e:
                raise KeycloakException(f"Failed to parse userinfo response: {e}", response)
        
        except httpx.RequestError as e:
            raise create_network_exception(e)
    
    async def get_well_known_config(self) -> Dict[str, Any]:
        """
        Get OpenID Connect discovery document (async).
        
        Returns:
            OpenID Connect discovery document
            
        Raises:
            KeycloakException: If the request fails
        """
        headers = self._prepare_headers()
        headers['Accept'] = 'application/json'
        
        try:
            response = await self.http_client.get(
                self.endpoints.well_known_endpoint,
                headers=headers,
            )
            
            self._handle_response_error(response)
            
            return response.json()
        
        except httpx.RequestError as e:
            raise create_network_exception(e)
    
    # =========================================================================
    # Admin Operations (Async)
    # =========================================================================
    
    def _get_admin_headers(self, access_token: str) -> Dict[str, str]:
        """Get headers for admin API requests (shared with sync client)."""
        headers = self._prepare_headers()
        headers.update(self._get_bearer_auth_header(access_token))
        headers['Content-Type'] = 'application/json'
        headers['Accept'] = 'application/json'
        return headers
    
    async def get_admin_token(
        self,
        username: str,
        password: str,
        client_id: str = "admin-cli"
    ) -> TokenResponse:
        """
        Get admin access token for management operations (async).
        
        Args:
            username: Admin username
            password: Admin password
            client_id: Admin client ID (defaults to 'admin-cli')
            
        Returns:
            Token response with admin access token
        """
        return await self.get_token_password(
            username=username,
            password=password,
            client_id=client_id,
            client_secret=None
        )
    
    async def create_user(
        self,
        admin_token: str,
        user_data: Dict[str, Any],
        temporary_password: Optional[str] = None
    ) -> str:
        """
        Create a new user in Keycloak (async).
        
        Args:
            admin_token: Admin access token
            user_data: User data dictionary
            temporary_password: Optional temporary password
            
        Returns:
            Created user's ID
        """
        headers = self._get_admin_headers(admin_token)
        
        payload = {"enabled": True, **user_data}
        
        if temporary_password:
            payload["credentials"] = [{
                "type": "password",
                "value": temporary_password,
                "temporary": True
            }]
        
        try:
            response = await self.http_client.post(
                self.endpoints.users_endpoint,
                headers=headers,
                json=payload,
            )
            
            self._handle_response_error(response)
            
            location = response.headers.get('Location', '')
            if location:
                return location.split('/')[-1]
            else:
                raise KeycloakException("User created but no Location header found", response)
        
        except httpx.RequestError as e:
            raise create_network_exception(e)
    
    async def get_user_by_username(
        self,
        admin_token: str,
        username: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get user by username (async).
        
        Args:
            admin_token: Admin access token
            username: Username to search for
            
        Returns:
            User data dictionary or None if not found
        """
        headers = self._get_admin_headers(admin_token)
        
        try:
            response = await self.http_client.get(
                self.endpoints.users_endpoint,
                headers=headers,
                params={"username": username, "exact": "true"}
            )
            
            self._handle_response_error(response)
            
            users = response.json()
            return users[0] if users else None
        
        except httpx.RequestError as e:
            raise create_network_exception(e)
    
    async def create_client(
        self,
        admin_token: str,
        client_data: Dict[str, Any]
    ) -> str:
        """
        Create a new client in Keycloak (async).
        
        Args:
            admin_token: Admin access token
            client_data: Client configuration dictionary
            
        Returns:
            Created client's internal ID
        """
        headers = self._get_admin_headers(admin_token)
        
        try:
            response = await self.http_client.post(
                self.endpoints.clients_endpoint,
                headers=headers,
                json=client_data,
            )
            
            self._handle_response_error(response)
            
            location = response.headers.get('Location', '')
            if location:
                return location.split('/')[-1]
            else:
                raise KeycloakException("Client created but no Location header found", response)
        
        except httpx.RequestError as e:
            raise create_network_exception(e)


# =========================================================================
# Utility Functions
# =========================================================================

def create_client_from_env(
    async_client: bool = False,
    **kwargs
) -> Union[KeycloakClient, AsyncKeycloakClient]:
    """
    Create a Keycloak client from environment variables.
    
    Expected environment variables:
    - KEYCLOAK_SERVER_URL: Keycloak server URL
    - KEYCLOAK_REALM: Keycloak realm name  
    - KEYCLOAK_CLIENT_ID: Default client ID
    - KEYCLOAK_CLIENT_SECRET: Default client secret (optional)
    
    Args:
        async_client: Whether to create an async client
        **kwargs: Additional arguments to pass to client constructor
        
    Returns:
        Configured Keycloak client
        
    Raises:
        ConfigurationError: If required environment variables are missing
    """
    import os
    from dotenv import load_dotenv
    
    # Load .env file if present
    load_dotenv()
    
    server_url = os.getenv('KEYCLOAK_SERVER_URL')
    realm = os.getenv('KEYCLOAK_REALM')
    client_id = os.getenv('KEYCLOAK_CLIENT_ID')
    client_secret = os.getenv('KEYCLOAK_CLIENT_SECRET')
    
    if not server_url:
        raise ConfigurationError("KEYCLOAK_SERVER_URL environment variable is required")
    if not realm:
        raise ConfigurationError("KEYCLOAK_REALM environment variable is required")
    
    client_kwargs = {
        'server_url': server_url,
        'realm': realm,
        'client_id': client_id,
        'client_secret': client_secret,
        **kwargs
    }
    
    if async_client:
        return AsyncKeycloakClient(**client_kwargs)
    else:
        return KeycloakClient(**client_kwargs)