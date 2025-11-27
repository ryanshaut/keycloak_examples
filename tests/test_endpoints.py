"""Tests for KeycloakEndpoints class."""

from pycloak.endpoints import KeycloakEndpoints, GrantTypes, ResponseTypes, Scopes, TokenTypes, ClientAuthMethods


class TestKeycloakEndpoints:
    """Test cases for KeycloakEndpoints."""
    
    def test_init_basic(self):
        """Test basic initialization."""
        endpoints = KeycloakEndpoints(
            server_url="https://keycloak.example.com",
            realm="test-realm"
        )
        
        assert endpoints.server_url == "https://keycloak.example.com/"
        assert endpoints.realm == "test-realm"
    
    def test_init_normalizes_server_url(self):
        """Test that server URL is normalized to end with slash."""
        endpoints = KeycloakEndpoints(
            server_url="https://keycloak.example.com",
            realm="test"
        )
        
        assert endpoints.server_url == "https://keycloak.example.com/"
        
        # Already has slash - should not add another
        endpoints2 = KeycloakEndpoints(
            server_url="https://keycloak.example.com/",
            realm="test"
        )
        
        assert endpoints2.server_url == "https://keycloak.example.com/"
    
    def test_base_urls(self):
        """Test realm and admin base URL generation."""
        endpoints = KeycloakEndpoints(
            server_url="https://keycloak.example.com",
            realm="test-realm"
        )
        
        assert endpoints.realm_base_url == "https://keycloak.example.com/realms/test-realm/"
        assert endpoints.admin_base_url == "https://keycloak.example.com/admin/realms/test-realm/"
    
    def test_auth_endpoints(self):
        """Test authentication and token endpoints."""
        endpoints = KeycloakEndpoints(
            server_url="https://keycloak.example.com",
            realm="test-realm"
        )
        
        expected_base = "https://keycloak.example.com/realms/test-realm/protocol/openid-connect"
        assert endpoints.token_endpoint == f"{expected_base}/token"
        assert endpoints.token_introspect_endpoint == f"{expected_base}/token/introspect"
        assert endpoints.userinfo_endpoint == f"{expected_base}/userinfo"
        assert endpoints.logout_endpoint == f"{expected_base}/logout"
        assert endpoints.revoke_endpoint == f"{expected_base}/revoke"
        assert endpoints.auth_endpoint == f"{expected_base}/auth"
    
    def test_discovery_endpoints(self):
        """Test discovery endpoints."""
        endpoints = KeycloakEndpoints(
            server_url="https://keycloak.example.com",
            realm="test-realm"
        )
        
        base = "https://keycloak.example.com/realms/test-realm"
        assert endpoints.well_known_endpoint == f"{base}/.well-known/openid-configuration"
        assert endpoints.certs_endpoint == f"{base}/protocol/openid-connect/certs"
    
    def test_admin_endpoints(self):
        """Test admin API endpoints."""
        endpoints = KeycloakEndpoints(
            server_url="https://keycloak.example.com",
            realm="test-realm"
        )
        
        base = "https://keycloak.example.com/admin/realms/test-realm"
        assert endpoints.users_endpoint == f"{base}/users"
        assert endpoints.clients_endpoint == f"{base}/clients"
        assert endpoints.roles_endpoint == f"{base}/roles"
        assert endpoints.groups_endpoint == f"{base}/groups"
        assert endpoints.sessions_endpoint == f"{base}/sessions"
    
    def test_user_specific_endpoints(self):
        """Test user-specific endpoint methods."""
        endpoints = KeycloakEndpoints(
            server_url="https://keycloak.example.com",
            realm="test-realm"
        )
        
        user_id = "123e4567-e89b-12d3-a456-426614174000"
        base = "https://keycloak.example.com/admin/realms/test-realm/users"
        
        assert endpoints.user_endpoint(user_id) == f"{base}/{user_id}"
        assert endpoints.user_sessions_endpoint(user_id) == f"{base}/{user_id}/sessions"
    
    def test_client_specific_endpoints(self):
        """Test client-specific endpoint methods."""
        endpoints = KeycloakEndpoints(
            server_url="https://keycloak.example.com",
            realm="test-realm"
        )
        
        client_id = "test-client-uuid"
        base = "https://keycloak.example.com/admin/realms/test-realm/clients"
        
        assert endpoints.client_endpoint(client_id) == f"{base}/{client_id}"
        assert endpoints.client_secret_endpoint(client_id) == f"{base}/{client_id}/client-secret"
        assert endpoints.client_roles_endpoint(client_id) == f"{base}/{client_id}/roles"
        assert endpoints.client_role_endpoint(client_id, "test-role") == f"{base}/{client_id}/roles/test-role"
    
    def test_role_endpoints(self):
        """Test role endpoint methods."""
        endpoints = KeycloakEndpoints(
            server_url="https://keycloak.example.com",
            realm="test-realm"
        )
        
        base = "https://keycloak.example.com/admin/realms/test-realm/roles"
        assert endpoints.role_endpoint("test-role") == f"{base}/test-role"
    
    def test_group_endpoints(self):
        """Test group endpoint methods."""
        endpoints = KeycloakEndpoints(
            server_url="https://keycloak.example.com",
            realm="test-realm"
        )
        
        group_id = "group-uuid"
        base = "https://keycloak.example.com/admin/realms/test-realm/groups"
        assert endpoints.group_endpoint(group_id) == f"{base}/{group_id}"
    
    def test_session_endpoints(self):
        """Test session endpoint methods."""
        endpoints = KeycloakEndpoints(
            server_url="https://keycloak.example.com",
            realm="test-realm"
        )
        
        session_id = "session-uuid"
        base = "https://keycloak.example.com/admin/realms/test-realm/sessions"
        assert endpoints.session_endpoint(session_id) == f"{base}/{session_id}"
    
    def test_build_url(self):
        """Test build_url utility method."""
        endpoints = KeycloakEndpoints(
            server_url="https://keycloak.example.com",
            realm="test-realm"
        )
        
        # Use default base URL (realm_base_url)
        url = endpoints.build_url("custom/path")
        assert url == "https://keycloak.example.com/realms/test-realm/custom/path"
        
        # Use custom base URL
        url = endpoints.build_url("custom/path", "https://custom.example.com/")
        assert url == "https://custom.example.com/custom/path"
    
    def test_get_all_endpoints(self):
        """Test get_all_endpoints method."""
        endpoints = KeycloakEndpoints(
            server_url="https://keycloak.example.com",
            realm="test-realm"
        )
        
        all_endpoints = endpoints.get_all_endpoints()
        
        # Check that we get a dictionary
        assert isinstance(all_endpoints, dict)
        
        # Check that it contains expected endpoints
        expected_endpoints = [
            'token_endpoint',
            'userinfo_endpoint', 
            'logout_endpoint',
            'auth_endpoint',
            'well_known_endpoint',
            'certs_endpoint',
            'users_endpoint',
            'clients_endpoint',
            'roles_endpoint'
        ]
        
        for endpoint_name in expected_endpoints:
            assert endpoint_name in all_endpoints
            assert isinstance(all_endpoints[endpoint_name], str)
            assert all_endpoints[endpoint_name].startswith('https://')


class TestConstants:
    """Test endpoint-related constants."""
    
    def test_grant_types(self):
        """Test grant type constants."""
        assert GrantTypes.AUTHORIZATION_CODE == "authorization_code"
        assert GrantTypes.CLIENT_CREDENTIALS == "client_credentials"
        assert GrantTypes.PASSWORD == "password"
        assert GrantTypes.REFRESH_TOKEN == "refresh_token"
        assert GrantTypes.JWT_BEARER == "urn:ietf:params:oauth:grant-type:jwt-bearer"
        assert GrantTypes.TOKEN_EXCHANGE == "urn:ietf:params:oauth:grant-type:token-exchange"
    
    def test_response_types(self):
        """Test response type constants."""
        assert ResponseTypes.CODE == "code"
        assert ResponseTypes.TOKEN == "token"
        assert ResponseTypes.ID_TOKEN == "id_token"
    
    def test_scopes(self):
        """Test scope constants."""
        assert Scopes.OPENID == "openid"
        assert Scopes.PROFILE == "profile"
        assert Scopes.EMAIL == "email"
        assert Scopes.ADDRESS == "address"
        assert Scopes.PHONE == "phone"
        assert Scopes.OFFLINE_ACCESS == "offline_access"
    
    def test_token_types(self):
        """Test token type constants."""
        assert TokenTypes.BEARER == "Bearer"
        assert TokenTypes.ACCESS_TOKEN == "urn:ietf:params:oauth:token-type:access_token"
        assert TokenTypes.REFRESH_TOKEN == "urn:ietf:params:oauth:token-type:refresh_token"
        assert TokenTypes.ID_TOKEN == "urn:ietf:params:oauth:token-type:id_token"
    
    def test_client_auth_methods(self):
        """Test client authentication method constants."""
        assert ClientAuthMethods.CLIENT_SECRET_POST == "client_secret_post"
        assert ClientAuthMethods.CLIENT_SECRET_BASIC == "client_secret_basic"
        assert ClientAuthMethods.CLIENT_SECRET_JWT == "client_secret_jwt"
        assert ClientAuthMethods.PRIVATE_KEY_JWT == "private_key_jwt"
        assert ClientAuthMethods.NONE == "none"