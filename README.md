# Keycloak Examples

Educational examples for Keycloak authentication patterns using raw HTTP API calls instead of high-level SDKs. This repository demonstrates three core authentication workflows:

- **User-to-App**: Standard user authentication flows  
- **App-to-App**: Service-to-service authentication using client credentials
- **On-Behalf-Of**: Delegated authentication scenarios

## 🎯 Project Goals

This project prioritizes **education and transparency** over production-ready abstractions. By using raw HTTP calls to Keycloak endpoints, developers can:

- Understand the underlying OAuth2/OpenID Connect flows
- See exactly what API calls are being made
- Learn Keycloak concepts without SDK abstractions
- Build custom implementations suited to their needs

## 🚀 Quick Start

### Prerequisites
- Python 3.12+
- [uv](https://docs.astral.sh/uv/) for dependency management
- A running Keycloak instance (see [setup instructions](docs/keycloak-setup.md))

### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/ryanshaut/keycloak_examples.git
cd keycloak_examples

# Set up development environment (installs uv if needed)
make setup

# Activate virtual environment
source .venv/bin/activate

# Run tests to verify setup
make test
```

## 📁 Project Structure

```
keycloak_examples/
├── src/
│   └── pycloak/           # Core Keycloak HTTP client library
│       ├── client.py      # Sync/async Keycloak API clients
│       ├── models.py      # Pydantic models for API responses
│       ├── endpoints.py   # Keycloak API endpoint definitions
│       └── exceptions.py  # Custom exception classes
├── examples/              # Authentication flow examples
│   ├── user_to_app/      # User authentication examples
│   ├── app_to_app/       # Service-to-service examples
│   └── on_behalf_of/     # Delegated authentication examples
├── tests/                 # Comprehensive test suite
└── docs/                  # Additional documentation
```

## 🔧 PyCloak Library Features

### Authentication Flows
- ✅ **Client Credentials**: App-to-app authentication
- ✅ **Authorization Code**: User authentication with PKCE support
- ✅ **Password Grant**: Legacy user authentication (discouraged)
- ✅ **Refresh Token**: Token renewal flows

### Token Management  
- ✅ **Token Introspection**: Validate and inspect tokens
- ✅ **UserInfo Endpoint**: Get user claims
- ✅ **Token Revocation**: Invalidate tokens
- ✅ **Logout**: End user sessions

### Admin Operations
- ✅ **User Management**: Create, read, update users
- ✅ **Client Management**: Create and configure clients  
- ✅ **Role Management**: Create roles and assign to users
- ✅ **Realm Configuration**: Manage Keycloak realms

### Discovery & Standards Compliance
- ✅ **OpenID Connect Discovery**: Auto-discover endpoints
- ✅ **JWKS**: JSON Web Key Set for token verification
- ✅ **OAuth2 & OpenID Connect**: Full standards compliance

## 📚 Usage Examples

### Basic Client Credentials Flow

```python
from pycloak import KeycloakClient

# Initialize client
client = KeycloakClient(
    server_url="https://your-keycloak.com",
    realm="your-realm",
    client_id="your-client",
    client_secret="your-secret"
)

# Get access token for app-to-app communication
token_response = client.get_token_client_credentials(
    scope="openid profile"
)

print(f"Access token: {token_response.access_token}")
print(f"Expires in: {token_response.expires_in} seconds")
```

### User Authentication with Authorization Code

```python
# After user authorization, exchange code for tokens
token_response = client.get_token_authorization_code(
    code="authorization_code_from_redirect",
    redirect_uri="https://your-app.com/callback",
    code_verifier="pkce_code_verifier"  # For PKCE
)

# Get user information
userinfo = client.get_userinfo(token_response.access_token)
print(f"Welcome, {userinfo.preferred_username}!")
```

### Admin Operations

```python
# Get admin token
admin_token = client.get_admin_token("admin", "admin_password")

# Create a new user
user_id = client.create_user(
    admin_token.access_token,
    user_data={
        "username": "newuser",
        "email": "user@example.com", 
        "firstName": "New",
        "lastName": "User"
    },
    temporary_password="temp123"
)

# Create a client application
client_data = {
    "clientId": "my-new-app",
    "name": "My Application",
    "enabled": True,
    "publicClient": False,
    "redirectUris": ["https://app.example.com/*"]
}

internal_client_id = client.create_client(
    admin_token.access_token, 
    client_data
)
```

### Async Support

```python
import asyncio
from pycloak import AsyncKeycloakClient

async def main():
    async with AsyncKeycloakClient(
        server_url="https://your-keycloak.com",
        realm="your-realm",
        client_id="your-client",
        client_secret="your-secret"
    ) as client:
        
        # All methods have async equivalents
        token_response = await client.get_token_client_credentials()
        userinfo = await client.get_userinfo(token_response.access_token)
        
        print(f"User: {userinfo.preferred_username}")

asyncio.run(main())
```

## 🧪 Development Commands

```bash
# Run tests
make test

# Run tests with coverage
make test-coverage

# Lint code
make lint

# Format code  
make format

# Type checking
make type-check

# Run all checks
make check

# Clean build artifacts
make clean
```

## 📋 Environment Configuration

Create a `.env` file for configuration:

```bash
# Keycloak server configuration
KEYCLOAK_SERVER_URL=https://your-keycloak-server.com
KEYCLOAK_REALM=your-realm-name

# Default client credentials (optional)
KEYCLOAK_CLIENT_ID=your-default-client-id
KEYCLOAK_CLIENT_SECRET=your-client-secret

# Admin credentials for management operations (optional)
KEYCLOAK_ADMIN_USERNAME=admin
KEYCLOAK_ADMIN_PASSWORD=admin-password
```

## 🏗️ Architecture Principles

### Raw HTTP Focus
- Direct HTTP requests show exactly what's happening
- No hidden abstractions or magic
- Easy to debug and understand

### Educational Clarity  
- Code demonstrates concepts rather than hiding them
- Comprehensive docstrings explain OAuth2/OIDC flows
- Error handling shows common Keycloak scenarios

### Production Notes
- Comments indicate what would be needed for production
- No implementation of retry logic, rate limiting, etc.
- Focus on learning rather than production-ready code

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes following the project standards
4. Add tests for new functionality
5. Run the full test suite (`make test`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## 📖 Further Reading

- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [OAuth 2.0 RFC](https://tools.ietf.org/html/rfc6749)
- [OpenID Connect Specification](https://openid.net/specs/openid-connect-core-1_0.html)
- [JWT RFC](https://tools.ietf.org/html/rfc7519)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Note**: This library is designed for educational purposes and learning Keycloak concepts. For production applications, consider using established SDKs or implement additional production-ready features like retry logic, rate limiting, and comprehensive error handling.


