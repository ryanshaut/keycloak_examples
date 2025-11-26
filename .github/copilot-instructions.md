# Keycloak Examples - AI Coding Agent Instructions

## Project Overview

This repository demonstrates Keycloak authentication/authorization patterns using raw HTTP API calls instead of high-level SDKs to provide clear, educational examples. The project uses `uv` for Python dependency management and focuses on three core authentication workflows:

- **User-to-App**: Standard user authentication flows
- **App-to-App**: Service-to-service authentication using client credentials
- **On-Behalf-Of**: Delegated authentication scenarios

## Architecture & Structure

The planned codebase follows this structure:
- `examples/` - Individual workflow examples with their own README files
- `pycloak/` - Core Keycloak library providing sync/async HTTP API methods
- `.env` - Environment variables with detailed explanations

## Development Standards

### Package Management
- Use `uv` for all Python dependency management
- Configuration in `pyproject.toml` (when created)
- Environment management through `uv` virtual environments

### Scripts
- Prefer Makefile over adhoc shell scripts for common tasks (setup, test, lint).

### Code Organization
- **Raw HTTP Focus**: Always use direct HTTP requests to Keycloak endpoints rather than high-level SDK abstractions
- **Educational Clarity**: Code should clearly demonstrate the underlying API calls and authentication flows
- **Dual Interface**: Provide both synchronous and asynchronous versions of API methods in `pycloak/`

### Environment Configuration
- All configuration through `.env` file with comprehensive comments explaining each variable
- Include Keycloak server details, realm configuration, client credentials, and endpoint URLs
- Document required vs optional environment variables clearly

### Example Structure
Each example in `examples/` should:
- Have its own README explaining the specific authentication flow
- Include complete, runnable code showing the full authentication sequence
- Demonstrate error handling for common Keycloak scenarios (expired tokens, invalid credentials)
- Show both token acquisition and API usage patterns
- When a specific configuration is needed in Keycloak, provide setup instructions in the example README AND where possible, automate the setup process.
- Include deprovisioning steps to clean up any created resources.

### HTTP Client Patterns
- Create reusable HTTP client utilities in `pycloak/`
- Include proper error handling for Keycloak-specific error responses
- Implement token refresh logic where applicable
- Note production considerations (retries, timeouts, rate limiting) in comments without implementing them

### Documentation Focus
- Emphasize the "why" behind each authentication flow
- Explain Keycloak concepts (realms, clients, roles) in context
- Document the mapping between high-level authentication concepts and raw HTTP calls
- Include OpenAPI/schema references where available

## Development Workflow

### Testing Keycloak Integration
- Assume a running Keycloak instance for examples
- Document Keycloak setup requirements in example READMs
- Include sample realm/client configurations where needed

### Code Quality
- Follow Python type hints for API methods
- Use meaningful variable names that reflect Keycloak terminology
- Include docstrings explaining authentication flow steps
- Comment non-obvious Keycloak API behaviors
- Provide tests for all `pycloak/` methods demonstrating expected usage
- While we're assuming Keycloak exists, don't expect users to manually configure anything. Try to automate setup as much as possible.

## Key Patterns to Maintain

1. **Explicit over Implicit**: Always show the full HTTP request/response cycle
2. **Educational Value**: Code should teach Keycloak concepts, not hide them
3. **Production Notes**: Comment on what would be needed for production use without implementing it
4. **Error Transparency**: Show how Keycloak errors map to HTTP responses

This project prioritizes learning and understanding over production-ready abstractions.