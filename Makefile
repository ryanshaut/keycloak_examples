
.PHONY: help setup test lint format check clean install dev-install

help: ## Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

setup: ## Set up development environment
	@echo "Setting up development environment..."
	# test if uv is installed
	@if ! command -v uv &> /dev/null; then \
		echo "uv could not be found, installing..."; \
		curl -LsSf https://astral.sh/uv/install.sh | sh; \
	else \
		echo "uv is already installed"; \
	fi
	# Clean any existing build artifacts
	rm -rf build/ dist/ *.egg-info/
	# Install dependencies and create virtual environment
	uv sync --dev
	@echo "Development environment ready! Activate with: source .venv/bin/activate"

install: ## Install package in production mode
	uv pip install .

dev-install: ## Install package in development mode
	uv pip install -e ".[dev]"

install-pre-commit: ## Install pre-commit hooks
	uv add --dev pre-commit
	uv run pre-commit install

test: ## Run tests
	uv run pytest tests/ -v

test-coverage: ## Run tests with coverage report
	uv run pytest tests/ --cov=src/pycloak --cov-report=html --cov-report=term-missing -v

test-fast: ## Run tests excluding slow ones
	uv run pytest tests/ -v -m "not slow"

lint: ## Run linting (ruff check)
	uv run ruff check src/ tests/

format: ## Format code (ruff format)
	uv run ruff format src/ tests/

format-check: ## Check code formatting without making changes
	uv run ruff format --check src/ tests/

type-check: ## Run type checking (mypy)
	uv run mypy src/pycloak

check: lint format-check type-check ## Run all checks (lint, format, type)

clean: ## Clean up build artifacts and cache
	@echo "Cleaning build artifacts..."
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	@echo "Cleaning Python cache files..."
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	@echo "Clean completed."

pre-commit: ## Run pre-commit hooks on all files
	uv run pre-commit run --all-files

build: ## Build the package
	@echo "Cleaning previous build..."
	rm -rf build/ dist/ *.egg-info/
	@echo "Installing build dependencies..."
	uv add --dev hatchling build
	@echo "Building package..."
	uv build

publish-test: ## Publish to test PyPI
	uv build
	uv publish --index-url https://test.pypi.org/simple/

publish: ## Publish to PyPI
	uv build
	uv publish

docker-build: ## Build Docker image for testing
	docker build -t keycloak-examples:latest .

docker-test: ## Run tests in Docker
	docker run --rm keycloak-examples:latest make test

update-deps: ## Update all dependencies
	uv sync --upgrade

validate: ## Validate package configuration
	@echo "Validating package configuration..."
	uv run python -m build --check-build-dependencies
	@echo "Checking imports..."
	uv run python -c "import sys; sys.path.insert(0, 'src'); import pycloak; print('✓ Package imports successfully')"

build-check: ## Check build without actually building
	@echo "Checking build configuration..."
	@python -c "try:\n    import tomllib\nexcept ImportError:\n    import tomli as tomllib\nwith open('pyproject.toml', 'rb') as f:\n    data = tomllib.load(f)\nprint('✓ pyproject.toml is valid')" 2>/dev/null || echo "⚠ Could not validate pyproject.toml"
	@echo "Checking package structure..."
	@if [ -d "src/pycloak" ]; then echo "✓ Package directory exists"; else echo "✗ Package directory missing"; exit 1; fi
	@if [ -f "src/pycloak/__init__.py" ]; then echo "✓ Package __init__.py exists"; else echo "✗ Package __init__.py missing"; exit 1; fi

# Legacy alias for backwards compatibility
local_setup: setup ## Alias for setup command