
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
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

pre-commit: ## Run pre-commit hooks on all files
	uv run pre-commit run --all-files

build: ## Build the package
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

# Legacy alias for backwards compatibility
local_setup: setup ## Alias for setup command