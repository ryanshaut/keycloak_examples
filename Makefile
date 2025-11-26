
local_setup:
	# test if uv is installed
	@if ! command -v uv &> /dev/null; then \
		echo "uv could not be found, installing..."; \
		curl -LsSf https://astral.sh/uv/install.sh | sh; \
	else \
		echo "uv is already installed"; \
	fi
	# create uv virtual environment