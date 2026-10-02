# Kdf108 Makefile

# Variables
DOTNET = dotnet
DOCFX = docfx
PROJECT_DIR = src/Kdf108
DOCS_DIR = docs
API_DOCS_DIR = $(DOCS_DIR)/api
DOCFX_PROJECT = docfx.json

# Default target
.PHONY: all
all: build

# Build the project
.PHONY: build
build:
	$(DOTNET) build

# Run tests
.PHONY: test
test:
	$(DOTNET) test

# Clean build artifacts
.PHONY: clean
clean:
	$(DOTNET) clean
	rm -rf $(API_DOCS_DIR)
	rm -rf _site
	rm -rf obj

# Install DocFX globally if not already installed
.PHONY: install-docfx
install-docfx:
	@command -v $(DOCFX) >/dev/null 2>&1 || (echo "Installing DocFX..." && $(DOTNET) tool install -g docfx)

# Generate documentation
.PHONY: docs
docs: install-docfx build
	@echo "Generating API documentation..."
	$(DOCFX) $(DOCFX_PROJECT) --serve=false

# Generate and serve documentation locally
.PHONY: docs-serve
docs-serve: install-docfx build
	@echo "Generating and serving API documentation..."
	$(DOCFX) $(DOCFX_PROJECT) --serve

# Generate documentation metadata only
.PHONY: docs-metadata
docs-metadata: install-docfx build
	@echo "Generating documentation metadata..."
	$(DOCFX) metadata $(DOCFX_PROJECT)

# Help target
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  make build         - Build the project"
	@echo "  make test          - Run tests"
	@echo "  make clean         - Clean build artifacts and generated docs"
	@echo "  make docs          - Generate API documentation"
	@echo "  make docs-serve    - Generate and serve documentation locally"
	@echo "  make docs-metadata - Generate documentation metadata only"
	@echo "  make help          - Show this help message"