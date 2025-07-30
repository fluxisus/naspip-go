# NASPIP Go Makefile
# Provides convenient commands for testing and development

.PHONY: help test test-all test-paseto test-protocol test-single clean

# Default target
help:
	@echo "Available commands:"
	@echo "  test        - Run all tests"
	@echo "  test-all    - Run all tests with verbose output"
	@echo "  test-paseto - Run only PASETO tests"
	@echo "  test-protocol - Run only protocol tests"
	@echo "  test-single - Run a single test (usage: make test-single TEST=TestName)"
	@echo "  clean       - Clean build artifacts"
	@echo ""
	@echo "Deployment commands:"
	@echo "  show-versions     - Show current version configuration"
	@echo "  release-branch    - Create release branch (usage: make release-branch NEW_VERSION=v4)"
	@echo "  prepare-release   - Prepare code for release (usage: make prepare-release NEW_VERSION=v4)"
	@echo ""
	@echo "Examples:"
	@echo "  make test-single TEST=TestVerifyUrlPayload"
	@echo "  make test-single TEST=TestCreateUrlPayment"
	@echo "  make show-versions"
	@echo "  make release-branch NEW_VERSION=v4"
	@echo "  make prepare-release NEW_VERSION=v4 RELEASE_TAG=v4.0.0"

# Run all tests
test:
	@echo "Running all tests..."
	go test ./...

# Run all tests with verbose output
test-all:
	@echo "Running all tests with verbose output..."
	go test ./... -v

# Run only PASETO tests
test-paseto:
	@echo "Running PASETO tests..."
	go test ./paseto -v

# Run only protocol tests
test-protocol:
	@echo "Running protocol tests..."
	go test ./protocol -v

# Run a single test (usage: make test-single TEST=TestName)
test-single:
	@if [ -z "$(TEST)" ]; then \
		echo "Error: TEST parameter is required"; \
		echo "Usage: make test-single TEST=TestName"; \
		echo "Example: make test-single TEST=TestVerifyUrlPayload"; \
		exit 1; \
	fi
	@echo "Running single test: $(TEST)"
	@go test ./... -run $(TEST) -v

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	go clean
	rm -f *.exe *.test

# Version variables (can be overridden)
CURRENT_VERSION ?= v3
NEW_VERSION ?= v4
RELEASE_TAG ?= $(NEW_VERSION).0.0

# Deployment helpers
.PHONY: prepare-release release-branch show-versions

# Show current version configuration
show-versions:
	@echo "Current version configuration:"
	@echo "  Current version: $(CURRENT_VERSION)"
	@echo "  New version: $(NEW_VERSION)"
	@echo "  Release tag: $(RELEASE_TAG)"
	@echo ""
	@echo "Usage examples:"
	@echo "  make prepare-release                    # Prepare for v4 (default)"
	@echo "  make prepare-release NEW_VERSION=v5     # Prepare for v5"
	@echo "  make prepare-release NEW_VERSION=v4 RELEASE_TAG=v4.1.0  # Custom tag"
	@echo "  make release-branch NEW_VERSION=v5      # Create release branch for v5"

# Prepare for new version release
prepare-release:
	@echo "Preparing for $(NEW_VERSION) release..."
	@echo "Current version: $(CURRENT_VERSION) -> New version: $(NEW_VERSION)"
	@echo ""
	@echo "Updating module path to $(NEW_VERSION)..."
	go mod edit -module=github.com/fluxisus/naspip-go/$(NEW_VERSION)
	@echo "Updating import paths..."
	find . -name "*.go" -exec sed -i '' 's|github.com/fluxisus/naspip-go/$(CURRENT_VERSION)|github.com/fluxisus/naspip-go/$(NEW_VERSION)|g' {} \;
	@echo "Updating protobuf package..."
	sed -i '' 's|option go_package = "encoding/protobuf";|option go_package = "github.com/fluxisus/naspip-go/$(NEW_VERSION)/encoding/protobuf";|g' encoding/protobuf/model.proto
	@echo "Running tests to ensure everything works..."
	make test-all
	@echo "✓ $(NEW_VERSION) preparation complete"
	@echo ""
	@echo "Next steps:"
	@echo "1. git add ."
	@echo "2. git commit -m 'Prepare for $(NEW_VERSION) release'"
	@echo "3. git push origin release/$(NEW_VERSION)"
	@echo "4. Create GitHub release with tag $(RELEASE_TAG)"

# Create release branch for new version
release-branch:
	@echo "Creating release branch for $(NEW_VERSION)..."
	git checkout -b release/$(NEW_VERSION)
	@echo "✓ Release branch created: release/$(NEW_VERSION)"
	@echo ""
	@echo "Next steps:"
	@echo "1. make prepare-release NEW_VERSION=$(NEW_VERSION)"
	@echo "2. git add ."
	@echo "3. git commit -m 'Prepare for $(NEW_VERSION) release'"
	@echo "4. git push origin release/$(NEW_VERSION)"

 