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
	@echo "Examples:"
	@echo "  make test-single TEST=TestVerifyUrlPayload"
	@echo "  make test-single TEST=TestCreateUrlPayment"

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