# Development Guide

This document explains how to use the development tools for the NASPIP Go project.

## Makefile

The project includes a Makefile with convenient commands for testing and development.

### Available Commands

```bash
# Show all available commands
make help

# Run all tests (quiet mode)
make test

# Run all tests with verbose output
make test-all

# Run only PASETO tests
make test-paseto

# Run only protocol tests
make test-protocol

# Run a single test
make test-single TEST=TestName

# Clean build artifacts
make clean
```

### Examples

```bash
# Run a specific test
make test-single TEST=TestVerifyUrlPayload
make test-single TEST=TestCreateUrlPayment

# Run tests for a specific package
make test-paseto
make test-protocol

# Run all tests with detailed output
make test-all
```

## Pre-commit Hook

The project includes a pre-commit hook that automatically runs before each commit to ensure code quality.

### What it does

The pre-commit hook performs the following checks:

1. **Tests**: Runs all tests to ensure nothing is broken
2. **Code Formatting**: Checks that code is properly formatted with `go fmt`
3. **Code Quality**: Runs `go vet` to check for common mistakes

### How it works

- The hook is automatically triggered when you run `git commit`
- If any check fails, the commit is blocked
- You must fix the issues before the commit can proceed

### Example Output

```
Running pre-commit checks...
Running all tests...
✓ All tests passed
Checking code formatting...
✓ Code formatting is correct
Running go vet...
✓ Go vet passed
✓ Pre-commit checks passed. Proceeding with commit...
```

### Troubleshooting

If the pre-commit hook fails:

1. **Tests failing**: Run `make test-all` to see detailed output
2. **Formatting issues**: Run `go fmt ./...` to fix formatting
3. **Vet issues**: Fix the issues reported by `go vet`

### Bypassing the hook (not recommended)

If you absolutely need to bypass the pre-commit hook (not recommended), you can use:

```bash
git commit --no-verify -m "Your message"
```

## Best Practices

1. **Always run tests** before committing: `make test`
2. **Use the Makefile** for consistent test execution
3. **Don't bypass the pre-commit hook** unless absolutely necessary
4. **Fix issues immediately** when the pre-commit hook fails
5. **Use descriptive commit messages** that explain what changed

## Adding New Tests

When adding new tests:

1. Follow the existing naming convention: `TestFunctionName`
2. Use the `assert` package for assertions
3. Test both success and failure cases
4. Run `make test` to ensure your tests pass
5. The pre-commit hook will automatically catch any issues

## Deploying New Versions

This section explains how to deploy a new version of the NASPIP protocol to GitHub.

### Current Version

The project is currently using version `v3` in import paths:
```
github.com/fluxisus/naspip-go/v3
```

### Quick Start

The easiest way to deploy a new version is using the Makefile:

```bash
# Show current version configuration
make show-versions

# Create release branch and prepare for v4 (default)
make release-branch
make prepare-release

# Or for a different version (e.g., v5)
make release-branch NEW_VERSION=v5
make prepare-release NEW_VERSION=v5 RELEASE_TAG=v5.0.0
```

### Manual Deployment Process

If you prefer to do it manually:

#### 1. Prepare for Release

Before deploying a new version:

1. **Ensure all tests pass**:
   ```bash
   make test-all
   ```

2. **Update version in go.mod**:
   ```bash
   # For v4, update the module path
   go mod edit -module=github.com/fluxisus/naspip-go/v4
   ```

3. **Update import paths** in all files:
   ```bash
   # Replace v3 with v4 in all Go files
   find . -name "*.go" -exec sed -i '' 's|github.com/fluxisus/naspip-go/v3|github.com/fluxisus/naspip-go/v4|g' {} \;
   ```

4. **Update protobuf package**:
   ```bash
   # Update go_package in model.proto
   # Change from: option go_package = "encoding/protobuf";
   # To: option go_package = "github.com/fluxisus/naspip-go/v4/encoding/protobuf";
   ```

5. **Regenerate protobuf files** (if needed):
   ```bash
   # If you have protoc installed
   protoc --go_out=. encoding/protobuf/model.proto
   ```

#### 2. Create and Push Release Branch

1. **Create a new branch** for the release:
   ```bash
   git checkout -b release/v4
   ```

2. **Commit all changes**:
   ```bash
   git add .
   git commit -m "Prepare for v4 release"
   ```

3. **Push the branch**:
   ```bash
   git push origin release/v4
   ```

#### 3. Create GitHub Release

1. **Go to GitHub** and navigate to the repository
2. **Click "Releases"** in the right sidebar
3. **Click "Create a new release"**
4. **Set the tag** to `v4.0.0` (or appropriate version)
5. **Set the target** to the `release/v4` branch
6. **Add release notes** describing the changes
7. **Publish the release**

#### 4. Update Dependent Projects

After the release is published, update dependent projects:

1. **Update go.mod** in dependent projects:
   ```bash
   go get github.com/fluxisus/naspip-go/v4@latest
   ```

2. **Update import statements**:
   ```bash
   # Replace v3 with v4 in all import statements
   find . -name "*.go" -exec sed -i '' 's|github.com/fluxisus/naspip-go/v3|github.com/fluxisus/naspip-go/v4|g' {} \;
   ```

3. **Run tests** to ensure compatibility:
   ```bash
   go test ./...
   ```

### Version Variables

The Makefile uses these variables (can be overridden):

- `CURRENT_VERSION`: Current version (default: v3)
- `NEW_VERSION`: Target version (default: v4)
- `RELEASE_TAG`: GitHub release tag (default: $(NEW_VERSION).0.0)

### Examples

```bash
# Deploy v4 (default)
make release-branch
make prepare-release

# Deploy v5
make release-branch NEW_VERSION=v5
make prepare-release NEW_VERSION=v5

# Deploy v4 with custom tag
make prepare-release NEW_VERSION=v4 RELEASE_TAG=v4.1.0

# Deploy v5 with custom tag
make prepare-release NEW_VERSION=v5 RELEASE_TAG=v5.2.0
```

### Version Compatibility

- **v3**: Current stable version
- **v4**: New version with URL payload support and improved validation
- **v5+**: Future versions with additional features

### Rollback Plan

If issues are discovered after deployment:

1. **Revert to previous version** in dependent projects:
   ```bash
   go get github.com/fluxisus/naspip-go/v3@latest
   ```

2. **Update import statements** back to previous version
3. **Test thoroughly** before considering the new version again

### Best Practices

1. **Always test thoroughly** before releasing
2. **Use semantic versioning** (v4.0.0, v4.1.0, etc.)
3. **Write clear release notes** explaining changes
4. **Test with dependent projects** before final release
5. **Have a rollback plan** ready
6. **Use the Makefile** for consistent deployment process 