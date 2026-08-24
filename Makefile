.PHONY: all help bootstrap bootstrap-force hooks-ensure tools sync dependencies verify-dependencies version version-set version-bump-major version-bump-minor version-bump-patch
.PHONY: lint test build install build-all package package-sign verify-release-key clean fmt fmt-check check-all precommit prepush pr-final license-audit
.PHONY: release-check release-prepare release-build release-preflight release-notes-check doctor validate-app-identity
.PHONY: release-clean release-download release-notes release-stage-anchors release-insert-anchors
.PHONY: release-checksums release-sign release-export-keys release-verify-checksums
.PHONY: release-verify-signatures release-verify-keys release-verify release-upload release
.PHONY: release-guard-tag-version
.PHONY: sync-embedded-identity verify-embedded-identity test-standalone-binary cdrl-verify

# Binary and version information
BINARY_NAME := decernor
BINARY_EXT :=
ifeq ($(OS),Windows_NT)
	BINARY_EXT := .exe
endif
VERSION := $(shell cat VERSION 2>/dev/null || echo "dev")
DECERNOR_RELEASE_TAG ?= v$(VERSION)
export DECERNOR_RELEASE_TAG
DECERNOR_MINISIGN_KEY ?=
DECERNOR_MINISIGN_PUB ?=
DECERNOR_PGP_KEY_ID ?=
DECERNOR_GPG_HOMEDIR ?=
DIST_RELEASE := dist/release
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildDate=$(BUILD_DATE)

# Go related variables
GOCMD := go
GOTEST := $(GOCMD) test
GOMOD := $(GOCMD) mod

# Build static binaries with cgo disabled. This project imports no C, so cgo
# buys nothing — and the goneat-tools-runner image exports CGO_ENABLED=1, which
# overrides Go's normal cross-compile default of 0 and makes `build-all` invoke
# gcc for every GOOS/GOARCH (cross targets then fail: "gcc: unrecognized option
# -m64"). Forcing 0 yields portable static binaries that cross-compile cleanly.
# NOTE: `:=` (not `?=`) on purpose — the image presets CGO_ENABLED=1 in the
# environment, and `?=` would treat that as "already set" and skip. A file
# assignment overrides the environment while still yielding to `make CGO_ENABLED=1`.
export CGO_ENABLED := 0

# Tool installation (user-space bin dir; overridable with BINDIR=...)
#
# Defaults:
# - macOS/Linux: $HOME/.local/bin
# - Windows (Git Bash / MSYS / MINGW / Cygwin): %USERPROFILE%\\bin (or $HOME/bin)
UNAME_S_RAW := $(shell uname -s 2>/dev/null || echo unknown)
IS_WINDOWS_SHELL := $(filter MINGW% MSYS% CYGWIN%,$(UNAME_S_RAW))

ifeq ($(strip $(IS_WINDOWS_SHELL)),)
DEFAULT_BINDIR := $(if $(HOME),$(HOME)/.local/bin,./bin)
else
CYGPATH_BIN := $(shell command -v cygpath 2>/dev/null)
ifeq ($(strip $(USERPROFILE)),)
DEFAULT_BINDIR := $(if $(HOME),$(HOME)/bin,./bin)
else
DEFAULT_BINDIR := $(if $(CYGPATH_BIN),$(shell cygpath -u "$(USERPROFILE)")/bin,$(USERPROFILE)/bin)
endif
endif

BINDIR ?= $(DEFAULT_BINDIR)

# Embedded identity mirror (build artifact contract)
EMBEDDED_IDENTITY_SRC := .fulmen/app.yaml
EMBEDDED_IDENTITY_DST := internal/assets/appidentity/app.yaml

# Tool versions
# Bump cadence: keep within a couple of minor releases of upstream goneat so
# local installs (via sfetch) track the toolbox runner image. CI/release do not
# use this — they get goneat from the goneat-tools-runner image.
GONEAT_VERSION ?= v0.5.16
SFETCH_BIN := $(shell command -v sfetch 2>/dev/null)
GONEAT_BIN = $(firstword $(wildcard $(BINDIR)/goneat$(BINARY_EXT)) $(shell command -v goneat 2>/dev/null))

# Platform detection
ifeq ($(OS),Windows_NT)
    PLATFORM := windows
else
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Linux)
        PLATFORM := linux
    endif
    ifeq ($(UNAME_S),Darwin)
        PLATFORM := mac
    endif
    ifneq (,$(findstring BSD,$(UNAME_S)))
        PLATFORM := bsd
    endif
endif

# Default target
all: fmt test

help:  ## Show this help message
	@printf "%b" '$(BINARY_NAME) CLI - Available Make Targets\n\nTargets:\n  help                  - Show this help message\n  bootstrap             - Install external tools (goneat) and dependencies\n  bootstrap-force       - Force reinstall external tools\n  tools                 - Verify external tools are available\n  sync                  - No-op placeholder for ecosystem compatibility\n  sync-embedded-identity - Sync embedded identity mirror (.fulmen → internal/assets)\n  verify-embedded-identity - Verify embedded identity mirror is in sync\n  dependencies          - Generate SBOM for supply-chain security\n  license-audit         - Audit dependency licenses\n  lint                  - Run lint/format/style checks\n  test                  - Run all tests\n  build                 - Build distributable artifacts\n  install               - Install binary to BINDIR (default: ~/.local/bin)\n  build-all             - Build multi-platform binaries\n  test-standalone-binary - Verify built binary works outside repo\n  clean                 - Remove build artifacts and caches\n  fmt                   - Format code\n  fmt-check             - Check formatting without mutating (CI gate)\n  version               - Print current version\n  version-set           - Set version to specific value (VERSION=x.y.z)\n  version-bump-major    - Bump major version\n  version-bump-minor    - Bump minor version\n  version-bump-patch    - Bump patch version\n  release-check         - Run release checklist validation\n  release-prepare       - Prepare for release\n  release-build         - Build release artifacts\n  check-all             - Run all quality checks (fmt, lint, test)\n  precommit             - Run pre-commit hooks\n  prepush               - Run pre-push hooks (tag/pushtag path)\n  pr-final              - Non-mutating PR gate (identity, fmt-check, lint, test, license, build-all)\n  doctor                - Run repository health checks\n  validate-app-identity - Validate app identity configuration\n  cdrl-verify           - Fast old-baseline residue detector\n'

bootstrap:  ## Install external tools via sfetch + goneat
	@echo "Installing external tools..."
	@if [ -z "$(SFETCH_BIN)" ]; then echo "❌ sfetch not found (required trust anchor)"; echo ""; echo "Install sfetch with:"; echo "  curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/install-sfetch.sh | bash"; echo ""; echo "Or install into a specific directory:"; echo "  curl -sSfL https://github.com/3leaps/sfetch/releases/latest/download/install-sfetch.sh | bash -s -- --dir \"$(BINDIR)\" --yes"; exit 1; else echo "✅ sfetch found: $$($(SFETCH_BIN) --version 2>&1 | head -n1)"; echo "→ sfetch self-verify (trust anchors):"; $(SFETCH_BIN) --self-verify; fi
	@mkdir -p "$(BINDIR)"; if [ "$(FORCE)" = "1" ] || [ "$(FORCE)" = "true" ]; then rm -f "$(BINDIR)/goneat$(BINARY_EXT)"; fi; if [ -x "$(BINDIR)/goneat$(BINARY_EXT)" ] && "$(BINDIR)/goneat$(BINARY_EXT)" --version 2>/dev/null | grep -q "$(GONEAT_VERSION)"; then echo "→ goneat already available at $(BINDIR)/goneat$(BINARY_EXT)"; else echo "→ Installing goneat $(GONEAT_VERSION) to $(BINDIR) via sfetch..."; $(SFETCH_BIN) --repo fulmenhq/goneat --tag $(GONEAT_VERSION) --dest-dir "$(BINDIR)"; fi
	@echo "→ Installing bootstrap, foundation, lint, security, and format tools via goneat..."
	@# Per-scope so a host-inapplicable tool (e.g. scoop is Windows-only and lives in
	@# the bootstrap scope) is non-fatal on macOS/Linux instead of aborting the chain.
	@for scope in bootstrap foundation lint security format; do \
		$(GONEAT_BIN) doctor tools --scope $$scope --install --yes \
			|| echo "⚠️  scope '$$scope' had tools unavailable on this platform (continuing)"; \
	done
	@echo "→ Download Go module dependencies..." && go mod download && go mod tidy && $(MAKE) hooks-ensure && echo "✅ Bootstrap completed. Ensure '$(BINDIR)' is on your PATH"

bootstrap-force:  ## Force reinstall external tools
	@$(MAKE) bootstrap FORCE=1

hooks-ensure:  ## Ensure git hooks are installed (idempotent)
	@if [ -d ".git" ] && [ -n "$(GONEAT_BIN)" ] && [ ! -x ".git/hooks/pre-commit" ]; then \
		echo "🔗 Installing git hooks with goneat..."; \
		$(GONEAT_BIN) hooks install 2>/dev/null || true; \
	fi

tools:  ## Verify external tools are available
	@echo "Verifying external tools..."
	@if [ -z "$(GONEAT_BIN)" ]; then echo "❌ goneat not found. Run 'make bootstrap' first."; exit 1; fi
	@echo "✅ goneat: $$($(GONEAT_BIN) --version 2>&1 | head -n1)"
	@echo "→ Checking tool scopes..."; $(GONEAT_BIN) doctor tools --scope bootstrap || echo "⚠️  Some bootstrap tools missing."; $(GONEAT_BIN) doctor tools --scope foundation || echo "⚠️  Some foundation tools missing. Run 'make bootstrap' to install."; $(GONEAT_BIN) doctor tools --scope security || echo "⚠️  Some security tools missing. Run 'make bootstrap' to install."; $(GONEAT_BIN) doctor tools --scope format || echo "⚠️  Some format tools missing. Run 'make bootstrap' to install."; $(GONEAT_BIN) doctor tools --scope lint || echo "⚠️  Some lint tools missing. Run 'make bootstrap' to install."
	@echo "✅ Tool verification completed"

sync:  ## Sync assets from Crucible SSOT (no-op for Decernor)
	@echo "⚠️  $(BINARY_NAME) microtool does not consume SSOT assets directly"
	@echo "✅ Sync target satisfied (no-op)"

sync-embedded-identity:  ## Copy .fulmen/app.yaml → internal/assets/appidentity/app.yaml
	@mkdir -p "$(dir $(EMBEDDED_IDENTITY_DST))"
	@cp "$(EMBEDDED_IDENTITY_SRC)" "$(EMBEDDED_IDENTITY_DST)"
	@echo "✅ Synced embedded identity mirror: $(EMBEDDED_IDENTITY_DST)"

verify-embedded-identity:  ## Fail if embedded identity mirror is out of sync
	@if [ ! -f "$(EMBEDDED_IDENTITY_SRC)" ]; then echo "❌ Missing $(EMBEDDED_IDENTITY_SRC)"; exit 1; fi
	@if [ ! -f "$(EMBEDDED_IDENTITY_DST)" ]; then echo "❌ Missing $(EMBEDDED_IDENTITY_DST) (run: make sync-embedded-identity)"; exit 1; fi
	@if ! cmp -s "$(EMBEDDED_IDENTITY_SRC)" "$(EMBEDDED_IDENTITY_DST)"; then \
		echo "❌ Embedded identity is out of sync."; \
		echo "   Run: make sync-embedded-identity (then commit the updated mirror)"; \
		diff -u "$(EMBEDDED_IDENTITY_SRC)" "$(EMBEDDED_IDENTITY_DST)" || true; \
		exit 1; \
	fi
	@echo "✅ Embedded identity mirror is in sync"

dependencies:  ## Generate SBOM for supply-chain security
	@if [ -z "$(GONEAT_BIN)" ]; then echo "❌ goneat not found. Run 'make bootstrap' first."; exit 1; fi
	@echo "Generating Software Bill of Materials (SBOM)..."; mkdir -p sbom; $(GONEAT_BIN) dependencies --sbom --sbom-output sbom/$(BINARY_NAME).cdx.json; echo "✅ SBOM generated at sbom/$(BINARY_NAME).cdx.json"

verify-dependencies:  ## Alias for dependencies (compatibility)
	@$(MAKE) dependencies

license-audit:  ## Audit dependency licenses (goneat — enforces .goneat/dependencies.yaml)
	@if [ -z "$(GONEAT_BIN)" ]; then echo "❌ goneat not found. Run 'make bootstrap' first."; exit 1; fi
	@echo "🧪 Auditing dependency licenses (goneat dependencies)..."
	@# goneat reads the forbidden/allowed policy from .goneat/dependencies.yaml and
	@# degrades gracefully on the go-licenses Go-1.26-stdlib quirk (raw go-licenses
	@# errors with "package X does not have module info").
	@$(GONEAT_BIN) dependencies --licenses --fail-on high
	@echo "✅ License audit passed"

version:  ## Print current version
	@echo "$(VERSION)"

version-set:  ## Set version to specific value (usage: make version-set VERSION=x.y.z)
	@if [ -z "$(VERSION)" ]; then \
		echo "❌ VERSION not specified. Usage: make version-set VERSION=x.y.z"; \
		exit 1; \
	fi
	@echo "$(VERSION)" > VERSION
	@echo "✅ Version set to $(VERSION)"

version-bump-major:  ## Bump major version
	@if [ -z "$(GONEAT_BIN)" ]; then \
		echo "❌ goneat not found. Run 'make bootstrap' first."; \
		exit 1; \
	fi
	@echo "Bumping major version..."
	@$(GONEAT_BIN) version bump major
	@echo "✅ Version bumped to $$(cat VERSION)"

version-bump-minor:  ## Bump minor version
	@if [ -z "$(GONEAT_BIN)" ]; then \
		echo "❌ goneat not found. Run 'make bootstrap' first."; \
		exit 1; \
	fi
	@echo "Bumping minor version..."
	@$(GONEAT_BIN) version bump minor
	@echo "✅ Version bumped to $$(cat VERSION)"

version-bump-patch:  ## Bump patch version
	@if [ -z "$(GONEAT_BIN)" ]; then \
		echo "❌ goneat not found. Run 'make bootstrap' first."; \
		exit 1; \
	fi
	@echo "Bumping patch version..."
	@$(GONEAT_BIN) version bump patch
	@echo "✅ Version bumped to $$(cat VERSION)"

release-notes-check:  ## Verify VERSION, identity yaml, and notes files for this cut
	@set -euo pipefail; \
	V=$$(tr -d ' \n' < VERSION); \
	YAML_V=$$(sed -n 's/^  version: "\(.*\)"/\1/p' $(EMBEDDED_IDENTITY_SRC) | head -1); \
	if [ -z "$$V" ]; then echo "❌ VERSION is empty"; exit 1; fi; \
	if [ "$$YAML_V" != "$$V" ]; then \
		echo "❌ $(EMBEDDED_IDENTITY_SRC) app.version ($$YAML_V) != VERSION ($$V)"; exit 1; \
	fi; \
	if ! grep -q "^## \[$$V\]" CHANGELOG.md; then \
		echo "❌ CHANGELOG.md missing ## [$$V] heading"; exit 1; \
	fi; \
	if [ ! -f "docs/releases/v$$V.md" ]; then \
		echo "❌ missing docs/releases/v$$V.md"; exit 1; \
	fi; \
	if ! grep -q "^## v$$V" RELEASE_NOTES.md; then \
		echo "❌ RELEASE_NOTES.md missing ## v$$V heading"; exit 1; \
	fi; \
	echo "✅ Release notes check passed ($$V)"

release-preflight: release-notes-check verify-embedded-identity fmt-check lint test  ## Non-mutating tag gate
	@if [ ! -f keys/expected-fingerprints.txt ] || [ ! -f keys/expected-fingerprints.ndjson ]; then \
		echo "❌ missing keys/expected-fingerprints.{txt,ndjson} — run make release-insert-anchors"; exit 1; \
	fi
	@echo "✅ Release preflight passed"

release-check: release-preflight  ## Alias for release-preflight

release-prepare: release-preflight  ## Alias for release-preflight

release-guard-tag-version: ## Verify DECERNOR_RELEASE_TAG matches VERSION
	@./scripts/release-guard-tag-version.sh

release-clean: ## Remove dist/release
	rm -rf $(DIST_RELEASE)
	@echo "[ok] $(DIST_RELEASE) cleaned"

release-download: ## Download unsigned archives from GitHub
	@if [ -z "$(DECERNOR_RELEASE_TAG)" ] || [ "$(DECERNOR_RELEASE_TAG)" = "v" ]; then \
		echo "error: set DECERNOR_RELEASE_TAG=vX.Y.Z" >&2; exit 2; \
	fi
	@./scripts/download-release-assets.sh $(DECERNOR_RELEASE_TAG) $(DIST_RELEASE)

release-notes: ## Copy docs/releases/vX.Y.Z.md into dist before checksums
	@src="docs/releases/$(DECERNOR_RELEASE_TAG).md"; \
	if [ ! -f "$$src" ]; then echo "❌ missing $$src" >&2; exit 1; fi; \
	mkdir -p "$(DIST_RELEASE)"; \
	cp "$$src" "$(DIST_RELEASE)/release-notes-$(DECERNOR_RELEASE_TAG).md"; \
	echo "[ok] copied $$src into the checksum set"

release-insert-anchors: ## Generate keys/ pins from DECERNOR_* env + decernor fingerprint
	@./scripts/insert-expected-fingerprints.sh

release-stage-anchors: ## Copy committed pins into dist before checksums (net-new)
	@./scripts/stage-release-anchors.sh $(DIST_RELEASE)

release-checksums: ## Generate SHA256SUMS and SHA512SUMS (archives + notes + pins)
	@./scripts/generate-checksums.sh $(DIST_RELEASE) $(DECERNOR_RELEASE_TAG)

release-sign: ## Sign checksum manifests (requires DECERNOR_MINISIGN_KEY)
	@if [ -z "$(DECERNOR_MINISIGN_KEY)" ]; then \
		echo "error: DECERNOR_MINISIGN_KEY is not set" >&2; exit 2; \
	fi
	@./scripts/sign-release-assets.sh $(DECERNOR_RELEASE_TAG) $(DIST_RELEASE)

release-export-keys: ## Export public signing keys (DECERNOR_MINISIGN_PUB + GPG env)
	@./scripts/export-release-keys.sh $(DIST_RELEASE)

release-verify-checksums: ## Verify SHA256SUMS against staged files
	@cd $(DIST_RELEASE) && shasum -a 256 -c SHA256SUMS

release-verify-signatures: ## Verify minisign/PGP signatures
	@./scripts/verify-signatures.sh $(DIST_RELEASE)

release-verify-keys: ## Public-only + pin match via decernor
	@./scripts/verify-public-keys.sh $(DIST_RELEASE)

release-verify: release-verify-checksums release-verify-signatures release-verify-keys
	@echo "[ok] All release verifications passed"

release-upload: release-verify ## Upload signed provenance (draft unchanged)
	@./scripts/upload-release-assets.sh $(DECERNOR_RELEASE_TAG) $(DIST_RELEASE)

# Serialized walk. Leaves stay independent. Stage anchors before checksums.
release: release-guard-tag-version ## Full signing workflow (after CI draft)
	$(MAKE) release-clean
	$(MAKE) release-download
	$(MAKE) release-notes
	$(MAKE) release-stage-anchors
	$(MAKE) release-checksums
	$(MAKE) release-sign
	$(MAKE) release-export-keys
	$(MAKE) release-upload
	@echo "[ok] Release $(DECERNOR_RELEASE_TAG) complete"

release-build: build-all  ## Build release artifacts (binaries + checksums)
	@echo "✅ Release build complete"

build: verify-embedded-identity  ## Build binary for current platform
	@echo "→ Building $(BINARY_NAME) v$(VERSION)..."
	@mkdir -p bin
	@# -buildvcs=false: version/commit/date come from -ldflags; VCS stamping is
	@# redundant and fails on container-owned checkouts ("error obtaining VCS status").
	@go build -buildvcs=false -ldflags="$(LDFLAGS)" -o bin/$(BINARY_NAME)$(BINARY_EXT) ./cmd/$(BINARY_NAME)
	@echo "✓ Binary built: bin/$(BINARY_NAME)$(BINARY_EXT)"

install: build  ## Install binary to BINDIR (default: ~/.local/bin)
	@echo "→ Installing $(BINARY_NAME) to $(BINDIR)..."
	@mkdir -p "$(BINDIR)"
	@rm -f "$(BINDIR)/$(BINARY_NAME)$(BINARY_EXT)"
	@cp bin/$(BINARY_NAME)$(BINARY_EXT) "$(BINDIR)/$(BINARY_NAME)$(BINARY_EXT)"
	@echo "✓ Installed: $(BINDIR)/$(BINARY_NAME)$(BINARY_EXT)"

test-standalone-binary: build  ## Verify built binary runs outside repo
	@echo "→ Standalone binary check (outside repo)..."
	@set -euo pipefail; \
	tmp=$$(mktemp -d "$${TMPDIR:-/var/tmp}/decernor-standalone.XXXXXX"); \
	trap 'rm -rf "$$tmp"' EXIT; \
	cp "bin/$(BINARY_NAME)$(BINARY_EXT)" "$$tmp/$(BINARY_NAME)$(BINARY_EXT)"; \
	"$$tmp/$(BINARY_NAME)$(BINARY_EXT)" version >/dev/null; \
	"$$tmp/$(BINARY_NAME)$(BINARY_EXT)" --help >/dev/null; \
	echo "✅ Standalone binary check passed"

build-all: verify-embedded-identity  ## Build multi-platform binaries and generate checksums
	@echo "→ Building for multiple platforms..."
	@mkdir -p bin
	@# -buildvcs=false: version/commit/date come from -ldflags (see `build`).
	@echo "Building Linux amd64..."
	@GOOS=linux GOARCH=amd64 go build -buildvcs=false -ldflags="$(LDFLAGS)" -o bin/$(BINARY_NAME)-linux-amd64 ./cmd/$(BINARY_NAME)
	@echo "Building Darwin amd64..."
	@GOOS=darwin GOARCH=amd64 go build -buildvcs=false -ldflags="$(LDFLAGS)" -o bin/$(BINARY_NAME)-darwin-amd64 ./cmd/$(BINARY_NAME)
	@echo "Building Darwin arm64..."
	@GOOS=darwin GOARCH=arm64 go build -buildvcs=false -ldflags="$(LDFLAGS)" -o bin/$(BINARY_NAME)-darwin-arm64 ./cmd/$(BINARY_NAME)
	@echo "Building Windows amd64..."
	@GOOS=windows GOARCH=amd64 go build -buildvcs=false -ldflags="$(LDFLAGS)" -o bin/$(BINARY_NAME)-windows-amd64.exe ./cmd/$(BINARY_NAME)
	@echo "Building Linux arm64..."
	@GOOS=linux GOARCH=arm64 go build -buildvcs=false -ldflags="$(LDFLAGS)" -o bin/$(BINARY_NAME)-linux-arm64 ./cmd/$(BINARY_NAME)
	@cd bin && (sha256sum * > SHA256SUMS.txt 2>/dev/null || shasum -a 256 * > SHA256SUMS.txt)
	@echo "✓ Multi-platform binaries built in bin/"

package: build-all  ## Package release archives and checksums to dist/release (no signing)
	@BINARY_NAME=$(BINARY_NAME) ./scripts/package-artifacts.sh

package-sign: build-all  ## Package release archives and sign SHA256SUMS (requires gpg, SIGN=1 optional)
	@SIGN=1 BINARY_NAME=$(BINARY_NAME) ./scripts/package-artifacts.sh

verify-release-key:  ## Verify exported public key contains no private material (run package-sign with SIGNING_KEY_ID)
	@./scripts/verify-public-key.sh dist/release/$(BINARY_NAME)-release-signing-key.asc

test: verify-embedded-identity  ## Run all tests
	@echo "Running test suite..."
	$(GOTEST) ./... -v -cover
	@$(MAKE) build
	@bash tests/release/ceremony_test.sh

lint:  ## Run lint checks with goneat
	@if [ -z "$(GONEAT_BIN)" ]; then echo "❌ goneat not found. Run 'make bootstrap' first."; exit 1; fi
	@echo "Running Go vet..." && $(GOCMD) vet ./... && echo "Running goneat assess (lint)..." && $(GONEAT_BIN) assess --categories lint --fail-on high --package-mode && echo "✅ Lint checks passed"

fmt:  ## Format code with goneat
	@if [ -z "$(GONEAT_BIN)" ]; then echo "❌ goneat not found. Run 'make bootstrap' first."; exit 1; fi
	@echo "Formatting with goneat..." && $(GONEAT_BIN) format && echo "✅ Formatting completed"

fmt-check:  ## Check formatting without mutating (CI gate)
	@if [ -z "$(GONEAT_BIN)" ]; then echo "❌ goneat not found. Run 'make bootstrap' first."; exit 1; fi
	@# Real non-mutating gate. `goneat assess --categories format` does NOT fail on
	@# format diffs (they sit below "high" severity), so use `goneat format --check`.
	@echo "Checking formatting with goneat..." && $(GONEAT_BIN) format --check && echo "✅ Formatting is clean"

check-all: fmt lint test  ## Run all quality checks (fmt, lint, test)
	@echo "✅ All quality checks passed"

precommit:  ## Run pre-commit hooks (format/lint/security + tests)
	@if [ -z "$(GONEAT_BIN)" ]; then echo "❌ goneat not found. Run 'make bootstrap' first."; exit 1; fi
	@$(MAKE) verify-embedded-identity
	@echo "Running pre-commit validation..." && $(GONEAT_BIN) assess --categories format,lint,security --fail-on critical --package-mode
	@$(MAKE) test
	@echo "✅ Pre-commit checks passed"

prepush: license-audit ## Run pre-push hooks (reserved for the tag/pushtag path)
	@if [ -z "$(GONEAT_BIN)" ]; then echo "❌ goneat not found. Run 'make bootstrap' first."; exit 1; fi
	@echo "Running pre-push validation..." && $(GONEAT_BIN) assess --categories format,lint,security,dependencies,dates,tools,maturity,repo-status --fail-on high --package-mode && echo "✅ Pre-push checks passed"

pr-final:  ## Non-mutating PR gate (identity + fmt-check + lint + test + license + build-all)
	@echo "🔒 Running pr-final gate (non-mutating)..."
	@$(MAKE) verify-embedded-identity
	@$(MAKE) fmt-check
	@$(MAKE) lint
	@$(MAKE) test
	@$(MAKE) license-audit
	@$(MAKE) build-all
	@echo "✅ pr-final gate passed"

clean:  ## Clean build artifacts and reports
	@echo "Cleaning artifacts..."
	@rm -rf bin/ dist/ coverage.out coverage.html sbom/ vendor/
	@echo "✅ Clean completed"

# Repository validation targets

doctor:  ## Run repository health checks
	@echo "🏥 Running repository health check..." && test -f .fulmen/app.yaml || (echo "❌ Missing .fulmen/app.yaml" && exit 1)
	@which go >/dev/null 2>&1 || (echo "❌ Go not installed" && exit 1)
	@test -f go.mod || (echo "❌ Missing go.mod" && exit 1)
	@$(MAKE) test > /dev/null 2>&1 || (echo "❌ Tests failed" && exit 1)
	@echo "🎉 Repository health check passed"

cdrl-verify:  ## Fast old-baseline residue detector
	@echo "🔎 Old-baseline residue scan..."
	@if ! command -v rg >/dev/null 2>&1; then echo "❌ rg not found. Install ripgrep or run 'make bootstrap'."; exit 1; fi
	@if [ ! -f .fulmen/app.yaml ]; then echo "❌ Missing .fulmen/app.yaml"; exit 1; fi
	@if [ ! -f go.mod ]; then echo "❌ Missing go.mod"; exit 1; fi
	@OLD_MODULE="github.com/fulmenhq/forge-microtool-gimlet"; \
	OLD_BINARY="gimlet"; \
	OLD_ENV="GIMLET_"; \
	CURRENT_MODULE=$$(grep '^module ' go.mod | head -n1 | cut -d' ' -f2); \
	CURRENT_BINARY=$$(grep -E '^\s*binary_name:' .fulmen/app.yaml | head -n1 | cut -d: -f2- | tr -d '"' | xargs); \
	CURRENT_ENV=$$(grep -E '^\s*env_prefix:' .fulmen/app.yaml | head -n1 | cut -d: -f2- | tr -d '"' | xargs); \
	echo "→ identity: $${CURRENT_MODULE} / $${CURRENT_BINARY} / $${CURRENT_ENV}"; \
	echo "→ scanning for unrelated Fulmen baseline residue (GRONINGEN_ / forge-workhorse-groningen)..."; \
	if rg -n 'GRONINGEN_|github.com/fulmenhq/forge-workhorse-groningen' --glob '*.{go,mod,sum,yaml,yml,sh}' --glob '.github/workflows/*' --glob '.env*' .; then \
		echo "❌ Unrelated baseline residue detected (see matches above)"; \
		exit 1; \
	fi; \
	if [ "$${CURRENT_MODULE}" = "$${OLD_MODULE}" ] && [ "$${CURRENT_BINARY}" = "$${OLD_BINARY}" ] && [ "$${CURRENT_ENV}" = "$${OLD_ENV}" ]; then \
		echo "ℹ️  Upstream baseline defaults detected."; \
		echo "✅ No unrelated baseline residue detected"; \
		exit 0; \
	fi; \
	echo "→ scanning for old Gimlet baseline residue..."; \
	if rg -n '\\bgimlet\\b|GIMLET_|forge-microtool-gimlet|fulmenhq/forge-microtool-gimlet' --glob '*.{go,md,yaml,yml,json,mod,sum}' --glob '!Makefile' --glob '!README.md' .; then \
		echo "❌ Old baseline residue detected (see matches above)"; \
		exit 1; \
	fi; \
	echo "✅ No old baseline residue detected"

validate-app-identity:  ## Detect hardcoded old-baseline references
	@echo "🔍 Scanning for hardcoded old-baseline references..."
	@echo "ℹ️  Note: Import paths and CLI usage examples are expected to contain '$(BINARY_NAME)'"
	@if grep -r "gimlet" \
		--exclude-dir=".git" \
		--exclude-dir=".fulmen" \
		--exclude-dir="docs" \
		--exclude-dir="assets" \
		--exclude-dir=".plans" \
		--exclude="*.md" \
		--exclude="Makefile" \
		--exclude=".gitignore" \
		cmd/ internal/ 2>/dev/null \
		| grep -v "github.com/fulmenhq/forge-microtool-gimlet" \
		| grep -v "gimlet example" \
		| grep -v "\.fulmen/app\.yaml"; then \
		echo "⚠️  Found 'gimlet' references (see above)"; \
		echo "   These may be legitimate references or need App Identity"; \
		echo "   Review each occurrence manually"; \
	else \
		echo "✅ No unexpected breed references found"; \
	fi

.DEFAULT_GOAL := help
