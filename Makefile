BINARY_NAME := terraform-provider-microsoftdefender
VERSION ?= $(shell cat version)
TASK_GOTOOLCHAIN ?= go1.27.0
GOLANGCI_LINT_VERSION ?= v2.13.2
GOVULNCHECK_VERSION ?= v1.1.4
GORELEASER_VERSION ?= v2.18.0

.PHONY: build fmt generate generate/docs lint release/check test testacc vulncheck

build:
	env GOTOOLCHAIN=$(TASK_GOTOOLCHAIN) go build -ldflags "-X main.version=$(VERSION)" -o bin/$(BINARY_NAME) .

fmt:
	env GOTOOLCHAIN=$(TASK_GOTOOLCHAIN) go fmt ./...

generate: generate/docs

generate/docs:
	env GOTOOLCHAIN=$(TASK_GOTOOLCHAIN) go generate ./...

lint:
	@if command -v aqua >/dev/null 2>&1; then env GOTOOLCHAIN=$(TASK_GOTOOLCHAIN) aqua exec -- golangci-lint run; else env GOTOOLCHAIN=$(TASK_GOTOOLCHAIN) go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run; fi

release/check:
	@if command -v aqua >/dev/null 2>&1; then aqua exec -- goreleaser check; else env GOTOOLCHAIN=$(TASK_GOTOOLCHAIN) go run github.com/goreleaser/goreleaser/v2@$(GORELEASER_VERSION) check; fi

test:
	env GOTOOLCHAIN=$(TASK_GOTOOLCHAIN) go test $(TESTARGS) $(if $(TEST),$(TEST),./...)

testacc:
	TF_ACC=1 env GOTOOLCHAIN=$(TASK_GOTOOLCHAIN) go test $(TESTARGS) -timeout 120m ./...

vulncheck:
	@if command -v aqua >/dev/null 2>&1; then env GOTOOLCHAIN=$(TASK_GOTOOLCHAIN) aqua exec -- govulncheck ./...; else env GOTOOLCHAIN=$(TASK_GOTOOLCHAIN) go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...; fi
