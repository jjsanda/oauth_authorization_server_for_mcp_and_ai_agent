GO      ?= go
BIN_DIR := bin
PKGS    := ./...

.PHONY: all build test race cover lint fmt vet e2e run-auth run-rs demo diagrams docker clean

all: build

build:
	$(GO) build -o $(BIN_DIR)/authserver ./cmd/authserver
	$(GO) build -o $(BIN_DIR)/resourceserver ./cmd/resourceserver
	$(GO) build -o $(BIN_DIR)/agent ./cmd/agent

test:
	$(GO) test $(PKGS)

race:
	$(GO) test -race $(PKGS)

# -coverpkg=./... attributes coverage across packages, so code exercised only
# through the end-to-end test (the agent, httpx) is counted honestly.
cover:
	$(GO) test -coverpkg=./... -coverprofile=coverage.out $(PKGS)
	$(GO) tool cover -html=coverage.out -o coverage.html
	@$(GO) tool cover -func=coverage.out | tail -1

vet:
	$(GO) vet $(PKGS)

fmt:
	gofmt -l -w .

lint: vet
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed; ran 'go vet' only (see https://golangci-lint.run)"; \
	fi
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed on:"; gofmt -l .; exit 1)

e2e:
	$(GO) test -race -v ./internal/e2e/...

run-auth:
	$(GO) run ./cmd/authserver

run-rs:
	$(GO) run ./cmd/resourceserver

# Full containerized demo: brings the stack up and runs the headless agent once.
demo:
	./scripts/demo.sh

diagrams:
	@for f in docs/diagrams/*.mmd; do \
		npx -y @mermaid-js/mermaid-cli -i $$f -o $${f%.mmd}.svg -b transparent; \
	done

docker:
	docker compose build

clean:
	rm -rf $(BIN_DIR) coverage.out coverage.html
