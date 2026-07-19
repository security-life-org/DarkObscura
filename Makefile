.PHONY: build test race vet lint core cli plugins clean tidy

BIN := bin
GOFLAGS :=

build: ## Build core + cli
	@mkdir -p $(BIN)
	go build $(GOFLAGS) -o $(BIN)/dobscura-core ./cmd/core
	go build $(GOFLAGS) -o $(BIN)/dobscura     ./cmd/cli

core: ## Build & run the backend daemon (requires authorization ack)
	go run ./cmd/core --i-have-authorization -v

gui: ## Launch the embedded desktop GUI (opens in browser)
	go run ./cmd/cli --gui

wizard: ## Run the interactive guided-scan wizard
	go run ./cmd/cli --wizard

cli: ## Build the CLI
	go build -o $(BIN)/dobscura ./cmd/cli

test: ## Run all tests
	go test ./...

race: ## Run tests under the race detector
	go test -race ./...

vet: ## go vet
	go vet ./...

lint: ## golangci-lint (if installed)
	@command -v golangci-lint >/dev/null 2>&1 && golangci-lint run || echo "golangci-lint not installed; skipping"

plugins: ## Build sample WASM plugins (Go -> wasip1)
	@mkdir -p $(BIN)/plugins
	GOOS=wasip1 GOARCH=wasm go build -o $(BIN)/plugins/jwt-inspect.wasm ./plugins/jwt-inspect

ebpf: ## Generate eBPF objects (Linux, needs clang + bpf2go)
	go generate ./internal/ebpf

tidy:
	go mod tidy

clean:
	rm -rf $(BIN)
