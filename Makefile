SHELL := /bin/bash
.DELETE_ON_ERROR:
.DEFAULT_GOAL := help

ENCLAVE_CID ?= 16
ENCLAVE_MEMORY ?= 512
ENCLAVE_CPU_COUNT ?= 2

SERVER_IP ?= 127.0.0.1
SERVER_PORT ?= 8080

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

COLOR_CYAN := "\033[36m"
COLOR_RESET := "\033[0m"
PADDING := 20

.PHONY: help
help: ## Show help
	@printf "%-$(PADDING)s %s\n" "TARGET" "DESCRIPTION"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf $(COLOR_CYAN)"%-$(PADDING)s"$(COLOR_RESET) " %s\n", $$1, $$2}'

# ---------------------------------------------------------------------------
# Clean
# ---------------------------------------------------------------------------

.PHONY: clean
clean: ## Clean build artifacts
	@echo "Cleaning build artifacts"
	cargo clean
	-docker rmi rafwne-enclave
	rm -f rafwne-enclave.eif
	rm -f root.pem

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

.PHONY: setup-docker
setup-docker: ## Install Docker (requires Ubuntu + sudo)
	@echo "Running scripts/setup-docker.sh"
	bash ./scripts/setup-docker.sh

.PHONY: setup-nitro-cli
setup-nitro-cli: ## Install Nitro Enclaves Driver and CLI
	@echo "Running scripts/setup-nitro-cli.sh"
	bash ./scripts/setup-nitro-cli.sh

.PHONY: setup-client
setup-client: ## Install Rust and dependencies
	@echo "Running scripts/setup-client.sh"
	bash ./scripts/setup-client.sh

.PHONY: download-root-ca
download-root-ca: ## Download AWS Nitro Enclaves root CA certificate
	@echo "Running scripts/download-root-ca.sh"
	bash ./scripts/download-root-ca.sh

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

rafwne-enclave.eif: ## Build enclave Docker image and create EIF file
	@echo "Building Docker image"
	docker build -t rafwne-enclave .
	@echo "Creating EIF file"
	nitro-cli build-enclave --docker-uri rafwne-enclave --output-file rafwne-enclave.eif

.PHONY: build-enclave
build-enclave: rafwne-enclave.eif

target/release/rafwne-proxy:
	@echo "Building vsock proxy"
	cargo build -p rafwne-proxy -r

.PHONY: build-proxy
build-proxy: target/release/rafwne-proxy ## Build vsock proxy

target/release/rafwne-client:
	@echo "Building client crate (release)"
	cargo build -p rafwne-client -r

.PHONY: build-client
build-client: target/release/rafwne-client ## Build client application

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

.PHONY: run-enclave
run-enclave: rafwne-enclave.eif ## Run Nitro Enclave
	@echo "Running Nitro Enclave"
	nitro-cli run-enclave \
		--eif-path rafwne-enclave.eif \
		--memory $(ENCLAVE_MEMORY) \
		--cpu-count $(ENCLAVE_CPU_COUNT) \
		--enclave-cid $(ENCLAVE_CID)

.PHONY: run-proxy
run-proxy: target/release/rafwne-proxy ## Run vsock proxy
	@echo "Running vsock proxy"
	./target/release/rafwne-proxy \
		--ip $(SERVER_IP) \
		--port $(SERVER_PORT) \
		--cid $(ENCLAVE_CID)

.PHONY: run-client
run-client: target/release/rafwne-client root.pem ## Run client application
	@echo "Running client"
	./target/release/rafwne-client

# ---------------------------------------------------------------------------
# Terminate
# ---------------------------------------------------------------------------

.PHONY: terminate-enclave
terminate-enclave: ## Terminate Nitro Enclave
	@echo "Terminating Nitro Enclave"
	@ENCLAVE_ID=$$(nitro-cli describe-enclaves \
		| jq -r --argjson cid $(ENCLAVE_CID) \
			'.[] | select(.State == "RUNNING" and .EnclaveCID == $$cid) | .EnclaveID' \
		| head -n1); \
	if [ -z "$$ENCLAVE_ID" ]; then \
		echo "ERROR: running enclave with CID=$(ENCLAVE_CID) not found"; \
		nitro-cli describe-enclaves; \
		exit 1; \
	fi; \
	echo "Enclave ID: $$ENCLAVE_ID"; \
	nitro-cli terminate-enclave --enclave-id "$$ENCLAVE_ID"; \
	echo "Enclave terminated"
