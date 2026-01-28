SHELL := /bin/bash

.PHONY: help setup-docker setup-nitro-cli setup-client download-root-ca build-enclave build-proxy build-client run-enclave run-proxy run-client terminate-enclave

ENCLAVE_CID ?= 16
ENCLAVE_MEMORY ?= 512
ENCLAVE_CPU_COUNT ?= 2

SERVER_IP ?= 127.0.0.1
SERVER_PORT ?= 8080

help:
	@echo "Targets:"
	@echo "  help              Show this help message"
	@echo "  For Parent VM:"
	@echo "    setup-docker      Install Docker (requires Ubuntu + sudo)"
	@echo "    setup-nitro-cli   Install Nitro Enclaves Driver and CLI"
	@echo "    build-enclave     Build enclave Docker image and create EIF file"
	@echo "    build-proxy       Build vsock proxy"
	@echo "    run-enclave       Run Nitro Enclave"
	@echo "    run-proxy         Run vsock proxy"
	@echo "    terminate-enclave Terminate Nitro Enclave"
	@echo "  For Client:"
	@echo "    setup-client      Install Rust and dependencies"
	@echo "    build-client      Build client application"
	@echo "    download-root-ca  Download AWS Nitro Enclaves root CA certificate"
	@echo "    run-client        Run client"

setup-docker:
	@echo "Running scripts/setup-docker.sh"
	@bash ./scripts/setup-docker.sh

setup-nitro-cli:
	@echo "Running scripts/setup-nitro-cli.sh"
	@bash ./scripts/setup-nitro-cli.sh

setup-client:
	@echo "Running scripts/setup-client.sh"
	@bash ./scripts/setup-client.sh

download-root-ca:
	@echo "Running scripts/download-root-ca.sh"
	@bash ./scripts/download-root-ca.sh

build-enclave:
	@echo "Building Docker image"
	@docker build -t rafwne-enclave ./enclave
	@echo "Creating EIF file"
	@nitro-cli build-enclave --docker-uri rafwne-enclave --output-file ./enclave/rafwne-enclave.eif

build-proxy:
	@echo "Building vsock proxy"
	@cargo build -p rafwne-proxy -r

build-client:
	@echo "Building client crate (release)"
	@cargo build -p rafwne-client -r

run-enclave:
	@echo "Running Nitro Enclave"
	@nitro-cli run-enclave --eif-path ./enclave/rafwne-enclave.eif --memory $(ENCLAVE_MEMORY) --cpu-count $(ENCLAVE_CPU_COUNT) --enclave-cid $(ENCLAVE_CID)

run-proxy:
	@echo "Running vsock proxy"
	@cargo run --release -p rafwne-proxy -- --ip $(SERVER_IP) --port $(SERVER_PORT) --cid $(ENCLAVE_CID)

run-client:
	@echo "Running client"
	@cargo run --release -p rafwne-client

terminate-enclave:
	@echo "Terminating Nitro Enclave"
	@ENCLAVE_ID="$$(nitro-cli describe-enclaves | jq -r '.[] | select(.State == "RUNNING" and .EnclaveCID == $(ENCLAVE_CID)) | .EnclaveID' | head -n1)"; \
	if [ -z "$$ENCLAVE_ID" ]; then \
		echo "ERROR: running enclave with CID=$(ENCLAVE_CID) not found"; \
		nitro-cli describe-enclaves; \
		exit 1; \
	fi; \
	echo "Enclave ID: $$ENCLAVE_ID"; \
	nitro-cli terminate-enclave --enclave-id "$$ENCLAVE_ID"; \
	echo "Enclave terminated"
