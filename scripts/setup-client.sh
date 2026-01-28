#!/bin/bash

set -e

# Install dependencies
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev git unzip

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
