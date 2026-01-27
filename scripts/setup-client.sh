#!/bin/bash

set -e

# Install dependencies
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev git unzip

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env

# Download AWS Nitro Enclaves root certificate
curl https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip -o AWS_NitroEnclaves_Root-G1.zip
unzip -o AWS_NitroEnclaves_Root-G1.zip -d .
rm AWS_NitroEnclaves_Root-G1.zip

# Make a stable filename expected by the Rust client (`root.pem`).
#./*.pem => root.pem
ls -la ./root.pem || cp ./*.pem root.pem
