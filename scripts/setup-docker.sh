#!/bin/bash

set -e

USERNAME="$(whoami)"

# Install dependencies
sudo apt-get update
sudo apt-get install -y build-essential

# Install Docker
sudo apt-get install -y docker.io
sudo usermod -aG docker "$USERNAME"
newgrp docker
sudo systemctl start docker
sudo systemctl enable docker
