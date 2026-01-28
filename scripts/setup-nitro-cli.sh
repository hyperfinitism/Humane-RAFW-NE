#!/bin/bash

set -e

KERNEL_VERSION="$(uname -r)"

# Install dependencies
sudo apt-get update
sudo apt-get install -y build-essential git clang libclang-dev llvm-dev linux-modules-extra-aws

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# Install Nitro Enclaves driver and CLI
git clone https://github.com/aws/aws-nitro-enclaves-cli -b v1.4.4

pushd aws-nitro-enclaves-cli/drivers/virt/nitro_enclaves
	sudo make
	sudo mkdir -p "/usr/lib/modules/$KERNEL_VERSION/kernel/drivers/virt/nitro_enclaves/"
	sudo cp nitro_enclaves.ko "/usr/lib/modules/$KERNEL_VERSION/kernel/drivers/virt/nitro_enclaves/nitro_enclaves.ko"
	sudo insmod "/usr/lib/modules/$KERNEL_VERSION/kernel/drivers/virt/nitro_enclaves/nitro_enclaves.ko"
popd

pushd aws-nitro-enclaves-cli
	export NITRO_CLI_INSTALL_DIR=/

	sudo make nitro-cli
	sudo make vsock-proxy
	sudo make NITRO_CLI_INSTALL_DIR=/ install
	source /etc/profile.d/nitro-cli-env.sh
	grep -qF 'source /etc/profile.d/nitro-cli-env.sh' "$HOME/.bashrc" \
		|| echo 'source /etc/profile.d/nitro-cli-env.sh' >> "$HOME/.bashrc"
	set +e
	( nitro-cli-config -i ) || echo "nitro-cli-config failed with exit code $?"
	set -e
popd

# Start and enable the Nitro Enclaves Allocator Service
sudo systemctl start nitro-enclaves-allocator.service
sudo systemctl enable nitro-enclaves-allocator.service
