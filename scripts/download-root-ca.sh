#!/bin/bash

set -e

# Download AWS Nitro Enclaves root certificate
AWS_CA_ZIP_FILE="AWS_NitroEnclaves_Root-G1.zip"
curl -fsSL https://aws-nitro-enclaves.amazonaws.com/"$AWS_CA_ZIP_FILE" -o "$AWS_CA_ZIP_FILE"

# Extract the first *.pem found inside the zip directly to ./root.pem
CA_PEM_PATH="$(unzip -Z1 "$AWS_CA_ZIP_FILE" | grep -Ei '\.pem$' | head -n1)"
if [ -z "$CA_PEM_PATH" ]; then
  echo "ERROR: no .pem file found inside $AWS_CA_ZIP_FILE" >&2
  unzip -Z1 "$AWS_CA_ZIP_FILE" >&2 || true
  exit 1
fi
unzip -p "$AWS_CA_ZIP_FILE" "$CA_PEM_PATH" > ./root.pem
chmod +r ./root.pem
rm -f "$AWS_CA_ZIP_FILE"
