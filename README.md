# Remote Attestation Framework for AWS Nitro Enclaves
![MSRV](https://img.shields.io/badge/MSRV-1.90.0-blue)

This repository demonstrates a simple end-to-end flow against an AWS Nitro Enclave: **ECDH key exchange & attestation verification → confidential computation (example: adding two integers)**.

- **Parent VM**: An AWS EC2 instance (Ubuntu 24.04) with Nitro Enclaves enabled. Runs the Enclave and the vsock proxy.
- **Client**: Can run on any machine, but this README assumes you run it on the Parent VM (localhost).

## Tested environment (detailed)

### Parent VM (AWS EC2)

- **Instance type**: `c5.xlarge`
  - vCPUs: 4
  - Memory: 8 GiB
  - CPU arch: `x86_64`
- **AMI**: Ubuntu Server 24.04 LTS
  - AMI ID: `ami-06e3c045d79fd65d9`
- **Storage**: 64 GiB `gp3`
- **Kernel**: 6.14.0-1018-aws
- **Nitro Enclaves**: Enabled
- **Nitro Enclaves CLI / driver**: v1.4.4
- **Rust toolchain**: v1.90.0

### Enclave

- **OS**: Ubuntu 24.04
- **Allocated vCPUs**: 2
- **Allocated Memory**: 512 MiB
- **OS**: Ubuntu 24.04
- **Rust toolchain**: v1.90.0

### Client

- Ran on the same Parent VM (localhost).

## Architecture

- `enclave/`: Enclave application (listens on vsock `port=5000`)
- `proxy/`: **untrusted** HTTP → vsock proxy (listens on HTTP `ip:port`, forwards to vsock `port=5000`)
- `client/`: Client app (POSTs JSON to the proxy, verifies attestation, then calls the confidential computing API)

## Quick start (all on the Parent VM)

Clone the repository:

```bash
git clone <THIS_REPOSITORY>
cd <THIS_REPOSITORY>
```

### 1. Parent VM setup (Ubuntu 24.04)

```bash
make setup-docker
make setup-nitro-cli
```

### 2. Client setup (this README runs it on the Parent VM)

```bash
make setup-client
```

### 3. Build the Enclave image and copy PCRs into `client-configs.json`

```bash
make build-enclave
```

When you run `make build-enclave`, PCR measurements are printed like this (example):

```text
Enclave Image successfully created.
{
  "Measurements": {
    "HashAlgorithm": "Sha384 { ... }",
    "PCR0": "...",
    "PCR1": "...",
    "PCR2": "..."
  }
}
```

Copy **PCR0/1/2** into `"PCRs"` in `client-configs.json`.

### 4. Build the vsock proxy

```bash
make build-proxy
```

### 5. Start the Enclave

```bash
make run-enclave
```

### 6. Start the vsock proxy

```bash
make run-proxy
```

### 7. Build and run the client

```bash
make build-client
make run-client
```

After ECDH key exchange and attestation verification, the client calls the Enclave’s “add two integers” API and then closes the session.

### 8. Stop the Enclave

```bash
make terminate-enclave
```

## Configuration

### Change Enclave Memory / vCPU Allocation

- **Update Makefile variables**
  - `ENCLAVE_MEMORY`（MiB）
  - `ENCLAVE_CPU_COUNT`
- **Update allocator config**
  - Update `/etc/nitro_enclaves/allocator.yaml` accordingly
- **Restart the allocator**
  ```bash
  sudo systemctl restart nitro-enclaves-allocator.service
  ```

### Change Proxy IP / port

- Update `SERVER_IP` / `SERVER_PORT` in `Makefile`
- Update `"server-ip"` / `"server-port"` in `client-configs.json`

If you run the client from a different machine, allow inbound access to `SERVER_PORT` in the Parent VM security group / firewall rules.

### Client configuration (`client-configs.json`)

- `"PCRs"`: Expected PCR values. Copy from `make build-enclave` output PCR[0-2].
- `"print-attestation-json"`: Print the attestation document payload as JSON if `true`
