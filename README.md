# Humane Remote Attestation Framework for AWS Nitro Enclaves (Humane-RAFW-NE)

![SemVer](https://img.shields.io/badge/Humane--RAFW--NE-0.1.0-blue)
![MSRV](https://img.shields.io/badge/MSRV-1.90.0-blue)
[![License](https://img.shields.io/badge/License-MIT-red)](/LICENSE)

This repository demonstrates a simple end-to-end flow against an AWS Nitro Enclave: **ECDH key exchange & attestation verification → confidential computation (example: adding two integers)**.

- **Parent VM**: An AWS EC2 instance (Ubuntu 24.04) with Nitro Enclaves enabled. Runs the Enclave and the vsock proxy.
- **Client**: Can run on any machine.

## Compatibility

### Server (Parent VM)

- **Cloud Platform**: AWS
- **Instance type**: any Nitro Enclaves capable instance
  - See [Parent instance requirements](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html#nitro-enclave-reqs)
  - Both x86_64 and AArch64 are supported
- **AMI**: Ubuntu Server 24.04 LTS
  - If you use other Linux distributions, manually setup the parent VM following the [Nitro CLI documentation](https://github.com/aws/aws-nitro-enclaves-cli)

### Client

The client code is architecture-independent. Ideally, it should be usable in any environment. It is currently only verified to work on Ubuntu (x86_64 / AArch64) and macOS (AArch64).

## Tested environments

Tested on the Parent VM environments listed below. For ease of testing, the Server (vsock proxy) runs on localhost (`127.0.0.1:8080`) on the Parent VM, and the Client also runs on the same Parent VM.

### Parent VM (AWS EC2)

#### Ubuntu 24.04 (x86_64)

- **Instance type**: `c5.xlarge`
  - vCPUs: 4
  - Memory: 8 GiB
  - CPU arch: x86_64
- **AMI**: Ubuntu Server 24.04 LTS
  - AMI ID: `ami-06e3c045d79fd65d9`
- **Storage**: 64 GiB gp3
- **Kernel**: 6.14.0-1018-aws
- **Nitro Enclaves**: Enabled
- **Nitro Enclaves CLI / driver**: v1.4.4

#### Ubuntu 24.04 (AArch64)

- **Instance type**: `m6g.xlarge`
  - vCPUs: 4
  - Memory: 16 GiB
  - CPU arch: AArch64
- **AMI**: Ubuntu Server 24.04 LTS
  - AMI ID: `ami-01da1dbf9ea3a6ee6`
- **Storage**: 64 GiB gp3
- **Kernel**: 6.14.0-1018-aws
- **Nitro Enclaves**: Enabled
- **Nitro Enclaves CLI / driver**: v1.4.4

### Nitro Enclave (inside the parent VM)

- **OS**: Ubuntu 24.04
- **Allocated vCPUs**: 2
- **Allocated Memory**: 512 MiB

### Client

Same as the parent VM.

## Architecture

- `enclave/`: Enclave application (listens on vsock port)
- `proxy/`: untrusted HTTP → vsock proxy (listens on HTTP, forwards to vsock port)
- `client/`: Client app (POSTs JSON to the proxy, verifies attestation, then calls the confidential computing API)

By default, the proxy listens on localhost `127.0.0.1:8080`. See [Configuration](#configuration) to change this.

## Quick start

Clone the repository:

```bash
git clone <THIS_REPOSITORY>
cd <THIS_REPOSITORY>
```

### 1. Parent VM setup

```bash
make setup-docker
make setup-nitro-cli
```

### 2. Client setup

```bash
make setup-client
make download-root-ca
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

### Proxy arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--ip` | HTTP server bind IP | `127.0.0.1` |
| `--port` | HTTP server port | `8080` |
| `--cid` | Enclave CID | `16` |
| `--vsock-port` | vsock port | `5000` |
| `--vsock-buffer-size` | Buffer size (bytes) | `8192` |

### Enclave arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--vsock-port` | vsock port | `5000` |
| `--vsock-buffer-size` | Buffer size (bytes) | `8192` |

### Client configuration (`client-configs.json`)

- `"server-ip"`: Proxy IP address
- `"server-port"`: Proxy port
- `"PCRs"`: Expected PCR values (copy from `make build-enclave` output)
- `"print-attestation-json"`: Print attestation document as JSON if `true`

## Customisation

### Change Proxy IP / port

- Update `SERVER_IP` / `SERVER_PORT` in `Makefile`
- Update `"server-ip"` / `"server-port"` in `client-configs.json`

If you run the client from a different machine, allow inbound access to `SERVER_PORT` in the Parent VM security group / firewall rules.

### Change Enclave Memory / vCPU Allocation

- **Update Makefile variables**
  - `ENCLAVE_MEMORY` (MiB)
  - `ENCLAVE_CPU_COUNT`
- **Update allocator config**
  - Update `/etc/nitro_enclaves/allocator.yaml` accordingly
- **Restart the allocator**
  ```bash
  sudo systemctl restart nitro-enclaves-allocator.service
  ```
