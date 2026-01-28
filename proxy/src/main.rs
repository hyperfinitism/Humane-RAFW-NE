// SPDX-License-Identifier:

//! HTTP -> vsock proxy (untrusted). Forwards request body bytes to the enclave vsock server and returns response bytes.

use anyhow::{Result, anyhow};
use clap::Parser;
use std::io::{Read, Write};
use tiny_http::{Header, Method, Response, Server, StatusCode};
use vsock::{VsockAddr, VsockStream};

const LENGTH_PREFIX_SIZE: usize = 4;

#[derive(Debug, Parser)]
#[command(name = "rafwne-proxy")]
struct Args {
    /// Bind IP address for the HTTP server.
    #[arg(long, default_value = "127.0.0.1")]
    ip: String,

    /// Bind port for the HTTP server.
    #[arg(long, default_value_t = 8080)]
    port: u16,

    /// Legacy/compat positional argument (often 0 / VMADDR_CID_ANY). Not used.
    #[arg(value_name = "HOST_CID", default_value_t = 0)]
    _host_cid: u32,

    /// Enclave CID to connect to (vsock).
    #[arg(long, default_value_t = 16)]
    cid: u32,

    /// Enclave vsock port to connect to.
    #[arg(long, default_value_t = 5000)]
    vsock_port: u32,

    /// Vsock buffer size in bytes.
    #[arg(long, default_value_t = 8192)]
    vsock_buffer_size: usize,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let bind = format!("{}:{}", args.ip, args.port);
    let max_body_size = args.vsock_buffer_size - LENGTH_PREFIX_SIZE;

    let server = Server::http(&bind).map_err(|e| anyhow!(e.to_string()))?;
    eprintln!(
        "proxy listening on http://{bind} -> vsock cid={} port={} (buffer_size={}, max_body={})",
        args.cid, args.vsock_port, args.vsock_buffer_size, max_body_size
    );

    for mut req in server.incoming_requests() {
        if req.method() != &Method::Post {
            let _ = req.respond(
                Response::from_string("only POST / supported").with_status_code(StatusCode(405)),
            );
            continue;
        }

        let mut body = Vec::new();
        if req
            .as_reader()
            .take(max_body_size as u64)
            .read_to_end(&mut body)
            .is_err()
        {
            let _ = req.respond(
                Response::from_string("failed to read request body")
                    .with_status_code(StatusCode(400)),
            );
            continue;
        }

        match forward_to_enclave(args.cid, args.vsock_port, &body, args.vsock_buffer_size) {
            Ok(resp_body) => {
                let mut resp = Response::from_data(resp_body);
                let hdr = Header::from_bytes(&b"content-type"[..], &b"application/json"[..])
                    .map_err(|_| anyhow!("failed to build response header"))?;
                resp.add_header(hdr);
                let _ = req.respond(resp.with_status_code(StatusCode(200)));
            }
            Err(e) => {
                let msg = format!("proxy error: {e}");
                let _ = req.respond(Response::from_string(msg).with_status_code(StatusCode(502)));
            }
        }
    }

    Ok(())
}

fn forward_to_enclave(cid: u32, port: u32, body: &[u8], buffer_size: usize) -> Result<Vec<u8>> {
    let addr = VsockAddr::new(cid, port);
    let mut stream = VsockStream::connect(&addr)?;

    // Write request with 4-byte big-endian length prefix
    let req_len = body.len() as u32;
    stream.write_all(&req_len.to_be_bytes())?;
    stream.write_all(body)?;

    // Read 4-byte big-endian length prefix for response
    let mut len_buf = [0u8; LENGTH_PREFIX_SIZE];
    stream.read_exact(&mut len_buf)?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;

    if resp_len > buffer_size - LENGTH_PREFIX_SIZE {
        return Err(anyhow!(
            "response too large: {} > {}",
            resp_len,
            buffer_size - LENGTH_PREFIX_SIZE
        ));
    }

    // Read the exact amount of data
    let mut buf = vec![0u8; resp_len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}
