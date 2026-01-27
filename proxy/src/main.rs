// SPDX-License-Identifier:

//! HTTP -> vsock proxy (untrusted). Forwards request body bytes to the enclave vsock server and returns response bytes.

use anyhow::{Result, anyhow};
use clap::Parser;
use std::io::{Read, Write};
use tiny_http::{Header, Method, Response, Server, StatusCode};
use vsock::{VsockAddr, VsockStream};

const MAX_BODY: usize = 128 * 1024;

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
}

fn main() -> Result<()> {
    let args = Args::parse();
    let bind = format!("{}:{}", args.ip, args.port);

    let server = Server::http(&bind).map_err(|e| anyhow!(e.to_string()))?;
    eprintln!(
        "proxy listening on http://{bind} -> vsock cid={} port={}",
        args.cid, args.vsock_port
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
            .take(MAX_BODY as u64)
            .read_to_end(&mut body)
            .is_err()
        {
            let _ = req.respond(
                Response::from_string("failed to read request body")
                    .with_status_code(StatusCode(400)),
            );
            continue;
        }

        match forward_to_enclave(args.cid, args.vsock_port, &body) {
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

fn forward_to_enclave(cid: u32, port: u32, body: &[u8]) -> Result<Vec<u8>> {
    let addr = VsockAddr::new(cid, port);
    let mut stream = VsockStream::connect(&addr)?;
    stream.write_all(body)?;

    let mut buf = vec![0u8; 8192];
    let n = stream.read(&mut buf)?;
    if n == 0 {
        return Err(anyhow!("empty response from enclave"));
    }
    buf.truncate(n);
    Ok(buf)
}
