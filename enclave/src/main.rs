// SPDX-License-Identifier:

//! This module provides a handler for the vsock connection with the parent VM.

use anyhow::Result;
use clap::Parser;
use std::io::{Read, Write};
use vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener, VsockStream};

mod crypto;
mod nsm;
mod session;
mod types;

const MAX_BUFFER_SIZE: usize = 8192;

#[derive(Debug, Parser)]
#[command(name = "rafwne-enclave")]
struct Args {
    /// Vsock port to listen on.
    #[arg(long, default_value_t = 5000)]
    vsock_port: u32,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let addr = VsockAddr::new(VMADDR_CID_ANY, args.vsock_port);
    let listener = VsockListener::bind(&addr)?;

    loop {
        let (mut stream, _) = listener.accept()?;
        let _ = handle_vsock_stream(&mut stream);
    }
}

pub(crate) fn handle_vsock_stream(stream: &mut VsockStream) -> Result<()> {
    let mut buffer = [0; MAX_BUFFER_SIZE];

    loop {
        match stream.read(&mut buffer) {
            Ok(0) => {
                break;
            }
            Ok(len) => {
                let request_str = String::from_utf8_lossy(&buffer[..len]);
                let request = match types::Request::from_json(&request_str) {
                    Ok(r) => r,
                    Err(e) => {
                        let response = types::Response::Error {
                            error: format!("invalid request: {e}"),
                        };
                        let response_str = response.to_json()?;
                        stream.write_all(response_str.as_bytes())?;
                        continue;
                    }
                };

                match request {
                    types::Request::Init => {
                        let sess = session::new_session()?;
                        let response = types::Response::Init {
                            session_id: sess.session_id.clone(),
                            enclave_pubkey_b64: crypto::b64_encode(&sess.enclave_pub),
                        };
                        session::insert_session(sess)?;
                        let response_str = response.to_json()?;
                        stream.write_all(response_str.as_bytes())?;
                    }
                    types::Request::KeyExchange {
                        session_id,
                        client_pubkey_b64,
                    } => {
                        let mut sess = session::take_session(&session_id)?;
                        let client_pub = crypto::b64_decode(&client_pubkey_b64)?;

                        let enclave_priv = sess.enclave_priv.take().ok_or_else(|| {
                            anyhow::anyhow!("session already completed key exchange")
                        })?;

                        let shared = session::ecdh_shared_secret(enclave_priv, &client_pub)?;

                        let ck = crypto::derive_key(&shared, b"CK");
                        let mk = crypto::derive_key(&shared, b"MK");
                        let vk = crypto::derive_key(&shared, b"VK");

                        sess.client_pub = Some(client_pub);
                        sess.ck = Some(ck);
                        sess.mk = Some(mk);
                        sess.vk = Some(vk);

                        let user_data = session::session_user_data(&sess)?;
                        let nonce = {
                            let rnd = nsm::get_random()?;
                            if rnd.len() >= 64 {
                                rnd[..64].to_vec()
                            } else {
                                rnd
                            }
                        };

                        let doc = nsm::get_attestation_document(user_data, nonce)?;
                        let response = types::Response::KeyExchange {
                            attestation_document_b64: crypto::b64_encode(&doc),
                        };
                        session::put_session(sess)?;
                        let response_str = response.to_json()?;
                        stream.write_all(response_str.as_bytes())?;
                    }
                    types::Request::Add { session_id, x, y } => {
                        let sess = session::get_session(&session_id)?;
                        let ck = sess
                            .ck
                            .as_ref()
                            .ok_or_else(|| anyhow::anyhow!("CK not set"))?;
                        let mk = sess
                            .mk
                            .as_ref()
                            .ok_or_else(|| anyhow::anyhow!("MK not set"))?;

                        let x_nonce = crypto::b64_decode(&x.nonce_b64)?;
                        let x_ct = crypto::b64_decode(&x.ciphertext_b64)?;
                        let y_nonce = crypto::b64_decode(&y.nonce_b64)?;
                        let y_ct = crypto::b64_decode(&y.ciphertext_b64)?;

                        let x_pt = crypto::aes128gcm_decrypt(&ck[..16], &x_nonce, &x_ct)?;
                        let y_pt = crypto::aes128gcm_decrypt(&ck[..16], &y_nonce, &y_ct)?;
                        let x_u32 = crypto::u32_from_le_bytes(&x_pt)?;
                        let y_u32 = crypto::u32_from_le_bytes(&y_pt)?;

                        let sum = x_u32
                            .checked_add(y_u32)
                            .ok_or_else(|| anyhow::anyhow!("u32 overflow"))?;
                        let sum_pt = crypto::u32_to_le_bytes(sum);

                        let sum_nonce = {
                            let rnd = nsm::get_random()?;
                            if rnd.len() < 12 {
                                return Err(anyhow::anyhow!("NSM random too short for nonce"));
                            }
                            rnd[..12].to_vec()
                        };
                        let sum_ct = crypto::aes128gcm_encrypt(&mk[..16], &sum_nonce, &sum_pt)?;

                        let response = types::Response::Add {
                            sum: types::EncryptedBlob {
                                nonce_b64: crypto::b64_encode(&sum_nonce),
                                ciphertext_b64: crypto::b64_encode(&sum_ct),
                            },
                        };
                        let response_str = response.to_json()?;
                        stream.write_all(response_str.as_bytes())?;
                    }
                    types::Request::Attest {
                        session_id,
                        user_data_b64,
                        nonce_b64,
                    } => {
                        let (user_data, nonce) = match (user_data_b64, nonce_b64) {
                            (Some(ud), Some(nc)) => {
                                (crypto::b64_decode(&ud)?, crypto::b64_decode(&nc)?)
                            }
                            (ud_opt, nc_opt) => {
                                let sid = session_id.ok_or_else(|| {
									anyhow::anyhow!("session_id is required when user_data/nonce not fully provided")
								})?;
                                let sess = session::get_session(&sid)?;
                                let ud = match ud_opt {
                                    Some(ud) => crypto::b64_decode(&ud)?,
                                    None => session::session_user_data(&sess)?,
                                };
                                let nc = match nc_opt {
                                    Some(nc) => crypto::b64_decode(&nc)?,
                                    None => {
                                        let rnd = nsm::get_random()?;
                                        if rnd.len() >= 64 {
                                            rnd[..64].to_vec()
                                        } else {
                                            rnd
                                        }
                                    }
                                };
                                (ud, nc)
                            }
                        };

                        let doc = nsm::get_attestation_document(user_data, nonce)?;
                        let response = types::Response::Attest {
                            attestation_document_b64: crypto::b64_encode(&doc),
                        };
                        let response_str = response.to_json()?;
                        stream.write_all(response_str.as_bytes())?;
                    }
                    types::Request::Close { session_id } => {
                        session::delete_session(&session_id)?;
                        let response = types::Response::CloseOk {};
                        let response_str = response.to_json()?;
                        stream.write_all(response_str.as_bytes())?;
                    }
                }
            }
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}
