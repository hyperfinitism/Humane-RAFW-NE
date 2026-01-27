// SPDX-License-Identifier:

use anyhow::{Result, anyhow};
use p256::elliptic_curve::rand_core::OsRng;
use p256::{EncodedPoint, PublicKey, SecretKey, ecdh::diffie_hellman};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;

mod attestation;
mod crypto;
mod types;

#[derive(Debug, Deserialize)]
struct ClientConfig {
    #[serde(rename = "server-ip")]
    server_ip: String,
    #[serde(rename = "server-port")]
    server_port: u16,
    #[serde(rename = "PCRs")]
    pcrs: BTreeMap<String, String>,
    #[serde(rename = "print-attestation-json")]
    print_attestation_json: bool,
}

fn parse_pcrs(cfg: &ClientConfig) -> Result<BTreeMap<u32, Vec<u8>>> {
    let mut out = BTreeMap::new();
    for (k, hex_str) in &cfg.pcrs {
        let idx: u32 = k.parse()?;
        let bytes = hex::decode(hex_str)?;
        out.insert(idx, bytes);
    }
    Ok(out)
}

fn post_json(server: &str, body: &str) -> Result<String> {
    let url = format!("http://{server}/");
    let mut resp = ureq::post(&url)
        .content_type("application/json")
        .send(body)?;
    let mut out = String::new();
    resp.body_mut().as_reader().read_to_string(&mut out)?;
    Ok(out)
}

fn main() -> Result<()> {
    // Load config
    let cfg_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "client-configs.json".to_string());
    let cfg_str = fs::read_to_string(&cfg_path)?;
    let cfg: ClientConfig = serde_json::from_str(&cfg_str)?;
    let expected_pcrs = parse_pcrs(&cfg)?;
    let print_attestation_json = cfg.print_attestation_json;

    let server = format!("{}:{}", cfg.server_ip, cfg.server_port);

    // 1. Init
    let init_req = types::Request::Init.to_json()?;
    let init_resp = post_json(&server, &init_req)?;
    let init_resp: types::Response = types::Response::from_json(&init_resp)?;
    let (session_id, enclave_pub_b64) = match init_resp {
        types::Response::Init {
            session_id,
            enclave_pubkey_b64,
        } => (session_id, enclave_pubkey_b64),
        types::Response::Error { error } => return Err(anyhow!("init failed: {error}")),
        other => return Err(anyhow!("unexpected init response: {other:?}")),
    };
    println!("session_id={session_id}");

    let enclave_pub_bytes = crypto::b64_decode(&enclave_pub_b64)?;

    // 2. Client ephemeral P-256 keypair + ECDH
    let client_priv = SecretKey::random(&mut OsRng);
    let client_pub = client_priv.public_key();
    let client_pub_bytes = EncodedPoint::from(client_pub).to_bytes().to_vec();

    let enclave_pub = PublicKey::from_sec1_bytes(&enclave_pub_bytes)
        .map_err(|e| anyhow!("bad enclave pubkey: {e}"))?;
    let shared = diffie_hellman(client_priv.to_nonzero_scalar(), enclave_pub.as_affine());
    let shared = shared.raw_secret_bytes().to_vec();

    let ck = crypto::derive_key(&shared, b"CK");
    let mk = crypto::derive_key(&shared, b"MK");
    let vk = crypto::derive_key(&shared, b"VK");

    // expected user_data = SHA256(client_pub || enclave_pub || VK)
    let mut ud_buf = Vec::new();
    ud_buf.extend_from_slice(&client_pub_bytes);
    ud_buf.extend_from_slice(&enclave_pub_bytes);
    ud_buf.extend_from_slice(&vk);
    let expected_user_data = crypto::sha256(&ud_buf);

    // 3. KeyExchange -> attestation doc
    let ke_req = types::Request::KeyExchange {
        session_id: session_id.clone(),
        client_pubkey_b64: crypto::b64_encode(&client_pub_bytes),
    }
    .to_json()?;
    let ke_resp = post_json(&server, &ke_req)?;
    let ke_resp: types::Response = types::Response::from_json(&ke_resp)?;
    let att_doc_b64 = match ke_resp {
        types::Response::KeyExchange {
            attestation_document_b64,
        } => attestation_document_b64,
        types::Response::Error { error } => return Err(anyhow!("keyexchange failed: {error}")),
        other => return Err(anyhow!("unexpected keyexchange response: {other:?}")),
    };
    if print_attestation_json {
        let json = attestation::attestation_payload_json(&att_doc_b64)?;
        println!("attestation payload (json):\n{json}");
    }

    // 4. Verify attestation doc (root.pem must exist)
    let root_pem = fs::read("root.pem")
		.or_else(|_| fs::read("client/root.pem"))
		.map_err(|_| anyhow!("missing AWS Nitro root certificate: root.pem (put it at repo root or client/root.pem)"))?;

    attestation::verify_attestation_document(
        &att_doc_b64,
        &root_pem,
        &expected_pcrs,
        &expected_user_data,
        None,
    )
    .map_err(|e| anyhow!("attestation verification failed: {e}"))?;
    println!("attestation verification: OK");

    // 5. Encrypt and send add request (100 + 200) using CK, receive sum encrypted with MK
    let x: u32 = 100;
    let y: u32 = 200;
    println!("plaintext x={x}, y={y}");

    let x_nonce = crypto::random_bytes(12)?;
    let y_nonce = crypto::random_bytes(12)?;

    let x_ct = crypto::aes128gcm_encrypt(&ck[..16], &x_nonce, &x.to_le_bytes())?;
    let y_ct = crypto::aes128gcm_encrypt(&ck[..16], &y_nonce, &y.to_le_bytes())?;
    println!(
        "encrypted x_ct_b64={}, y_ct_b64={}",
        crypto::b64_encode(&x_ct),
        crypto::b64_encode(&y_ct)
    );

    let add_req = types::Request::Add {
        session_id: session_id.clone(),
        x: types::EncryptedBlob {
            nonce_b64: crypto::b64_encode(&x_nonce),
            ciphertext_b64: crypto::b64_encode(&x_ct),
        },
        y: types::EncryptedBlob {
            nonce_b64: crypto::b64_encode(&y_nonce),
            ciphertext_b64: crypto::b64_encode(&y_ct),
        },
    }
    .to_json()?;
    let add_resp = post_json(&server, &add_req)?;
    let add_resp: types::Response = types::Response::from_json(&add_resp)?;

    let sum_blob = match add_resp {
        types::Response::Add { sum } => sum,
        types::Response::Error { error } => return Err(anyhow!("add failed: {error}")),
        other => return Err(anyhow!("unexpected add response: {other:?}")),
    };

    let sum_nonce = crypto::b64_decode(&sum_blob.nonce_b64)?;
    let sum_ct = crypto::b64_decode(&sum_blob.ciphertext_b64)?;
    let sum_pt = crypto::aes128gcm_decrypt(&mk[..16], &sum_nonce, &sum_ct)?;
    println!("encrypted sum_ct_b64={}", crypto::b64_encode(&sum_ct));
    let sum = u32::from_le_bytes(
        sum_pt
            .try_into()
            .map_err(|_| anyhow!("bad sum plaintext size"))?,
    );
    println!("decrypted sum={sum}");

    // 6. Close
    let close_req = types::Request::Close {
        session_id: session_id.clone(),
    }
    .to_json()?;
    let close_resp = post_json(&server, &close_req)?;
    let close_resp: types::Response = types::Response::from_json(&close_resp)?;
    match close_resp {
        types::Response::CloseOk {} => println!("session closed"),
        types::Response::Error { error } => return Err(anyhow!("close failed: {error}")),
        other => return Err(anyhow!("unexpected close response: {other:?}")),
    }

    Ok(())
}
