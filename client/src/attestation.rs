// SPDX-License-Identifier: MIT

//! Nitro Enclaves attestation document verification.

use anyhow::{Result, anyhow};
use aws_nitro_enclaves_cose::{CoseSign1, crypto::Openssl};
use base64::Engine as _;
use minicbor::Decoder;
use openssl::x509::X509 as OpensslX509;
use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde::Serialize;
use std::collections::BTreeMap;
use x509_parser::prelude::*;

#[derive(Debug)]
pub struct AttestationPayload {
    pub pcrs: BTreeMap<u32, Vec<u8>>,
    pub user_data: Option<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
    pub certificate: Vec<u8>,
    pub cabundle: Option<Vec<Vec<u8>>>,
}

#[derive(Debug, Serialize)]
struct AttestationPayloadJsonView {
    pcrs: BTreeMap<u32, String>,   // hex
    user_data: Option<String>,     // base64
    nonce: Option<String>,         // base64
    certificate: String,           // base64 (DER)
    cabundle: Option<Vec<String>>, // base64 (DER)
}

fn cbor_container_done(d: &Decoder, len: Option<u64>, count: u64) -> bool {
    match len {
        Some(n) => count >= n,
        None => matches!(d.datatype(), Ok(minicbor::data::Type::Break)),
    }
}

fn cbor_consume_break(d: &mut Decoder, len: Option<u64>) {
    if len.is_none() {
        d.set_position(d.position() + 1);
    }
}

fn decode_attestation_payload(bytes: &[u8]) -> Result<AttestationPayload> {
    let mut d = Decoder::new(bytes);
    let map_len = d.map().map_err(|e| anyhow!("expected CBOR map: {e}"))?;

    let mut pcrs = BTreeMap::new();
    let mut user_data = None;
    let mut nonce = None;
    let mut certificate = None;
    let mut cabundle = None;

    let mut i = 0u64;
    while !cbor_container_done(&d, map_len, i) {
        let key = d.str().map_err(|e| anyhow!("expected text key: {e}"))?;
        match key {
            "pcrs" => {
                let inner_len = d.map().map_err(|e| anyhow!("pcrs: expected map: {e}"))?;
                let mut j = 0u64;
                while !cbor_container_done(&d, inner_len, j) {
                    let idx = d.u32().map_err(|e| anyhow!("pcrs key: {e}"))?;
                    let val = d.bytes().map_err(|e| anyhow!("pcrs value: {e}"))?.to_vec();
                    pcrs.insert(idx, val);
                    j += 1;
                }
                cbor_consume_break(&mut d, inner_len);
            }
            "certificate" => {
                certificate = Some(d.bytes().map_err(|e| anyhow!("certificate: {e}"))?.to_vec());
            }
            "cabundle" => {
                if matches!(d.datatype(), Ok(minicbor::data::Type::Null)) {
                    d.null().map_err(|e| anyhow!("cabundle null: {e}"))?;
                } else {
                    let arr_len = d
                        .array()
                        .map_err(|e| anyhow!("cabundle: expected array: {e}"))?;
                    let mut bundle = Vec::new();
                    let mut j = 0u64;
                    while !cbor_container_done(&d, arr_len, j) {
                        bundle.push(
                            d.bytes()
                                .map_err(|e| anyhow!("cabundle entry: {e}"))?
                                .to_vec(),
                        );
                        j += 1;
                    }
                    cbor_consume_break(&mut d, arr_len);
                    cabundle = Some(bundle);
                }
            }
            "user_data" => {
                if matches!(d.datatype(), Ok(minicbor::data::Type::Null)) {
                    d.null().map_err(|e| anyhow!("user_data null: {e}"))?;
                } else {
                    user_data = Some(d.bytes().map_err(|e| anyhow!("user_data: {e}"))?.to_vec());
                }
            }
            "nonce" => {
                if matches!(d.datatype(), Ok(minicbor::data::Type::Null)) {
                    d.null().map_err(|e| anyhow!("nonce null: {e}"))?;
                } else {
                    nonce = Some(d.bytes().map_err(|e| anyhow!("nonce: {e}"))?.to_vec());
                }
            }
            _ => {
                d.skip()
                    .map_err(|e| anyhow!("skip unknown field '{key}': {e}"))?;
            }
        }
        i += 1;
    }
    cbor_consume_break(&mut d, map_len);

    Ok(AttestationPayload {
        pcrs,
        user_data,
        nonce,
        certificate: certificate.ok_or_else(|| anyhow!("missing 'certificate' field"))?,
        cabundle,
    })
}

pub fn attestation_payload_json(attestation_doc_b64: &str) -> Result<String> {
    let doc_cbor = base64::engine::general_purpose::STANDARD
        .decode(attestation_doc_b64)
        .map_err(|e| anyhow!("base64 decode failed: {e}"))?;

    let cose =
        CoseSign1::from_bytes(&doc_cbor).map_err(|e| anyhow!("COSE decode failed: {e:?}"))?;
    let payload_bytes = cose
        .get_payload::<Openssl>(None)
        .map_err(|e| anyhow!("COSE payload read failed: {e:?}"))?;

    let payload = decode_attestation_payload(&payload_bytes)?;

    let pcrs_hex = payload
        .pcrs
        .into_iter()
        .map(|(k, v)| (k, hex::encode(v)))
        .collect::<BTreeMap<_, _>>();

    let b64 = base64::engine::general_purpose::STANDARD;
    let view = AttestationPayloadJsonView {
        pcrs: pcrs_hex,
        user_data: payload.user_data.map(|b| b64.encode(b)),
        nonce: payload.nonce.map(|b| b64.encode(b)),
        certificate: b64.encode(&payload.certificate),
        cabundle: payload
            .cabundle
            .map(|v| v.into_iter().map(|b| b64.encode(b)).collect()),
    };

    Ok(serde_json::to_string_pretty(&view)?)
}

fn x509_pubkey_sec1(cert: &X509Certificate) -> Result<Vec<u8>> {
    Ok(cert.public_key().subject_public_key.data.to_vec())
}

fn verify_x509_sig_ecdsa_sha384(child: &X509Certificate, parent: &X509Certificate) -> Result<()> {
    let parent_pk = x509_pubkey_sec1(parent)?;
    let vk = VerifyingKey::from_sec1_bytes(&parent_pk)
        .map_err(|e| anyhow!("invalid parent pubkey: {e}"))?;

    let tbs = child.tbs_certificate.as_ref();
    let sig_der = child.signature_value.data.as_ref();
    let sig = Signature::from_der(sig_der).map_err(|e| anyhow!("invalid DER signature: {e}"))?;
    vk.verify(tbs, &sig)
        .map_err(|e| anyhow!("certificate signature verify failed: {e}"))?;
    Ok(())
}

fn load_x509_der(der: &[u8]) -> Result<X509Certificate<'_>> {
    let (_, cert) = parse_x509_certificate(der).map_err(|e| anyhow!("x509 parse failed: {e}"))?;
    Ok(cert)
}

fn load_root_pem(pem: &[u8]) -> Result<Vec<u8>> {
    let (_, pem) =
        x509_parser::pem::parse_x509_pem(pem).map_err(|e| anyhow!("root pem parse failed: {e}"))?;
    Ok(pem.contents.to_vec())
}

pub fn verify_attestation_document(
    attestation_doc_b64: &str,
    root_pem: &[u8],
    expected_pcrs: &BTreeMap<u32, Vec<u8>>,
    expected_user_data: &[u8],
    expected_nonce: Option<&[u8]>,
) -> Result<()> {
    let doc_cbor = base64::engine::general_purpose::STANDARD
        .decode(attestation_doc_b64)
        .map_err(|e| anyhow!("base64 decode failed: {e}"))?;

    // COSE decode (accepts tagged/untagged Sign1).
    let cose =
        CoseSign1::from_bytes(&doc_cbor).map_err(|e| anyhow!("COSE decode failed: {e:?}"))?;
    let payload_bytes = cose
        .get_payload::<Openssl>(None)
        .map_err(|e| anyhow!("COSE payload read failed: {e:?}"))?;

    let payload = decode_attestation_payload(&payload_bytes)?;

    // 1. Verify certificate chain: root -> cabundle... -> leaf
    let root_der = load_root_pem(root_pem)?;
    let root = load_x509_der(&root_der)?;
    let leaf = load_x509_der(&payload.certificate)?;

    let mut issuer = root;
    if let Some(bundle) = payload.cabundle.as_ref() {
        for der in bundle {
            let cert = load_x509_der(der)?;
            verify_x509_sig_ecdsa_sha384(&cert, &issuer)?;
            issuer = cert;
        }
    }
    verify_x509_sig_ecdsa_sha384(&leaf, &issuer)?;

    // 2. Verify COSE signature using the leaf certificate public key.
    let leaf_x509 = OpensslX509::from_der(&payload.certificate)
        .map_err(|e| anyhow!("openssl x509 parse failed: {e}"))?;
    let leaf_pkey = leaf_x509
        .public_key()
        .map_err(|e| anyhow!("openssl public key extract failed: {e}"))?;
    let ok = cose
        .verify_signature::<Openssl>(&leaf_pkey)
        .map_err(|e| anyhow!("COSE signature verification failed: {e:?}"))?;
    if !ok {
        return Err(anyhow!("COSE signature invalid"));
    }

    // 3. Verify report contents (PCRs + user_data (+ nonce if provided))
    for (idx, expected) in expected_pcrs {
        let actual = payload
            .pcrs
            .get(idx)
            .ok_or_else(|| anyhow!("PCR{idx} missing in attestation document"))?;
        if actual.as_slice() != expected.as_slice() {
            return Err(anyhow!("PCR{idx} mismatch"));
        }
    }

    let ud: &[u8] = payload
        .user_data
        .as_deref()
        .ok_or_else(|| anyhow!("user_data missing"))?;
    if ud != expected_user_data {
        return Err(anyhow!("user_data mismatch"));
    }

    if let Some(exp_nonce) = expected_nonce {
        let n: &[u8] = payload
            .nonce
            .as_deref()
            .ok_or_else(|| anyhow!("nonce missing"))?;
        if n != exp_nonce {
            return Err(anyhow!("nonce mismatch"));
        }
    }

    Ok(())
}
