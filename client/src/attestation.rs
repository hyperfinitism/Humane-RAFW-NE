// SPDX-License-Identifier:

//! Nitro Enclaves attestation document verification.

use anyhow::{Result, anyhow};
use aws_nitro_enclaves_cose::{CoseSign1, crypto::Openssl};
use base64::Engine as _;
use openssl::x509::X509 as OpensslX509;
use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::collections::BTreeMap;
use x509_parser::prelude::*;

#[derive(Debug, Deserialize)]
pub struct AttestationPayload {
    #[serde(default)]
    pub pcrs: BTreeMap<u32, ByteBuf>,

    #[serde(default)]
    pub user_data: Option<ByteBuf>,

    #[serde(default)]
    pub nonce: Option<ByteBuf>,

    pub certificate: ByteBuf,

    #[serde(default)]
    pub cabundle: Option<Vec<ByteBuf>>,
}

#[derive(Debug, Serialize)]
struct AttestationPayloadJsonView {
    pcrs: BTreeMap<u32, String>,   // hex
    user_data: Option<String>,     // base64
    nonce: Option<String>,         // base64
    certificate: String,           // base64 (DER)
    cabundle: Option<Vec<String>>, // base64 (DER)
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

    let payload: AttestationPayload = serde_cbor::from_slice(&payload_bytes)
        .map_err(|e| anyhow!("payload cbor parse failed: {e}"))?;

    let pcrs_hex = payload
        .pcrs
        .into_iter()
        .map(|(k, v)| (k, hex::encode(v.as_ref())))
        .collect::<BTreeMap<_, _>>();

    let b64 = base64::engine::general_purpose::STANDARD;
    let view = AttestationPayloadJsonView {
        pcrs: pcrs_hex,
        user_data: payload.user_data.map(|b| b64.encode(b.as_ref())),
        nonce: payload.nonce.map(|b| b64.encode(b.as_ref())),
        certificate: b64.encode(payload.certificate.as_ref()),
        cabundle: payload
            .cabundle
            .map(|v| v.into_iter().map(|b| b64.encode(b.as_ref())).collect()),
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

    let payload: AttestationPayload = serde_cbor::from_slice(&payload_bytes)
        .map_err(|e| anyhow!("payload cbor parse failed: {e}"))?;

    // 1. Verify certificate chain: root -> cabundle... -> leaf
    let root_der = load_root_pem(root_pem)?;
    let root = load_x509_der(&root_der)?;
    let leaf = load_x509_der(payload.certificate.as_ref())?;

    let mut issuer = root;
    if let Some(bundle) = payload.cabundle.as_ref() {
        for der in bundle {
            let cert = load_x509_der(der.as_ref())?;
            verify_x509_sig_ecdsa_sha384(&cert, &issuer)?;
            issuer = cert;
        }
    }
    verify_x509_sig_ecdsa_sha384(&leaf, &issuer)?;

    // 2. Verify COSE signature using the leaf certificate public key.
    let leaf_x509 = OpensslX509::from_der(payload.certificate.as_ref())
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
        if actual.as_ref() != expected {
            return Err(anyhow!("PCR{idx} mismatch"));
        }
    }

    let ud = payload
        .user_data
        .as_ref()
        .map(|b| b.as_ref())
        .ok_or_else(|| anyhow!("user_data missing"))?;
    if ud != expected_user_data {
        return Err(anyhow!("user_data mismatch"));
    }

    if let Some(exp_nonce) = expected_nonce {
        let n = payload
            .nonce
            .as_ref()
            .map(|b| b.as_ref())
            .ok_or_else(|| anyhow!("nonce missing"))?;
        if n != exp_nonce {
            return Err(anyhow!("nonce mismatch"));
        }
    }

    Ok(())
}
