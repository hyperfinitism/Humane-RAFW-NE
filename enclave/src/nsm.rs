// SPDX-License-Identifier:

//! This module provides wrapper functions to request operations from the Nitro Secure Module (NSM) driver.

use anyhow::Result;
use aws_nitro_enclaves_nsm_api::{
    api::{Request, Response},
    driver,
};

/// Get random bytes from the NSM.
pub(crate) fn get_random() -> Result<Vec<u8>> {
    let nsm_fd = driver::nsm_init();

    let request = Request::GetRandom {};

    let response = driver::nsm_process_request(nsm_fd, request);

    match response {
        Response::GetRandom { random } => Ok(random),
        Response::Error(error) => Err(anyhow::anyhow!("error getting random bytes: {:?}", error)),
        _ => Err(anyhow::anyhow!(
            "error getting random bytes: unexpected response: {:#?}",
            response
        )),
    }
}

/// Get an attestation document from the NSM.
pub(crate) fn get_attestation_document(user_data: Vec<u8>, nonce: Vec<u8>) -> Result<Vec<u8>> {
    let nsm_fd = driver::nsm_init();

    let request = Request::Attestation {
        public_key: None,
        user_data: Some(user_data.clone().into()),
        nonce: Some(nonce.clone().into()),
    };

    let response = driver::nsm_process_request(nsm_fd, request);

    match response {
        Response::Attestation { document } => Ok(document),
        Response::Error(error) => Err(anyhow::anyhow!(
            "error getting attestation document: {:?}",
            error
        )),
        _ => Err(anyhow::anyhow!(
            "error getting attestation document: unexpected response: {:#?}",
            response
        )),
    }
}
