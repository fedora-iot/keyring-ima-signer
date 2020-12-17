use crate::HashAlgo;

use std::convert::TryInto;

use anyhow::{Context, Result};
use openssl::hash::hash;

mod keyutils;
use keyutils::Key;

pub(crate) fn hash_and_sign(signkey: &Key, hash_algo: &HashAlgo, data: &[u8]) -> Result<Vec<u8>> {
    let digest = hash(
        hash_algo
            .try_into()
            .with_context(|| "Unable to determine message digest".to_string())?,
        data,
    )
    .with_context(|| "Error hashing message".to_string())?;

    signkey
        .sign(hash_algo, &digest)
        .with_context(|| "Error signing data".to_string())
}

pub(crate) fn get_signing_key(description: &str) -> Result<Key> {
    Key::from_key_description(description)
        .with_context(|| "Unable to find key with description".to_string())
}
