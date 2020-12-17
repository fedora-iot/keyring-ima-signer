use crate::HashAlgo;

use anyhow::{bail, Context, Result};
use sha1::Sha1;
use sha2::{Digest, Sha256};

mod keyutils;
use keyutils::Key;

fn sign_digest(
    signkey: &Key,
    hash_algo: &HashAlgo,
    digest: &[u8],
    siglen: usize,
) -> Result<Vec<u8>> {
    let mut signature = signkey
        .sign(hash_algo, digest)
        .with_context(|| "Error signing data".to_string())?;

    // https://github.com/mathstuf/rust-keyutils/pull/55
    unsafe {
        // This is equal to the number of bytes in the key
        signature.set_len(siglen);
    }

    Ok(signature)
}

pub(crate) fn hash_and_sign(
    signkey: &Key,
    hash_algo: &HashAlgo,
    data: &[u8],
    siglen: usize,
) -> Result<Vec<u8>> {
    let digest = match hash_algo {
        HashAlgo::Sha1 => {
            let mut hasher = Sha1::new();
            hasher.update(&data);
            hasher.digest().bytes().to_vec()
        }
        HashAlgo::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(&data);
            hasher.finalize().as_slice().to_vec()
        }
        _ => bail!("Unsupported hash algorithm {:?} selected", hash_algo),
    };

    sign_digest(signkey, hash_algo, &digest, siglen)
}

pub(crate) fn get_signing_key(description: &str) -> Result<Key> {
    Key::from_key_description(description)
        .with_context(|| "Unable to find key with description".to_string())
}
