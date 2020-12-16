use std::fs;

use anyhow::{Context, Result};
use keyutils::{Key, KeyctlEncoding, KeyctlHash, PublicKeyOptions};
use sha2::{Digest, Sha256};

fn sign_digest(signkey: &Key, digest: &[u8]) -> Result<Vec<u8>> {
    let options = PublicKeyOptions {
        encoding: Some(KeyctlEncoding::RsassaPkcs1V15),
        hash: Some(KeyctlHash::Sha256),
    };
    let mut signature = signkey
        .sign(&options, digest)
        .with_context(|| format!("Error signing data"))?;

    // https://github.com/mathstuf/rust-keyutils/pull/55
    unsafe {
        // This is equal to the number of bytes in the key
        signature.set_len(2048 / 8);
    }

    Ok(signature)
}

fn hash_and_sign(signkey: &Key, data: &[u8]) -> Result<Vec<u8>> {
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let digest = hasher.finalize();

    sign_digest(signkey, &digest)
}

fn main() -> Result<()> {
    let signkey = Key::request::<keyutils::keytypes::Asymmetric, _, _, _>("signkey", None, None)?;

    let data = fs::read("loadkey.sh").with_context(|| format!("Error reading rsakey.pem"))?;

    let signature = hash_and_sign(&signkey, &data);
    println!("Signature: {:?}", signature);

    Ok(())
}
