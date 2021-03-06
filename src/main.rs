use std::convert::TryFrom;
use std::env;
use std::fs;
use std::path::Path;

use anyhow::{anyhow, Context, Error, Result};
use openssl::hash::{hash, MessageDigest};

mod ima;
mod signing;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[allow(dead_code)] // Many of these we never use, but we need them to keep the numbers correct
enum HashAlgo {
    Md4,
    Md5,
    Sha1,
    RipeMd160,
    Sha256,
    Sha384,
    Sha512,
    Sha224,
    RipeMd128,
    RipeMd256,
    RipeMd320,
    Wp256,
    Wp384,
    Wp512,
    Tgr128,
    Tgr160,
    Tgr192,
    Sm3256,
    Streebog256,
    Streebog512,
}

impl TryFrom<&str> for HashAlgo {
    type Error = Error;
    fn try_from(hastr: &str) -> Result<Self> {
        match &hastr.to_lowercase()[..] {
            "sha256" => Ok(HashAlgo::Sha256),
            "sha1" => Ok(HashAlgo::Sha1),
            _ => Err(anyhow!("Unsupported hash algorithm: {}", hastr)),
        }
    }
}

impl TryFrom<&HashAlgo> for MessageDigest {
    type Error = Error;
    fn try_from(hash_algo: &HashAlgo) -> Result<Self> {
        match hash_algo {
            HashAlgo::Sha1 => Ok(MessageDigest::sha1()),
            HashAlgo::Sha256 => Ok(MessageDigest::sha256()),
            _ => Err(anyhow!("Unsupported hash algorithm: {:?}", hash_algo)),
        }
    }
}

impl HashAlgo {
    fn to_pkey_opt(&self) -> Result<&'static str> {
        match self {
            HashAlgo::Sha1 => Ok("sha1"),
            HashAlgo::Sha256 => Ok("sha256"),
            _ => Err(anyhow!("Unsupported hash algorithm: {:?}", self)),
        }
    }
}

fn get_keyid_from_cert(cert_path: &str) -> Result<Vec<u8>> {
    let cert_contents =
        fs::read(cert_path).with_context(|| "Error reading certificate".to_string())?;

    let cert = if cert_contents[0] == b'-' {
        // Assume this is PEM
        openssl::x509::X509::from_pem(&cert_contents)
            .with_context(|| "Error parsing certificate PEM".to_string())
    } else {
        openssl::x509::X509::from_der(&cert_contents)
            .with_context(|| "Error parsing certificate DER".to_string())
    }?;

    let pubkey_rsa = cert
        .public_key()
        .with_context(|| "Error getting certificate public key".to_string())?
        .rsa()
        .with_context(|| "Error parsing RSA key".to_string())?;
    let pubkey_bytes = pubkey_rsa
        .public_key_to_der_pkcs1()
        .with_context(|| "Error building DER representation of public key".to_string())?;

    let digest = hash(MessageDigest::sha1(), &pubkey_bytes)
        .with_context(|| "Error hashing public key".to_string())?;
    let keyid_bytes = &digest[16..20];

    Ok(keyid_bytes.to_vec())
}

fn update_presigned(args: env::Args) -> Result<()> {
    for filename in args {
        let filename = Path::new(&filename);
        let sigfilename = format!("{}.sig", filename.display());
        let sigfile = Path::new(&sigfilename);

        let sighdr = fs::read(sigfile)
            .with_context(|| format!("Error reading signature file {}", sigfile.display()))?;
        ima::write_signature(filename, &sighdr, false)?;
        fs::remove_file(sigfile)
            .with_context(|| format!("Error deleting signature file {}", sigfile.display()))?;
    }
    Ok(())
}

fn sign_single_file(filepath: &Path, signkey: &signing::Key, keyid: &[u8], hash_algo: &HashAlgo, use_xattr: bool) -> Result<()> {

    let data =
        fs::read(filepath).with_context(|| format!("Error reading {}", filepath.display()))?;

    let signature = signing::hash_and_sign(&signkey, &hash_algo, &data)
        .with_context(|| format!("Error signing {}", filepath.display()))?;

    let hdr = ima::build_signature_header(&keyid, &hash_algo, &signature);

    ima::write_signature(filepath, &hdr, !use_xattr)
        .with_context(|| format!("Error writing signature for {}", filepath.display()))
}

fn sign_recursive(filepath: &Path, signkey: &signing::Key, keyid: &[u8], hash_algo: &HashAlgo, use_xattr: bool) -> Result<()> {
    for child in fs::read_dir(filepath)? {
        let child = child?;

        if child.file_type()?.is_dir() {
            sign_recursive(&child.path(), signkey, keyid, hash_algo, use_xattr)?;
            continue;
        }
        if child.file_type()?.is_symlink() {
            return Ok(())
        }
        // We are just a file
        sign_single_file(&child.path(), signkey, keyid, hash_algo, use_xattr)?;
    }
    Ok(())
}

fn main() -> Result<()> {
    let mut args = env::args();
    // Skip the path
    args.next();

    let key_description = args
        .next()
        .with_context(|| "Please provide key description".to_string())?;
    if key_description == "--presigned" {
        return update_presigned(args);
    }
    let signkey = signing::get_signing_key(&key_description)
        .with_context(|| format!("Error loading key with description {}", &key_description))?;

    let cert_path = args
        .next()
        .with_context(|| "Please provide public certificate path".to_string())?;
    let keyid = get_keyid_from_cert(&cert_path)
        .with_context(|| format!("Unable to parse public certificate {}", &cert_path))?;

    let hash_algo = args
        .next()
        .with_context(|| "Please provide hash algorithm".to_string())?;
    let hash_algo = HashAlgo::try_from(&hash_algo[..])
        .with_context(|| format!("Unable to parse hash algo {}", &hash_algo))?;

    let mut use_xattr = false;
    let mut do_recursive = false;

    for file_to_sign in args {
        if file_to_sign == "--xattr" {
            use_xattr = true;
            continue;
        }
        if file_to_sign == "--sigfile" {
            use_xattr = false;
            continue;
        }
        if file_to_sign == "--recursive" || file_to_sign == "-r" {
            do_recursive = true;
            continue;
        }
        if file_to_sign == "--" {
            continue;
        }

        if do_recursive {
            sign_recursive(Path::new(&file_to_sign), &signkey, &keyid, &hash_algo, use_xattr)?;
        } else {
            sign_single_file(Path::new(&file_to_sign), &signkey, &keyid, &hash_algo, use_xattr)?;
        }
    }

    Ok(())
}
