use std::convert::{TryFrom, TryInto};
use std::env;
use std::fs::{self, File};
use std::io::prelude::*;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Error, Result};
use keyutils::{Key, KeyctlEncoding, KeyctlHash, PublicKeyOptions};
use sha1::Sha1;
use sha2::{Digest, Sha256};

const IMA_DIGSIG_HEADER: u8 = 0x3;
const IMA_DIGSIG_V2: u8 = 0x2;

const XATTR_IMA: &str = "security.ima";

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

impl TryFrom<HashAlgo> for KeyctlHash {
    type Error = Error;
    fn try_from(ha: HashAlgo) -> Result<Self> {
        match ha {
            HashAlgo::Sha1 => Ok(KeyctlHash::Sha1),
            HashAlgo::Sha256 => Ok(KeyctlHash::Sha256),
            HashAlgo::Sha384 => Ok(KeyctlHash::Sha384),
            HashAlgo::Sha512 => Ok(KeyctlHash::Sha512),
            _ => Err(anyhow!("Unsupported hash algorithm {:?}", ha)),
        }
    }
}

fn build_ima_signature(keyid: &[u8], hash_algo: &HashAlgo, signature: &[u8]) -> Vec<u8> {
    /*
    C struct:
    struct signature_v2_hdr {
        uint8_t version;	/* signature format version */
        uint8_t	hash_algo;	/* Digest algorithm [enum pkey_hash_algo] */
        uint32_t keyid;		/* IMA key identifier - not X509/PGP specific*/
        uint16_t sig_size;	/* signature size */
        uint8_t sig[0];		/* signature payload */
    } __packed;
    */

    let mut buffer = Vec::with_capacity(265);

    let sig_size: u16 = signature.len() as u16;

    buffer.push(IMA_DIGSIG_HEADER);
    buffer.push(IMA_DIGSIG_V2);
    buffer.push(*hash_algo as u8);
    buffer.extend_from_slice(&keyid);
    buffer.extend_from_slice(&sig_size.to_be_bytes());
    buffer.extend_from_slice(signature);

    buffer
}

fn sign_digest(
    signkey: &Key,
    hash_algo: &HashAlgo,
    digest: &[u8],
    siglen: usize,
) -> Result<Vec<u8>> {
    let options = PublicKeyOptions {
        encoding: Some(KeyctlEncoding::RsassaPkcs1V15),
        hash: Some((*hash_algo).try_into()?),
    };
    let mut signature = signkey
        .sign(&options, digest)
        .with_context(|| "Error signing data".to_string())?;

    // https://github.com/mathstuf/rust-keyutils/pull/55
    unsafe {
        // This is equal to the number of bytes in the key
        signature.set_len(siglen);
    }

    Ok(signature)
}

fn hash_and_sign(
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

fn get_keyid_and_keylen_from_cert(cert_path: &str) -> Result<(Vec<u8>, usize)> {
    let cert_contents =
        fs::read(cert_path).with_context(|| "Error reading certificate".to_string())?;

    let (rem, decoded_pem) = x509_parser::pem::parse_x509_pem(&cert_contents)
        .with_context(|| "Error parsing certificate".to_string())?;
    if !rem.is_empty() {
        bail!("Certificate has remaining PEM bytes");
    }
    if decoded_pem.label != "CERTIFICATE" {
        bail!(
            "Certificate has label '{}', not 'CERTIFICATE'",
            decoded_pem.label
        );
    }
    let (rem, x509_cert) = x509_parser::parse_x509_certificate(&decoded_pem.contents)
        .with_context(|| "Error parsing certificate DER".to_string())?;
    if !rem.is_empty() {
        bail!("Certificate has remaining DER bytes");
    }
    if x509_cert
        .tbs_certificate
        .subject_pki
        .algorithm
        .algorithm
        .to_id_string()
        != "1.2.840.113549.1.1.1"
    {
        bail!(
            "Certificate has invalid OID: '{}' != '1.2.840.113549.1.1.1' (RSA)",
            x509_cert
                .tbs_certificate
                .subject_pki
                .algorithm
                .algorithm
                .to_id_string()
        );
    }

    let pubkey = x509_cert
        .tbs_certificate
        .subject_pki
        .subject_public_key
        .data;
    let keylen = pubkey.len() - 14;

    let mut hasher = Sha1::new();
    hasher.update(pubkey);
    let digest = hasher.digest().bytes();
    let keyid_bytes = &digest[16..20];

    Ok((keyid_bytes.to_vec(), keylen))
}

fn write_ima_sig(filename: &Path, imahdr: &[u8], sigfile: bool) -> Result<()> {
    if sigfile {
        let sigfilename = format!("{}.sig", filename.display());
        let mut file = File::create(&sigfilename)
            .with_context(|| format!("Unable to open signature file {}", &sigfilename))?;
        file.write_all(imahdr)
            .with_context(|| format!("Unable to write signature file {}", &sigfilename))?;
        file.sync_all()
            .with_context(|| format!("Unable to sync signature file {}", &sigfilename))
    } else {
        xattr::set(filename, XATTR_IMA, imahdr)
            .with_context(|| "Unable to set the IMA xattr".to_string())
    }
}

fn update_presigned(args: env::Args) -> Result<()> {
    for filename in args {
        let filename = Path::new(&filename);
        let sigfilename = format!("{}.sig", filename.display());
        let sigfile = Path::new(&sigfilename);

        let sighdr = fs::read(sigfile)
            .with_context(|| format!("Error reading signature file {}", sigfile.display()))?;
        write_ima_sig(filename, &sighdr, false)?;
        fs::remove_file(sigfile)
            .with_context(|| format!("Error deleting signature file {}", sigfile.display()))?;
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
    let key_description_copy = key_description.clone();
    let signkey =
        Key::request::<keyutils::keytypes::Asymmetric, _, _, _>(key_description, None, None)
            .with_context(|| {
                format!(
                    "Unable to find key with description {}",
                    &key_description_copy
                )
            })?;

    let cert_path = args
        .next()
        .with_context(|| "Please provide public certificate path".to_string())?;
    let (keyid, keylen) = get_keyid_and_keylen_from_cert(&cert_path)
        .with_context(|| format!("Unable to parse public certificate {}", &cert_path))?;

    let hash_algo = args
        .next()
        .with_context(|| "Please provide hash algorithm".to_string())?;
    let hash_algo = HashAlgo::try_from(&hash_algo[..])
        .with_context(|| format!("Unable to parse hash algo {}", &hash_algo))?;

    let mut use_xattr = false;

    for file_to_sign in args {
        if file_to_sign == "--xattr" {
            use_xattr = true;
            continue;
        }
        if file_to_sign == "--sigfile" {
            use_xattr = false;
            continue;
        }
        if file_to_sign == "--" {
            continue;
        }

        let filepath = Path::new(&file_to_sign);

        let data =
            fs::read(filepath).with_context(|| format!("Error reading {}", filepath.display()))?;

        let signature = hash_and_sign(&signkey, &hash_algo, &data, keylen)
            .with_context(|| format!("Error signing {}", filepath.display()))?;

        let hdr = build_ima_signature(&keyid, &hash_algo, &signature);

        write_ima_sig(filepath, &hdr, !use_xattr)
            .with_context(|| format!("Error writing signature for {}", filepath.display()))?;

        println!("Signed {}", filepath.display());
    }

    Ok(())
}
