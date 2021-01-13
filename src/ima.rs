use crate::HashAlgo;

use anyhow::{Context, Result};

use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

const IMA_DIGSIG_HEADER: u8 = 0x3;
const IMA_DIGSIG_V2: u8 = 0x2;

const XATTR_IMA: &str = "security.ima";

pub(crate) fn build_signature_header(
    keyid: &[u8],
    hash_algo: &HashAlgo,
    signature: &[u8],
) -> Vec<u8> {
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

pub(crate) fn write_signature(filename: &Path, imahdr: &[u8], sigfile: bool) -> Result<()> {
    if sigfile {
        let sigfilename = format!("{}.sig", filename.display());
        let mut file = File::create(&sigfilename)
            .with_context(|| format!("Unable to open signature file {}", &sigfilename))?;
        file.write_all(imahdr)
            .with_context(|| format!("Unable to write signature file {}", &sigfilename))?;
        file.sync_all()
            .with_context(|| format!("Unable to sync signature file {}", &sigfilename))?;

        println!("{}", sigfilename);
    } else {
        xattr::set(filename, XATTR_IMA, imahdr)
            .with_context(|| "Unable to set the IMA xattr".to_string())?;

        println!("{}", filename.display());
    }

    Ok(())
}
