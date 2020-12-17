use crate::HashAlgo;

use std::convert::TryFrom;
use std::ffi::CString;
use std::num::NonZeroI32;
use std::ptr;

use anyhow::{Context, Result};

#[derive(Default)]
#[repr(C)]
pub struct PKeyQueryKernel {
    supported_ops: u32,
    key_size: u32,
    max_data_size: u16,
    max_sig_size: u16,
    max_enc_size: u16,
    max_dec_size: u16,
    _spare: [u32; 10],
}

fn cstring(s: &str) -> Result<CString> {
    CString::new(s.as_bytes()).with_context(|| format!("Unable to build cstring out of '{}'", s))
}

fn check_syscall(res: libc::c_long) -> Result<libc::c_long> {
    if res == -1 {
        Err(errno::errno().into())
    } else {
        Ok(res)
    }
}

fn ignore(res: libc::c_long) {
    assert_eq!(res, 0);
}

macro_rules! syscall {
    ( $( $arg:expr, )* ) => {
        check_syscall(libc::syscall($( $arg, )*))
    };
}

macro_rules! keyctl {
    ( $( $arg:expr, )* ) => {
        syscall!(libc::SYS_keyctl, $( $arg, )*)
    };
}

fn keyctl_pkey_query(key: KeyringSerial, info: &str) -> Result<PKeyQueryKernel> {
    let mut query: PKeyQueryKernel = Default::default();
    let info_cstr = cstring(info).with_context(|| "Error building info cstring".to_string())?;
    unsafe {
        keyctl!(
            libc::KEYCTL_PKEY_QUERY,
            key.get(),
            0,
            info_cstr.as_ptr(),
            &mut query as *mut PKeyQueryKernel,
        )
    }
    .map(ignore)?;

    Ok(query)
}

#[repr(C)]
struct PKeyOpParamsKernel {
    key_id: i32,
    in_len: u32,
    out_len: u32,
    in2_len: u32,
}

pub fn keyctl_pkey_sign(
    key: KeyringSerial,
    info: &str,
    data: &[u8],
    buffer: &mut Vec<u8>,
) -> Result<i64> {
    let params = PKeyOpParamsKernel {
        key_id: key.get(),
        in_len: data.len() as u32,
        out_len: buffer.capacity() as u32,
        in2_len: 0,
    };

    let info_cstr = cstring(info).with_context(|| "Error building info cstring".to_string())?;
    unsafe {
        keyctl!(
            libc::KEYCTL_PKEY_SIGN,
            &params as *const PKeyOpParamsKernel,
            info_cstr.as_ptr(),
            data.as_ptr(),
            buffer.as_mut_ptr(),
        )
    }
    .with_context(|| "Error returned during signing".to_string())
}

type KeyringSerial = NonZeroI32;

#[derive(Debug)]
pub(crate) struct Key {
    serial: KeyringSerial,
    max_sig_size: u16,
}

impl Key {
    pub(crate) fn from_key_description(description: &str) -> Result<Self> {
        let type_cstr =
            cstring("asymmetric").with_context(|| "Error building type cstring".to_string())?;
        let desc_cstr = cstring(description)
            .with_context(|| "Error building description cstring".to_string())?;
        let opt_callout: *const libc::c_char = ptr::null();

        let serial = unsafe {
            syscall!(
                libc::SYS_request_key,
                type_cstr.as_ptr(),
                desc_cstr.as_ptr(),
                opt_callout,
                0,
            )
        }?;

        let serial =
            i32::try_from(serial).with_context(|| "Kernel provided invalid result".to_string())?;
        let serial =
            NonZeroI32::try_from(serial).with_context(|| "Zero key-id found".to_string())?;

        let key_info = keyctl_pkey_query(serial, "enc=pkcs1")
            .with_context(|| "Unable to get key information".to_string())?;

        Ok(Key {
            serial,
            max_sig_size: key_info.max_sig_size,
        })
    }

    pub(super) fn sign(&self, hash_algo: &HashAlgo, data: &[u8]) -> Result<Vec<u8>> {
        let info = format!("enc=pkcs1 hash={}", hash_algo.to_pkey_opt()?);

        let mut buffer = Vec::with_capacity(self.max_sig_size as usize);
        let sz = keyctl_pkey_sign(self.serial, &info, data, &mut buffer)
            .with_context(|| "Error requesting signature".to_string())?;
        unsafe {
            buffer.set_len(sz as usize);
        }
        Ok(buffer)
    }
}
