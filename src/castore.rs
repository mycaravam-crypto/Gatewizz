//! `gatewizz ca install|remove`: the CA files and the CurrentUser Root store, plus DPAPI for `ca.key`.
//!
//! A per-user root is enough for the .NET wizz tools and needs no admin rights. Windows asks the user to confirm
//! every add to and delete from that store with its own prompt.

use std::path::Path;
use std::time::SystemTime;

use crate::ca::{self, CA_NAME, Ca};

/// Creates the CA in `dir` unless it is there, then trusts it for the current user. Safe to re-run.
pub fn install(dir: &Path) -> Result<String, String> {
    let (cert, key) = (dir.join(ca::CERT_FILE), dir.join(ca::KEY_FILE));
    let created = !cert.exists() && !key.exists();
    let ca = if created {
        let ca = Ca::generate(SystemTime::now())?;
        ca.save(dir)?;
        ca
    } else {
        Ca::load(dir)?
    };
    sys::trust(ca.cert_der())?;
    Ok(format!(
        "{} {} and trusted it for the current user",
        if created { "created" } else { "found" },
        cert.display()
    ))
}

/// Removes every gatewizz CA from the store, then both files, then `dir` if that left it empty.
pub fn remove(dir: &Path) -> Result<String, String> {
    let removed = sys::untrust_all(CA_NAME)?;
    for name in [ca::CERT_FILE, ca::KEY_FILE] {
        let path = dir.join(name);
        match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                return Err(format!("{}: {e}", path.display()));
            }
            _ => {}
        }
    }
    // Fails while events or anything else are left in it, which is what we want.
    let _ = std::fs::remove_dir(dir);
    Ok(format!(
        "removed {removed} gatewizz CA certificate(s) from the store and the CA files in {}",
        dir.display()
    ))
}

/// Encrypts with DPAPI for the current user.
pub fn protect(plain: &[u8]) -> Result<Vec<u8>, String> {
    sys::protect(plain)
}

/// Decrypts what `protect` wrote, for the same user only.
pub fn unprotect(blob: &[u8]) -> Result<Vec<u8>, String> {
    sys::unprotect(blob)
}

#[cfg(not(windows))]
mod sys {
    const UNSUPPORTED: &str = "the CA store needs Windows";

    pub fn protect(_: &[u8]) -> Result<Vec<u8>, String> {
        Err(UNSUPPORTED.into())
    }
    pub fn unprotect(_: &[u8]) -> Result<Vec<u8>, String> {
        Err(UNSUPPORTED.into())
    }
    pub fn trust(_: &[u8]) -> Result<(), String> {
        Err(UNSUPPORTED.into())
    }
    pub fn untrust_all(_: &str) -> Result<usize, String> {
        Err(UNSUPPORTED.into())
    }
}

#[cfg(windows)]
mod sys {
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
    use windows_sys::Win32::Security::Cryptography::{
        CERT_CONTEXT, CERT_FIND_SUBJECT_STR_W, CERT_NAME_ATTR_TYPE, CERT_STORE_ADD_USE_EXISTING,
        CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_CURRENT_USER, CRYPT_INTEGER_BLOB,
        CRYPTPROTECT_UI_FORBIDDEN, CertAddEncodedCertificateToStore, CertCloseStore,
        CertDeleteCertificateFromStore, CertDuplicateCertificateContext,
        CertFindCertificateInStore, CertGetNameStringW, CertOpenStore, CryptProtectData,
        CryptUnprotectData, HCERTSTORE, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING, szOID_COMMON_NAME,
    };

    const ENCODING: u32 = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

    fn last_error(what: &str) -> String {
        format!(
            "{what} failed: {}",
            std::io::Error::from_raw_os_error(unsafe { GetLastError() } as i32)
        )
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    fn blob(bytes: &[u8]) -> Result<CRYPT_INTEGER_BLOB, String> {
        let len = u32::try_from(bytes.len()).map_err(|_| "data too large".to_string())?;
        Ok(CRYPT_INTEGER_BLOB {
            cbData: len,
            pbData: bytes.as_ptr().cast_mut(),
        })
    }

    /// Copies a DPAPI output blob and frees it.
    fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
        // SAFETY: DPAPI returned `cbData` bytes at `pbData`, allocated with LocalAlloc.
        let bytes = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec();
        unsafe { LocalFree(out.pbData.cast()) };
        bytes
    }

    pub fn protect(plain: &[u8]) -> Result<Vec<u8>, String> {
        let input = blob(plain)?;
        let mut out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: null_mut(),
        };
        let description = wide("gatewizz CA key");
        // SAFETY: every pointer is valid for the call; `out` is freed by `take`.
        let ok = unsafe {
            CryptProtectData(
                &input,
                description.as_ptr(),
                null(),
                null(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if ok == 0 {
            return Err(last_error("CryptProtectData"));
        }
        Ok(take(out))
    }

    pub fn unprotect(protected: &[u8]) -> Result<Vec<u8>, String> {
        let input = blob(protected)?;
        let mut out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: null_mut(),
        };
        // SAFETY: as in `protect`; no description is requested.
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                null_mut(),
                null(),
                null(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if ok == 0 {
            return Err(last_error("CryptUnprotectData"));
        }
        Ok(take(out))
    }

    /// The CurrentUser Root store, closed on drop.
    struct Store(HCERTSTORE);

    impl Store {
        fn open_root() -> Result<Store, String> {
            let name = wide("Root");
            // SAFETY: `name` outlives the call.
            let store = unsafe {
                CertOpenStore(
                    CERT_STORE_PROV_SYSTEM_W,
                    0,
                    0,
                    CERT_SYSTEM_STORE_CURRENT_USER,
                    name.as_ptr().cast(),
                )
            };
            if store.is_null() {
                return Err(last_error("opening the CurrentUser Root store"));
            }
            Ok(Store(store))
        }
    }

    impl Drop for Store {
        fn drop(&mut self) {
            unsafe { CertCloseStore(self.0, 0) };
        }
    }

    pub fn trust(cert: &[u8]) -> Result<(), String> {
        let store = Store::open_root()?;
        let len = u32::try_from(cert.len()).map_err(|_| "certificate too large".to_string())?;
        // USE_EXISTING: a CA already in the store is left alone, so re-running asks nothing.
        // SAFETY: `cert` is valid for `len` bytes; no context is returned.
        let ok = unsafe {
            CertAddEncodedCertificateToStore(
                store.0,
                ENCODING,
                cert.as_ptr(),
                len,
                CERT_STORE_ADD_USE_EXISTING,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(last_error("adding the CA to the CurrentUser Root store"));
        }
        Ok(())
    }

    /// The certificate's common name.
    fn common_name(ctx: *const CERT_CONTEXT) -> String {
        let mut buf = [0u16; 256];
        // SAFETY: `ctx` is a live context from the store; the buffer length is passed.
        let n = unsafe {
            CertGetNameStringW(
                ctx,
                CERT_NAME_ATTR_TYPE,
                0,
                szOID_COMMON_NAME.cast(),
                buf.as_mut_ptr(),
                buf.len() as u32,
            )
        };
        String::from_utf16_lossy(&buf[..(n as usize).saturating_sub(1)])
    }

    pub fn untrust_all(name: &str) -> Result<usize, String> {
        let store = Store::open_root()?;
        let needle = wide(name);
        let (mut prev, mut removed): (*const CERT_CONTEXT, usize) = (null(), 0);
        loop {
            // SAFETY: the find frees `prev` and returns the next match or null.
            let ctx = unsafe {
                CertFindCertificateInStore(
                    store.0,
                    ENCODING,
                    0,
                    CERT_FIND_SUBJECT_STR_W,
                    needle.as_ptr().cast(),
                    prev,
                )
            };
            if ctx.is_null() {
                return Ok(removed);
            }
            // The find matches a substring of the subject; only an exact common name is ours.
            if common_name(ctx) == name {
                // SAFETY: deleting frees the duplicate, and `ctx` stays valid for the next find.
                if unsafe { CertDeleteCertificateFromStore(CertDuplicateCertificateContext(ctx)) }
                    == 0
                {
                    let err = last_error("removing the CA from the CurrentUser Root store");
                    unsafe {
                        windows_sys::Win32::Security::Cryptography::CertFreeCertificateContext(ctx)
                    };
                    return Err(err);
                }
                removed += 1;
            }
            prev = ctx;
        }
    }
}
