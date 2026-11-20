//! The local CA that TLS interception (#19) signs leaf certificates with.
//!
//! `ca.cer` holds the public certificate (DER) and `ca.key` the PKCS#8 key encrypted with DPAPI for the current
//! user, both in `%LOCALAPPDATA%\gatewizz`. Generation and leaf issuance are pure; the file store and the Windows
//! certificate store are Windows-only.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use time::{Duration, OffsetDateTime};

/// Subject CN of the CA, also how `ca remove` finds it in the certificate store.
pub const CA_NAME: &str = "gatewizz local CA";
const CA_VALIDITY: Duration = Duration::days(5 * 365);
const LEAF_VALIDITY: Duration = Duration::days(7);
/// A cached leaf this close to expiry is issued again.
const LEAF_RENEW: Duration = Duration::days(1);
/// Back-dates certificates so a client clock slightly behind still accepts them.
const CLOCK_SKEW: Duration = Duration::hours(1);
const LEAF_CACHE: usize = 256;

/// A leaf certificate and its private key, both DER (the key as PKCS#8).
#[derive(Debug)]
#[allow(dead_code)] // `key` is read by TLS interception (#19)
pub struct Leaf {
    pub cert: Vec<u8>,
    pub key: Vec<u8>,
    not_after: OffsetDateTime,
}

pub struct Ca {
    cert: Vec<u8>,
    issuer: Issuer<'static, KeyPair>,
    leaves: Mutex<HashMap<String, Arc<Leaf>>>,
}

/// The CA's fixed parameters. An issuer rebuilt from them and the stored key signs leaves that chain to the
/// stored certificate: the subject DN, key usages and key identifier method are all that rcgen takes from them.
fn ca_params() -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, CA_NAME);
    params
        .distinguished_name
        .push(DnType::OrganizationName, "gatewizz");
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
}

impl Ca {
    /// A new CA with a fresh ECDSA P-256 key.
    pub fn generate() -> Result<Self, String> {
        let key = KeyPair::generate().map_err(|e| format!("[ca] cannot generate key: {e}"))?;
        let mut params = ca_params();
        let now = OffsetDateTime::now_utc();
        params.not_before = now - CLOCK_SKEW;
        params.not_after = now + CA_VALIDITY;
        let cert = params
            .self_signed(&key)
            .map_err(|e| format!("[ca] cannot sign CA: {e}"))?;
        Self::from_parts(cert.der().to_vec(), key)
    }

    fn from_parts(cert: Vec<u8>, key: KeyPair) -> Result<Self, String> {
        // ponytail: a byte search for the public key instead of parsing the certificate; enough to catch a
        // ca.cer and ca.key that do not belong together.
        let public = key.public_key_raw();
        if !cert.windows(public.len()).any(|w| w == public) {
            return Err("[ca] ca.cer does not match ca.key".into());
        }
        Ok(Self {
            cert,
            issuer: Issuer::new(ca_params(), key),
            leaves: Mutex::new(HashMap::new()),
        })
    }

    /// The CA certificate, DER.
    pub fn cert(&self) -> &[u8] {
        &self.cert
    }

    /// A leaf for `host` (a DNS name or an IP address), from the cache while it is not close to expiry.
    #[allow(dead_code)] // used by TLS interception (#19)
    pub fn leaf(&self, host: &str) -> Result<Arc<Leaf>, String> {
        let now = OffsetDateTime::now_utc();
        let mut leaves = self.leaves.lock().expect("leaf cache poisoned");
        if let Some(leaf) = leaves.get(host).filter(|l| l.not_after - now > LEAF_RENEW) {
            return Ok(leaf.clone());
        }
        let leaf = Arc::new(self.issue(host, now)?);
        if leaves.len() >= LEAF_CACHE {
            leaves.retain(|_, l| l.not_after - now > LEAF_RENEW);
        }
        if leaves.len() >= LEAF_CACHE {
            // ponytail: drops the whole cache when full; an LRU if hosts churn past LEAF_CACHE.
            leaves.clear();
        }
        leaves.insert(host.to_string(), leaf.clone());
        Ok(leaf)
    }

    fn issue(&self, host: &str, now: OffsetDateTime) -> Result<Leaf, String> {
        let invalid =
            |e: rcgen::Error| format!("[ca] cannot issue a certificate for {host:?}: {e}");
        let key = KeyPair::generate().map_err(invalid)?;
        let mut params = CertificateParams::new(vec![host.to_string()]).map_err(invalid)?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, host);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        params.not_before = now - CLOCK_SKEW;
        params.not_after = now + LEAF_VALIDITY;
        let cert = params.signed_by(&key, &self.issuer).map_err(invalid)?;
        Ok(Leaf {
            cert: cert.der().to_vec(),
            key: key.serialize_der(),
            not_after: params.not_after,
        })
    }

    /// Reads `ca.cer` and the DPAPI-protected `ca.key` from `dir`.
    pub fn load(dir: &Path) -> Result<Self, String> {
        let read = |name: &str| {
            let path = dir.join(name);
            std::fs::read(&path).map_err(|e| format!("[ca] cannot read {}: {e}", path.display()))
        };
        let cert = read("ca.cer")?;
        let key_path = dir.join("ca.key");
        let key = sys::unprotect(&read("ca.key")?)
            .map_err(|e| format!("[ca] cannot decrypt {}: {e}", key_path.display()))?;
        let key = KeyPair::try_from(key)
            .map_err(|e| format!("[ca] {} holds no valid key: {e}", key_path.display()))?;
        Self::from_parts(cert, key)
    }

    /// Writes `ca.cer` and `ca.key` (DPAPI-protected) into `dir`.
    pub fn save(&self, dir: &Path) -> Result<(), String> {
        let key = sys::protect(self.issuer.key().serialized_der())
            .map_err(|e| format!("[ca] cannot encrypt the key: {e}"))?;
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("[ca] cannot create {}: {e}", dir.display()))?;
        for (name, bytes) in [("ca.key", &key), ("ca.cer", &self.cert)] {
            let path = dir.join(name);
            std::fs::write(&path, bytes)
                .map_err(|e| format!("[ca] cannot write {}: {e}", path.display()))?;
        }
        Ok(())
    }
}

/// `gatewizz ca install`: creates the CA in `dir` if missing and trusts it for the current user.
pub fn install(dir: &Path) -> Result<String, String> {
    let ca = if dir.join("ca.cer").exists() || dir.join("ca.key").exists() {
        Ca::load(dir)?
    } else {
        let ca = Ca::generate()?;
        ca.save(dir)?;
        ca
    };
    sys::trust(ca.cert())?;
    Ok(format!(
        "gatewizz: CA installed in {} and trusted for the current user",
        dir.display()
    ))
}

/// `gatewizz ca remove`: removes every gatewizz CA from the current user's Root store and deletes both files.
pub fn remove(dir: &Path) -> Result<String, String> {
    let removed = sys::distrust()?;
    for name in ["ca.key", "ca.cer"] {
        let path = dir.join(name);
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("[ca] cannot delete {}: {e}", path.display())),
        }
    }
    Ok(format!(
        "gatewizz: removed {removed} CA certificate(s) from the store and the files in {}",
        dir.display()
    ))
}

#[cfg(not(windows))]
mod sys {
    const ONLY_WINDOWS: &str = "needs Windows";

    pub fn protect(_data: &[u8]) -> Result<Vec<u8>, String> {
        Err(ONLY_WINDOWS.into())
    }
    pub fn unprotect(_data: &[u8]) -> Result<Vec<u8>, String> {
        Err(ONLY_WINDOWS.into())
    }
    pub fn trust(_cert: &[u8]) -> Result<(), String> {
        Err(ONLY_WINDOWS.into())
    }
    pub fn distrust() -> Result<usize, String> {
        Err(ONLY_WINDOWS.into())
    }
}

#[cfg(windows)]
mod sys {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CERT_FIND_SUBJECT_STR_W, CERT_STORE_ADD_USE_EXISTING, CERT_STORE_PROV_SYSTEM_W,
        CERT_SYSTEM_STORE_CURRENT_USER, CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN,
        CertAddEncodedCertificateToStore, CertCloseStore, CertDeleteCertificateFromStore,
        CertFindCertificateInStore, CertOpenStore, CryptProtectData, CryptUnprotectData,
        HCERTSTORE, X509_ASN_ENCODING,
    };

    fn last_error() -> String {
        std::io::Error::last_os_error().to_string()
    }

    fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr().cast_mut(),
        }
    }

    /// Copies a blob that DPAPI allocated and frees it.
    fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
        let data = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec();
        unsafe { LocalFree(out.pbData.cast()) };
        data
    }

    pub fn protect(data: &[u8]) -> Result<Vec<u8>, String> {
        let mut out = CRYPT_INTEGER_BLOB::default();
        let ok = unsafe {
            CryptProtectData(
                &blob(data),
                null(),
                null(),
                null(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if ok == 0 {
            return Err(last_error());
        }
        Ok(take(out))
    }

    pub fn unprotect(data: &[u8]) -> Result<Vec<u8>, String> {
        let mut out = CRYPT_INTEGER_BLOB::default();
        let ok = unsafe {
            CryptUnprotectData(
                &blob(data),
                null_mut(),
                null(),
                null(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if ok == 0 {
            return Err(last_error());
        }
        Ok(take(out))
    }

    /// The current user's Root store, closed on drop.
    struct Root(HCERTSTORE);
    impl Root {
        fn open() -> Result<Self, String> {
            let name: Vec<u16> = "Root\0".encode_utf16().collect();
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
                return Err(format!("[ca] cannot open the Root store: {}", last_error()));
            }
            Ok(Self(store))
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            unsafe { CertCloseStore(self.0, 0) };
        }
    }

    /// Adds the certificate; Windows asks the user to confirm. An existing copy is kept.
    pub fn trust(cert: &[u8]) -> Result<(), String> {
        let root = Root::open()?;
        let ok = unsafe {
            CertAddEncodedCertificateToStore(
                root.0,
                X509_ASN_ENCODING,
                cert.as_ptr(),
                cert.len() as u32,
                CERT_STORE_ADD_USE_EXISTING,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(format!(
                "[ca] cannot add the CA to the Root store: {}",
                last_error()
            ));
        }
        Ok(())
    }

    /// Deletes every certificate whose subject contains the CA name; returns how many.
    pub fn distrust() -> Result<usize, String> {
        let root = Root::open()?;
        let name: Vec<u16> = super::CA_NAME.encode_utf16().chain([0]).collect();
        let mut removed = 0;
        loop {
            // Restart from the top each time: a deleted context cannot serve as the previous one.
            let cert = unsafe {
                CertFindCertificateInStore(
                    root.0,
                    X509_ASN_ENCODING,
                    0,
                    CERT_FIND_SUBJECT_STR_W,
                    name.as_ptr().cast(),
                    null(),
                )
            };
            if cert.is_null() {
                return Ok(removed);
            }
            // Frees the context, also on failure.
            if unsafe { CertDeleteCertificateFromStore(cert) } == 0 {
                return Err(format!(
                    "[ca] cannot remove the CA from the Root store: {}",
                    last_error()
                ));
            }
            removed += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pki_types::{CertificateDer, ServerName, UnixTime};

    fn verify(ca: &Ca, leaf: &Leaf, host: &str) -> Result<(), webpki::Error> {
        let ca_der = CertificateDer::from(ca.cert());
        let anchors = [webpki::anchor_from_trusted_cert(&ca_der)?];
        let leaf_der = CertificateDer::from(leaf.cert.as_slice());
        let cert = webpki::EndEntityCert::try_from(&leaf_der)?;
        cert.verify_for_usage(
            &[webpki::ring::ECDSA_P256_SHA256],
            &anchors,
            &[],
            UnixTime::now(),
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )?;
        cert.verify_is_valid_for_subject_name(&ServerName::try_from(host).unwrap())
    }

    #[test]
    fn leaves_verify_for_their_host_only() {
        let ca = Ca::generate().unwrap();
        for host in ["api.example.com", "127.0.0.1", "::1"] {
            verify(&ca, &ca.leaf(host).unwrap(), host).unwrap();
        }
        let leaf = ca.leaf("api.example.com").unwrap();
        assert!(verify(&ca, &leaf, "other.example.com").is_err());
        assert!(verify(&Ca::generate().unwrap(), &leaf, "api.example.com").is_err());
    }

    #[test]
    fn generated_ca_is_a_ca() {
        // webpki does not check a trust anchor's CA flag, so look for the encoded extensions instead.
        let contains = |der: &[u8], part: &[u8]| der.windows(part.len()).any(|w| w == part);
        // basicConstraints (2.5.29.19), critical, cA TRUE, pathLen 0.
        let ca_basic = [
            0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01,
            0xff, 0x02, 0x01, 0x00,
        ];
        let ca = Ca::generate().unwrap();
        assert!(contains(ca.cert(), &ca_basic));
        let leaf = ca.leaf("example.com").unwrap();
        assert!(!contains(&leaf.cert, &ca_basic[..5]) || !contains(&leaf.cert, &ca_basic[10..]));
    }

    #[test]
    fn rebuilt_issuer_signs_verifying_leaves() {
        let ca = Ca::generate().unwrap();
        let key = KeyPair::try_from(ca.issuer.key().serialize_der()).unwrap();
        let reloaded = Ca::from_parts(ca.cert().to_vec(), key).unwrap();
        verify(&ca, &reloaded.leaf("example.com").unwrap(), "example.com").unwrap();
    }

    #[test]
    fn mismatched_files_are_rejected() {
        let ca = Ca::generate().unwrap();
        let err = Ca::from_parts(ca.cert().to_vec(), KeyPair::generate().unwrap())
            .err()
            .unwrap();
        assert!(err.contains("does not match"), "{err}");
    }

    #[test]
    fn leaf_cache_reuses_and_is_bounded() {
        let ca = Ca::generate().unwrap();
        let a = ca.leaf("a.example.com").unwrap();
        assert!(Arc::ptr_eq(&a, &ca.leaf("a.example.com").unwrap()));
        for i in 0..LEAF_CACHE + 10 {
            ca.leaf(&format!("h{i}.example.com")).unwrap();
            assert!(ca.leaves.lock().unwrap().len() <= LEAF_CACHE);
        }
    }

    #[test]
    fn invalid_host_is_an_error() {
        let ca = Ca::generate().unwrap();
        assert!(ca.leaf("bad\u{e9}.example.com").is_err());
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("gatewizz-ca-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn loading_a_missing_store_names_the_file() {
        let err = Ca::load(&temp_dir("missing")).err().unwrap();
        assert!(err.contains("ca.cer"), "{err}");
    }

    #[cfg(windows)]
    #[test]
    fn key_round_trips_through_dpapi() {
        let dir = temp_dir("roundtrip");
        let ca = Ca::generate().unwrap();
        ca.save(&dir).unwrap();
        let stored = std::fs::read(dir.join("ca.key")).unwrap();
        let plain = ca.issuer.key().serialized_der();
        assert!(!stored.windows(plain.len()).any(|w| w == plain));
        let loaded = Ca::load(&dir).unwrap();
        assert_eq!(loaded.cert(), ca.cert());
        verify(&ca, &loaded.leaf("example.com").unwrap(), "example.com").unwrap();

        std::fs::write(dir.join("ca.key"), b"corrupt").unwrap();
        let err = Ca::load(&dir).err().unwrap();
        assert!(err.contains("ca.key"), "{err}");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
