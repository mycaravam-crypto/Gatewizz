//! The local CA that TLS interception signs leaf certificates with.
//!
//! Generation and leaf issuance are pure and tested on every OS. The CA lives in `%LOCALAPPDATA%\gatewizz\` as
//! `ca.cer` (the public certificate, DER) and `ca.key` (PKCS#8, encrypted with DPAPI for the current user), so the
//! key is never on disk in the clear. Trusting the CA is `gatewizz ca install` (see `castore.rs`).

// Leaf issuance and the cache are used by TLS interception, the next M2 issue; until then only the tests reach them.
#![cfg_attr(not(test), allow(dead_code))]

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SanType,
};

use crate::castore;

/// The CA's common name. `ca remove` deletes every certificate with exactly this name from the Root store.
pub const CA_NAME: &str = "gatewizz local CA";
const CA_ORG: &str = "gatewizz";

/// Five years: long enough not to bother anyone, short enough that a forgotten CA ends.
const CA_VALIDITY: Duration = Duration::from_secs(5 * 365 * 24 * 3600);
const LEAF_VALIDITY: Duration = Duration::from_secs(7 * 24 * 3600);
/// A cached leaf with less than this left is issued again.
const LEAF_RENEW: Duration = Duration::from_secs(24 * 3600);
/// Backdating absorbs a client clock that runs a little behind.
const BACKDATE: Duration = Duration::from_secs(3600);
/// Hosts with a cached leaf; a few tools talk to far fewer model hosts.
const LEAF_CACHE: usize = 256;

pub const CERT_FILE: &str = "ca.cer";
pub const KEY_FILE: &str = "ca.key";

/// A CA that can sign leaves.
pub struct Ca {
    cert: Vec<u8>,
    issuer: Issuer<'static, KeyPair>,
    leaves: Leaves,
}

/// A leaf certificate for one host and its own private key.
pub struct Leaf {
    pub cert: Vec<u8>,
    /// PKCS#8 DER.
    pub key: Vec<u8>,
    pub not_after: SystemTime,
}

/// The CA's parameters. They are rebuilt when the CA is loaded: a leaf names the issuer by this subject and by the
/// key identifier, which is derived from the key, so the rebuilt issuer signs leaves that chain to `ca.cer`.
fn ca_params(now: SystemTime) -> CertificateParams {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, CA_NAME);
    dn.push(DnType::OrganizationName, CA_ORG);
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = (now - BACKDATE).into();
    params.not_after = (now + CA_VALIDITY).into();
    params
}

impl Ca {
    /// A new CA with a fresh P-256 key.
    pub fn generate(now: SystemTime) -> Result<Ca, String> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| format!("cannot generate CA key: {e}"))?;
        let params = ca_params(now);
        let cert = params
            .self_signed(&key)
            .map_err(|e| format!("cannot create CA certificate: {e}"))?;
        Ok(Ca {
            cert: cert.der().to_vec(),
            issuer: Issuer::new(params, key),
            leaves: Leaves::new(LEAF_CACHE),
        })
    }

    /// The CA from its certificate and PKCS#8 key. Errors name the file at fault.
    fn from_parts(cert: Vec<u8>, key_pkcs8: &[u8]) -> Result<Ca, String> {
        let key = KeyPair::try_from(key_pkcs8)
            .map_err(|e| format!("{KEY_FILE}: not a usable key: {e}"))?;
        if key.algorithm() != &PKCS_ECDSA_P256_SHA256 {
            return Err(format!("{KEY_FILE}: not a P-256 key"));
        }
        // ponytail: a byte search for the public key instead of parsing ca.cer; it catches a swapped or corrupted
        // file, not a hand-crafted one. Parse with x509-parser if a crafted ca.cer ever matters.
        let public = key.public_key_raw();
        if !cert.windows(public.len()).any(|w| w == public) {
            return Err(format!(
                "{CERT_FILE}: does not hold the certificate for {KEY_FILE}"
            ));
        }
        // Only the subject and key identifier reach the leaves, so the validity here does not matter.
        Ok(Ca {
            cert,
            issuer: Issuer::new(ca_params(SystemTime::now()), key),
            leaves: Leaves::new(LEAF_CACHE),
        })
    }

    /// The leaf for `host` from this CA's cache, issued if missing or close to expiry.
    pub fn leaf(&self, host: &str) -> Result<Arc<Leaf>, String> {
        self.leaves.get(self, host, SystemTime::now())
    }

    /// The public certificate, DER.
    pub fn cert_der(&self) -> &[u8] {
        &self.cert
    }

    /// A leaf for a DNS name or an IP address, with a fresh P-256 key.
    pub fn issue(&self, host: &str, now: SystemTime) -> Result<Leaf, String> {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let san = match host.parse::<IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName(
                host.try_into()
                    .map_err(|e| format!("{host:?}: not a host name: {e}"))?,
            ),
        };
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| format!("cannot generate leaf key: {e}"))?;
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.subject_alt_names = vec![san];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.use_authority_key_identifier_extension = true;
        let not_after = now + LEAF_VALIDITY;
        params.not_before = (now - BACKDATE).into();
        params.not_after = not_after.into();
        let cert = params
            .signed_by(&key, &self.issuer)
            .map_err(|e| format!("cannot sign leaf for {host}: {e}"))?;
        Ok(Leaf {
            cert: cert.der().to_vec(),
            key: key.serialize_der(),
            not_after,
        })
    }

    /// Loads `ca.cer` and `ca.key` from `dir`. Errors name the file.
    pub fn load(dir: &Path) -> Result<Ca, String> {
        let read = |name: &str| {
            let path = dir.join(name);
            std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))
        };
        let cert = read(CERT_FILE)?;
        let key = castore::unprotect(&read(KEY_FILE)?)
            .map_err(|e| format!("{}: cannot decrypt: {e}", dir.join(KEY_FILE).display()))?;
        Ca::from_parts(cert, &key).map_err(|e| format!("{}: {e}", dir.display()))
    }

    /// Writes `ca.key` (encrypted) and `ca.cer` to `dir`, creating it. Never overwrites an existing file.
    pub fn save(&self, dir: &Path) -> Result<(), String> {
        let key = castore::protect(self.issuer.key().serialized_der())?;
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        for (name, bytes) in [(KEY_FILE, &key), (CERT_FILE, &self.cert)] {
            let path = dir.join(name);
            let write = || -> std::io::Result<()> {
                use std::io::Write;
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)?;
                file.write_all(bytes)?;
                file.sync_all()
            };
            write().map_err(|e| format!("{}: {e}", path.display()))?;
        }
        Ok(())
    }
}

/// `%LOCALAPPDATA%\gatewizz`, where the CA and the events live.
pub fn default_dir() -> Result<PathBuf, String> {
    std::env::var_os("LOCALAPPDATA")
        .map(|dir| Path::new(&dir).join("gatewizz"))
        .ok_or_else(|| "LOCALAPPDATA is not set".into())
}

/// Leaves cached per host, at most `max`, each re-issued when close to expiry.
pub struct Leaves {
    max: usize,
    map: Mutex<HashMap<String, Arc<Leaf>>>,
}

impl Leaves {
    pub fn new(max: usize) -> Leaves {
        Leaves {
            max: max.max(1),
            map: Mutex::new(HashMap::new()),
        }
    }

    /// The cached leaf for `host`, or a new one. A full cache drops the leaf that expires first.
    pub fn get(&self, ca: &Ca, host: &str, now: SystemTime) -> Result<Arc<Leaf>, String> {
        let host = host.to_ascii_lowercase();
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(leaf) = map.get(&host)
            && leaf.not_after > now + LEAF_RENEW
        {
            return Ok(leaf.clone());
        }
        // ponytail: issuing under the lock serialises new hosts (about a millisecond each); fine for a few tools.
        let leaf = Arc::new(ca.issue(&host, now)?);
        if !map.contains_key(&host)
            && map.len() >= self.max
            && let Some(oldest) = map
                .iter()
                .min_by_key(|(_, l)| l.not_after)
                .map(|(h, _)| h.clone())
        {
            map.remove(&oldest);
        }
        map.insert(host, leaf.clone());
        Ok(leaf)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.map.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
    use webpki::{EndEntityCert, KeyUsage, anchor_from_trusted_cert};

    fn verify(ca: &[u8], leaf: &[u8], host: &str, now: SystemTime) -> Result<(), webpki::Error> {
        let ca = CertificateDer::from(ca);
        let anchors = [anchor_from_trusted_cert(&ca)?];
        let leaf = CertificateDer::from(leaf);
        let ee = EndEntityCert::try_from(&leaf)?;
        let time = UnixTime::since_unix_epoch(now.duration_since(SystemTime::UNIX_EPOCH).unwrap());
        ee.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &anchors,
            &[],
            time,
            KeyUsage::server_auth(),
            None,
            None,
        )?;
        ee.verify_is_valid_for_subject_name(&ServerName::try_from(host).unwrap())
    }

    #[test]
    fn generated_ca_is_a_ca() {
        let ca = Ca::generate(SystemTime::now()).unwrap();
        // It signs leaves that verify, and it carries its name and the CA basic constraints.
        let leaf = ca.issue("example.com", SystemTime::now()).unwrap();
        verify(ca.cert_der(), &leaf.cert, "example.com", SystemTime::now()).unwrap();
        let der = ca.cert_der();
        assert!(der.windows(CA_NAME.len()).any(|w| w == CA_NAME.as_bytes()));
        // basicConstraints: cA TRUE, pathLenConstraint 0.
        assert!(
            der.windows(8)
                .any(|w| w == [0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00])
        );
    }

    #[test]
    fn leaves_verify_for_their_host_only() {
        let now = SystemTime::now();
        let ca = Ca::generate(now).unwrap();
        for host in ["api.example.com", "127.0.0.1", "::1"] {
            let leaf = ca.issue(host, now).unwrap();
            verify(ca.cert_der(), &leaf.cert, host, now).unwrap();
            let key = KeyPair::try_from(leaf.key.as_slice()).unwrap();
            let public = key.public_key_raw();
            assert!(
                leaf.cert.windows(public.len()).any(|w| w == public),
                "{host}: leaf key"
            );
            assert!(
                verify(ca.cert_der(), &leaf.cert, "other.example.com", now).is_err(),
                "{host}"
            );
            assert!(
                verify(ca.cert_der(), &leaf.cert, "10.0.0.1", now).is_err(),
                "{host}"
            );
        }
        let leaf = ca.issue("[::1]", now).unwrap();
        verify(ca.cert_der(), &leaf.cert, "::1", now).unwrap();
    }

    #[test]
    fn leaf_expires_and_another_ca_does_not_verify() {
        let now = SystemTime::now();
        let ca = Ca::generate(now).unwrap();
        let leaf = ca.issue("example.com", now).unwrap();
        assert!(
            verify(
                ca.cert_der(),
                &leaf.cert,
                "example.com",
                now + LEAF_VALIDITY + BACKDATE
            )
            .is_err()
        );
        let other = Ca::generate(now).unwrap();
        assert!(verify(other.cert_der(), &leaf.cert, "example.com", now).is_err());
    }

    #[test]
    fn rejects_a_bad_host() {
        let ca = Ca::generate(SystemTime::now()).unwrap();
        assert!(ca.issue("bad\u{e9}.example", SystemTime::now()).is_err());
    }

    #[test]
    fn reloaded_ca_signs_leaves_that_chain_to_the_stored_cert() {
        let now = SystemTime::now();
        let ca = Ca::generate(now).unwrap();
        let reloaded =
            Ca::from_parts(ca.cert_der().to_vec(), ca.issuer.key().serialized_der()).unwrap();
        let leaf = reloaded.issue("example.com", now).unwrap();
        verify(ca.cert_der(), &leaf.cert, "example.com", now).unwrap();
    }

    #[test]
    fn mismatched_or_corrupted_parts_name_the_file() {
        let (a, b) = (
            Ca::generate(SystemTime::now()).unwrap(),
            Ca::generate(SystemTime::now()).unwrap(),
        );
        let err = Ca::from_parts(a.cert_der().to_vec(), b.issuer.key().serialized_der())
            .err()
            .unwrap();
        assert!(err.starts_with(CERT_FILE), "{err}");
        let err = Ca::from_parts(a.cert_der().to_vec(), b"garbage")
            .err()
            .unwrap();
        assert!(err.starts_with(KEY_FILE), "{err}");
    }

    #[test]
    fn cache_is_bounded_and_reuses_leaves() {
        let now = SystemTime::now();
        let ca = Ca::generate(now).unwrap();
        let cache = Leaves::new(2);
        let first = cache.get(&ca, "a.example", now).unwrap();
        assert!(Arc::ptr_eq(
            &first,
            &cache.get(&ca, "A.example", now).unwrap()
        ));
        let second = Duration::from_secs(1);
        let b = cache.get(&ca, "b.example", now + second).unwrap();
        cache.get(&ca, "c.example", now + 2 * second).unwrap();
        assert_eq!(cache.len(), 2);
        // a.example expired first, so it was dropped and comes back new; b.example is still cached.
        assert!(Arc::ptr_eq(&b, &cache.get(&ca, "b.example", now).unwrap()));
        assert!(!Arc::ptr_eq(
            &first,
            &cache.get(&ca, "a.example", now).unwrap()
        ));
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn ca_leaf_uses_its_own_cache() {
        let ca = Ca::generate(SystemTime::now()).unwrap();
        let leaf = ca.leaf("api.example.com").unwrap();
        assert!(Arc::ptr_eq(&leaf, &ca.leaf("API.example.com").unwrap()));
        verify(
            ca.cert_der(),
            &leaf.cert,
            "api.example.com",
            SystemTime::now(),
        )
        .unwrap();
    }

    #[test]
    fn cache_renews_a_leaf_close_to_expiry() {
        let now = SystemTime::now();
        let ca = Ca::generate(now).unwrap();
        let cache = Leaves::new(8);
        let first = cache.get(&ca, "a.example", now).unwrap();
        let later = now + LEAF_VALIDITY - LEAF_RENEW;
        let renewed = cache.get(&ca, "a.example", later).unwrap();
        assert!(!Arc::ptr_eq(&first, &renewed));
        verify(
            ca.cert_der(),
            &renewed.cert,
            "a.example",
            later + LEAF_RENEW,
        )
        .unwrap();
    }

    #[cfg(not(windows))]
    #[test]
    fn storage_is_windows_only() {
        let ca = Ca::generate(SystemTime::now()).unwrap();
        let dir = std::env::temp_dir().join(format!("gatewizz-ca-none-{}", std::process::id()));
        assert!(ca.save(&dir).is_err());
        assert!(!dir.exists());
    }

    #[cfg(windows)]
    mod windows {
        use super::*;

        fn temp(name: &str) -> PathBuf {
            let dir =
                std::env::temp_dir().join(format!("gatewizz-ca-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            dir
        }

        #[test]
        fn key_round_trips_through_dpapi_and_is_not_on_disk_in_the_clear() {
            let dir = temp("roundtrip");
            let ca = Ca::generate(SystemTime::now()).unwrap();
            ca.save(&dir).unwrap();
            let plain = ca.issuer.key().serialized_der();
            let stored = std::fs::read(dir.join(KEY_FILE)).unwrap();
            assert!(!stored.windows(plain.len()).any(|w| w == plain));
            let loaded = Ca::load(&dir).unwrap();
            assert_eq!(loaded.issuer.key().serialized_der(), plain);
            assert_eq!(loaded.cert_der(), ca.cert_der());
            assert!(ca.save(&dir).is_err(), "save never overwrites");
            std::fs::remove_dir_all(dir).unwrap();
        }

        #[test]
        fn missing_or_corrupted_files_are_named() {
            let dir = temp("broken");
            let err = Ca::load(&dir).err().unwrap();
            assert!(err.contains(CERT_FILE), "{err}");
            Ca::generate(SystemTime::now()).unwrap().save(&dir).unwrap();
            std::fs::write(dir.join(KEY_FILE), b"corrupted").unwrap();
            let err = Ca::load(&dir).err().unwrap();
            assert!(err.contains(KEY_FILE), "{err}");
            std::fs::remove_file(dir.join(KEY_FILE)).unwrap();
            let err = Ca::load(&dir).err().unwrap();
            assert!(err.contains(KEY_FILE), "{err}");
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
}
