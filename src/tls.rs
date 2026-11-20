//! TLS interception of CONNECT tunnels (#19): the client's TLS is terminated with a leaf from the local CA, and each
//! decrypted request goes upstream over a TLS connection of gatewizz's own, verified against the OS store.

use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector, client, server};

use crate::ca::Ca;

/// Both sides speak HTTP/1.1 only; h2 is out of scope (PLAN.md).
const ALPN: &[u8] = b"http/1.1";

pub struct Interceptor {
    ca: Ca,
    provider: Arc<CryptoProvider>,
    upstream: TlsConnector,
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

impl Interceptor {
    /// Upstream certificates are verified by the platform (on Windows, the certificate store). There is no switch to
    /// skip verification.
    pub fn new(ca: Ca) -> Result<Self, String> {
        let provider = provider();
        let verifier = rustls_platform_verifier::Verifier::new(provider.clone())
            .map_err(|e| format!("[tls] cannot load the platform verifier: {e}"))?;
        // `dangerous()` is only rustls's name for plugging in a verifier; the platform verifier verifies fully.
        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("[tls] {e}"))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        Ok(Self::with_upstream(ca, config))
    }

    /// With a given upstream client config; tests pass one that trusts a test CA.
    pub fn with_upstream(ca: Ca, mut upstream: ClientConfig) -> Self {
        upstream.alpn_protocols = vec![ALPN.to_vec()];
        Self {
            ca,
            provider: provider(),
            upstream: TlsConnector::from(Arc::new(upstream)),
        }
    }

    /// Terminates the client's TLS with a leaf for `host`, the CONNECT target.
    pub async fn accept<IO>(
        &self,
        host: &str,
        io: IO,
    ) -> Result<server::TlsStream<IO>, &'static str>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let leaf = self
            .ca
            .leaf(host)
            .map_err(|_| "cannot issue a certificate for the host")?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf.key.clone()));
        let mut config = ServerConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()
            .and_then(|b| {
                b.with_no_client_auth()
                    .with_single_cert(vec![CertificateDer::from(leaf.cert.clone())], key)
            })
            .map_err(|_| "cannot build the TLS server config")?;
        config.alpn_protocols = vec![ALPN.to_vec()];
        TlsAcceptor::from(Arc::new(config))
            .accept(io)
            .await
            .map_err(|_| "client TLS handshake failed")
    }

    /// Opens gatewizz's own TLS connection to the upstream; fails before any request byte is sent.
    pub async fn connect(
        &self,
        host: &str,
        tcp: TcpStream,
    ) -> Result<client::TlsStream<TcpStream>, &'static str> {
        let name = ServerName::try_from(host.to_string()).map_err(|_| "invalid upstream name")?;
        self.upstream
            .connect(name, tcp)
            .await
            .map_err(|err| upstream_failure(&err))
    }
}

fn upstream_failure(err: &std::io::Error) -> &'static str {
    match err
        .get_ref()
        .and_then(|e| e.downcast_ref::<rustls::Error>())
    {
        Some(rustls::Error::InvalidCertificate(_)) => "upstream certificate rejected",
        _ => "upstream TLS handshake failed",
    }
}

/// An exact host name, or `*.suffix` for any name below the suffix (not the suffix itself). Case-insensitive.
pub fn host_matches(pattern: &str, host: &str) -> bool {
    let (pattern, host) = (pattern.to_ascii_lowercase(), host.to_ascii_lowercase());
    match pattern.strip_prefix("*.") {
        Some(suffix) => host
            .strip_suffix(suffix)
            .is_some_and(|rest| rest.len() > 1 && rest.ends_with('.')),
        None => pattern == host,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_exact_and_wildcard_hosts() {
        assert!(host_matches("api.example.com", "API.example.com"));
        assert!(!host_matches("api.example.com", "x.api.example.com"));
        assert!(host_matches("*.example.com", "api.example.com"));
        assert!(host_matches("*.example.com", "a.b.example.com"));
        assert!(!host_matches("*.example.com", "example.com"));
        assert!(!host_matches("*.example.com", "badexample.com"));
        assert!(host_matches("127.0.0.1", "127.0.0.1"));
    }
}
