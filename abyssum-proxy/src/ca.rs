//! The local certificate authority used for TLS termination.
//!
//! To *observe* HTTPS content (the whole point — auth tokens and IDOR params live
//! in the body), the proxy TLS-terminates using a locally-generated CA that the
//! operator trusts on their test client. This is TLS termination for observation,
//! not interception: traffic is never held or altered.
//!
//! The CA key is persisted (so the operator trusts one CA across restarts), and a
//! leaf certificate is minted per destination host on demand and cached. The CA is
//! rebuilt from fixed parameters plus the persisted key on every start, so the
//! issuer identity is stable without needing to re-parse the stored certificate.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::error::{Error, Result};

/// The CA's distinguished name — fixed, so a CA rebuilt from the persisted key on
/// restart is identical to the one whose certificate the operator imported.
const CA_COMMON_NAME: &str = "Abyssum Observing Proxy CA";

/// Owns the CA key + certificate and mints/caches per-host leaf TLS configs.
pub struct CertAuthority {
    /// The CA key pair (reloaded from or written to disk).
    ca_key: KeyPair,
    /// Fixed CA parameters (rebuilt each start), used to construct the [`Issuer`].
    ca_params: CertificateParams,
    /// The CA certificate in PEM — written to disk for the operator to trust.
    ca_cert_pem: String,
    /// Per-host `rustls` server configs, minted on first use.
    cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl CertAuthority {
    /// Load the CA from `dir` (reusing `ca_key.pem` / `ca_cert.pem` if present, else
    /// generating and persisting them). The directory is created if absent.
    pub async fn load_or_create(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        tokio::fs::create_dir_all(&dir).await?;
        let key_path = dir.join("ca_key.pem");
        let cert_path = dir.join("ca_cert.pem");

        let ca_key = match tokio::fs::read_to_string(&key_path).await {
            Ok(pem) => KeyPair::from_pem(&pem).map_err(ca_err)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key = KeyPair::generate().map_err(ca_err)?;
                write_private(&key_path, &key.serialize_pem()).await?;
                key
            }
            Err(e) => return Err(e.into()),
        };

        let ca_params = ca_params()?;
        let ca_cert = ca_params.self_signed(&ca_key).map_err(ca_err)?;
        let ca_cert_pem = ca_cert.pem();
        // Persist the certificate for the operator to import into their test client.
        // (Rewritten each start; it is stable because the key and params are.)
        tokio::fs::write(&cert_path, ca_cert_pem.as_bytes()).await?;

        Ok(Self {
            ca_key,
            ca_params,
            ca_cert_pem,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// The CA certificate in PEM — hand this to the operator to trust.
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// The `rustls` server config presenting a leaf certificate for `host`, minting
    /// and caching it on first use. `host` is the destination host from the CONNECT
    /// request (no port).
    pub fn server_config_for(&self, host: &str) -> Result<Arc<ServerConfig>> {
        if let Some(existing) = self.cache.lock().unwrap().get(host).cloned() {
            return Ok(existing);
        }
        let config = Arc::new(self.mint_server_config(host)?);
        self.cache
            .lock()
            .unwrap()
            .insert(host.to_string(), config.clone());
        Ok(config)
    }

    /// Mint a fresh leaf certificate for `host`, signed by the CA, and wrap it in a
    /// single-cert `rustls` server config (ring provider, no client auth).
    fn mint_server_config(&self, host: &str) -> Result<ServerConfig> {
        let leaf_key = KeyPair::generate().map_err(ca_err)?;
        let mut params = CertificateParams::new(vec![host.to_string()]).map_err(ca_err)?;
        params
            .distinguished_name
            .push(DnType::CommonName, host.to_string());
        params.is_ca = IsCa::NoCa;
        params.use_authority_key_identifier_extension = true;
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);

        let issuer = Issuer::from_params(&self.ca_params, &self.ca_key);
        let leaf = params.signed_by(&leaf_key, &issuer).map_err(ca_err)?;

        let cert_der: CertificateDer<'static> = leaf.der().clone();
        let key_der: PrivateKeyDer<'static> =
            PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into();

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(ca_err)?
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .map_err(ca_err)?;
        Ok(config)
    }
}

/// The fixed CA parameters: a self-signed CA valid for certificate signing.
fn ca_params() -> Result<CertificateParams> {
    let mut params = CertificateParams::new(Vec::<String>::new()).map_err(ca_err)?;
    params
        .distinguished_name
        .push(DnType::CommonName, CA_COMMON_NAME);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    Ok(params)
}

/// Write a private-key file with owner-only permissions from the moment it is
/// created — never a window where the CA key (which can mint intercepting certs) is
/// world-readable. On Unix the file is opened `create_new` with mode `0o600`; other
/// platforms fall back to a plain write.
async fn write_private(path: &PathBuf, contents: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::io::AsyncWriteExt;
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .await?;
        file.write_all(contents.as_bytes()).await?;
        file.flush().await?;
    }
    #[cfg(not(unix))]
    {
        tokio::fs::write(path, contents.as_bytes()).await?;
    }
    Ok(())
}

/// Wrap an rcgen/rustls error as an [`Error::Tls`].
fn ca_err<E: std::fmt::Display>(e: E) -> Error {
    Error::Tls(e.to_string())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// The persisted CA key — which can mint intercepting certs — is owner-only from
    /// creation, never briefly world-readable.
    #[tokio::test]
    async fn ca_key_file_is_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        CertAuthority::load_or_create(dir.path()).await.unwrap();
        let mode = std::fs::metadata(dir.path().join("ca_key.pem"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "CA key file is owner-only");
    }
}
