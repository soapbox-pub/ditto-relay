//! The ACME account and certificates, kept on disk.
//!
//! Each CA gets a directory of its own, named for its directory URL's host,
//! since an account belongs to one CA, and switching between Let's Encrypt
//! and its staging CA shouldn't serve one's certificate under the other:
//!
//! ```text
//! acme-v02.api.letsencrypt.org/account.json
//! acme-v02.api.letsencrypt.org/<domain>.pem       chain, then key
//! acme-v02.api.letsencrypt.org/<domain>.http-01   if HTTP-01 worked last
//! ```
//!
//! Both hold private keys, so they're readable by the relay's user alone.

use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, anyhow, bail};
use instant_acme::AccountCredentials;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;

pub struct Store {
    dir: PathBuf,
}

/// A certificate and its key, ready to serve.
pub struct Certificate {
    pub key: Arc<CertifiedKey>,
    /// Its validity period, in Unix seconds.
    pub not_before: i64,
    pub not_after: i64,
}

impl Store {
    /// The store in `root` for the CA at `directory`. Nothing is written
    /// until there's something to keep.
    pub fn new(root: &Path, directory: &str) -> anyhow::Result<Store> {
        let url = url::Url::parse(directory)
            .with_context(|| format!("not a valid ACME directory URL: {directory}"))?;
        let host = url
            .host_str()
            .ok_or_else(|| anyhow!("the ACME directory URL has no host: {directory}"))?;
        let name = match url.port() {
            Some(port) => format!("{host}_{port}"),
            None => host.to_string(),
        };
        Ok(Store {
            dir: root.join(name),
        })
    }

    fn account_path(&self) -> PathBuf {
        self.dir.join("account.json")
    }

    fn certificate_path(&self, domain: &str) -> PathBuf {
        self.dir.join(format!("{domain}.pem"))
    }

    fn http01_path(&self, domain: &str) -> PathBuf {
        self.dir.join(format!("{domain}.http-01"))
    }

    /// Whether `domain`'s last certificate was validated over HTTP-01.
    pub fn http01_worked(&self, domain: &str) -> bool {
        self.http01_path(domain).exists()
    }

    pub fn remember_http01(&self, domain: &str, worked: bool) -> anyhow::Result<()> {
        let path = self.http01_path(domain);
        let result = match worked {
            true => write_private(&path, b""),
            false => match std::fs::remove_file(&path) {
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error),
                _ => Ok(()),
            },
        };
        result
            .with_context(|| format!("couldn't note which challenge worked in {}", path.display()))
    }

    pub fn load_account(&self) -> anyhow::Result<Option<AccountCredentials>> {
        let path = self.account_path();
        let Some(text) = read_if_exists(&path)? else {
            return Ok(None);
        };
        let credentials = serde_json::from_slice(&text)
            .with_context(|| format!("{} is not an ACME account", path.display()))?;
        Ok(Some(credentials))
    }

    pub fn save_account(&self, credentials: &AccountCredentials) -> anyhow::Result<()> {
        let path = self.account_path();
        write_private(&path, &serde_json::to_vec_pretty(credentials)?)
            .with_context(|| format!("couldn't write {}", path.display()))
    }

    pub fn load_certificate(&self, domain: &str) -> anyhow::Result<Option<Certificate>> {
        let path = self.certificate_path(domain);
        let Some(pem) = read_if_exists(&path)? else {
            return Ok(None);
        };
        let certificate = Certificate::from_pem(&pem)
            .with_context(|| format!("{} is not a usable certificate", path.display()))?;
        Ok(Some(certificate))
    }

    /// Keep `chain` and `key`, both PEM, for `domain`, and return them ready
    /// to serve.
    pub fn save_certificate(
        &self,
        domain: &str,
        chain: &str,
        key: &str,
    ) -> anyhow::Result<Certificate> {
        let pem = format!("{}\n{}", chain.trim_end(), key);
        let certificate = Certificate::from_pem(pem.as_bytes())
            .context("the CA issued an unusable certificate")?;
        let path = self.certificate_path(domain);
        write_private(&path, pem.as_bytes())
            .with_context(|| format!("couldn't write {}", path.display()))?;
        Ok(certificate)
    }
}

impl Certificate {
    pub fn from_pem(pem: &[u8]) -> anyhow::Result<Certificate> {
        let chain = CertificateDer::pem_slice_iter(pem)
            .collect::<Result<Vec<_>, _>>()
            .context("its certificates can't be read")?;
        let Some(leaf) = chain.first() else {
            bail!("it holds no certificate")
        };
        let key = PrivateKeyDer::from_pem_slice(pem).context("its private key can't be read")?;
        let (_, parsed) = x509_parser::parse_x509_certificate(leaf)
            .map_err(|error| anyhow!("its certificate can't be parsed: {error}"))?;
        let validity = parsed.validity();
        let (not_before, not_after) = (
            validity.not_before.timestamp(),
            validity.not_after.timestamp(),
        );
        let signer = rustls::crypto::ring::sign::any_supported_type(&key)
            .context("its private key isn't a supported type")?;
        let key = CertifiedKey::new(chain, signer);
        key.keys_match()
            .context("its private key doesn't match its certificate")?;
        Ok(Certificate {
            key: Arc::new(key),
            not_before,
            not_after,
        })
    }

    /// When to renew it: with a third of its lifetime left, which is a month
    /// for a 90-day certificate and two days for a six-day one.
    pub fn renew_at(&self) -> i64 {
        self.not_after - (self.not_after - self.not_before).max(0) / 3
    }

    /// How many whole days it has left.
    pub fn days_left(&self) -> i64 {
        (self.not_after - now()).max(0) / 86_400
    }
}

pub fn now() -> i64 {
    crate::event::now().into()
}

fn read_if_exists(path: &Path) -> anyhow::Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("couldn't read {}", path.display())),
    }
}

/// Write `bytes` to `path`, readable by its owner alone, in a directory only
/// they may enter if it has to be made, replacing whatever was there in one
/// step, so a crash never leaves half a key.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    let temporary = path.with_extension("tmp");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&temporary, path)
}
