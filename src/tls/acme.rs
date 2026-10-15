//! Getting and renewing the certificate over ACME (RFC 8555).
//!
//! A certificate is asked for when there's none, and again once a third of
//! its lifetime is left. Each attempt tries TLS-ALPN-01 first, answered on
//! the HTTPS port, then HTTP-01 if port 80 is being listened on, or HTTP-01
//! first if that's what worked last, as behind Cloudflare's proxy. A failed
//! attempt is retried after a minute, then two, and so on up to an hour:
//! Let's Encrypt allows only a few failed validations an hour, and a
//! misconfigured DNS record doesn't fix itself any faster.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, Order,
    OrderStatus, RetryPolicy,
};
use rcgen::{CertificateParams, CustomExtension, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use tokio_util::sync::CancellationToken;

use super::State;
use super::store::{Certificate, Store, now};

/// The longest between checks on the certificate, so a clock that jumps
/// or a machine that sleeps can't carry it past its renewal.
const CHECK_INTERVAL: Duration = Duration::from_secs(12 * 60 * 60);
const FIRST_RETRY: Duration = Duration::from_secs(60);
const LAST_RETRY: Duration = Duration::from_secs(60 * 60);
/// How long the CA has to validate a challenge, and then to issue.
const ORDER_TIMEOUT: Duration = Duration::from_secs(120);

pub struct Acme {
    pub domain: String,
    pub directory: String,
    pub email: Option<String>,
    /// Whether HTTP-01 challenges can be answered, on port 80.
    pub http01: bool,
    /// A CA certificate to trust the directory by instead of the system's,
    /// for a test CA.
    pub root: Option<PathBuf>,
    pub store: Store,
    pub state: Arc<State>,
}

impl Acme {
    pub async fn run(self, cancel: CancellationToken) {
        let mut retry = FIRST_RETRY;
        loop {
            let due = match self.store.load_certificate(&self.domain) {
                Ok(Some(certificate)) => Some(certificate.renew_at()),
                Ok(None) => None,
                Err(error) => {
                    tracing::warn!("{error:#}; getting a new one");
                    None
                }
            };
            let wait = match due {
                Some(at) if at > now() => {
                    Duration::from_secs((at - now()) as u64).min(CHECK_INTERVAL)
                }
                _ => {
                    let issued = tokio::select! {
                        issued = self.issue() => issued,
                        () = cancel.cancelled() => return,
                    };
                    match issued {
                        Ok(certificate) => {
                            tracing::info!(
                                "got a TLS certificate for {}, which expires in {} days",
                                self.domain,
                                certificate.days_left()
                            );
                            self.state.certificate.store(Some(certificate.key));
                            retry = FIRST_RETRY;
                            continue;
                        }
                        Err(error) => {
                            tracing::error!(
                                "couldn't get a TLS certificate for {}, trying again in {}s: {error:#}",
                                self.domain,
                                retry.as_secs()
                            );
                            let wait = retry;
                            retry = (retry * 2).min(LAST_RETRY);
                            wait
                        }
                    }
                }
            };
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                () = cancel.cancelled() => return,
            }
        }
    }

    /// Get a certificate from the CA, trying each challenge it can answer.
    async fn issue(&self) -> anyhow::Result<Certificate> {
        let account = self.account().await?;
        let http01_worked = self.store.http01_worked(&self.domain);
        let mut failure = None;
        for kind in challenges(self.http01, http01_worked) {
            match self.order(&account, &kind).await {
                Ok((chain, key)) => {
                    let certificate = self.store.save_certificate(&self.domain, &chain, &key)?;
                    let http01 = kind == ChallengeType::Http01;
                    if http01 != http01_worked
                        && let Err(error) = self.store.remember_http01(&self.domain, http01)
                    {
                        tracing::warn!("{error:#}");
                    }
                    return Ok(certificate);
                }
                Err(error) => {
                    tracing::warn!("{kind:?} validation of {} failed: {error:#}", self.domain);
                    failure = Some(error);
                }
            }
        }
        Err(failure.expect("TLS-ALPN-01 is always tried"))
    }

    pub(super) async fn account(&self) -> anyhow::Result<Account> {
        let builder = || match &self.root {
            Some(root) => Account::builder_with_root(root),
            None => Account::builder(),
        };
        if let Some(credentials) = self.store.load_account()? {
            return builder()?
                .from_credentials(credentials)
                .await
                .context("couldn't reach the ACME CA");
        }
        let contact = self.email.as_ref().map(|email| format!("mailto:{email}"));
        let contact: Vec<&str> = contact.iter().map(String::as_str).collect();
        let new = NewAccount {
            contact: &contact,
            terms_of_service_agreed: true,
            only_return_existing: false,
        };
        let (account, credentials) = builder()?
            .create(&new, self.directory.clone(), None)
            .await
            .context("couldn't create an ACME account")?;
        self.store.save_account(&credentials)?;
        tracing::info!("created an ACME account with {}", self.directory);
        Ok(account)
    }

    /// One order, validated by `kind`: the certificate chain and its key,
    /// both PEM.
    pub(super) async fn order(
        &self,
        account: &Account,
        kind: &ChallengeType,
    ) -> anyhow::Result<(String, String)> {
        let identifiers = [Identifier::Dns(self.domain.clone())];
        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .context("couldn't place an order")?;
        // However the order ends, the challenge stops being answered.
        let _cleanup = Cleanup(&self.state);

        let mut authorizations = order.authorizations();
        while let Some(authorization) = authorizations.next().await {
            let mut authorization = authorization?;
            match authorization.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                status => bail!("the CA has the authorization {status:?}"),
            }
            let mut challenge = authorization
                .challenge(kind.clone())
                .ok_or_else(|| anyhow!("the CA doesn't offer {kind:?}"))?;
            let key_authorization = challenge.key_authorization();
            match kind {
                ChallengeType::TlsAlpn01 => {
                    let certificate = alpn_challenge_certificate(
                        &self.domain,
                        key_authorization.digest().as_ref(),
                    )?;
                    self.state.alpn_challenge.store(Some(Arc::new(certificate)));
                }
                _ => {
                    self.state.http_challenges.lock().unwrap().insert(
                        challenge.token.clone(),
                        key_authorization.as_str().to_string(),
                    );
                }
            }
            challenge.set_ready().await?;
        }

        let retries = RetryPolicy::new()
            .initial_delay(Duration::from_secs(1))
            .timeout(ORDER_TIMEOUT);
        let status = order.poll_ready(&retries).await?;
        if status != OrderStatus::Ready {
            match challenge_problem(&mut order, kind).await {
                Some(problem) => bail!("the CA left the order {status:?}: {problem}"),
                None => bail!("the CA left the order {status:?}"),
            }
        }
        let key = order
            .finalize()
            .await
            .context("couldn't finalize the order")?;
        let chain = order
            .poll_certificate(&retries)
            .await
            .context("couldn't fetch the certificate")?;
        Ok((chain, key))
    }
}

/// The challenges to try, in order: TLS-ALPN-01, answered on the HTTPS port,
/// then HTTP-01 if port 80 is listened on. HTTP-01 goes first if it's what
/// worked last time: behind a proxy that ends TLS itself, as Cloudflare's
/// does, TLS-ALPN-01 can't reach the relay, and would spend one of the CA's
/// few failures an hour on every renewal.
fn challenges(http01: bool, http01_worked: bool) -> Vec<ChallengeType> {
    match (http01, http01_worked) {
        (false, _) => vec![ChallengeType::TlsAlpn01],
        (true, false) => vec![ChallengeType::TlsAlpn01, ChallengeType::Http01],
        (true, true) => vec![ChallengeType::Http01, ChallengeType::TlsAlpn01],
    }
}

/// What the CA says went wrong with the order's `kind` challenge, such as
/// "Timeout during connect (likely firewall problem)".
async fn challenge_problem(order: &mut Order, kind: &ChallengeType) -> Option<String> {
    let mut authorizations = order.authorizations();
    while let Some(Ok(mut authorization)) = authorizations.next().await {
        let state = authorization.refresh().await.ok()?;
        let problem = state
            .challenges
            .iter()
            .filter(|challenge| challenge.r#type == *kind)
            .find_map(|challenge| challenge.error.as_ref());
        if let Some(problem) = problem {
            return Some(
                problem
                    .detail
                    .clone()
                    .unwrap_or_else(|| problem.to_string()),
            );
        }
    }
    None
}

struct Cleanup<'a>(&'a State);

impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        self.0.alpn_challenge.store(None);
        self.0.http_challenges.lock().unwrap().clear();
    }
}

/// The self-signed certificate a TLS-ALPN-01 challenge is answered with:
/// for the domain, carrying the key authorization's digest (RFC 8737 §3).
pub fn alpn_challenge_certificate(domain: &str, digest: &[u8]) -> anyhow::Result<CertifiedKey> {
    let mut params = CertificateParams::new(vec![domain.to_string()])?;
    params.custom_extensions = vec![CustomExtension::new_acme_identifier(digest)];
    let key = KeyPair::generate()?;
    let certificate = params.self_signed(&key)?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let signer = rustls::crypto::ring::sign::any_supported_type(&key)?;
    Ok(CertifiedKey::new(vec![certificate.der().clone()], signer))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tries_first_what_worked_last() {
        use ChallengeType::{Http01, TlsAlpn01};
        assert_eq!(challenges(false, false), [TlsAlpn01]);
        assert_eq!(challenges(false, true), [TlsAlpn01]);
        assert_eq!(challenges(true, false), [TlsAlpn01, Http01]);
        assert_eq!(challenges(true, true), [Http01, TlsAlpn01]);
    }
}
