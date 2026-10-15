//! HTTPS served by the relay itself, so nothing needs to sit in front of it.
//!
//! A certificate for `public_url`'s domain comes from an ACME CA, Let's
//! Encrypt by default, and is renewed in the background and swapped in
//! without a restart (see [`acme`]). The CA proves the relay holds the
//! domain by TLS-ALPN-01, answered on the HTTPS port itself, or failing that
//! by HTTP-01 on port 80, which otherwise redirects to HTTPS.
//!
//! The certificate and the ACME account are kept in `[tls] dir` (see
//! [`store`]), so a restart serves at once instead of asking again.

mod acme;
mod store;
#[cfg(test)]
pub(crate) mod tests;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwapOption;
use axum::Router;
use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tokio_util::sync::CancellationToken;

use crate::config;
pub use store::Certificate;
use store::Store;

/// The ALPN protocol a CA's TLS-ALPN-01 validation offers (RFC 8737).
const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";

/// How long a client has to finish its TLS handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

const CHALLENGE_PATH: &str = "/.well-known/acme-challenge/";

/// Everything the relay needs to serve HTTPS for its domain.
pub struct Tls {
    domain: String,
    state: Arc<State>,
    acme: acme::Acme,
}

/// What the HTTPS listener, the HTTP listener, and the ACME client share.
#[derive(Default)]
struct State {
    /// The certificate served, once there is one.
    certificate: ArcSwapOption<CertifiedKey>,
    /// The certificate a pending TLS-ALPN-01 challenge is answered with.
    alpn_challenge: ArcSwapOption<CertifiedKey>,
    /// Pending HTTP-01 challenges: token to key authorization.
    http_challenges: Mutex<HashMap<String, String>>,
}

impl Tls {
    /// TLS for the domain `config` names, with any certificate already kept
    /// loaded and ready to serve.
    pub fn open(config: &config::Tls) -> anyhow::Result<Tls> {
        let store = Store::new(&config.dir, &config.directory)?;
        let state = Arc::new(State::default());
        match store.load_certificate(&config.domain) {
            Ok(Some(certificate)) => {
                tracing::info!(
                    "loaded the TLS certificate for {}, which expires in {} days",
                    config.domain,
                    certificate.days_left()
                );
                state.certificate.store(Some(certificate.key));
            }
            Ok(None) => tracing::info!(
                "no TLS certificate for {} yet; asking {} for one",
                config.domain,
                config.directory
            ),
            // Its renewal will say so too, and replace it.
            Err(error) => tracing::warn!("{error:#}"),
        }
        let acme = acme::Acme {
            domain: config.domain.clone(),
            directory: config.directory.clone(),
            email: config.email.clone(),
            http01: config.http_bind.is_some(),
            root: None,
            store,
            state: state.clone(),
        };
        Ok(Tls {
            domain: config.domain.clone(),
            state,
            acme,
        })
    }

    /// Accept HTTPS connections on `listener`, with the certificate as it's
    /// renewed.
    pub fn listener(&self, listener: TcpListener) -> std::io::Result<TlsListener> {
        TlsListener::new(listener, server_config(self.state.clone()))
    }

    /// What serves plain HTTP: the CA's HTTP-01 challenges, and a redirect
    /// to HTTPS for everything else.
    pub fn redirect_router(&self) -> Router {
        redirect_router(self.domain.clone(), self.state.clone())
    }

    /// Get a certificate if there isn't a current one, and renew it as it
    /// nears expiry, until `cancel` fires.
    pub fn start(self, cancel: CancellationToken) -> JoinHandle<()> {
        // The ACME client's own TLS takes its cryptography from the process.
        let _ = rustls::crypto::ring::default_provider().install_default();
        tokio::spawn(self.acme.run(cancel))
    }
}

/// The certificate `config` would serve, if one has been got: what
/// `ditto-relay check` reports.
pub fn stored(config: &config::Tls) -> anyhow::Result<Option<Certificate>> {
    Store::new(&config.dir, &config.directory)?.load_certificate(&config.domain)
}

fn server_config(state: Arc<State>) -> Arc<rustls::ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions")
        .with_no_client_auth()
        .with_cert_resolver(state);
    // HTTP/1.1 alone, which WebSockets are upgraded from.
    config.alpn_protocols = vec![b"http/1.1".to_vec(), ACME_TLS_ALPN.to_vec()];
    Arc::new(config)
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("State")
            .field("certificate", &self.certificate.load().is_some())
            .finish_non_exhaustive()
    }
}

impl ResolvesServerCert for State {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // Only a CA validating a challenge offers acme-tls/1, and it offers
        // nothing else (RFC 8737 §3).
        let validating = hello
            .alpn()
            .is_some_and(|mut protocols| protocols.any(|protocol| protocol == ACME_TLS_ALPN));
        match validating {
            true => self.alpn_challenge.load_full(),
            false => self.certificate.load_full(),
        }
    }
}

fn redirect_router(domain: String, state: Arc<State>) -> Router {
    Router::new().fallback(move |request: Request| {
        let response = redirect(&domain, &state, &request);
        async move { response }
    })
}

/// Plain HTTP's answer to `request`: the key authorization a CA's HTTP-01
/// challenge asks for, or else a redirect to the same path over HTTPS.
fn redirect(domain: &str, state: &State, request: &Request) -> Response {
    if let Some(token) = request.uri().path().strip_prefix(CHALLENGE_PATH) {
        let key_authorization = state.http_challenges.lock().unwrap().get(token).cloned();
        return match key_authorization {
            Some(key_authorization) => (
                [(header::CONTENT_TYPE, "application/octet-stream")],
                key_authorization,
            )
                .into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        };
    }
    // To the one domain the certificate is for, whatever Host was asked
    // for, so the redirect can't be pointed anywhere else.
    let path = request
        .uri()
        .path_and_query()
        .map_or("/", |path| path.as_str());
    match HeaderValue::try_from(format!("https://{domain}{path}")) {
        Ok(location) => (
            StatusCode::PERMANENT_REDIRECT,
            [(header::LOCATION, location)],
        )
            .into_response(),
        Err(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}

/// HTTPS connections, as a listener for `axum::serve`. Each handshake is
/// done on a task of its own, under a timeout, so a client that's slow to
/// finish one holds up nobody else, as it would if `accept` did it.
pub struct TlsListener {
    connections: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    local_addr: SocketAddr,
}

impl TlsListener {
    fn new(listener: TcpListener, config: Arc<rustls::ServerConfig>) -> std::io::Result<Self> {
        let local_addr = listener.local_addr()?;
        let (sender, connections) = mpsc::channel(64);
        tokio::spawn(handshake(listener, TlsAcceptor::from(config), sender));
        Ok(TlsListener {
            connections,
            local_addr,
        })
    }
}

/// Accept connections on `listener` and pass on those whose handshake
/// succeeds, until the [`TlsListener`] is dropped.
async fn handshake(
    mut listener: TcpListener,
    acceptor: TlsAcceptor,
    sender: mpsc::Sender<(TlsStream<TcpStream>, SocketAddr)>,
) {
    loop {
        let (stream, peer) = tokio::select! {
            accepted = axum::serve::Listener::accept(&mut listener) => accepted,
            () = sender.closed() => return,
        };
        let (acceptor, sender) = (acceptor.clone(), sender.clone());
        tokio::spawn(async move {
            // A failed handshake is a scanner, a client that hung up, or one
            // that came before there was a certificate: nothing to log.
            let Ok(Ok(stream)) =
                tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await
            else {
                return;
            };
            // A CA validating a challenge needed only the handshake.
            if stream.get_ref().1.alpn_protocol() == Some(ACME_TLS_ALPN) {
                return;
            }
            let _ = sender.send((stream, peer)).await;
        });
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, SocketAddr) {
        match self.connections.recv().await {
            Some(connection) => connection,
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
}
