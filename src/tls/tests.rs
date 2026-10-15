use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, StatusCode};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use super::acme::alpn_challenge_certificate;
use super::store::Store;
use super::*;

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A CA, and a certificate for `localhost` from it: the chain and key as a
/// CA would hand them over, PEM.
pub struct Issued {
    pub ca: CertificateDer<'static>,
    chain: String,
    key: String,
}

pub fn issue(validity: Option<(i64, i64)>) -> Issued {
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    if let Some((not_before, not_after)) = validity {
        params.not_before = time::OffsetDateTime::from_unix_timestamp(not_before).unwrap();
        params.not_after = time::OffsetDateTime::from_unix_timestamp(not_after).unwrap();
    }
    let key = KeyPair::generate().unwrap();
    let leaf = params.signed_by(&key, &ca).unwrap();
    Issued {
        ca: ca.as_ref().der().clone(),
        chain: format!("{}{}", leaf.pem(), ca.as_ref().pem()),
        key: key.serialize_pem(),
    }
}

fn with_certificate(issued: &Issued) -> Arc<State> {
    let state = Arc::new(State::default());
    let pem = format!("{}{}", issued.chain, issued.key);
    state
        .certificate
        .store(Some(Certificate::from_pem(pem.as_bytes()).unwrap().key));
    state
}

/// HTTPS on `listener`, with `issued`'s certificate.
pub fn listener(issued: &Issued, listener: TcpListener) -> TlsListener {
    TlsListener::new(listener, server_config(with_certificate(issued))).unwrap()
}

/// `router` served over HTTPS on a port of its own, with `state`'s
/// certificate, as the relay serves it.
async fn serve(state: Arc<State>, router: Router) -> SocketAddr {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = tcp.local_addr().unwrap();
    let listener = TlsListener::new(tcp, server_config(state)).unwrap();
    let app = router.into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move {
        axum::serve(axum::serve::ListenerExt::tap_io(listener, |_| {}), app).await
    });
    address
}

/// A client that trusts `ca`, offering `alpn`.
pub fn trusting(ca: &CertificateDer<'static>, alpn: &[&[u8]]) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.clone()).unwrap();
    let mut config = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    config
}

pub async fn connect(address: SocketAddr, config: rustls::ClientConfig) -> TlsStream<TcpStream> {
    try_connect(address, config).await.unwrap()
}

async fn try_connect(
    address: SocketAddr,
    config: rustls::ClientConfig,
) -> std::io::Result<TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(address).await.unwrap();
    TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
}

/// What a GET of `/` over `stream` is answered with.
async fn get(mut stream: TlsStream<TcpStream>) -> String {
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = String::new();
    // A TLS stream closed without close_notify is an error, after the body.
    let _ = stream.read_to_string(&mut response).await;
    response
}

/// Accepts any certificate, and remembers it. Signatures go unchecked too:
/// webpki won't parse a challenge certificate, whose critical extension it
/// doesn't know.
#[derive(Debug, Default)]
struct Recording(Mutex<Option<CertificateDer<'static>>>);

impl ServerCertVerifier for Recording {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        *self.0.lock().unwrap() = Some(end_entity.clone().into_owned());
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[tokio::test]
async fn serves_the_certificate_and_knows_who_connected() {
    let issued = issue(None);
    let router = Router::new()
        .fallback(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move { peer.to_string() });
    let address = serve(with_certificate(&issued), router).await;

    // Verified against the CA: the chain is served whole.
    let stream = connect(address, trusting(&issued.ca, &[b"http/1.1"])).await;
    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
    let local = stream.get_ref().0.local_addr().unwrap();
    let response = get(stream).await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.ends_with(&local.to_string()), "{response}");

    // Without ALPN too.
    let stream = connect(address, trusting(&issued.ca, &[])).await;
    assert!(get(stream).await.starts_with("HTTP/1.1 200"));
}

#[tokio::test]
async fn a_slow_handshake_holds_up_nobody() {
    let issued = issue(None);
    let address = serve(
        with_certificate(&issued),
        Router::new().fallback(|| async { "hi" }),
    )
    .await;
    // Connected, and never a word.
    let _stalled = TcpStream::connect(address).await.unwrap();
    let stream = tokio::time::timeout(
        Duration::from_secs(5),
        connect(address, trusting(&issued.ca, &[])),
    )
    .await
    .unwrap();
    assert!(get(stream).await.ends_with("hi"));
}

#[tokio::test]
async fn with_no_certificate_yet_handshakes_fail() {
    let address = serve(Arc::new(State::default()), Router::new()).await;
    let issued = issue(None);
    assert!(
        try_connect(address, trusting(&issued.ca, &[]))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn a_validating_ca_gets_the_challenge_certificate() {
    let issued = issue(None);
    let state = with_certificate(&issued);
    let address = serve(state.clone(), Router::new()).await;
    let recording = Arc::new(Recording::default());
    let config = |alpn: &[u8]| {
        let mut config = rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(recording.clone())
            .with_no_client_auth();
        config.alpn_protocols = vec![alpn.to_vec()];
        config
    };

    // No challenge pending: the CA's handshake fails.
    assert!(try_connect(address, config(ACME_TLS_ALPN)).await.is_err());

    let challenge = alpn_challenge_certificate("localhost", &[7; 32]).unwrap();
    let challenge_der = challenge.cert[0].clone();
    state.alpn_challenge.store(Some(Arc::new(challenge)));
    let stream = connect(address, config(ACME_TLS_ALPN)).await;
    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(ACME_TLS_ALPN));
    assert_eq!(
        recording.0.lock().unwrap().take(),
        Some(challenge_der.clone())
    );
    // It carries the digest, in the critical id-pe-acmeIdentifier extension.
    let (_, parsed) = x509_parser::parse_x509_certificate(&challenge_der).unwrap();
    let extension = parsed
        .extensions()
        .iter()
        .find(|extension| extension.oid.to_id_string() == "1.3.6.1.5.5.7.1.31")
        .unwrap();
    assert!(extension.critical);
    assert!(extension.value.ends_with(&[7; 32]));

    // Everyone else still gets the real one.
    drop(connect(address, config(b"http/1.1")).await);
    assert_eq!(
        recording.0.lock().unwrap().take().as_deref(),
        Some(state.certificate.load().as_ref().unwrap().cert[0].as_ref())
    );
}

#[tokio::test]
async fn plain_http_redirects_and_answers_challenges() {
    let state = State::default();
    state
        .http_challenges
        .lock()
        .unwrap()
        .insert("tok".into(), "tok.thumb".into());
    let send = |method: Method, uri: &str| {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header("host", "evil.example")
            .body(Body::empty())
            .unwrap();
        redirect("relay.example.com", &state, &request)
    };

    let response = send(Method::GET, "/.well-known/acme-challenge/tok");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    assert_eq!(&body[..], b"tok.thumb");
    let response = send(Method::GET, "/.well-known/acme-challenge/other");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let response = send(Method::POST, "/x?y=1");
    assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
    assert_eq!(
        response.headers()["location"],
        "https://relay.example.com/x?y=1"
    );
    let response = send(Method::GET, "/");
    assert_eq!(response.headers()["location"], "https://relay.example.com/");
}

#[test]
fn keeps_certificates_privately_per_ca() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("tls");
    let store = Store::new(
        &root,
        "https://acme-staging-v02.api.letsencrypt.org/directory",
    )
    .unwrap();
    assert!(store.load_certificate("localhost").unwrap().is_none());
    assert!(store.load_account().unwrap().is_none());
    // Nothing's written until there's something to keep.
    assert!(!root.exists());

    let issued = issue(Some((1_800_000_000, 1_800_000_000 + 90 * 86400)));
    let saved = store
        .save_certificate("localhost", &issued.chain, &issued.key)
        .unwrap();
    let mode =
        |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    let path = root.join("acme-staging-v02.api.letsencrypt.org/localhost.pem");
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(path.parent().unwrap()), 0o700);
    let loaded = store.load_certificate("localhost").unwrap().unwrap();
    assert_eq!(loaded.key.cert, saved.key.cert);
    assert_eq!(loaded.key.cert.len(), 2);
    // A month before a 90-day certificate expires.
    assert_eq!(loaded.renew_at(), 1_800_000_000 + 60 * 86400);

    // Another CA's certificates are its own.
    let other = Store::new(&root, "https://localhost:14000/dir").unwrap();
    assert!(other.load_certificate("localhost").unwrap().is_none());

    // A key that isn't the certificate's is refused before it's kept.
    let stranger = issue(None);
    assert!(
        store
            .save_certificate("localhost", &issued.chain, &stranger.key)
            .is_err()
    );
    assert!(Certificate::from_pem(issued.chain.as_bytes()).is_err());
}

#[test]
fn remembers_whether_http01_worked() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path(), crate::config::LETS_ENCRYPT).unwrap();
    assert!(!store.http01_worked("relay.example.com"));
    store.remember_http01("relay.example.com", true).unwrap();
    assert!(store.http01_worked("relay.example.com"));
    assert!(!store.http01_worked("other.example.com"));
    store.remember_http01("relay.example.com", false).unwrap();
    assert!(!store.http01_worked("relay.example.com"));
    store.remember_http01("relay.example.com", false).unwrap();
}

/// Gets real certificates from Pebble, Let's Encrypt's test CA, by both
/// challenges. Pebble validates against 127.0.0.1, so the relay listens
/// where it looks: 5001 for TLS-ALPN-01 and 5002 for HTTP-01, its defaults.
///
/// ```text
/// docker run -d --name challtestsrv --network host ghcr.io/letsencrypt/pebble-challtestsrv -defaultIPv4 127.0.0.1 -defaultIPv6 "" -http01 "" -tlsalpn01 "" -https01 "" -doh ""
/// docker run -d --name pebble --network host -e PEBBLE_VA_NOSLEEP=1 ghcr.io/letsencrypt/pebble -dnsserver 127.0.0.1:8053
/// docker cp pebble:/test/certs/pebble.minica.pem /tmp/pebble.minica.pem
/// PEBBLE_ROOT=/tmp/pebble.minica.pem cargo test pebble -- --ignored
/// ```
#[tokio::test]
#[ignore = "needs a Pebble ACME server"]
async fn pebble() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let root = std::env::var("PEBBLE_ROOT").expect("PEBBLE_ROOT: Pebble's CA certificate");
    let directory =
        std::env::var("PEBBLE_DIRECTORY").unwrap_or_else(|_| "https://localhost:14000/dir".into());
    let dir = tempfile::tempdir().unwrap();
    let state = Arc::new(State::default());
    let acme = acme::Acme {
        domain: "relay.test".into(),
        directory: directory.clone(),
        email: Some("ops@relay.test".into()),
        http01: true,
        root: Some(root.into()),
        store: Store::new(dir.path(), &directory).unwrap(),
        state: state.clone(),
    };

    let tls = TcpListener::bind("127.0.0.1:5001").await.unwrap();
    let tls = TlsListener::new(tls, server_config(state.clone())).unwrap();
    tokio::spawn(async move { axum::serve(tls, Router::new()).await });
    let http = TcpListener::bind("127.0.0.1:5002").await.unwrap();
    let redirect = redirect_router("relay.test".into(), state.clone());
    tokio::spawn(async move { axum::serve(http, redirect).await });

    let account = acme.account().await.unwrap();
    for kind in [
        instant_acme::ChallengeType::TlsAlpn01,
        instant_acme::ChallengeType::Http01,
    ] {
        let (chain, key) = acme
            .order(&account, &kind)
            .await
            .unwrap_or_else(|error| panic!("{kind:?}: {error:#}"));
        let certificate = acme
            .store
            .save_certificate("relay.test", &chain, &key)
            .unwrap();
        assert!(certificate.not_after > store::now());
        assert!(
            state.alpn_challenge.load().is_none()
                && state.http_challenges.lock().unwrap().is_empty()
        );
    }
    // The account is kept, and used again.
    assert!(acme.store.load_account().unwrap().is_some());
    acme.account().await.unwrap();
}
