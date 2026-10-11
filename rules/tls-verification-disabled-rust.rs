use reqwest::Client;

fn insecure_clients() {
    // ruleid: rust-tls-verification-disabled
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build();

    // ruleid: rust-tls-verification-disabled
    let other = reqwest::ClientBuilder::new()
        .danger_accept_invalid_hostnames(true)
        .build();

    // ruleid: rust-tls-verification-disabled
    connector.set_verify(SslVerifyMode::NONE);
}

fn custom_verifiers() {
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    // ruleid: rust-tls-custom-certificate-verifier
    config.dangerous().set_certificate_verifier(Arc::new(PinnedVerifier::new(pin)));
}

fn secure_clients() {
    // ok: rust-tls-verification-disabled
    let client = Client::builder()
        .danger_accept_invalid_certs(false)
        .add_root_certificate(ca)
        .build();

    // ok: rust-tls-verification-disabled
    connector.set_verify(SslVerifyMode::PEER);

    // ok: rust-tls-custom-certificate-verifier
    let config = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
}
