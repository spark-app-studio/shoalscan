fn connect(user: &str, password: &str, api_key: &str, session: &Session) {
    // ruleid: rust-secret-in-log
    tracing::info!("connecting {} with {}", user, password);

    // ruleid: rust-secret-in-log
    debug!(key = %api_key, "using key");

    // ruleid: rust-secret-in-log
    log::warn!("token {}", session.access_token);

    // ruleid: rust-secret-in-log
    warn!("retrying with {}", client_secret);

    // ruleid: rust-secret-in-log
    tracing::error!(user, token = ?refresh_token, "refresh failed");

    // ruleid: rust-secret-in-log
    tracing::info!("using {api_token}");

    // ruleid: rust-secret-in-log
    log::debug!("t={refresh_token:?}");

    // ruleid: rust-secret-in-log
    info!(?api_token, "authenticated");

    // ruleid: rust-secret-in-log
    tracing::warn!(user, %client_secret, "retry");

    // ruleid: rust-secret-in-log
    info!(%password);

    // ruleid: rust-secret-in-log
    println!("password: {}", password);

    // ruleid: rust-secret-in-log
    eprintln!("using {api_token}");

    // ok: rust-secret-in-log
    println!("user: {}", user);

    // ok: rust-secret-in-log
    tracing::info!("using {token_count} tokens");

    // ok: rust-secret-in-log
    tracing::info!("connecting {}", user);

    // ok: rust-secret-in-log
    tracing::info!("token refreshed for {}", user);

    // ok: rust-secret-in-log
    info!(tokens = token_count, "budget");

    // ok: rust-secret-in-log
    println!("{}", user);
}
