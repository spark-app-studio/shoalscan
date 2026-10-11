// ruleid: rust-plain-http-url
const DEFAULT: &str = "http://reg.vendor.io/v2";

fn uses_default() {
    // ok: rust-plain-http-url
    connect(DEFAULT);
}

fn urls() {
    // ruleid: rust-plain-http-url
    let registry = "http://registry.vendor.io/v2";

    // ok: rust-plain-http-url
    let local = "http://[::1]:8081/";

    // ok: rust-plain-http-url
    let secure = "https://registry.vendor.io/v2";
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_plain_urls() {
        // ok: rust-plain-http-url
        let url = "http://registry.vendor.io/v2";
    }
}

#[tokio::test]
async fn plain_url_in_async_test() {
    // ok: rust-plain-http-url
    let url = "http://registry.vendor.io/v2";
}
