// Fixture for the test-scope tests: each temp_dir() call is a finding.

pub fn shipped() {
    let _ = std::env::temp_dir();
}

#[cfg(test)]
mod tests {
    fn in_test_module() {
        let _ = std::env::temp_dir();
        std::process::exit(1);
    }
}

#[cfg(any(test, feature = "x"))]
mod any_test {
    fn not_test_only() {
        let _ = std::env::temp_dir();
    }
}

#[cfg(test)]
mod helpers;

mod outer {
    #[cfg(test)]
    mod inner {
        fn nested() {
            let _ = std::env::temp_dir();
        }
    }
}

#[test]
fn top_level_test() {
    let _ = std::env::temp_dir();
}

#[cfg(test)]
impl Fixture {
    fn build() {
        let _ = std::env::temp_dir();
    }
}

const NOTE: &str = "#[cfg(test)] mod fake { std::env::temp_dir() }";
