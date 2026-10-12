// Tests for the scope rules: `opengrep scan --test scope/`.

// ok: rust-cfg-test-item, rust-test-fn, rust-tokio-test-fn, rust-rstest-fn
fn shipped() {}

// ruleid: rust-cfg-test-item
#[cfg(test)]
fn helper() {}

// ruleid: rust-cfg-test-item
#[cfg(
    test
)]
pub async fn split_attribute<T: Clone>(x: T) -> Result<(), ()> {
    Ok(())
}

// ruleid: rust-cfg-test-item
#[cfg(test)]
/// A doc comment between the attribute and the item.
impl Fixture {
    fn build() {}
}

// ruleid: rust-cfg-test-item
#[cfg(test)]
impl<T> Default for Fixture<T> where T: Clone {
    fn default() -> Self { todo!() }
}

// ruleid: rust-cfg-test-item
#[cfg(test)]
const TEST_NAME: &str = "fixture";

// ruleid: rust-cfg-test-item
#[cfg(test)]
static TEST_LABEL: &str = "fixture";

// ok: rust-cfg-test-item
#[cfg(any(test, feature = "x"))]
fn any_test() {}

// ok: rust-cfg-test-item
#[cfg(all(test, unix))]
fn all_test() {}

// ok: rust-cfg-test-item
#[cfg(not(test))]
fn not_test() {}

// ok: rust-cfg-test-item
#[cfg(feature = "test")]
fn feature_test() {}

// ok: rust-cfg-test-item
#[cfg_attr(test, allow(dead_code))]
fn cfg_attr_test() {}

// ok: rust-cfg-test-item
#[cfg(test, unix)]
fn two_predicates() {}

// ok: rust-cfg-test-item
const S: &str = "#[cfg(test)] fn in_a_string() {}";

// #[cfg(test)]
// ok: rust-cfg-test-item
fn after_a_comment() {}

// ruleid: rust-test-fn
#[test]
fn unit() {}

// ruleid: rust-test-fn
#[test]
#[should_panic]
fn panics() {}

// ruleid: rust-test-fn
#[ignore]
#[test]
fn ignored() {}

// ruleid: rust-tokio-test-fn
#[tokio::test]
async fn async_test() {}

// ruleid: rust-tokio-test-fn
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn async_test_with_arguments() {}

// ruleid: rust-rstest-fn
#[rstest]
#[case(1)]
fn parametrised(#[case] x: u8) {}

// ok: rust-test-fn, rust-rstest-fn
#[test_case(1; "one")]
fn test_case_keeps_its_function(x: u8) {}

// ok: rust-tokio-test-fn
#[tokio::main]
async fn main() {}

mod outer {
    // Opengrep drops the attributes of items inside a module body, so these
    // are not test scope (fail closed).
    // ok: rust-cfg-test-item
    #[cfg(test)]
    fn nested_helper() {}

    // ok: rust-test-fn
    #[test]
    fn nested_test() {}
}
