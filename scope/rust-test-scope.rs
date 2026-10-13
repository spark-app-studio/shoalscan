// Tests for the scope rules: `opengrep scan --test scope/`.

// ok: rust-cfg-test-item
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

// ruleid: rust-cfg-test-item
#[cfg(all(test, unix))]
fn all_test() {}

// ruleid: rust-cfg-test-item
#[cfg(all(unix, test))]
impl Fixture {}

// ok: rust-cfg-test-item
#[cfg(all(unix, not(test)))]
fn all_not_test() {}

// ok: rust-cfg-test-item
#[cfg(all(any(test, unix), unix))]
fn all_any_test() {}

// ok: rust-cfg-test-item
#[cfg(r#test)]
fn raw_test() {}

// ok: rust-cfg-test-item
#[cfg_attr(feature = "x", cfg(test))]
fn cfg_attr_cfg_test() {}

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

// ok: rust-cfg-test-item
#[test]
fn unit() {}

// ok: rust-cfg-test-item
#[test]
#[should_panic]
fn panics() {}

// ok: rust-cfg-test-item
#[ignore]
#[test]
fn ignored() {}

// ok: rust-cfg-test-item
#[tokio::test]
async fn async_test() {}

// ok: rust-cfg-test-item
#[rstest]
#[case(1)]
fn parametrised(#[case] x: u8) {}

// ok: rust-cfg-test-item
#[test_case(1; "one")]
fn test_case_keeps_its_function(x: u8) {}

// ok: rust-cfg-test-item
#[tokio::main]
async fn main() {}

mod outer {
    // Opengrep drops the attributes of items inside a module body, so these
    // are not test scope (fail closed).
    // ok: rust-cfg-test-item
    #[cfg(test)]
    fn nested_helper() {}

    // ok: rust-cfg-test-item
    #[test]
    fn nested_test() {}
}
