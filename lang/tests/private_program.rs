#![cfg(feature = "private-program")]

use anchor_lang::prelude::*;

anchor_lang::program_security_txt!(
    name: "Private fixture name",
    project_url: "https://example.invalid/private-fixture",
    contacts: "mailto:security@example.invalid",
    policy: "https://example.invalid/policy",
    source_code: "https://example.invalid/source",
    source_release: "v1.2.3",
    source_revision: "deadbeef",
    auditors: "Private Auditor",
);

#[error_code]
enum PrivateError {
    #[msg("private error message")]
    Secret,
}

fn comparison_failure() -> Result<()> {
    require_eq!(7u64, 9u64, PrivateError::Secret);
    Ok(())
}

#[test]
fn errors_keep_only_the_numeric_code() {
    let error = comparison_failure().unwrap_err();
    let Error::AnchorError(error) = error else {
        panic!("expected Anchor error");
    };

    assert_eq!(error.error_code_number, 6000);
    assert!(error.error_name.is_empty());
    assert!(error.error_msg.is_empty());
    assert!(error.error_origin.is_none());
    assert!(error.compared_values.is_none());
}

#[test]
fn security_txt_keeps_only_release_and_revision() {
    assert!(SECURITY_TXT.contains("source_release\0v1.2.3\0"));
    assert!(SECURITY_TXT.contains("source_revision\0deadbeef\0"));
    for private_value in [
        "Private fixture name",
        "security@example.invalid",
        "Private Auditor",
        "source_code",
    ] {
        assert!(!SECURITY_TXT.contains(private_value));
    }
}
