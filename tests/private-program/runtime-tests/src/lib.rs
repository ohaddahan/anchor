use {
    anchor_lang::{
        solana_program::{instruction::Instruction, system_program},
        AccountDeserialize, InstructionData, ToAccountMetas,
    },
    litesvm::{
        types::{FailedTransactionMetadata, TransactionMetadata},
        LiteSVM,
    },
    solana_keypair::Keypair,
    solana_message::{Message, VersionedMessage},
    solana_signer::Signer,
    solana_transaction::versioned::VersionedTransaction,
    std::{collections::BTreeMap, fs, path::Path},
};

pub const SEMANTIC_LOG: &str =
    "PRIVATE_FIXTURE_SEMANTIC_RUNTIME_LOG https://example.invalid/src/runtime.rs";

#[derive(Clone, Debug)]
pub struct SuccessObservation {
    pub logs: Vec<String>,
    pub compute_units: u64,
}

#[derive(Clone, Debug)]
pub struct FailureObservation {
    pub error: String,
    pub logs: Vec<String>,
    pub compute_units: u64,
}

#[derive(Clone, Debug)]
pub struct ExerciseResult {
    pub value: u64,
    pub initialize: SuccessObservation,
    pub set_value: SuccessObservation,
    pub explicit_log: SuccessObservation,
    pub comparison: FailureObservation,
    pub account_constraint: FailureObservation,
    pub panic: FailureObservation,
    pub macro_failures: BTreeMap<String, FailureObservation>,
}

fn transaction(
    svm: &LiteSVM,
    payer: &Keypair,
    instruction: Instruction,
    additional_signers: &[&Keypair],
) -> VersionedTransaction {
    let blockhash = svm.latest_blockhash();
    let message = Message::new_with_blockhash(&[instruction], Some(&payer.pubkey()), &blockhash);
    let mut signers = vec![payer];
    signers.extend_from_slice(additional_signers);
    VersionedTransaction::try_new(VersionedMessage::Legacy(message), &signers).unwrap()
}

fn success(metadata: TransactionMetadata) -> SuccessObservation {
    SuccessObservation {
        logs: metadata.logs,
        compute_units: metadata.compute_units_consumed,
    }
}

fn failure(metadata: FailedTransactionMetadata) -> FailureObservation {
    FailureObservation {
        error: format!("{:?}", metadata.err),
        logs: metadata.meta.logs,
        compute_units: metadata.meta.compute_units_consumed,
    }
}

fn send_failure(
    svm: &mut LiteSVM,
    payer: &Keypair,
    instruction: Instruction,
) -> FailureObservation {
    failure(
        svm.send_transaction(transaction(svm, payer, instruction, &[]))
            .unwrap_err(),
    )
}

fn no_accounts(data: Vec<u8>) -> Instruction {
    Instruction::new_with_bytes(
        private_program_fixture::id(),
        &data,
        private_program_fixture::accounts::NoAccounts {}.to_account_metas(None),
    )
}

pub fn exercise_artifact(artifact: &Path) -> ExerciseResult {
    let program_id = private_program_fixture::id();
    let payer = Keypair::new();
    let state = Keypair::new();
    let mut svm = LiteSVM::new();
    svm.add_program(program_id, &fs::read(artifact).unwrap())
        .unwrap();
    svm.airdrop(&payer.pubkey(), 1_000_000_000).unwrap();

    let initialize = Instruction::new_with_bytes(
        program_id,
        &private_program_fixture::instruction::Initialize { value: 41 }.data(),
        private_program_fixture::accounts::Initialize {
            state: state.pubkey(),
            payer: payer.pubkey(),
            system_program: system_program::ID,
        }
        .to_account_metas(None),
    );
    let initialize = success(
        svm.send_transaction(transaction(&svm, &payer, initialize, &[&state]))
            .unwrap(),
    );

    let set_value = Instruction::new_with_bytes(
        program_id,
        &private_program_fixture::instruction::SetValue { value: 42 }.data(),
        private_program_fixture::accounts::SetValue {
            state: state.pubkey(),
            authority: payer.pubkey(),
        }
        .to_account_metas(None),
    );
    let set_value = success(
        svm.send_transaction(transaction(&svm, &payer, set_value, &[]))
            .unwrap(),
    );

    let state_account = svm.get_account(&state.pubkey()).unwrap();
    let mut data: &[u8] = &state_account.data;
    let value = private_program_fixture::State::try_deserialize(&mut data)
        .unwrap()
        .value;

    let explicit_log = success(
        svm.send_transaction(transaction(
            &svm,
            &payer,
            no_accounts(private_program_fixture::instruction::ExplicitProtocolLog {}.data()),
            &[],
        ))
        .unwrap(),
    );

    let comparison = send_failure(
        &mut svm,
        &payer,
        no_accounts(
            private_program_fixture::instruction::FailComparison { left: 7, right: 9 }.data(),
        ),
    );

    let mut account_metas = private_program_fixture::accounts::SetValue {
        state: state.pubkey(),
        authority: payer.pubkey(),
    }
    .to_account_metas(None);
    account_metas[0].is_writable = false;
    let account_constraint = send_failure(
        &mut svm,
        &payer,
        Instruction::new_with_bytes(
            program_id,
            &private_program_fixture::instruction::SetValue { value: 43 }.data(),
            account_metas,
        ),
    );

    let panic = send_failure(
        &mut svm,
        &payer,
        no_accounts(private_program_fixture::instruction::PanicSite {}.data()),
    );

    let macro_instructions = [
        (
            "err!",
            private_program_fixture::instruction::FailCustom {}.data(),
        ),
        (
            "error!",
            private_program_fixture::instruction::FailErrorMacro {}.data(),
        ),
        (
            "require!",
            private_program_fixture::instruction::FailRequire {}.data(),
        ),
        (
            "require_neq!",
            private_program_fixture::instruction::FailNeq {}.data(),
        ),
        (
            "require_gt!",
            private_program_fixture::instruction::FailGt {}.data(),
        ),
        (
            "require_gte!",
            private_program_fixture::instruction::FailGte {}.data(),
        ),
        (
            "require_keys_eq!",
            private_program_fixture::instruction::FailKeysEq {}.data(),
        ),
        (
            "require_keys_neq!",
            private_program_fixture::instruction::FailKeysNeq {}.data(),
        ),
    ];
    let macro_failures = macro_instructions
        .into_iter()
        .map(|(name, data)| {
            (
                name.to_owned(),
                send_failure(&mut svm, &payer, no_accounts(data)),
            )
        })
        .collect();

    ExerciseResult {
        value,
        initialize,
        set_value,
        explicit_log,
        comparison,
        account_constraint,
        panic,
        macro_failures,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn logs_contain(observation: &FailureObservation, needle: &str) -> bool {
        observation.logs.iter().any(|log| log.contains(needle))
    }

    fn assert_numeric_error_matches(
        normal: &FailureObservation,
        private: &FailureObservation,
        code: u32,
    ) {
        let expected = format!("Custom({code})");
        assert!(normal.error.contains(&expected), "{}", normal.error);
        assert!(private.error.contains(&expected), "{}", private.error);
    }

    fn assert_private_diagnostics_absent(observation: &FailureObservation) {
        for diagnostic in [
            "Instruction:",
            "AnchorError",
            "ProgramError",
            "ValuesMustMatch",
            "PRIVATE_FIXTURE_ERROR_MESSAGE",
            "src/lib.rs",
            "Left:",
            "Right:",
            "caused by account",
        ] {
            assert!(!logs_contain(observation, diagnostic), "{diagnostic:?}");
        }
    }

    #[test]
    fn normal_and_private_artifacts_have_identical_runtime_results() {
        let artifacts = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("target/private-program-artifacts");
        let normal = std::env::var_os("ANCHOR_PRIVATE_NORMAL_SO")
            .map(Into::into)
            .unwrap_or_else(|| artifacts.join("normal.so"));
        let private = std::env::var_os("ANCHOR_PRIVATE_PRIVATE_SO")
            .map(Into::into)
            .unwrap_or_else(|| artifacts.join("private.so"));
        let normal = exercise_artifact(&normal);
        let private = exercise_artifact(&private);

        assert_eq!(normal.value, 42);
        assert_eq!(private.value, normal.value);
        assert!(normal
            .set_value
            .logs
            .iter()
            .any(|log| log.contains("Instruction: SetValue")));
        assert!(!private
            .set_value
            .logs
            .iter()
            .any(|log| log.contains("Instruction:")));
        assert_numeric_error_matches(&normal.comparison, &private.comparison, 6000);

        for expected in [
            "Instruction: FailComparison",
            "programs/private-program-fixture/src/lib.rs",
            "ValuesMustMatch",
            "PRIVATE_FIXTURE_ERROR_MESSAGE",
            "Left: 7",
            "Right: 9",
        ] {
            assert!(logs_contain(&normal.comparison, expected), "{expected:?}");
        }
        assert_private_diagnostics_absent(&private.comparison);

        assert_numeric_error_matches(
            &normal.account_constraint,
            &private.account_constraint,
            2000,
        );
        for expected in [
            "ConstraintMut",
            "account: state",
            "A mut constraint was violated",
        ] {
            assert!(
                logs_contain(&normal.account_constraint, expected),
                "{expected:?}"
            );
        }
        assert_private_diagnostics_absent(&private.account_constraint);

        assert_eq!(normal.macro_failures.len(), private.macro_failures.len());
        for (name, normal_failure) in &normal.macro_failures {
            let private_failure = &private.macro_failures[name];
            assert_numeric_error_matches(normal_failure, private_failure, 6000);
            assert!(logs_contain(normal_failure, "ValuesMustMatch"), "{name}");
            assert!(
                logs_contain(normal_failure, "PRIVATE_FIXTURE_ERROR_MESSAGE"),
                "{name}"
            );
            assert_private_diagnostics_absent(private_failure);
        }

        assert!(normal
            .panic
            .logs
            .iter()
            .any(|log| log.contains("PRIVATE_FIXTURE_PANIC_DIAGNOSTIC")));
        assert!(!private.panic.logs.iter().any(|log| {
            log.contains("PRIVATE_FIXTURE_PANIC_DIAGNOSTIC") || log.contains("src/lib.rs")
        }));

        assert!(normal
            .explicit_log
            .logs
            .iter()
            .any(|log| log.contains(SEMANTIC_LOG)));
        assert!(private
            .explicit_log
            .logs
            .iter()
            .any(|log| log.contains(SEMANTIC_LOG)));
    }
}
