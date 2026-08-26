# Anchor private program build comparison

> Generated from the purpose-built SBF fixture by `tests/private-program/test.sh`.

## Outcome

- **36.51% smaller** primary fixture ELF: 151,992 B → 96,504 B.
- **75.15% smaller** minimal secondary ELF: 57,848 B → 14,376 B.
- **79.41% fewer printable bytes** and 11 → 0 detected source-path strings.
- **Same program behavior:** state ends at `42`; both modes return custom error code `6000`.
- **Same off-chain API:** normal and private IDLs are byte-identical (`sha256:4fce5d968ed30153ae2d2f3c462fef95fcfa3131f7267d360a2c1b530c3c2074`).

Private errors do more than remove the file path. Normal mode logs the instruction name, file and line, error name, message, and compared values. Private mode emits none of that Anchor diagnostic log; the Solana transaction result still exposes the stable numeric code.

## Artifact overview

| Measurement | Normal | Private | Reduction |
|---|---:|---:|---:|
| ELF size | 151,992 B | 96,504 B | 36.51% |
| Printable strings | 201 | 114 | 43.28% |
| Printable bytes | 12,105 | 2,492 | 79.41% |
| Detected source paths | 11 | 0 | 11 removed |
| Security metadata fields | 9 | 2 | release + revision only |
| Dynamic symbols | 13 | 11 | required ABI retained |
| Static symbol sections | 0 | 0 | absent in both deploy ELFs |
| Debug sections | 0 | 0 | absent in both deploy ELFs |

## Section density

| Section | Normal | Private | Reduction |
|---|---:|---:|---:|
| `.text` | 117,288 B | 82,464 B | 29.69% |
| `.rodata` | 14,372 B | 5,248 B | 63.48% |
| `.data.rel.ro` | 4,656 B | 1,736 B | 62.71% |
| `.rel.dyn` | 14,048 B | 5,408 B | 61.50% |

## Runtime error comparison

Both executions return `InstructionError(0, Custom(6000))` / `InstructionError(0, Custom(6000))`.

### Normal

```text
Program log: Instruction: FailComparison
Program log: AnchorError thrown in programs/private-program-fixture/src/lib.rs:32. Error Code: ValuesMustMatch. Error Number: 6000. Error Message: PRIVATE_FIXTURE_ERROR_MESSAGE.
Program log: Left: 7
Program log: Right: 9
Program Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS failed: custom program error: 0x1770
```

### Private

```text
Program Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS failed: custom program error: 0x1770
```

The comparison failure consumed **2,700 CU normally** and **280 CU privately** (89.63% less for this fixture). This is a fixture measurement, not a general compute guarantee.

## Preserved and removed

| Surface | Normal | Private |
|---|---|---|
| Numeric custom error code | `6000` | `6000` |
| Successful state transition | `42` | `42` |
| Explicit application `msg!` | Preserved | Preserved |
| Semantic URL containing `/src/` | Preserved | Preserved |
| Error name/message/file/values in logs | Present | Removed |
| Account constraint name/message in logs | Present | Removed; code `2000` retained |
| Panic output and location | Present | Silent |
| Panic message literal in ELF | Present | Present |
| Security fields | name, project_url, contacts, policy, source_code, source_release, source_revision, auditors, acknowledgements | source_release, source_revision |
| Defined dynamic exports | SECURITY_TXT, custom_panic, entrypoint | SECURITY_TXT, custom_panic, entrypoint |

The panic literal is intentionally reported separately: the private panic handler is silent, but arbitrary user-authored panic strings are not rewritten because they cannot be safely distinguished from semantic program strings after linking.

## Methodology

- Toolchain: solana-cargo-build-sbf 3.1.10 · platform-tools v1.52 · rustc 1.89.0
- Normal: `anchor build --no-private --ignore-keys`
- Private: `anchor build --private --ignore-keys`
- Runtime: the same normal/private ELFs executed in LiteSVM.
- Coverage: successful state writes, `error!`, `err!`, `require!`, comparison/key macros, account constraints, panic behavior, explicit logs, mixed normal/private multi-program workspaces, manifest feature authority, normal debug symbols, custom SBF output directories, `--no-idl`, and IDL equality.
