#!/usr/bin/env bash
set -euo pipefail

workspace_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "$workspace_dir/../.." && pwd)"
anchor_bin="$repo_dir/target/debug/anchor"
artifact_dir="$workspace_dir/target/private-program-artifacts"
normal_target_dir="$workspace_dir/target/normal-program-build"
debug_target_dir="$workspace_dir/target/debug-program-build"
custom_out_dir="$artifact_dir/custom-sbf-out"

cargo build --manifest-path "$repo_dir/Cargo.toml" -p anchor-cli --bin anchor
mkdir -p "$artifact_dir"

CARGO_TARGET_DIR="$normal_target_dir" NO_DNA=1 "$anchor_bin" build --no-private --ignore-keys
cp "$normal_target_dir/deploy/private_program_fixture.so" "$artifact_dir/normal.so"
cp "$normal_target_dir/deploy/private_program_secondary.so" "$artifact_dir/normal-secondary.so"
cp "$normal_target_dir/idl/private_program_fixture.json" "$artifact_dir/normal.json"
cp "$normal_target_dir/idl/private_program_secondary.json" "$artifact_dir/normal-secondary.json"
if grep -a -q "Instruction: ManifestPrivate" \
    "$normal_target_dir/deploy/private_program_manifest.so"; then
    echo "--no-private disabled a manifest-authoritative private feature" >&2
    exit 1
fi

NO_DNA=1 "$anchor_bin" build --private --ignore-keys
cp "$workspace_dir/target/deploy/private_program_fixture.so" "$artifact_dir/private.so"
cp "$workspace_dir/target/deploy/private_program_secondary.so" "$artifact_dir/private-secondary.so"
cp "$workspace_dir/target/idl/private_program_fixture.json" "$artifact_dir/private.json"
cp "$workspace_dir/target/idl/private_program_secondary.json" "$artifact_dir/private-secondary.json"
cmp "$artifact_dir/normal.json" "$workspace_dir/target/idl/private_program_fixture.json"
cmp "$artifact_dir/normal-secondary.json" "$workspace_dir/target/idl/private_program_secondary.json"

grep -a -q "AnchorError occurred" "$artifact_dir/normal.so"
grep -a -q "Instruction: Initialize" "$artifact_dir/normal.so"
grep -q "PRIVATE_FIXTURE_ERROR_MESSAGE" "$artifact_dir/normal.json"
grep -a -q "PRIVATE_FIXTURE_PROJECT_NAME" "$artifact_dir/normal.so"
if grep -a -q "PRIVATE_FIXTURE_ERROR_MESSAGE" "$artifact_dir/private.so"; then
    echo "private artifact retained the custom error message" >&2
    exit 1
fi
if grep -a -q "Instruction: Initialize" "$artifact_dir/private.so"; then
    echo "private artifact retained the instruction log" >&2
    exit 1
fi
if grep -a -q "PRIVATE_FIXTURE_PROJECT_NAME" "$artifact_dir/private.so"; then
    echo "private artifact retained excess security metadata" >&2
    exit 1
fi
grep -a -q "private-fixture-v1" "$artifact_dir/private.so"
grep -a -q "private-fixture-revision" "$artifact_dir/private.so"
grep -a -q "PRIVATE_FIXTURE_SEMANTIC_RUNTIME_LOG" "$artifact_dir/private.so"
grep -a -q "https://example.invalid/src/runtime.rs" "$artifact_dir/private.so"

# Exercise the --no-idl path independently; the prior IDL remains the parity reference.
NO_DNA=1 "$anchor_bin" build --private --no-idl --ignore-keys

# Anchor.toml private activation works without an explicit CLI flag.
NO_DNA=1 "$anchor_bin" build --program-name private_program_secondary --no-idl --ignore-keys

# Normal debug builds must retain their symbol table; private mode rejects the conflict.
CARGO_TARGET_DIR="$debug_target_dir" NO_DNA=1 "$anchor_bin" build \
    --program-name private_program_fixture --no-private --no-idl --ignore-keys -- --debug
test -n "$(strings -a "$debug_target_dir/deploy/private_program_fixture.so" | grep '^\.symtab$')"
if NO_DNA=1 "$anchor_bin" build --program-name private_program_fixture \
    --private --no-idl --ignore-keys -- --debug >"$artifact_dir/private-debug.log" 2>&1; then
    echo "private debug build unexpectedly succeeded" >&2
    exit 1
fi
grep -q "incompatible with private program mode" "$artifact_dir/private-debug.log"

# A caller-supplied cargo-build-sbf output directory remains authoritative.
NO_DNA=1 "$anchor_bin" build --program-name private_program_secondary \
    --no-private --no-idl --ignore-keys -- --sbf-out-dir "$custom_out_dir"
test -f "$custom_out_dir/private_program_secondary.so"

ANCHOR_PRIVATE_NORMAL_SO="$artifact_dir/normal.so" \
ANCHOR_PRIVATE_PRIVATE_SO="$artifact_dir/private.so" \
cargo test --manifest-path "$workspace_dir/Cargo.toml" -p private-program-runtime-tests

cargo run --manifest-path "$workspace_dir/Cargo.toml" \
    -p private-program-runtime-tests --bin private-program-report
