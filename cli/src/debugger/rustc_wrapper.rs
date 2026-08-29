//! Shared RUSTC_WRAPPER shim for Anchor's debugger and private SBF builds.
//!
//! ## Problem
//!
//! The Solana toolchain's cargo passes `-Zremap-cwd-prefix=` (empty
//! replacement) to rustc for every SBF crate. This strips `DW_AT_comp_dir`
//! from the DWARF, making all source paths relative. When multiple crates
//! share filenames like `src/lib.rs`, the debugger can't tell them apart
//! and may show source from the wrong crate.
//!
//! ## Solution
//!
//! `anchor debugger` sets `RUSTC_WRAPPER` to the `anchor` binary itself.
//! Cargo then invokes `anchor <real-rustc> <args...>` for every rustc
//! call. This module detects that invocation pattern (the env var
//! `__ANCHOR_RUSTC_WRAPPER=1` disambiguates from normal CLI usage) and
//! replaces `-Zremap-cwd-prefix=` with `-Zremap-cwd-prefix=$CWD`,
//! preserving absolute paths in the debug info.
//!
//! The sentinel env var is necessary because `RUSTC_WRAPPER` mode passes
//! a path as argv[1] (the real rustc binary), which clap would reject as
//! an unknown subcommand. The check in `main.rs` runs before clap
//! parsing so the process never hits the normal CLI dispatch.
//!
//! ## Performance
//!
//! The wrapper adds ~1ms of fork+exec overhead per rustc invocation.
//! This is negligible compared to actual compilation time.

use std::process;

/// Env var set by `anchor debugger` before calling `cargo build-sbf`.
/// When present, the process knows it was invoked as a RUSTC_WRAPPER
/// and should rewrite args instead of running the normal CLI.
pub const WRAPPER_SENTINEL: &str = "__ANCHOR_RUSTC_WRAPPER";
pub const DEBUGGER_MODE: &str = "debugger";
pub const PRIVATE_MODE: &str = "private";
pub const CHAIN_WRAPPER: &str = "__ANCHOR_CHAIN_RUSTC_WRAPPER";

/// If we're running as a RUSTC_WRAPPER (sentinel env var is set),
/// rewrite the rustc args and exec the real compiler. Never returns.
///
/// If we're NOT in wrapper mode, returns `false` so the caller can
/// proceed with normal CLI parsing.
pub fn maybe_exec_as_wrapper() -> bool {
    let Some(mode) = std::env::var_os(WRAPPER_SENTINEL) else {
        return false;
    };
    let mode = mode.to_string_lossy();

    let args: Vec<String> = std::env::args().collect();
    // RUSTC_WRAPPER invocation: argv[0]=anchor, argv[1]=rustc, argv[2..]=args
    if args.len() < 2 {
        eprintln!("anchor rustc-wrapper: expected <rustc> <args...>");
        process::exit(1);
    }

    let rustc = &args[1];
    let cwd = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_default();

    let rewritten = rewrite_args(&mode, &args[2..], &cwd);

    let chained_wrapper = std::env::var_os(CHAIN_WRAPPER);
    let (compiler, compiler_args) = match chained_wrapper {
        Some(wrapper) => {
            let mut compiler_args = Vec::with_capacity(rewritten.len() + 1);
            compiler_args.push(rustc.clone());
            compiler_args.extend(rewritten);
            (wrapper, compiler_args)
        }
        None => (rustc.into(), rewritten),
    };

    let status = process::Command::new(&compiler)
        .args(&compiler_args)
        .status()
        .unwrap_or_else(|e| {
            eprintln!(
                "anchor rustc-wrapper: failed to exec {}: {e}",
                compiler.to_string_lossy()
            );
            process::exit(1);
        });

    process::exit(status.code().unwrap_or(1));
}

fn rewrite_args(mode: &str, args: &[String], cwd: &str) -> Vec<String> {
    let mut rewritten: Vec<String> = args
        .iter()
        .map(|arg| {
            if mode == DEBUGGER_MODE && arg == "-Zremap-cwd-prefix=" {
                format!("-Zremap-cwd-prefix={cwd}")
            } else {
                arg.clone()
            }
        })
        .collect();

    let is_sbf_compile = rewritten
        .windows(2)
        .any(|args| args[0] == "--target" && (args[1].contains("sbf") || args[1].contains("bpf")))
        || rewritten.iter().any(|arg| {
            arg.strip_prefix("--target=")
                .is_some_and(|target| target.contains("sbf") || target.contains("bpf"))
        });
    if mode == PRIVATE_MODE && is_sbf_compile {
        rewritten.extend([
            "-Zlocation-detail=none".to_owned(),
            "-Cdebuginfo=0".to_owned(),
            "-Cstrip=symbols".to_owned(),
        ]);
    }
    rewritten
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).to_owned()).collect()
    }

    #[test]
    fn debugger_restores_only_the_cwd_remap() {
        assert_eq!(
            rewrite_args(
                DEBUGGER_MODE,
                &args(&["-Zremap-cwd-prefix=", "--crate-name", "fixture"]),
                "/workspace"
            ),
            args(&["-Zremap-cwd-prefix=/workspace", "--crate-name", "fixture"])
        );
    }

    #[test]
    fn private_flags_apply_only_to_sbf_compilations() {
        let sbf = rewrite_args(
            PRIVATE_MODE,
            &args(&[
                "--crate-name",
                "fixture",
                "--target",
                "sbpf-solana-solana",
                "--cfg",
                "feature=\"custom\"",
            ]),
            "/workspace",
        );
        assert!(sbf.ends_with(&args(&[
            "-Zlocation-detail=none",
            "-Cdebuginfo=0",
            "-Cstrip=symbols"
        ])));
        assert!(sbf.contains(&"feature=\"custom\"".to_owned()));

        let host_probe = args(&["-vV"]);
        assert_eq!(
            rewrite_args(PRIVATE_MODE, &host_probe, "/workspace"),
            host_probe
        );
    }
}
