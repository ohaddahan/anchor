use {
    object::{Object, ObjectSection, ObjectSymbol},
    private_program_runtime_tests::{
        exercise_artifact, ExerciseResult, FailureObservation, SuccessObservation,
    },
    sha2::{Digest, Sha256},
    std::{collections::BTreeMap, fs, path::Path, process::Command},
};

const SECURITY_TXT_BEGIN: &[u8] = b"=======BEGIN SECURITY.TXT V1=======\0";
const SECURITY_TXT_END: &[u8] = b"=======END SECURITY.TXT V1=======\0";

#[derive(Debug)]
struct ArtifactMetrics {
    size: u64,
    sections: BTreeMap<String, u64>,
    printable_strings: usize,
    printable_bytes: usize,
    source_paths: usize,
    static_symbol_sections: usize,
    debug_sections: usize,
    dynamic_symbols: usize,
    defined_dynamic_symbols: Vec<String>,
    security_fields: Vec<String>,
    panic_literal: bool,
    semantic_log: bool,
}

struct ReportData<'a> {
    normal: &'a ArtifactMetrics,
    private: &'a ArtifactMetrics,
    normal_secondary: &'a ArtifactMetrics,
    private_secondary: &'a ArtifactMetrics,
    normal_runtime: &'a ExerciseResult,
    private_runtime: &'a ExerciseResult,
    idl_hash: &'a str,
    toolchain: &'a str,
}

fn main() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("runtime-tests has a workspace parent");
    let artifacts = workspace.join("target/private-program-artifacts");
    let reports = workspace.join("reports");

    let normal_path = artifacts.join("normal.so");
    let private_path = artifacts.join("private.so");
    let normal_secondary_path = artifacts.join("normal-secondary.so");
    let private_secondary_path = artifacts.join("private-secondary.so");
    let normal_idl_path = artifacts.join("normal.json");
    let private_idl_path = artifacts.join("private.json");

    let normal = metrics(&normal_path);
    let private = metrics(&private_path);
    let normal_secondary = metrics(&normal_secondary_path);
    let private_secondary = metrics(&private_secondary_path);
    let normal_runtime = exercise_artifact(&normal_path);
    let private_runtime = exercise_artifact(&private_path);
    assert!(
        normal.semantic_log,
        "normal ELF lost the semantic log literal"
    );
    assert!(
        private.semantic_log,
        "private ELF lost the semantic log literal"
    );
    let normal_idl = fs::read(&normal_idl_path).expect("read normal IDL");
    let private_idl = fs::read(&private_idl_path).expect("read private IDL");
    assert_eq!(normal_idl, private_idl, "normal and private IDLs differ");
    let idl_hash = sha256(&normal_idl);
    let toolchain = toolchain_version();

    let report = ReportData {
        normal: &normal,
        private: &private,
        normal_secondary: &normal_secondary,
        private_secondary: &private_secondary,
        normal_runtime: &normal_runtime,
        private_runtime: &private_runtime,
        idl_hash: &idl_hash,
        toolchain: &toolchain,
    };
    let markdown = markdown_report(&report);
    let html = html_report(&report);

    fs::create_dir_all(&reports).expect("create reports directory");
    fs::write(reports.join("private-program-comparison.md"), markdown)
        .expect("write Markdown report");
    fs::write(reports.join("private-program-comparison.html"), html).expect("write HTML report");
    println!("Generated {}", reports.display());
}

fn metrics(path: &Path) -> ArtifactMetrics {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let file = object::File::parse(bytes.as_slice())
        .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()));
    let sections = file
        .sections()
        .filter_map(|section| Some((section.name().ok()?.to_owned(), section.size())))
        .collect::<BTreeMap<_, _>>();
    let strings = printable_strings(&bytes);
    let source_paths = strings
        .iter()
        .filter(|string| {
            !string.windows(3).any(|window| window == b"://")
                && (string.windows(5).any(|window| window == b"/src/")
                    || string.windows(5).any(|window| window == b"\\src\\")
                    || string
                        .windows(16)
                        .any(|window| window == b"/.cargo/registry"))
        })
        .count();
    let static_symbol_sections = sections
        .keys()
        .filter(|name| matches!(name.as_str(), ".symtab" | ".strtab"))
        .count();
    let debug_sections = sections
        .keys()
        .filter(|name| name.starts_with(".debug") || name.starts_with(".zdebug"))
        .count();
    let dynamic_symbols = file.dynamic_symbols().count();
    let defined_dynamic_symbols = file
        .dynamic_symbols()
        .filter(|symbol| !symbol.is_undefined())
        .filter_map(|symbol| symbol.name().ok().map(str::to_owned))
        .filter(|name| !name.is_empty())
        .collect();

    ArtifactMetrics {
        size: bytes.len() as u64,
        sections,
        printable_strings: strings.len(),
        printable_bytes: strings.iter().map(|string| string.len()).sum(),
        source_paths,
        static_symbol_sections,
        debug_sections,
        dynamic_symbols,
        defined_dynamic_symbols,
        security_fields: security_fields(&bytes),
        panic_literal: contains(&bytes, b"PRIVATE_FIXTURE_PANIC_DIAGNOSTIC"),
        semantic_log: contains(&bytes, b"PRIVATE_FIXTURE_SEMANTIC_RUNTIME_LOG"),
    }
}

fn printable_strings(bytes: &[u8]) -> Vec<&[u8]> {
    let mut strings = Vec::new();
    let mut start = None;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if byte.is_ascii_graphic() || byte == b' ' {
            start.get_or_insert(index);
        } else if let Some(begin) = start.take() {
            if index - begin >= 4 {
                strings.push(&bytes[begin..index]);
            }
        }
    }
    if let Some(begin) = start {
        if bytes.len() - begin >= 4 {
            strings.push(&bytes[begin..]);
        }
    }
    strings
}

fn security_fields(bytes: &[u8]) -> Vec<String> {
    let Some(start) = find(bytes, SECURITY_TXT_BEGIN) else {
        return Vec::new();
    };
    let body_start = start + SECURITY_TXT_BEGIN.len();
    let Some(relative_end) = find(&bytes[body_start..], SECURITY_TXT_END) else {
        return Vec::new();
    };
    bytes[body_start..body_start + relative_end]
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .step_by(2)
        .filter_map(|field| std::str::from_utf8(field).ok().map(str::to_owned))
        .collect()
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    find(haystack, needle).is_some()
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn toolchain_version() -> String {
    Command::new("cargo")
        .args(["build-sbf", "--version"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|output| {
            output
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .collect::<Vec<_>>()
                .join(" · ")
        })
        .unwrap_or_else(|| "cargo-build-sbf version unavailable".to_owned())
}

fn section(metrics: &ArtifactMetrics, name: &str) -> u64 {
    metrics.sections.get(name).copied().unwrap_or_default()
}

fn saved(normal: u64, private: u64) -> u64 {
    normal.saturating_sub(private)
}

fn reduction(normal: u64, private: u64) -> f64 {
    if normal == 0 {
        0.0
    } else {
        saved(normal, private) as f64 * 100.0 / normal as f64
    }
}

fn number(value: u64) -> String {
    let digits = value.to_string();
    let mut output = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, character) in digits.chars().enumerate() {
        if index != 0 && (digits.len() - index).is_multiple_of(3) {
            output.push(',');
        }
        output.push(character);
    }
    output
}

fn relevant_logs(observation: &FailureObservation) -> String {
    observation
        .logs
        .iter()
        .filter(|log| log.contains("Program log:") || log.contains("failed:"))
        .cloned()
        .collect::<Vec<_>>()
        .join("\n")
}

fn success_logs(observation: &SuccessObservation) -> String {
    observation.logs.join("\n")
}

fn markdown_report(report: &ReportData<'_>) -> String {
    let normal = report.normal;
    let private = report.private;
    let normal_secondary = report.normal_secondary;
    let private_secondary = report.private_secondary;
    let normal_runtime = report.normal_runtime;
    let private_runtime = report.private_runtime;
    let idl_hash = report.idl_hash;
    let toolchain = report.toolchain;
    let section_rows = [".text", ".rodata", ".data.rel.ro", ".rel.dyn"]
        .into_iter()
        .map(|name| {
            let normal_size = section(normal, name);
            let private_size = section(private, name);
            format!(
                "| `{name}` | {} B | {} B | {:.2}% |",
                number(normal_size),
                number(private_size),
                reduction(normal_size, private_size)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let normal_logs = relevant_logs(&normal_runtime.comparison);
    let private_logs = relevant_logs(&private_runtime.comparison);
    let normal_success_logs = success_logs(&normal_runtime.set_value);
    let private_success_logs = success_logs(&private_runtime.set_value);

    format!(
        r#"# Anchor private program build comparison

> Generated from the purpose-built SBF fixture by `tests/private-program/test.sh`.

## Outcome

- **{size_reduction:.2}% smaller** primary fixture ELF: {normal_size} B → {private_size} B.
- **{secondary_reduction:.2}% smaller** minimal secondary ELF: {secondary_normal} B → {secondary_private} B.
- **{printable_reduction:.2}% fewer printable bytes** and {normal_paths} → {private_paths} detected source-path strings.
- **Same program behavior:** state ends at `42`; both modes return custom error code `6000`.
- **Same off-chain API:** normal and private IDLs are byte-identical (`sha256:{idl_hash}`).

Private errors do more than remove the file path. Normal mode logs the instruction name, file and line, error name, message, and compared values. Private mode emits none of that Anchor diagnostic log; the Solana transaction result still exposes the stable numeric code.

## Artifact overview

| Measurement | Normal | Private | Reduction |
|---|---:|---:|---:|
| ELF size | {normal_size} B | {private_size} B | {size_reduction:.2}% |
| Printable strings | {normal_strings} | {private_strings} | {string_reduction:.2}% |
| Printable bytes | {normal_printable} | {private_printable} | {printable_reduction:.2}% |
| Detected source paths | {normal_paths} | {private_paths} | {path_reduction} removed |
| Security metadata fields | {normal_security} | {private_security} | release + revision only |
| Dynamic symbols | {normal_dynamic} | {private_dynamic} | required ABI retained |
| Static symbol sections | {normal_static} | {private_static} | absent in both deploy ELFs |
| Debug sections | {normal_debug} | {private_debug} | absent in both deploy ELFs |

## Section density

| Section | Normal | Private | Reduction |
|---|---:|---:|---:|
{section_rows}

## Successful instruction comparison

Both executions write the same value (`42`) and succeed. The normal build adds an Anchor-generated instruction-name log; private mode removes it while retaining Solana's loader-level `invoke`, `consumed`, and `success` lines.

### Normal

```text
{normal_success_logs}
```

### Private

```text
{private_success_logs}
```

The successful `set_value` instruction consumed **{normal_success_cu} CU normally** and **{private_success_cu} CU privately** ({success_cu_reduction:.2}% less for this fixture).

## Runtime error comparison

Both executions return `{normal_error}` / `{private_error}`.

### Normal

```text
{normal_logs}
```

### Private

```text
{private_logs}
```

The comparison failure consumed **{normal_cu} CU normally** and **{private_cu} CU privately** ({cu_reduction:.2}% less for this fixture). This is a fixture measurement, not a general compute guarantee.

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
| Panic message literal in ELF | {normal_panic} | {private_panic} |
| Security fields | {normal_security_fields} | {private_security_fields} |
| Defined dynamic exports | {normal_exports} | {private_exports} |

The panic literal is intentionally reported separately: the private panic handler is silent, but arbitrary user-authored panic strings are not rewritten because they cannot be safely distinguished from semantic program strings after linking.

## Methodology

- Toolchain: {toolchain}
- Normal: `anchor build --no-private --ignore-keys`
- Private: `anchor build --private --ignore-keys`
- Runtime: the same normal/private ELFs executed in LiteSVM.
- Coverage: successful state writes, `error!`, `err!`, `require!`, comparison/key macros, account constraints, panic behavior, explicit logs, mixed normal/private multi-program workspaces, manifest feature authority, normal debug symbols, custom SBF output directories, `--no-idl`, and IDL equality.
"#,
        size_reduction = reduction(normal.size, private.size),
        normal_size = number(normal.size),
        private_size = number(private.size),
        secondary_reduction = reduction(normal_secondary.size, private_secondary.size),
        secondary_normal = number(normal_secondary.size),
        secondary_private = number(private_secondary.size),
        printable_reduction = reduction(
            normal.printable_bytes as u64,
            private.printable_bytes as u64
        ),
        normal_paths = normal.source_paths,
        private_paths = private.source_paths,
        idl_hash = idl_hash,
        normal_strings = normal.printable_strings,
        private_strings = private.printable_strings,
        string_reduction = reduction(
            normal.printable_strings as u64,
            private.printable_strings as u64
        ),
        normal_printable = number(normal.printable_bytes as u64),
        private_printable = number(private.printable_bytes as u64),
        path_reduction = normal.source_paths.saturating_sub(private.source_paths),
        normal_security = normal.security_fields.len(),
        private_security = private.security_fields.len(),
        normal_dynamic = normal.dynamic_symbols,
        private_dynamic = private.dynamic_symbols,
        normal_static = normal.static_symbol_sections,
        private_static = private.static_symbol_sections,
        normal_debug = normal.debug_sections,
        private_debug = private.debug_sections,
        normal_success_logs = normal_success_logs,
        private_success_logs = private_success_logs,
        normal_success_cu = number(normal_runtime.set_value.compute_units),
        private_success_cu = number(private_runtime.set_value.compute_units),
        success_cu_reduction = reduction(
            normal_runtime.set_value.compute_units,
            private_runtime.set_value.compute_units
        ),
        normal_error = normal_runtime.comparison.error,
        private_error = private_runtime.comparison.error,
        normal_cu = number(normal_runtime.comparison.compute_units),
        private_cu = number(private_runtime.comparison.compute_units),
        cu_reduction = reduction(
            normal_runtime.comparison.compute_units,
            private_runtime.comparison.compute_units
        ),
        normal_panic = yes_no(normal.panic_literal),
        private_panic = yes_no(private.panic_literal),
        normal_security_fields = normal.security_fields.join(", "),
        private_security_fields = private.security_fields.join(", "),
        normal_exports = normal.defined_dynamic_symbols.join(", "),
        private_exports = private.defined_dynamic_symbols.join(", "),
    )
}

fn html_report(report: &ReportData<'_>) -> String {
    let normal = report.normal;
    let private = report.private;
    let normal_secondary = report.normal_secondary;
    let private_secondary = report.private_secondary;
    let normal_runtime = report.normal_runtime;
    let private_runtime = report.private_runtime;
    let idl_hash = report.idl_hash;
    let toolchain = report.toolchain;
    let size_reduction = reduction(normal.size, private.size);
    let printable_reduction = reduction(
        normal.printable_bytes as u64,
        private.printable_bytes as u64,
    );
    let cu_reduction = reduction(
        normal_runtime.comparison.compute_units,
        private_runtime.comparison.compute_units,
    );
    let success_cu_reduction = reduction(
        normal_runtime.set_value.compute_units,
        private_runtime.set_value.compute_units,
    );
    let section_rows = [".text", ".rodata", ".data.rel.ro", ".rel.dyn"]
        .into_iter()
        .map(|name| {
            let normal_size = section(normal, name);
            let private_size = section(private, name);
            format!(
                "<tr><th><code>{name}</code></th><td>{}</td><td>{}</td><td class=\"gain\">−{:.2}%</td></tr>",
                number(normal_size),
                number(private_size),
                reduction(normal_size, private_size)
            )
        })
        .collect::<String>();

    let template = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark">
  <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='12' fill='%23080b0d'/%3E%3Cpath d='M16 45 30 14h8L24 45zm18 0 8-18h7l-8 18z' fill='%23c9ff45'/%3E%3C/svg%3E">
  <title>Anchor Private Build — Forensic Comparison</title>
  <style>
    :root { --ink:#080b0d; --paper:#e8e4d8; --muted:#98a09e; --line:#293137; --acid:#c9ff45; --ember:#ff6b35; --cyan:#61dafb; }
    * { box-sizing:border-box; }
    html { background:var(--ink); scroll-behavior:smooth; }
    body { margin:0; color:var(--paper); font-family:"Azeret Mono","IBM Plex Mono","Courier New",monospace; background:radial-gradient(circle at 86% 5%,rgba(201,255,69,.13),transparent 26rem),radial-gradient(circle at 10% 42%,rgba(97,218,251,.08),transparent 30rem),linear-gradient(rgba(255,255,255,.025) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.025) 1px,transparent 1px),var(--ink); background-size:auto,auto,34px 34px,34px 34px,auto; }
    body:before { content:""; position:fixed; inset:0; pointer-events:none; opacity:.22; background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 180 180' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.92' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='.13'/%3E%3C/svg%3E"); }
    main { width:min(1180px,calc(100% - 32px)); margin:auto; padding:28px 0 80px; }
    .mast { border-top:1px solid var(--paper); display:grid; grid-template-columns:1fr auto; gap:20px; padding:14px 0 72px; color:var(--muted); font-size:11px; letter-spacing:.12em; text-transform:uppercase; }
    .hero { display:grid; grid-template-columns:minmax(0,1.2fr) minmax(360px,.8fr); gap:48px; align-items:end; padding-bottom:64px; }
    .kicker { color:var(--acid); font-size:12px; letter-spacing:.22em; text-transform:uppercase; }
    h1,h2 { font-family:"Bodoni Moda","Iowan Old Style","Palatino Linotype",serif; font-weight:500; letter-spacing:-.045em; }
    h1 { margin:18px 0 22px; font-size:clamp(54px,9vw,118px); line-height:.82; max-width:850px; }
    h1 em { color:var(--acid); font-style:italic; }
    .dek { max-width:690px; color:#bcc3c0; font:15px/1.7 "Azeret Mono","IBM Plex Mono",monospace; }
    .hero-stat { border-left:1px solid var(--line); padding-left:28px; }
    .hero-stat strong { display:block; color:var(--acid); font-family:"Bodoni Moda","Iowan Old Style",serif; font-size:clamp(72px,7.5vw,104px); font-weight:500; line-height:.75; letter-spacing:-.07em; white-space:nowrap; }
    .hero-stat span { display:block; margin-top:18px; color:var(--muted); font-size:11px; letter-spacing:.14em; text-transform:uppercase; }
    .rule { height:7px; background:linear-gradient(90deg,var(--acid) 0 var(--size-width),var(--line) var(--size-width)); margin:22px 0 8px; }
    .section { border-top:1px solid var(--line); padding:54px 0; }
    .section-head { display:grid; grid-template-columns:150px 1fr; gap:24px; margin-bottom:34px; }
    .index { color:var(--acid); font-size:12px; letter-spacing:.18em; }
    h2 { margin:0; font-size:clamp(34px,5vw,66px); line-height:.95; }
    .cards { display:grid; grid-template-columns:repeat(4,1fr); gap:1px; background:var(--line); border:1px solid var(--line); }
    .card { background:#0c1013; padding:24px; min-height:176px; }
    .card .label { color:var(--muted); font-size:10px; letter-spacing:.13em; text-transform:uppercase; }
    .card strong { display:block; margin:25px 0 6px; color:var(--paper); font-family:"Bodoni Moda","Iowan Old Style",serif; font-size:42px; font-weight:500; letter-spacing:-.04em; }
    .card .delta,.gain { color:var(--acid); }
    table { width:100%; border-collapse:collapse; font-size:13px; }
    th,td { border-bottom:1px solid var(--line); padding:15px 12px; text-align:right; }
    th:first-child,td:first-child { text-align:left; }
    thead th { color:var(--muted); font-size:10px; letter-spacing:.13em; text-transform:uppercase; }
    code { color:var(--cyan); }
    .terminal-grid { display:grid; grid-template-columns:1fr 1fr; gap:16px; }
    .terminal { min-width:0; border:1px solid var(--line); background:#050708; box-shadow:0 22px 80px rgba(0,0,0,.28); }
    .terminal header { display:flex; justify-content:space-between; padding:12px 14px; border-bottom:1px solid var(--line); color:var(--muted); font-size:10px; letter-spacing:.14em; text-transform:uppercase; }
    .terminal.normal header { border-left:4px solid var(--ember); }
    .terminal.private header { border-left:4px solid var(--acid); }
    pre { margin:0; min-height:270px; padding:22px; overflow:auto; white-space:pre-wrap; color:#c6ceca; font:12px/1.65 "Azeret Mono","IBM Plex Mono",monospace; }
    .callout { display:grid; grid-template-columns:1fr 2fr; gap:32px; margin-top:28px; padding:24px; border:1px solid rgba(201,255,69,.45); background:rgba(201,255,69,.055); }
    .callout strong { color:var(--acid); text-transform:uppercase; letter-spacing:.12em; font-size:11px; }
    .callout p { margin:0; color:#c4cbc7; line-height:1.65; }
    .check-grid { display:grid; grid-template-columns:repeat(2,1fr); gap:12px; }
    .check { display:flex; gap:13px; align-items:flex-start; border:1px solid var(--line); background:#0c1013; padding:17px; color:#c4cbc7; font-size:12px; line-height:1.55; }
    .check:before { content:"✓"; color:var(--acid); font-weight:700; }
    .hash { overflow-wrap:anywhere; color:var(--muted); font-size:11px; }
    footer { border-top:1px solid var(--paper); padding-top:18px; display:flex; justify-content:space-between; gap:20px; color:var(--muted); font-size:10px; line-height:1.6; text-transform:uppercase; letter-spacing:.1em; }
    @media (max-width:820px) { .hero,.section-head,.callout { grid-template-columns:1fr; } .cards { grid-template-columns:1fr 1fr; } .terminal-grid { grid-template-columns:1fr; } .hero-stat { border-left:0; border-top:1px solid var(--line); padding:28px 0 0; } }
    @media (max-width:520px) { main { width:min(100% - 20px,1180px); } .cards,.check-grid { grid-template-columns:1fr; } th,td { padding:12px 6px; font-size:11px; } .mast { grid-template-columns:1fr; padding-bottom:48px; } }
    @media (prefers-reduced-motion:no-preference) { .hero>* { animation:rise .7s ease both; } .hero-stat { animation-delay:.12s; } @keyframes rise { from { opacity:0; transform:translateY(18px); } } }
  </style>
</head>
<body style="--size-width:__PRIVATE_REMAINDER__%">
<main>
  <div class="mast"><span>Anchor / SBF forensic build dossier</span><span>__TOOLCHAIN__</span></div>
  <section class="hero">
    <div><div class="kicker">Private program mode · measured</div><h1>Less surface.<br><em>Same protocol.</em></h1><p class="dek">A normal and private build of the same Anchor program, inspected at the ELF boundary and executed through the same LiteSVM flow. Numeric errors, state transitions, IDLs, and explicit protocol logs stay stable; framework diagnostics and provenance disappear.</p></div>
    <aside class="hero-stat"><strong>−__SIZE_REDUCTION__%</strong><span>primary ELF size</span><div class="rule"></div><span>__NORMAL_SIZE__ B → __PRIVATE_SIZE__ B</span></aside>
  </section>

  <section class="section"><div class="section-head"><span class="index">01 / PAYLOAD</span><h2>What changed on disk</h2></div>
    <div class="cards">
      <article class="card"><span class="label">ELF bytes</span><strong>__PRIVATE_SIZE__</strong><span class="delta">−__SIZE_SAVED__ B</span></article>
      <article class="card"><span class="label">Printable bytes</span><strong>__PRIVATE_PRINTABLE__</strong><span class="delta">−__PRINTABLE_REDUCTION__%</span></article>
      <article class="card"><span class="label">Source paths</span><strong>__PRIVATE_PATHS__</strong><span>from __NORMAL_PATHS__ normal</span></article>
      <article class="card"><span class="label">Minimal fixture</span><strong>−__SECONDARY_REDUCTION__%</strong><span>__SECONDARY_NORMAL__ → __SECONDARY_PRIVATE__ B</span></article>
    </div>
    <table><thead><tr><th>Section</th><th>Normal bytes</th><th>Private bytes</th><th>Reduction</th></tr></thead><tbody>__SECTION_ROWS__</tbody></table>
  </section>

  <section class="section"><div class="section-head"><span class="index">02 / SUCCESS</span><h2>Same result. Less narration.</h2></div>
    <div class="terminal-grid">
      <article class="terminal normal"><header><span>Normal / SetValue</span><span>__NORMAL_SUCCESS_CU__ CU</span></header><pre>__NORMAL_SUCCESS_LOGS__</pre></article>
      <article class="terminal private"><header><span>Private / SetValue</span><span>__PRIVATE_SUCCESS_CU__ CU</span></header><pre>__PRIVATE_SUCCESS_LOGS__</pre></article>
    </div>
    <div class="callout"><strong>Generated log removed</strong><p>Both executions write <code>42</code> and succeed. Private mode removes <code>Program log: Instruction: SetValue</code>; Solana's loader-level <code>invoke</code>, <code>consumed</code>, and <code>success</code> lines remain. This fixture uses <strong>__SUCCESS_CU_REDUCTION__% less CU</strong> on the successful path.</p></div>
  </section>

  <section class="section"><div class="section-head"><span class="index">03 / ERROR</span><h2>The code stays. The explanation goes.</h2></div>
    <div class="terminal-grid">
      <article class="terminal normal"><header><span>Normal / Custom(6000)</span><span>__NORMAL_CU__ CU</span></header><pre>__NORMAL_LOGS__</pre></article>
      <article class="terminal private"><header><span>Private / Custom(6000)</span><span>__PRIVATE_CU__ CU</span></header><pre>__PRIVATE_LOGS__</pre></article>
    </div>
    <div class="callout"><strong>Not only the path</strong><p>Normal mode exposes the instruction name, file and line, error name, full message, and compared values. Private mode emits no Anchor diagnostic log at all. Solana still returns the stable numeric custom code <code>6000</code>.</p></div>
  </section>

  <section class="section"><div class="section-head"><span class="index">04 / CONTRACT</span><h2>What remains invariant</h2></div>
    <div class="check-grid">
      <div class="check">Successful state transition ends at <code>42</code> in both builds.</div>
      <div class="check">Custom failures return <code>6000</code>; account constraints return <code>2000</code>.</div>
      <div class="check">Explicit <code>msg!</code>, <code>sol_log_data</code>, and a semantic URL containing <code>/src/</code> remain.</div>
      <div class="check">IDL bytes are identical: <span class="hash">sha256:__IDL_HASH__</span></div>
      <div class="check">Defined dynamic exports remain <code>__PRIVATE_EXPORTS__</code>.</div>
      <div class="check">Security metadata contracts from <code>__NORMAL_SECURITY__</code> to <code>__PRIVATE_SECURITY__</code>.</div>
    </div>
  </section>

  <section class="section"><div class="section-head"><span class="index">05 / LIMIT</span><h2>Privacy, not obfuscation</h2></div>
    <div class="callout"><strong>Honest boundary</strong><p>The panic handler is silent and locations are removed, but the user-authored panic literal remains in this ELF. It is not post-link scrubbed because arbitrary panic text cannot be safely distinguished from semantic protocol strings. Required loader exports and syscalls also remain.</p></div>
  </section>

  <footer><span>Generated by tests/private-program/test.sh</span><span>Mixed workspace · Debug · Custom out · LiteSVM · ELF audit</span></footer>
</main>
</body>
</html>
"#;

    template
        .replace(
            "__PRIVATE_REMAINDER__",
            &format!("{:.2}", 100.0 - size_reduction),
        )
        .replace("__TOOLCHAIN__", &escape_html(toolchain))
        .replace("__SIZE_REDUCTION__", &format!("{size_reduction:.2}"))
        .replace("__NORMAL_SIZE__", &number(normal.size))
        .replace("__PRIVATE_SIZE__", &number(private.size))
        .replace("__SIZE_SAVED__", &number(saved(normal.size, private.size)))
        .replace(
            "__PRIVATE_PRINTABLE__",
            &number(private.printable_bytes as u64),
        )
        .replace(
            "__PRINTABLE_REDUCTION__",
            &format!("{printable_reduction:.2}"),
        )
        .replace("__NORMAL_PATHS__", &normal.source_paths.to_string())
        .replace("__PRIVATE_PATHS__", &private.source_paths.to_string())
        .replace(
            "__SECONDARY_REDUCTION__",
            &format!(
                "{:.2}",
                reduction(normal_secondary.size, private_secondary.size)
            ),
        )
        .replace("__SECONDARY_NORMAL__", &number(normal_secondary.size))
        .replace("__SECONDARY_PRIVATE__", &number(private_secondary.size))
        .replace("__SECTION_ROWS__", &section_rows)
        .replace(
            "__NORMAL_SUCCESS_CU__",
            &number(normal_runtime.set_value.compute_units),
        )
        .replace(
            "__PRIVATE_SUCCESS_CU__",
            &number(private_runtime.set_value.compute_units),
        )
        .replace(
            "__SUCCESS_CU_REDUCTION__",
            &format!("{success_cu_reduction:.2}"),
        )
        .replace(
            "__NORMAL_SUCCESS_LOGS__",
            &escape_html(&success_logs(&normal_runtime.set_value)),
        )
        .replace(
            "__PRIVATE_SUCCESS_LOGS__",
            &escape_html(&success_logs(&private_runtime.set_value)),
        )
        .replace(
            "__NORMAL_CU__",
            &number(normal_runtime.comparison.compute_units),
        )
        .replace(
            "__PRIVATE_CU__",
            &number(private_runtime.comparison.compute_units),
        )
        .replace(
            "__NORMAL_LOGS__",
            &escape_html(&relevant_logs(&normal_runtime.comparison)),
        )
        .replace(
            "__PRIVATE_LOGS__",
            &escape_html(&relevant_logs(&private_runtime.comparison)),
        )
        .replace("__IDL_HASH__", idl_hash)
        .replace(
            "__PRIVATE_EXPORTS__",
            &escape_html(&private.defined_dynamic_symbols.join(", ")),
        )
        .replace(
            "__NORMAL_SECURITY__",
            &escape_html(&normal.security_fields.join(", ")),
        )
        .replace(
            "__PRIVATE_SECURITY__",
            &escape_html(&private.security_fields.join(", ")),
        )
        .replace("__CU_REDUCTION__", &format!("{cu_reduction:.2}"))
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "Present"
    } else {
        "Absent"
    }
}
