use {
    anyhow::{anyhow, bail, Context, Result},
    object::{Object, ObjectSection, ObjectSymbol, SymbolKind},
    std::{fs, ops::Range, path::Path},
};

const SECURITY_TXT_BEGIN: &[u8] = b"=======BEGIN SECURITY.TXT V1=======\0";
const SECURITY_TXT_END: &[u8] = b"=======END SECURITY.TXT V1=======\0";

const ANCHOR_DIAGNOSTICS: &[&[u8]] = &[
    b"Instruction: ",
    b"AnchorError occurred",
    b"AnchorError thrown in",
    b"AnchorError caused by account",
    b"ProgramError occurred",
    b"ProgramError thrown in",
    b"ProgramError caused by account",
    b"Error Code:",
    b"Error Number:",
    b"Error Message:",
    b"Left:",
    b"Right:",
];

pub fn finalize_artifact(
    path: &Path,
    program_name: &str,
    workspace_root: Option<&Path>,
) -> Result<()> {
    let mut bytes = fs::read(path)
        .with_context(|| format!("read private program artifact {}", path.display()))?;
    let data_ranges = private_data_ranges(&bytes, path)?;
    scrub_source_paths(&mut bytes, &data_ranges, workspace_root);
    audit_artifact(&bytes, path, program_name, workspace_root)?;
    replace_atomically(path, &bytes)
}

fn private_data_ranges(bytes: &[u8], path: &Path) -> Result<Vec<Range<usize>>> {
    let file = object::File::parse(bytes)
        .with_context(|| format!("parse private program ELF {}", path.display()))?;
    Ok(file
        .sections()
        .filter_map(|section| {
            matches!(section.name().ok()?, ".rodata" | ".data.rel.ro")
                .then(|| section.file_range())
                .flatten()
        })
        .filter_map(|(offset, size)| {
            let start = usize::try_from(offset).ok()?;
            let size = usize::try_from(size).ok()?;
            let end = start.checked_add(size)?;
            (end <= bytes.len()).then_some(start..end)
        })
        .collect())
}

fn replace_atomically(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("private program artifact has no parent: {}", path.display()))?;
    let file_name = path.file_name().ok_or_else(|| {
        anyhow!(
            "private program artifact has no file name: {}",
            path.display()
        )
    })?;
    let temporary = parent.join(format!(
        ".{}.anchor-private-{}.tmp",
        file_name.to_string_lossy(),
        std::process::id()
    ));
    let permissions = fs::metadata(path)?.permissions();
    fs::write(&temporary, bytes)
        .with_context(|| format!("write temporary private artifact {}", temporary.display()))?;
    fs::set_permissions(&temporary, permissions)?;
    fs::rename(&temporary, path).with_context(|| {
        format!(
            "replace private program artifact {} with {}",
            path.display(),
            temporary.display()
        )
    })?;
    Ok(())
}

fn audit_artifact(
    bytes: &[u8],
    path: &Path,
    program_name: &str,
    workspace_root: Option<&Path>,
) -> Result<()> {
    let file = object::File::parse(bytes)
        .with_context(|| format!("parse private program ELF {}", path.display()))?;

    audit_sections(&file)?;
    audit_dynamic_symbols(&file)?;
    audit_security_txt(bytes)?;

    let strings = printable_strings(bytes);
    if strings
        .iter()
        .any(|string| looks_like_source_path(string, workspace_root))
    {
        bail!("private program audit failed: source path string remains in artifact");
    }
    if ANCHOR_DIAGNOSTICS.iter().any(|template| {
        bytes
            .windows(template.len())
            .any(|window| window == *template)
    }) {
        bail!("private program audit failed: Anchor diagnostic template remains in artifact");
    }

    println!(
        "Private program audit passed for {program_name}: {} remaining printable strings",
        strings.len()
    );
    Ok(())
}

fn scrub_source_paths(
    bytes: &mut [u8],
    data_ranges: &[Range<usize>],
    workspace_root: Option<&Path>,
) {
    let mut scrub_ranges = Vec::new();
    for data_range in data_ranges {
        let section = &bytes[data_range.clone()];
        let string_ranges = printable_string_ranges(section);
        for string_range in string_ranges {
            let string = &section[string_range.clone()];
            for path_range in source_path_ranges(string, workspace_root) {
                let start = data_range.start + string_range.start + path_range.start;
                let end = data_range.start + string_range.start + path_range.end;
                scrub_ranges.push(start..end);
            }
        }
    }
    scrub_ranges.sort_by_key(|range| (range.start, range.end));
    scrub_ranges.dedup();
    for range in scrub_ranges {
        bytes[range].fill(0);
    }
}

fn audit_sections(file: &object::File<'_>) -> Result<()> {
    let forbidden = file.sections().filter_map(|section| {
        let name = section.name().ok()?;
        (name == ".symtab"
            || name == ".strtab"
            || name.starts_with(".debug")
            || name.starts_with(".zdebug"))
        .then_some(name.to_owned())
    });
    let count = forbidden.count();
    if count != 0 {
        bail!("private program audit failed: {count} debug or static symbol sections remain");
    }
    Ok(())
}

fn audit_dynamic_symbols(file: &object::File<'_>) -> Result<()> {
    let mut unexpected = 0usize;
    for symbol in file.dynamic_symbols() {
        let Ok(name) = symbol.name() else {
            unexpected += 1;
            continue;
        };
        if name.is_empty() || symbol.kind() == SymbolKind::Section {
            continue;
        }

        let allowed = if symbol.is_undefined() {
            is_allowed_runtime_import(name)
        } else {
            matches!(
                name,
                "entrypoint" | "custom_panic" | "custom_alloc_free" | "SECURITY_TXT"
            )
        };
        if !allowed {
            unexpected += 1;
        }
    }

    if unexpected != 0 {
        bail!("private program audit failed: {unexpected} unexpected dynamic symbols remain");
    }
    Ok(())
}

fn is_allowed_runtime_import(name: &str) -> bool {
    name.starts_with("sol_")
        || matches!(
            name,
            "abort" | "memcmp" | "memcpy" | "memmove" | "memset" | "rust_begin_unwind"
        )
}

fn audit_security_txt(bytes: &[u8]) -> Result<()> {
    let starts = find_all(bytes, SECURITY_TXT_BEGIN);
    if starts.len() > 1 {
        bail!("private program audit failed: multiple SECURITY_TXT records remain");
    }
    let Some(start) = starts.first().copied() else {
        return Ok(());
    };
    let body_start = start + SECURITY_TXT_BEGIN.len();
    let relative_end = bytes[body_start..]
        .windows(SECURITY_TXT_END.len())
        .position(|window| window == SECURITY_TXT_END)
        .ok_or_else(|| anyhow!("private program audit failed: unterminated SECURITY_TXT record"))?;
    let body = &bytes[body_start..body_start + relative_end];
    let parts = body
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.len() % 2 != 0 {
        bail!("private program audit failed: malformed SECURITY_TXT record");
    }

    let mut source_release = 0usize;
    let mut source_revision = 0usize;
    for pair in parts.chunks_exact(2) {
        match pair[0] {
            b"source_release" => source_release += 1,
            b"source_revision" => source_revision += 1,
            _ => bail!("private program audit failed: non-minimal SECURITY_TXT field remains"),
        }
    }
    if source_release > 1 || source_revision > 1 {
        bail!("private program audit failed: duplicate SECURITY_TXT provenance field");
    }
    Ok(())
}

fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    haystack
        .windows(needle.len())
        .enumerate()
        .filter_map(|(index, window)| (window == needle).then_some(index))
        .collect()
}

fn printable_strings(bytes: &[u8]) -> Vec<&[u8]> {
    printable_string_ranges(bytes)
        .into_iter()
        .map(|range| &bytes[range])
        .collect()
}

fn printable_string_ranges(bytes: &[u8]) -> Vec<Range<usize>> {
    let mut strings = Vec::new();
    let mut start = None;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if byte.is_ascii_graphic() || byte == b' ' {
            start.get_or_insert(index);
        } else if let Some(begin) = start.take() {
            if index - begin >= 4 {
                strings.push(begin..index);
            }
        }
    }
    if let Some(begin) = start {
        if bytes.len() - begin >= 4 {
            strings.push(begin..bytes.len());
        }
    }
    strings
}

fn looks_like_source_path(string: &[u8], workspace_root: Option<&Path>) -> bool {
    !source_path_ranges(string, workspace_root).is_empty()
}

fn source_path_ranges(string: &[u8], workspace_root: Option<&Path>) -> Vec<Range<usize>> {
    let lower = string
        .iter()
        .map(u8::to_ascii_lowercase)
        .collect::<Vec<_>>();
    if lower.windows(3).any(|window| window == b"://") {
        return Vec::new();
    }

    let mut starts = Vec::new();
    if let Some(workspace_root) = workspace_root.and_then(Path::to_str) {
        starts.extend(find_all(
            &lower,
            workspace_root.to_ascii_lowercase().as_bytes(),
        ));
    }

    for marker in [
        b"/.cargo/registry/".as_slice(),
        b"/rust/library/",
        b"/platform-tools/",
    ] {
        for marker_start in find_all(&lower, marker) {
            starts.push(
                lower[..=marker_start]
                    .iter()
                    .position(|byte| *byte == b'/')
                    .unwrap_or(marker_start),
            );
        }
    }

    for prefix in [
        b"programs/".as_slice(),
        b"examples/",
        b"tests/",
        b"library/",
        b"src/",
    ] {
        starts.extend(find_all(&lower, prefix));
    }

    let mut ranges = starts
        .into_iter()
        .filter_map(|start| {
            lower[start..]
                .windows(3)
                .position(|window| window == b".rs")
                .map(|relative_end| start..start + relative_end + 3)
        })
        .collect::<Vec<_>>();
    ranges.sort_by_key(|range| (range.start, range.end));
    ranges.dedup();
    ranges
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_txt_accepts_only_provenance() {
        let mut bytes = SECURITY_TXT_BEGIN.to_vec();
        bytes.extend_from_slice(b"source_release\0v1\0source_revision\0abc\0");
        bytes.extend_from_slice(SECURITY_TXT_END);
        assert!(audit_security_txt(&bytes).is_ok());

        let mut bytes = SECURITY_TXT_BEGIN.to_vec();
        bytes.extend_from_slice(b"name\0secret\0");
        bytes.extend_from_slice(SECURITY_TXT_END);
        assert!(audit_security_txt(&bytes).is_err());
    }

    #[test]
    fn source_path_detection_is_specific() {
        assert!(looks_like_source_path(b"programs/demo/src/lib.rs", None));
        assert!(looks_like_source_path(b"diagnosticsrc/lib.rs", None));
        assert!(!looks_like_source_path(b"semantic-seed", None));
        assert!(!looks_like_source_path(
            b"https://example.com/src/metadata.rs",
            None
        ));
    }

    #[test]
    fn source_path_scrub_preserves_adjacent_and_url_strings() {
        let mut bytes = b"KEEPsrc/lib.rsTAIL\0https://example.com/src/metadata.rs\0".to_vec();
        let len = bytes.len();
        let data_range = 0..len;
        scrub_source_paths(&mut bytes, std::slice::from_ref(&data_range), None);

        assert!(bytes.starts_with(b"KEEP"));
        assert!(bytes.windows(4).any(|window| window == b"TAIL"));
        assert!(bytes
            .windows(b"https://example.com/src/metadata.rs".len())
            .any(|window| window == b"https://example.com/src/metadata.rs"));
        assert!(!bytes.windows(10).any(|window| window == b"src/lib.rs"));
    }

    #[test]
    fn source_path_scrub_is_limited_to_selected_sections() {
        let mut bytes = b"src/outside.rs\0src/inside.rs\0".to_vec();
        let inside_start = b"src/outside.rs\0".len();
        let len = bytes.len();
        let data_range = inside_start..len;
        scrub_source_paths(&mut bytes, std::slice::from_ref(&data_range), None);

        assert!(bytes
            .windows(b"src/outside.rs".len())
            .any(|window| window == b"src/outside.rs"));
        assert!(!bytes
            .windows(b"src/inside.rs".len())
            .any(|window| window == b"src/inside.rs"));
    }

    #[test]
    fn failed_audit_does_not_mutate_the_artifact() {
        let directory = tempfile::tempdir().unwrap();
        let artifact = directory.path().join("invalid.so");
        let original = b"programs/private/src/lib.rs";
        fs::write(&artifact, original).unwrap();

        assert!(finalize_artifact(&artifact, "invalid", None).is_err());
        assert_eq!(fs::read(artifact).unwrap(), original);
    }
}
