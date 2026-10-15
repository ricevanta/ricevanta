//! Source policy for the agent workspace (spec section 1.1 and review N-04),
//! checked over the repository files so every `agent-unit` run enforces it
//! until `scripts/ci/check_policy.py` carries the same rules:
//!
//! - `CheckedDir::new` is called only from the OS crates `agent/crates/os-*`,
//!   so no other crate can wrap an unchecked directory as checked.
//! - Unsafe code appears only in `os-macos` and `os-windows`; there every
//!   unsafe block is preceded by a `// SAFETY:` comment and sits in a
//!   function annotated `#[expect(unsafe_code, reason = "...")]`.
//! - No crate under `agent/` declares an `extern` block.
//! - The two native crates declare `unsafe_code = "deny"`; every other crate
//!   inherits the workspace lints, whose `forbid` cannot be relaxed.

use std::fs;
use std::path::{Path, PathBuf};

const NATIVE: [&str; 2] = ["os-macos", "os-windows"];

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The code part of a line: everything before a `//` comment.
fn code(line: &str) -> &str {
    match line.find("//") {
        Some(at) => &line[..at],
        None => line,
    }
}

fn has_unsafe_item(code: &str) -> bool {
    let words: Vec<&str> = code
        .split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '{'))
        .filter(|w| !w.is_empty())
        .collect();
    words
        .windows(2)
        .any(|w| w[0] == "unsafe" && matches!(w[1], "{" | "fn" | "impl" | "extern" | "trait"))
        || words.last() == Some(&"unsafe")
        || code.contains("unsafe{")
}

fn declares_extern_block(code: &str) -> bool {
    let trimmed = code.trim_start();
    (trimmed.starts_with("extern \"") || trimmed.contains("unsafe extern \""))
        && trimmed.trim_end().ends_with('{')
}

/// Violations in one native-crate source text.
fn native_violations(name: &str, text: &str) -> Vec<String> {
    let lines: Vec<&str> = text.lines().collect();
    let mut found = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if !has_unsafe_item(code(line)) {
            continue;
        }
        let at = format!("{name}:{}", index + 1);
        if code(line).contains("unsafe fn") || code(line).contains("unsafe impl") {
            found.push(format!("{at}: unsafe fn or impl"));
            continue;
        }
        // A `// SAFETY:` comment within the statement's preceding lines,
        // with no other unsafe block in between.
        let safety = lines[..index]
            .iter()
            .rev()
            .take(12)
            .take_while(|l| !has_unsafe_item(code(l)))
            .any(|l| l.trim_start().starts_with("// SAFETY:"));
        if !safety {
            found.push(format!("{at}: unsafe block without a // SAFETY: comment"));
        }
        // The enclosing function, and its attributes.
        let Some(fn_line) = lines[..index].iter().rposition(|l| {
            let c = code(l).trim_start();
            c.starts_with("fn ") || c.contains(" fn ") || c.starts_with("pub") && c.contains("fn ")
        }) else {
            found.push(format!("{at}: unsafe outside a function"));
            continue;
        };
        let expected = lines[..fn_line]
            .iter()
            .rev()
            .take_while(|l| {
                let t = l.trim_start();
                t.starts_with("#[")
                    || t.starts_with("unsafe_code")
                    || t.starts_with("reason")
                    || t.starts_with("deprecated")
                    || t.starts_with(')')
                    || t.starts_with(']')
                    || t.starts_with("///")
            })
            .any(|l| l.contains("unsafe_code"));
        let attributes: String = lines[..fn_line]
            .iter()
            .rev()
            .take(12)
            .copied()
            .collect::<Vec<_>>()
            .join("\n");
        if !(expected && attributes.contains("#[expect(") && attributes.contains("reason")) {
            found.push(format!(
                "{at}: enclosing function lacks #[expect(unsafe_code, reason = ...)]"
            ));
        }
    }
    found
}

/// Violations in one source text of any crate.
fn common_violations(name: &str, crate_name: &str, text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let c = code(line);
        let at = format!("{name}:{}", index + 1);
        if declares_extern_block(c) {
            found.push(format!("{at}: extern block"));
        }
        if !crate_name.starts_with("os-") && c.contains("CheckedDir::new(") {
            found.push(format!("{at}: CheckedDir::new outside agent/crates/os-*"));
        }
        if !NATIVE.contains(&crate_name) && has_unsafe_item(c) {
            found.push(format!("{at}: unsafe code outside the native crates"));
        }
    }
    found
}

#[test]
fn agent_sources_follow_the_policy() {
    let crates = workspace().join("crates");
    let mut violations = Vec::new();
    let mut checked = 0;
    for entry in fs::read_dir(&crates).unwrap().flatten() {
        let crate_name = entry.file_name().to_string_lossy().into_owned();
        let manifest = fs::read_to_string(entry.path().join("Cargo.toml")).unwrap();
        if NATIVE.contains(&crate_name.as_str()) {
            if !manifest.contains("unsafe_code = \"deny\"")
                || manifest.contains("[lints]\nworkspace = true")
            {
                violations.push(format!("{crate_name}: must declare unsafe_code = \"deny\""));
            }
        } else if !manifest.contains("[lints]\nworkspace = true") {
            violations.push(format!("{crate_name}: must inherit the workspace lints"));
        }
        let mut files = Vec::new();
        rust_files(&entry.path(), &mut files);
        for file in files {
            if file.ends_with("os/tests/policy.rs") {
                continue;
            }
            let text = fs::read_to_string(&file).unwrap();
            let name = file.strip_prefix(&crates).unwrap().display().to_string();
            violations.extend(common_violations(&name, &crate_name, &text));
            if NATIVE.contains(&crate_name.as_str()) {
                violations.extend(native_violations(&name, &text));
            }
            checked += 1;
        }
    }
    assert!(checked > 20, "only {checked} files scanned");
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

#[test]
fn the_checker_finds_each_violation() {
    // Red cases: each rule must fire on a fixture that breaks it.
    let missing_safety =
        "#[expect(unsafe_code, reason = \"x\")]\nfn f() {\n    let a = unsafe { g() };\n}\n";
    assert!(
        native_violations("f.rs", missing_safety)
            .iter()
            .any(|v| v.contains("SAFETY"))
    );
    let missing_expect = "fn f() {\n    // SAFETY: fine.\n    let a = unsafe { g() };\n}\n";
    assert!(
        native_violations("f.rs", missing_expect)
            .iter()
            .any(|v| v.contains("expect"))
    );
    let unsafe_fn = "pub unsafe fn f() {}\n";
    assert!(!native_violations("f.rs", unsafe_fn).is_empty());
    let good = "#[expect(\n    unsafe_code,\n    reason = \"x\"\n)]\nfn f() {\n    // SAFETY: fine.\n    let a = unsafe { g() };\n}\n";
    assert_eq!(native_violations("f.rs", good), Vec::<String>::new());

    let extern_block = "extern \"C\" {\n    fn g();\n}\n";
    assert!(!common_violations("f.rs", "os-macos", extern_block).is_empty());
    let checked_dir = "let d = CheckedDir::new(file, object, path);\n";
    assert!(!common_violations("f.rs", "core", checked_dir).is_empty());
    assert!(common_violations("f.rs", "os-linux", checked_dir).is_empty());
    let portable_unsafe = "fn f() { unsafe { g() } }\n";
    assert!(!common_violations("f.rs", "json", portable_unsafe).is_empty());
    assert!(common_violations("f.rs", "os-windows", portable_unsafe).is_empty());
    // Comments and lint names are not code.
    let comment = "// unsafe { not code }\n#![forbid(unsafe_code)]\n";
    assert!(common_violations("f.rs", "json", comment).is_empty());
}
