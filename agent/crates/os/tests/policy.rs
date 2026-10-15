//! Source policy for the agent workspace (spec section 1.1, reviews N-04
//! and R-04), checked over the repository files by a small Rust tokenizer
//! that understands strings, raw strings, character literals, lifetimes
//! and nested comments, so every `agent-unit` run enforces:
//!
//! - `CheckedDir::new` is called only from the OS crates `agent/crates/os-*`.
//! - The `unsafe` keyword appears only in `os-macos` and `os-windows`, and
//!   there only as an `unsafe { ... }` block: no `unsafe fn`, `unsafe impl`,
//!   `unsafe trait`, `unsafe extern` or edition-2024 `#[unsafe(...)]`
//!   attribute.
//! - Every unsafe block is preceded by a `// SAFETY:` comment and sits in a
//!   function whose own attribute block carries
//!   `#[expect(unsafe_code, reason = "...")]`.
//! - No `allow(unsafe_code)` anywhere, so a stray `allow` cannot replace
//!   the `expect` that fails when unused.
//! - No `extern` block anywhere under `agent/`.
//! - The two native crates declare `unsafe_code = "deny"`; every other
//!   crate inherits the workspace lints, whose `forbid` cannot be relaxed.
//!
//! Plan Task 4 also names `scripts/ci/check_policy.py` for these rules; this
//! test is the agent-side enforcement until the CI owner ports them.

use std::fs;
use std::path::{Path, PathBuf};

const NATIVE: [&str; 2] = ["os-macos", "os-windows"];

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Ident(String),
    Punct(char),
    Literal,
    Lifetime,
}

#[derive(Debug)]
struct Lexed {
    /// Tokens with their 1-based line.
    tokens: Vec<(usize, Tok)>,
    /// Comment texts (without the `//` or `/*` markers) with their line.
    comments: Vec<(usize, String)>,
}

fn lex(text: &str) -> Lexed {
    let chars: Vec<char> = text.chars().collect();
    let mut tokens = Vec::new();
    let mut comments = Vec::new();
    let mut line = 1;
    let mut i = 0;
    let at = |i: usize| chars.get(i).copied().unwrap_or('\0');
    while i < chars.len() {
        let c = chars[i];
        if c == '\n' {
            line += 1;
            i += 1;
        } else if c.is_whitespace() {
            i += 1;
        } else if c == '/' && at(i + 1) == '/' {
            let start = i + 2;
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            let body: String = chars[start..i].iter().collect();
            comments.push((line, body.trim_start_matches(['/', '!']).to_owned()));
        } else if c == '/' && at(i + 1) == '*' {
            let (start_line, start) = (line, i + 2);
            let mut depth = 1;
            i += 2;
            while i < chars.len() && depth > 0 {
                if chars[i] == '/' && at(i + 1) == '*' {
                    depth += 1;
                    i += 2;
                } else if chars[i] == '*' && at(i + 1) == '/' {
                    depth -= 1;
                    i += 2;
                } else {
                    if chars[i] == '\n' {
                        line += 1;
                    }
                    i += 1;
                }
            }
            let end = i.saturating_sub(2).max(start);
            comments.push((start_line, chars[start..end].iter().collect()));
        } else if let Some((after_quote, hashes)) = raw_string_prefix(&chars, i) {
            // r"...", r#"..."#, br"...", cr#"..."#
            i = after_quote;
            let start_line = line;
            while i < chars.len() {
                if chars[i] == '"' && (1..=hashes).all(|k| at(i + k) == '#') {
                    i += 1 + hashes;
                    break;
                }
                if chars[i] == '\n' {
                    line += 1;
                }
                i += 1;
            }
            tokens.push((start_line, Tok::Literal));
        } else if c == '"' || ((c == 'b' || c == 'c') && at(i + 1) == '"') {
            let start_line = line;
            i += if c == '"' { 1 } else { 2 };
            while i < chars.len() && chars[i] != '"' {
                if chars[i] == '\\' {
                    i += 1;
                }
                if at(i) == '\n' {
                    line += 1;
                }
                i += 1;
            }
            i += 1;
            tokens.push((start_line, Tok::Literal));
        } else if c == '\'' || (c == 'b' && at(i + 1) == '\'') {
            let q = if c == '\'' { i } else { i + 1 };
            if at(q + 1) == '\\' {
                // Escaped character literal.
                i = q + 2;
                while i < chars.len() && chars[i] != '\'' {
                    i += 1;
                }
                i += 1;
                tokens.push((line, Tok::Literal));
            } else if at(q + 2) == '\'' {
                i = q + 3;
                tokens.push((line, Tok::Literal));
            } else {
                // A lifetime or label.
                i = q + 1;
                while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                tokens.push((line, Tok::Lifetime));
            }
        } else if c.is_ascii_digit() {
            while i < chars.len()
                && (chars[i].is_alphanumeric()
                    || chars[i] == '_'
                    || (chars[i] == '.' && at(i + 1).is_ascii_digit()))
            {
                i += 1;
            }
            tokens.push((line, Tok::Literal));
        } else if c.is_alphabetic() || c == '_' {
            let start = i;
            if c == 'r' && at(i + 1) == '#' {
                i += 2; // raw identifier
            }
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect();
            tokens.push((line, Tok::Ident(word.trim_start_matches("r#").to_owned())));
        } else {
            tokens.push((line, Tok::Punct(c)));
            i += 1;
        }
    }
    Lexed { tokens, comments }
}

/// When a raw string starts at `i`, the index after its opening quote and
/// its number of hashes.
fn raw_string_prefix(chars: &[char], i: usize) -> Option<(usize, usize)> {
    // Not the tail of a longer identifier such as `bar`.
    if i > 0 && (chars[i - 1].is_alphanumeric() || chars[i - 1] == '_') {
        return None;
    }
    let mut j = i;
    if matches!(chars.get(j), Some('b' | 'c')) {
        j += 1;
    }
    if chars.get(j) != Some(&'r') {
        return None;
    }
    j += 1;
    let mut hashes = 0;
    while chars.get(j) == Some(&'#') {
        hashes += 1;
        j += 1;
    }
    (chars.get(j) == Some(&'"')).then_some((j + 1, hashes))
}

fn ident(tok: &Tok, word: &str) -> bool {
    matches!(tok, Tok::Ident(w) if w == word)
}

fn tok_at(tokens: &[(usize, Tok)], index: usize) -> Option<&Tok> {
    tokens.get(index).map(|(_, t)| t)
}

/// For every `fn` with a body: the index of its body's `{` and the
/// identifiers of its own contiguous attribute block.
fn functions(tokens: &[(usize, Tok)]) -> Vec<(usize, String)> {
    const QUALIFIERS: [&str; 9] = [
        "pub", "crate", "super", "self", "in", "const", "async", "unsafe", "extern",
    ];
    let mut found = Vec::new();
    for (index, (_, tok)) in tokens.iter().enumerate() {
        if !ident(tok, "fn") || !matches!(tok_at(tokens, index + 1), Some(Tok::Ident(_))) {
            continue;
        }
        // Walk back over qualifiers, then over `#[...]` attributes.
        let mut k = index;
        while k > 0 {
            match &tokens[k - 1].1 {
                Tok::Ident(w) if QUALIFIERS.contains(&w.as_str()) => k -= 1,
                Tok::Punct('(' | ')') | Tok::Literal => k -= 1,
                _ => break,
            }
        }
        let mut attributes = String::new();
        while k >= 2 && tokens[k - 1].1 == Tok::Punct(']') {
            let mut depth = 0;
            let mut m = k - 1;
            loop {
                match tokens[m].1 {
                    Tok::Punct(']') => depth += 1,
                    Tok::Punct('[') => depth -= 1,
                    _ => {}
                }
                if depth == 0 || m == 0 {
                    break;
                }
                m -= 1;
            }
            if m == 0 || tokens[m - 1].1 != Tok::Punct('#') {
                break;
            }
            for (_, t) in &tokens[m..k] {
                if let Tok::Ident(w) = t {
                    attributes.push_str(w);
                    attributes.push(' ');
                }
            }
            k = m - 1;
        }
        // The body: the first `{` outside parentheses and brackets, unless a
        // `;` ends a declaration first.
        let mut depth = 0i32;
        for (j, (_, t)) in tokens.iter().enumerate().skip(index + 2) {
            match t {
                Tok::Punct('(' | '[') => depth += 1,
                Tok::Punct(')' | ']') => depth -= 1,
                Tok::Punct('{') if depth == 0 => {
                    found.push((j, attributes));
                    break;
                }
                Tok::Punct(';') if depth == 0 => break,
                _ => {}
            }
        }
    }
    found
}

/// Violations in one source text of crate `crate_name`.
fn violations(name: &str, crate_name: &str, text: &str) -> Vec<String> {
    let native = NATIVE.contains(&crate_name);
    let lexed = lex(text);
    let tokens = &lexed.tokens;
    let bodies = functions(tokens);
    let mut found = Vec::new();
    let mut scopes: Vec<(i32, String)> = Vec::new();
    let mut depth = 0i32;
    let mut last_unsafe_line = 0;
    for (index, (line, tok)) in tokens.iter().enumerate() {
        let at = format!("{name}:{line}");
        let next = tok_at(tokens, index + 1);
        match tok {
            Tok::Punct('{') => {
                depth += 1;
                if let Some((_, attrs)) = bodies.iter().find(|(open, _)| *open == index) {
                    scopes.push((depth, attrs.clone()));
                }
            }
            Tok::Punct('}') => {
                if scopes.last().is_some_and(|(d, _)| *d == depth) {
                    scopes.pop();
                }
                depth -= 1;
            }
            Tok::Ident(w) if w == "extern" => {
                let block = matches!(next, Some(Tok::Punct('{')))
                    || (matches!(next, Some(Tok::Literal))
                        && matches!(tok_at(tokens, index + 2), Some(Tok::Punct('{'))));
                if block {
                    found.push(format!("{at}: extern block"));
                }
            }
            Tok::Ident(w) if w == "allow" => {
                let in_group = tokens[index + 1..]
                    .iter()
                    .map(|(_, t)| t)
                    .take_while(|t| **t != Tok::Punct(')'))
                    .any(|t| ident(t, "unsafe_code"));
                if in_group {
                    found.push(format!("{at}: allow(unsafe_code)"));
                }
            }
            Tok::Ident(w) if w == "CheckedDir" => {
                let path_new = matches!(next, Some(Tok::Punct(':')))
                    && matches!(tok_at(tokens, index + 2), Some(Tok::Punct(':')))
                    && tok_at(tokens, index + 3).is_some_and(|t| ident(t, "new"));
                if path_new && !crate_name.starts_with("os-") {
                    found.push(format!("{at}: CheckedDir::new outside agent/crates/os-*"));
                }
            }
            Tok::Ident(w) if w == "unsafe" => {
                if !native {
                    found.push(format!("{at}: unsafe outside the native crates"));
                    continue;
                }
                if !matches!(next, Some(Tok::Punct('{'))) {
                    found.push(format!("{at}: unsafe other than a block"));
                    continue;
                }
                let safety = lexed.comments.iter().any(|(l, text)| {
                    *l < *line
                        && *l + 12 >= *line
                        && *l > last_unsafe_line
                        && text.trim_start().starts_with("SAFETY:")
                });
                if !safety {
                    found.push(format!("{at}: unsafe block without a // SAFETY: comment"));
                }
                let expected = scopes.last().is_some_and(|(_, attrs)| {
                    attrs.contains("expect unsafe_code") && attrs.contains("reason")
                });
                if !expected {
                    found.push(format!(
                        "{at}: enclosing function lacks its own #[expect(unsafe_code, reason = ...)]"
                    ));
                }
                last_unsafe_line = *line;
            }
            _ => {}
        }
    }
    found
}

fn workspace_crates() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
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

#[test]
fn agent_sources_follow_the_policy() {
    let crates = workspace_crates();
    let mut found = Vec::new();
    let mut checked = 0;
    for entry in fs::read_dir(&crates).unwrap().flatten() {
        let crate_name = entry.file_name().to_string_lossy().into_owned();
        let manifest = fs::read_to_string(entry.path().join("Cargo.toml")).unwrap();
        if NATIVE.contains(&crate_name.as_str()) {
            if !manifest.contains("unsafe_code = \"deny\"")
                || manifest.contains("[lints]\nworkspace = true")
            {
                found.push(format!("{crate_name}: must declare unsafe_code = \"deny\""));
            }
        } else if !manifest.contains("[lints]\nworkspace = true") {
            found.push(format!("{crate_name}: must inherit the workspace lints"));
        }
        let mut files = Vec::new();
        rust_files(&entry.path(), &mut files);
        for file in files {
            let text = fs::read_to_string(&file).unwrap();
            let name = file.strip_prefix(&crates).unwrap().display().to_string();
            found.extend(violations(&name, &crate_name, &text));
            checked += 1;
        }
    }
    assert!(checked > 30, "only {checked} files scanned");
    assert!(found.is_empty(), "{}", found.join("\n"));
}

fn fires(crate_name: &str, text: &str, needle: &str) -> bool {
    violations("f.rs", crate_name, text)
        .iter()
        .any(|v| v.contains(needle))
}

#[test]
fn each_rule_fires_on_a_violating_fixture() {
    let good = "#[expect(\n    unsafe_code,\n    reason = \"x\"\n)]\nfn f() {\n    // SAFETY: fine.\n    let a = unsafe { g() };\n}\n";
    assert_eq!(violations("f.rs", "os-macos", good), Vec::<String>::new());

    let missing_safety =
        "#[expect(unsafe_code, reason = \"x\")]\nfn f() {\n    let a = unsafe { g() };\n}\n";
    assert!(fires("os-macos", missing_safety, "SAFETY"));
    let missing_expect = "fn f() {\n    // SAFETY: fine.\n    let a = unsafe { g() };\n}\n";
    assert!(fires("os-macos", missing_expect, "expect"));
    assert!(fires(
        "os-macos",
        "pub unsafe fn f() {}\n",
        "other than a block"
    ));
    assert!(fires(
        "os-macos",
        "unsafe impl Send for X {}\n",
        "other than a block"
    ));
    assert!(fires(
        "os-windows",
        "unsafe trait T {}\n",
        "other than a block"
    ));
    assert!(fires(
        "os-windows",
        "extern \"C\" {\n    fn g();\n}\n",
        "extern block"
    ));
    assert!(fires(
        "os-windows",
        "extern {\n    fn g();\n}\n",
        "extern block"
    ));
    assert!(fires(
        "os-windows",
        "unsafe extern \"C\" {\n    fn g();\n}\n",
        "extern block"
    ));
    let checked = "let d = CheckedDir::new(file, object, path);\n";
    assert!(fires("core", checked, "CheckedDir"));
    assert!(!fires("os-linux", checked, "CheckedDir"));
    assert!(fires(
        "json",
        "fn f() { unsafe { g() } }\n",
        "outside the native"
    ));
}

#[test]
fn review_bypasses_are_closed() {
    // R-04 (1): an `allow` next to another function's `expect`.
    let borrowed_expect = "#[expect(unsafe_code, reason = \"x\")]\nfn a() {\n    // SAFETY: fine.\n    unsafe { g() };\n}\n#[allow(unsafe_code)]\nfn b() {\n    // SAFETY: fine.\n    unsafe { g() };\n}\n";
    assert!(fires("os-windows", borrowed_expect, "allow(unsafe_code)"));
    assert!(fires("os-windows", borrowed_expect, "lacks its own"));
    // R-04 (2): `//` inside a string literal does not hide code.
    let url = "fn f() { let u = \"https://x\"; unsafe { g() } }\n";
    assert!(fires("os-windows", url, "SAFETY"));
    assert!(fires("json", url, "outside the native"));
    // R-04 (3): edition 2024 unsafe attributes.
    assert!(fires(
        "os-windows",
        "#[unsafe(no_mangle)]\nfn f() {}\n",
        "other than a block"
    ));
    assert!(fires(
        "json",
        "#[unsafe(export_name = \"x\")]\nfn f() {}\n",
        "outside the native"
    ));
}

#[test]
fn literals_and_comments_are_not_code() {
    let text = concat!(
        "// unsafe { not code }\n",
        "/* unsafe { /* nested */ still a comment } */\n",
        "#![forbid(unsafe_code)]\n",
        "const A: &str = \"unsafe { }\";\n",
        "const B: &str = r#\"extern \"C\" { } unsafe {\"#;\n",
        "const C: char = '\\'';\n",
        "fn f<'a>(x: &'a str) -> &'a str { x }\n",
        "const D: &[u8] = b\"CheckedDir::new(\";\n",
        "extern \"system\" fn callback() {}\n",
        "fn bar() -> u8 { b'r' }\n",
    );
    assert_eq!(violations("f.rs", "json", text), Vec::<String>::new());
}
