//! Every shell this package's code starts is behind the real-shell gate.
//!
//! `src/real_shell_gate.rs` lets a test run text in a real shell only inside
//! the shell-truth suite sandbox. This audit keeps it that way: it reads the
//! source of `build.rs`, `src/`, `tests/`, `benches/` and `examples/`, finds
//! each `Command::new(..)` whose program is a shell, and requires either a
//! `real_shell_gate::allowed(` call between the spawn and the header of the
//! `fn` that holds it, or a `// real-shell-gate: exempt (<reason>)` comment
//! right above it (production code, or a test that hands the shell only
//! constant text). A gate in another function, such as the test just above,
//! does not count. It is a static check: it runs no shell and no test it
//! inspects.
//!
//! It cannot see a shell started some other way (a variable it does not
//! recognise, a script run by name, an agent that runs its own shell). Gate
//! those by hand, as `tests/repro_419_opencode_plugin_executes.rs` does.

use std::path::{Path, PathBuf};

/// Shell programs, by file name without `.exe`.
const SHELLS: &[&str] = &[
    "sh",
    "bash",
    "dash",
    "zsh",
    "ksh",
    "mksh",
    "fish",
    "pwsh",
    "powershell",
    "cmd",
];

/// How far above a spawn its exemption comment may be.
const EXEMPT_WINDOW: usize = 3;

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// The program named by the text after `Command::new(`.
fn spawned_program(after: &str) -> String {
    let after = after.trim_start();
    if let Some(literal) = after.strip_prefix('"') {
        return literal.split('"').next().unwrap_or_default().to_string();
    }
    after
        .trim_start_matches('&')
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect()
}

fn is_shell(program: &str) -> bool {
    let name = program.rsplit(['/', '\\']).next().unwrap_or(program);
    let name = name.to_ascii_lowercase();
    let name = name.strip_suffix(".exe").unwrap_or(&name);
    // A variable such as `shell` holds a shell path chosen by the test.
    SHELLS.contains(&name) || name.contains("shell")
}

/// Whether `line` starts a function: `fn name`, after any of `pub(..)`,
/// `const`, `async`, `unsafe` and `extern "abi"`.
fn is_fn_header(line: &str) -> bool {
    let mut words = line.split_whitespace();
    for word in words.by_ref() {
        let qualifier = word.starts_with("pub")
            || ["const", "async", "unsafe", "extern"].contains(&word)
            || (word.starts_with('"') && word.ends_with('"') && word.len() > 1);
        if !qualifier {
            return word == "fn";
        }
    }
    false
}

/// How one file's shell spawns are guarded.
#[derive(Debug, Default, PartialEq, Eq)]
struct Spawns {
    gated: usize,
    exempt: usize,
    /// 1-based line and program of each spawn with neither.
    ungated: Vec<(usize, String)>,
}

fn classify(source: &str) -> Spawns {
    let lines: Vec<&str> = source.lines().collect();
    let mut spawns = Spawns::default();
    for (offset, _) in source.match_indices("Command::new(") {
        let line = source[..offset].matches('\n').count();
        if lines[line].trim_start().starts_with("//") {
            continue;
        }
        let program = spawned_program(&source[offset + "Command::new(".len()..]);
        if !is_shell(&program) {
            continue;
        }
        // The gate must run in the function that spawns: from its header
        // down to the spawn. Without a header above, only the spawn line.
        let header = (0..=line)
            .rev()
            .find(|&index| is_fn_header(lines[index]))
            .unwrap_or(line);
        let exempt_from = line.saturating_sub(EXEMPT_WINDOW);
        if lines[header..=line]
            .iter()
            .any(|text| text.contains("real_shell_gate::allowed("))
        {
            spawns.gated += 1;
        } else if lines[exempt_from..=line]
            .iter()
            .any(|text| text.contains("// real-shell-gate: exempt ("))
        {
            spawns.exempt += 1;
        } else {
            spawns.ungated.push((line + 1, program));
        }
    }
    spawns
}

#[test]
fn every_real_shell_spawn_is_gated_or_exempt() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = vec![root.join("build.rs")];
    for dir in ["src", "tests", "benches", "examples"] {
        rust_files(&root.join(dir), &mut files);
    }
    files.sort();

    let mut ungated = Vec::new();
    let mut gated = 0;
    let mut exempt = 0;
    for file in &files {
        let relative = file.strip_prefix(root).unwrap_or(file);
        if relative == Path::new("tests/real_shell_gate_audit.rs") {
            continue;
        }
        let Ok(source) = std::fs::read_to_string(file) else {
            assert!(!file.exists(), "cannot read {}", file.display());
            continue;
        };
        let spawns = classify(&source);
        gated += spawns.gated;
        exempt += spawns.exempt;
        for (line, program) in spawns.ungated {
            ungated.push(format!(
                "{}:{line}: Command::new({program})",
                relative.display()
            ));
        }
    }

    assert!(
        ungated.is_empty(),
        "these spawns run a real shell without the gate. In the function that \
         spawns, return early unless `real_shell_gate::allowed(\"<test name>\")` \
         (see src/real_shell_gate.rs), or, for production code or constant shell \
         text only, put `// real-shell-gate: exempt (<reason>)` right above the \
         spawn:\n{}",
        ungated.join("\n")
    );
    // Not vacuous: the scan must still find the spawns gated today
    // (word_splitting.rs, hook.rs, cli.rs, cli_e2e.rs, droid_install.rs) and
    // the exempt ones in cli.rs.
    assert!(gated >= 11, "found only {gated} gated shell spawns");
    assert!(exempt >= 4, "found only {exempt} exempt shell spawns");
}

/// A gate counts only inside the spawning function. New shell tests tend to
/// land right after a gated one, so a gate in the test above must not count.
#[test]
fn a_gate_in_another_function_does_not_count() {
    let source = r#"
#[test]
fn gated_test() {
    if !crate::real_shell_gate::allowed("gated_test") {
        return;
    }
    let output = std::process::Command::new("/bin/sh").arg("-c").output();
}

#[test]
fn ungated_test_right_after() {
    let output = std::process::Command::new("/bin/sh").args(["-c", case]).output();
}

pub(crate) async fn shell_helper(shell: &str) {
    // real-shell-gate: exempt (constant text)
    Command::new(shell).arg("-c").arg("true");
}

fn not_a_shell() {
    Command::new("git").arg("status");
}
"#;
    assert_eq!(
        classify(source),
        Spawns {
            gated: 1,
            exempt: 1,
            ungated: vec![(12, "/bin/sh".to_string())],
        }
    );
}

#[test]
fn fn_headers_are_recognised() {
    for header in [
        "fn plain() {",
        "    pub fn public() {",
        "pub(crate) const unsafe fn qualified() {",
        "    pub(super) async fn later() {",
        r#"unsafe extern "C" fn callback() {"#,
    ] {
        assert!(is_fn_header(header), "{header}");
    }
    for other in [
        "let fnord = 1;",
        "// fn in a comment",
        r#""fn in a string","#,
        "Command::new(shell)",
    ] {
        assert!(!is_fn_header(other), "{other}");
    }
}
