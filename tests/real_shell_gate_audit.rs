//! Every shell this package's code starts is behind the real-shell gate.
//!
//! `src/real_shell_gate.rs` lets a test run text in a real shell only inside
//! the shell-truth suite sandbox. This audit keeps it that way: it reads the
//! source of `src/`, `tests/`, `benches/` and `examples/`, finds each
//! `Command::new(..)` whose program is a shell, and requires either a
//! `real_shell_gate::allowed(` call in the lines just before it, or a
//! `// real-shell-gate: exempt (<reason>)` comment right above it (production
//! code, or a test that hands the shell only constant text). It is a static
//! check: it runs no shell and no test it inspects.
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

/// How far above a spawn its gate may be: the top of a test, or the block
/// that holds the spawn.
const GATE_WINDOW: usize = 40;
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

#[test]
fn every_real_shell_spawn_is_gated_or_exempt() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
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
        let source = std::fs::read_to_string(file).expect("read Rust source");
        let lines: Vec<&str> = source.lines().collect();
        for (offset, _) in source.match_indices("Command::new(") {
            let line = source[..offset].matches('\n').count();
            if lines[line].trim_start().starts_with("//") {
                continue;
            }
            let program = spawned_program(&source[offset + "Command::new(".len()..]);
            if !is_shell(&program) {
                continue;
            }
            let before = |window: usize| &lines[line.saturating_sub(window)..=line];
            if before(GATE_WINDOW)
                .iter()
                .any(|text| text.contains("real_shell_gate::allowed("))
            {
                gated += 1;
            } else if before(EXEMPT_WINDOW)
                .iter()
                .any(|text| text.contains("// real-shell-gate: exempt ("))
            {
                exempt += 1;
            } else {
                ungated.push(format!(
                    "{}:{}: Command::new({program})",
                    relative.display(),
                    line + 1
                ));
            }
        }
    }

    assert!(
        ungated.is_empty(),
        "these spawns run a real shell without the gate. Return early unless \
         `real_shell_gate::allowed(\"<test name>\")` (see src/real_shell_gate.rs), or, \
         for production code or constant shell text only, put \
         `// real-shell-gate: exempt (<reason>)` right above the spawn:\n{}",
        ungated.join("\n")
    );
    // Not vacuous: the scan must still find the spawns gated today
    // (word_splitting.rs, hook.rs, cli.rs, cli_e2e.rs, droid_install.rs) and
    // the exempt ones in cli.rs.
    assert!(gated >= 11, "found only {gated} gated shell spawns");
    assert!(exempt >= 4, "found only {exempt} exempt shell spawns");
}
