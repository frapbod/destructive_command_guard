//! A POSIX shell (macOS and WSL Bash, Git Bash) substitutes `$x`, `${x}`,
//! `$(…)` and backquotes inside a double-quoted `-c`/`-e` argument, an
//! unquoted-delimiter heredoc body and a double-quoted here-string before a
//! Python, Node, Ruby, Perl or PHP program reads it. The value lands in the
//! program's string literal first, then in the quotes of the shell the
//! program hands that string. Measured with Linux bash (fake interpreters
//! that record their argv): `python3 -c "import os; os.system(\"'gi${x}t'
//! reset --hard\")"` hands Python `os.system("'git' reset --hard")` with `x`
//! unset, and Linux dash and bash run `git reset --hard` from that string.

use destructive_command_guard::evaluator::evaluate_command_with_pack_order_at_path_in_dialect;
use destructive_command_guard::normalize::ShellDialect;
use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::{Config, EvaluationDecision, LayeredAllowlist};
use std::io::Write;
use std::process::{Command, Stdio};

const HOOK_TEST_TIMEOUT_MS: &str = "30000";

fn dcg_binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

#[derive(Clone, Copy, Debug)]
enum Protocol {
    Claude,
    Codex,
}

fn payload(protocol: Protocol, command: &str, cwd: &std::path::Path) -> serde_json::Value {
    match protocol {
        Protocol::Claude => serde_json::json!({
            "session_id": "sess-posix-outer-interp",
            "transcript_path": "/tmp/claude/transcript.jsonl",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_use_id": "toolu_posix_outer_interp",
        }),
        // `turn_id` selects Codex's protocol.
        Protocol::Codex => serde_json::json!({
            "session_id": "019dd11d-b795-7261-a9cb-9b85a5dadf16",
            "turn_id": "turn-posix-outer-interp",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.5",
            "permission_mode": "default",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_use_id": "call_posix_outer_interp",
        }),
    }
}

/// What the agent reads: "allow" for empty stdout, else the decision.
fn hook_decision(protocol: Protocol, command: &str) -> String {
    let temp = tempfile::tempdir().expect("temp dir");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let payload = payload(protocol, command, temp.path()).to_string();
    let mut child = Command::new(dcg_binary())
        .env_clear()
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_NO_SELF_HEAL", "1")
        .env("DCG_HOOK_TIMEOUT_MS", HOOK_TEST_TIMEOUT_MS)
        .env("DCG_HEREDOC_TIMEOUT_MS", HOOK_TEST_TIMEOUT_MS)
        .env("DCG_AST_TIMEOUT_MS", HOOK_TEST_TIMEOUT_MS)
        .current_dir(temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dcg");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(payload.as_bytes())
        .expect("write payload");
    let out = child.wait_with_output().expect("wait");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{protocol:?}: the hook must exit with a verdict on {command:?}\nstderr: {stderr}"
    );
    if stdout.trim().is_empty() {
        return "allow".to_string();
    }
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("{protocol:?}: stdout is not one JSON value ({e}): {stdout}"));
    parsed["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .unwrap_or("<missing>")
        .to_string()
}

fn decision_in(command: &str, dialect: ShellDialect) -> EvaluationDecision {
    let enabled: std::collections::HashSet<String> =
        ["core.git", "core.filesystem", "windows.filesystem"]
            .into_iter()
            .map(str::to_string)
            .collect();
    let ordered = REGISTRY.expand_enabled_ordered(&enabled);
    let keywords = REGISTRY.collect_enabled_keywords(&enabled);
    let index = REGISTRY.build_enabled_keyword_index(&ordered);
    let config = Config::default();
    let overrides = config.overrides.compile();
    let heredoc = config.heredoc_settings();
    evaluate_command_with_pack_order_at_path_in_dialect(
        command,
        &keywords,
        &ordered,
        index.as_ref(),
        &overrides,
        &LayeredAllowlist::default(),
        &heredoc,
        None,
        dialect,
    )
    .decision
}

/// Checks each command in `dialects` and in both hook formats, and reports
/// every miss at once.
fn misses(commands: &[&str], dialects: &[ShellDialect], want: EvaluationDecision) -> Vec<String> {
    let hook_want = if want == EvaluationDecision::Deny {
        "deny"
    } else {
        "allow"
    };
    let mut misses = Vec::new();
    for command in commands {
        for &dialect in dialects {
            let got = decision_in(command, dialect);
            if got != want {
                misses.push(format!("{dialect:?}: {command:?} -> {got:?}"));
            }
        }
        for protocol in [Protocol::Claude, Protocol::Codex] {
            let got = hook_decision(protocol, command);
            if got != hook_want {
                misses.push(format!("{protocol:?}: {command:?} -> {got}"));
            }
        }
    }
    misses
}

const POSIX: [ShellDialect; 2] = [ShellDialect::Posix, ShellDialect::Unknown];

/// A value the parent shell substitutes is unknown text in the string a
/// program's sink hands a shell, including inside that shell's single
/// quotes, so it can complete a command name (`'gi${x}t'`), end one
/// (`'gi$x'`), or be empty. Each language's shell sinks, wrappers before
/// the interpreter, and stdin sources the parent expands.
#[test]
fn outer_values_in_an_interpreter_program_are_unknown_shell_text() {
    let misses = misses(
        &[
            r#"python3 -c "import os; os.system(\"'gi${x}t' reset --hard\")""#,
            r#"python3 -c "import os; os.system(\"'gi$x' reset --hard\")""#,
            r#"python3 -c "import os; os.system(\"'gi$(true)t' reset --hard\")""#,
            r#"python3 -c "import os; os.system(\"'gi`true`t' reset --hard\")""#,
            r#"python3 -c "import os; os.system(\"gi${x}t reset --hard\")""#,
            r#"python3 -c "import os; os.system(\"echo ok; 'gi${x}t' reset --hard\")""#,
            r#"python3 -c "import os; os.system(\"r'm${x}' -rf ~/\")""#,
            r#"python3 -c "import subprocess; subprocess.run(\"'gi${x}t' reset --hard\", shell=True)""#,
            r#"python3 -c "import subprocess; subprocess.run(['gi${x}t', 'reset', '--hard'])""#,
            r#"python -c "import os; os.popen(\"'gi${x}t' reset --hard\")""#,
            r#"node -e "require('child_process').execSync(\"'gi${x}t' reset --hard\")""#,
            r#"node -e "require('child_process').execSync('\'gi${x}t\' reset --hard')""#,
            r#"perl -e "system(\"'gi${x}t' reset --hard\")""#,
            r#"ruby -e "system(\"'gi${x}t' reset --hard\")""#,
            r#"php -r "system('\'gi${x}t\' reset --hard');""#,
            r#"sudo python3 -c "import os; os.system(\"'gi${x}t' reset --hard\")""#,
            r#"env FOO=1 python3 -c "import os; os.system(\"'gi${x}t' reset --hard\")""#,
            r#"timeout 5 python3 -c "import os; os.system(\"'gi${x}t' reset --hard\")""#,
            "python3 <<EOF\nimport os; os.system(\"'gi${x}t' reset --hard\")\nEOF",
            "python3 - <<EOF\nimport os\nos.system(\"'gi$(true)t' reset --hard\")\nEOF",
            "node <<EOF\nrequire('child_process').execSync(\"'gi${x}t' reset --hard\")\nEOF",
            r#"python3 <<< "import os; os.system(\"'gi${x}t' reset --hard\")""#,
        ],
        &POSIX,
        EvaluationDecision::Deny,
    );
    assert!(misses.is_empty(), "misses:\n{}", misses.join("\n"));
}

/// Every sink shape dcg denies for a literal command (`os.system('''git
/// reset --hard''')`, Ruby backquotes, `%x(…)`, `IO.popen`, `Open3`) also
/// denies when a parent value lands in that command. These shapes are read
/// by the AST rules and the backstop, which match the sink's literal text,
/// so the program is also read with every value empty. Linux bash hands
/// each interpreter exactly the literal program (fake interpreters).
#[test]
fn outer_values_in_every_literal_sink_shape_deny() {
    let misses = misses(
        &[
            r#"python3 -c "import os; os.system('''gi${x}t reset --hard''')""#,
            r#"python3 -c "import os; os.system(\"\"\"gi${x}t reset --hard\"\"\")""#,
            r#"python3 -c "import os; os.system(r\"gi${x}t reset --hard\")""#,
            r#"python3 -c "import os; os.system(f\"gi${x}t reset --hard\")""#,
            r#"python3 -c "import subprocess as s; s.run(\"gi$(true)t reset --hard\", shell=True)""#,
            r#"ruby -e "\`gi${x}t reset --hard\`""#,
            r#"ruby -e "%x(gi${x}t reset --hard)""#,
            r#"ruby -e "IO.popen(\"gi${x}t reset --hard\")""#,
            r#"ruby -e "require \"open3\"; Open3.capture2(\"gi${x}t reset --hard\")""#,
            "python3 <<EOF\nimport os; os.system('''gi${x}t reset --hard''')\nEOF",
            "python3 <<EOF\nimport os; os.system(\"\"\"gi${x}t reset --hard\"\"\")\nEOF",
            "python3 <<EOF\nimport os; os.system(r\"gi${x}t reset --hard\")\nEOF",
            "python3 <<EOF\nimport os; os.system(f\"gi${x}t reset --hard\")\nEOF",
            "python3 <<EOF\nimport subprocess as s; s.run(\"gi${x}t reset --hard\", shell=True)\nEOF",
            "ruby <<EOF\n\\`gi${x}t reset --hard\\`\nEOF",
            "ruby <<EOF\n%x(gi${x}t reset --hard)\nEOF",
            "ruby <<EOF\nIO.popen(\"gi${x}t reset --hard\")\nEOF",
            "ruby <<EOF\nrequire \"open3\"; Open3.capture2(\"gi${x}t reset --hard\")\nEOF",
        ],
        &POSIX,
        EvaluationDecision::Deny,
    );
    assert!(misses.is_empty(), "misses:\n{}", misses.join("\n"));
}

/// The same sink shapes with a harmless command stay allowed.
#[test]
fn outer_values_in_literal_sink_shapes_with_harmless_commands_stay_allowed() {
    let misses = misses(
        &[
            r#"python3 -c "import os; os.system('''git status ${x}''')""#,
            r#"python3 -c "import os; os.system(\"\"\"ls ${d}\"\"\")""#,
            r#"python3 -c "import os; os.system(r\"echo ${x}\")""#,
            r#"python3 -c "import os; os.system(f\"git log ${x}\")""#,
            r#"python3 -c "import subprocess as s; s.run(\"ls ${d}\", shell=True)""#,
            r#"ruby -e "\`echo ${x}\`""#,
            r#"ruby -e "%x(ls ${d})""#,
            r#"ruby -e "IO.popen(\"ls ${d}\")""#,
            r#"ruby -e "require \"open3\"; Open3.capture2(\"git status ${x}\")""#,
            "python3 <<EOF\nimport os; os.system('''git status ${x}''')\nEOF",
            "python3 <<EOF\nimport subprocess as s; s.run(\"ls ${d}\", shell=True)\nEOF",
            "ruby <<EOF\n\\`echo ${x}\\`\nEOF",
            "ruby <<EOF\nIO.popen(\"ls ${d}\")\nEOF",
        ],
        &POSIX,
        EvaluationDecision::Allow,
    );
    assert!(misses.is_empty(), "misses:\n{}", misses.join("\n"));
}

/// Text the parent shell does not expand reaches the program as written (its
/// single quotes, an escaped `$`, a quoted heredoc delimiter), and a value
/// where the program's shell cannot make it a command stays harmless.
#[test]
fn interpreter_text_the_parent_does_not_make_a_command_stays_allowed() {
    let misses = misses(
        &[
            r#"python3 -c "import os; print('$HOME')""#,
            r#"python3 -c "print(${x})""#,
            r#"python3 -c "import os; os.system(\"echo '$HOME'\")""#,
            r#"python3 -c "import os; os.system(\"ls ${dir}\")""#,
            r#"python3 -c "import os; os.system(\"git status ${x}\")""#,
            r#"python3 -c "import os; os.system(\"echo 'gi${x}t reset --hard'\")""#,
            r#"python3 -c "import os; os.system(\"'gi\${x}t' reset --hard\")""#,
            r#"python3 -c 'import os; os.system("'"'"'gi${x}t'"'"' reset --hard")'"#,
            "python3 <<'EOF'\nimport os; os.system(\"'gi${x}t' reset --hard\")\nEOF",
            r#"node -e "console.log('${HOME}')""#,
            r#"ruby -e "puts \"${HOME}\"""#,
        ],
        &POSIX,
        EvaluationDecision::Allow,
    );
    assert!(misses.is_empty(), "misses:\n{}", misses.join("\n"));
}
