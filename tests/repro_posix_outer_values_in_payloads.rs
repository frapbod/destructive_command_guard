//! A POSIX shell (macOS and WSL Bash, Git Bash) substitutes `$x`, `${x}`,
//! `$(…)` and backquotes inside a double-quoted argument before the program
//! it starts reads it. Measured with Linux bash (fake `bash` and `cmd.exe`
//! that record their argv): `bash -c "'gi${x}t' reset --hard"` hands bash
//! `'git' reset --hard`, `cmd.exe /c "gi${X}t reset --hard"` hands cmd.exe
//! `git reset --hard`, and `cmd.exe /c "$X reset --hard"` hands it
//! ` reset --hard`, with `x` and `X` unset.

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
            "session_id": "sess-posix-outer-values",
            "transcript_path": "/tmp/claude/transcript.jsonl",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_use_id": "toolu_posix_outer_values",
        }),
        // `turn_id` selects Codex's protocol.
        Protocol::Codex => serde_json::json!({
            "session_id": "019dd11d-b795-7261-a9cb-9b85a5dadf16",
            "turn_id": "turn-posix-outer-values",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.5",
            "permission_mode": "default",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_use_id": "call_posix_outer_values",
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

/// A value the parent shell substitutes is unknown text where the child
/// shell reads it, including inside the child's single quotes, so it can
/// complete a command name (`'gi${x}t'`), be one (`'$x'`), or be empty.
#[test]
fn outer_values_in_a_shell_payload_are_unknown_child_text() {
    let misses = misses(
        &[
            r#"bash -c "'gi${x}t' reset --hard""#,
            r#"bash -c "'$x' reset --hard""#,
            r#"bash -c "'gi$(true)t' reset --hard""#,
            r#"bash -c "'gi`true`t' reset --hard""#,
            r#"bash -c "\"gi${x}t\" reset --hard""#,
            r#"bash -c "'gi'$x't' reset --hard""#,
            r"bash -c gi${x}t' reset --hard'",
            r#"bash -c "git 're${x}set' --hard""#,
            r#"bash -c "r'm${x}' -rf /""#,
            r#"bash -c "echo ok; 'gi${x}t' reset --hard""#,
            r#"bash -c "\$'gi${x}t' reset --hard""#,
            r#"sh -c "'gi${x}t' reset --hard""#,
            r#"bash -lc "'gi${x}t' reset --hard""#,
            r#"sudo bash -c "'gi${x}t' reset --hard""#,
            r#"env bash -c "'gi${x}t' reset --hard""#,
            r#"ssh host "'gi${x}t' reset --hard""#,
            r#"ssh host "'gi${x}t'" reset --hard"#,
            r#"bash -c "echo $(git reset --hard)""#,
            r#"x="'; git reset --hard; '"; bash -c "echo '$x'""#,
            r#"x="'; git reset --hard; '"; ssh host "echo '$x'""#,
        ],
        &POSIX,
        EvaluationDecision::Deny,
    );
    assert!(misses.is_empty(), "misses:\n{}", misses.join("\n"));
}

/// PowerShell substitutes `$x`, `${x}` and `$(…)` in a double-quoted
/// argument too (pwsh 7.5, fake `bash` and `ssh`: `bash -c "'gi${x}t' reset
/// --hard"` hands bash `'git' reset --hard`), so the child reads the same
/// unknown text. A value the command binds is judged with its text.
#[test]
fn powershell_values_in_a_shell_payload_are_unknown_child_text() {
    let misses = misses(
        &[
            r#"bash -c "'gi${x}t' reset --hard""#,
            r#"bash -c "'$x' reset --hard""#,
            r#"bash -c "'gi$('')t' reset --hard""#,
            r#"sh -c "'gi$x' reset --hard""#,
            r#"ssh host "'gi${x}t' reset --hard""#,
            r#"$x = "'; git reset --hard; '"; bash -c "echo '$x'""#,
        ],
        &[ShellDialect::PowerShell, ShellDialect::Unknown],
        EvaluationDecision::Deny,
    );
    assert!(misses.is_empty(), "misses:\n{}", misses.join("\n"));
}

/// Text the parent shell does not expand reaches the child as written: its
/// single quotes, an escaped `$`, and an ANSI-C quote.
#[test]
fn text_the_parent_does_not_expand_stays_as_written() {
    let misses = misses(
        &[
            r#"bash -c "echo '$HOME'""#,
            r#"bash -c "echo $HOME""#,
            r#"bash -c "cd '$PWD' && git status""#,
            r#"bash -c 'echo "$HOME"'"#,
            r#"bash -c "git status $x""#,
            r#"bash -c "'gi\${x}t' reset --hard""#,
            r"bash -c $'echo \'${x}\''",
            r#"ssh host "ls '$HOME'""#,
            r"cmd.exe /c 'gi${X}t reset --hard'",
        ],
        &POSIX,
        EvaluationDecision::Allow,
    );
    assert!(misses.is_empty(), "misses:\n{}", misses.join("\n"));
}

/// A value the parent shell substitutes into a cmd payload is unknown cmd
/// text: a top-level `cmd /c` fails closed on it, as on `%X%`.
#[test]
fn outer_values_in_a_cmd_payload_are_unknown_cmd_text() {
    let misses = misses(
        &[
            r#"cmd.exe /c "gi${X}t reset --hard""#,
            r#"cmd.exe /c "$X reset --hard""#,
            r#"cmd.exe /c "r${X}d /s /q C:\x""#,
            r#"cmd /c "gi${X}t reset --hard""#,
            r#"cmd.exe /k "gi${X}t reset --hard""#,
            r#"cmd.exe /d /s /c "gi${X}t reset --hard""#,
            r"cmd.exe /c gi${X}t reset --hard",
            r#"cmd.exe /c "gi"${X}"t reset --hard""#,
            r#"cmd.exe /c "gi$(true)t reset --hard""#,
            r#"cmd.exe /c "gi`true`t reset --hard""#,
            r#"cmd.exe //c "gi${X}t reset --hard""#,
        ],
        &POSIX,
        EvaluationDecision::Deny,
    );
    assert!(misses.is_empty(), "misses:\n{}", misses.join("\n"));
}

/// The same rule makes a harmless-looking value fail closed: cmd cannot
/// know it before the parent shell runs, exactly like `%USERNAME%`.
#[test]
fn harmless_outer_values_in_a_cmd_payload_fail_closed_like_cmd_variables() {
    let misses = misses(
        &[
            r#"cmd.exe /c "echo $HOME""#,
            r#"cmd.exe /c "dir $(pwd)""#,
            r#"cmd.exe /c "echo %USERNAME%""#,
        ],
        &[ShellDialect::Posix],
        EvaluationDecision::Deny,
    );
    assert!(misses.is_empty(), "misses:\n{}", misses.join("\n"));
}
