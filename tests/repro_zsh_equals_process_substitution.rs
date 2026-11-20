//! zsh runs the body of a `=(…)` process substitution and puts the name of
//! a temporary file with its output in its place, as `<(…)` puts a pipe's
//! name. Measured with `scripts/shell-truth` (zsh 5.9): zsh runs
//! `git reset --hard` for `echo =(git reset --hard)`, `X==(git reset --hard)`
//! and `echo ${x:-=(git reset --hard)}`, while Bash 5.3 and Linux Bash 5.2
//! report a syntax error and run nothing. dcg did not know the form, read
//! the body as a plain word after `echo` and allowed the line. zsh is the
//! macOS login shell, where Claude Code and Codex run their commands.

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

fn payload(
    protocol: Protocol,
    tool_name: &str,
    command: &str,
    cwd: &std::path::Path,
) -> serde_json::Value {
    match protocol {
        Protocol::Claude => serde_json::json!({
            "session_id": "sess-zsh-equals-subst",
            "transcript_path": "/tmp/claude/transcript.jsonl",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "toolu_zsh_equals_subst",
        }),
        // `turn_id` selects Codex's protocol.
        Protocol::Codex => serde_json::json!({
            "session_id": "019dd11d-b795-7261-a9cb-9b85a5dadf15",
            "turn_id": "turn-zsh-equals-subst",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.5",
            "permission_mode": "default",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "call_zsh_equals_subst",
        }),
    }
}

/// What the agent reads: "allow" for empty stdout, else the decision.
fn hook_decision(protocol: Protocol, tool_name: &str, command: &str) -> String {
    let temp = tempfile::tempdir().expect("temp dir");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let payload = payload(protocol, tool_name, command, temp.path()).to_string();
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

/// Checks each command in its dialects and in both hook formats with
/// `tool`, and reports every miss at once.
fn expect_everywhere(
    commands: &[String],
    dialects: &[ShellDialect],
    tool: &str,
    want: EvaluationDecision,
) -> Vec<String> {
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
            let got = hook_decision(protocol, tool, command);
            if got != hook_want {
                misses.push(format!("{protocol:?} {tool}: {command:?} -> {got}"));
            }
        }
    }
    misses
}

fn strings(commands: &[&str]) -> Vec<String> {
    commands
        .iter()
        .map(|command| (*command).to_string())
        .collect()
}

const POSIX: [ShellDialect; 2] = [ShellDialect::Posix, ShellDialect::Unknown];

/// Each place zsh runs a `=(…)` body: a word start, an assignment value and
/// the word after a `${…}` operator.
#[test]
fn a_zsh_equals_process_substitution_body_is_judged() {
    let misses = expect_everywhere(
        &strings(&[
            "echo =(git reset --hard)",
            "printf %s =(git reset --hard)",
            "=(git reset --hard)",
            "echo x;=(git reset --hard)",
            "echo x|=(git reset --hard)",
            "echo =(git reset --hard)x",
            "cat <=(git reset --hard)",
            "echo $(echo =(git reset --hard))",
            "echo `echo =(git reset --hard)`",
            "X==(git reset --hard)",
            "X=1 Y==(git reset --hard) true",
            "local X==(git reset --hard)",
            "echo ${x:-=(git reset --hard)}",
            "echo ${x==(git reset --hard)}",
            "echo ${x/1/=(git reset --hard)}",
            "echo ${x-=(git reset --hard)}",
            "echo ${x:+=(git reset --hard)}",
            "echo ${x[1]:-=(git reset --hard)}",
            "echo $x${y:-${z:-=(git reset --hard)}}",
            "echo >=(git reset --hard)",
            "echo 2>=(git reset --hard)",
            "echo =(git clean -fdx)",
            "echo =(git push --force origin main)",
            "zsh -c 'echo =(git reset --hard)'",
        ]),
        &POSIX,
        "Bash",
        EvaluationDecision::Deny,
    );
    assert!(misses.is_empty(), "allowed:\n{}", misses.join("\n"));
}

/// A value after a `=(…)` word reaches a cmd payload: zsh hands cmd
/// `echo <temp file>&rd /s /q C:\x`.
#[test]
fn a_value_after_a_zsh_equals_process_substitution_reaches_a_cmd_payload() {
    let command = r"X='&rd /s /q C:\x'; cmd.exe /c echo =(true)$X";
    let mut misses = Vec::new();
    for dialect in POSIX {
        let got = decision_in(command, dialect);
        if got != EvaluationDecision::Deny {
            misses.push(format!("{dialect:?}: {command:?} -> {got:?}"));
        }
    }
    assert!(misses.is_empty(), "allowed:\n{}", misses.join("\n"));
}

/// zsh runs no body for these (inside a word, in quotes, an array
/// assignment, a `${…}` pattern), or runs only a harmless one.
#[test]
fn other_equals_parens_and_harmless_bodies_stay_allowed() {
    let misses = expect_everywhere(
        &strings(&[
            "echo =(git status)",
            "diff =(ls) =(ls -a)",
            "X==(git log -1)",
            "echo ${x:-=(date)}",
            "x=(a b c)",
            "x+=(a b)",
            "echo a=(b)",
            "echo '=(git reset --hard)'",
            "echo \"=(git reset --hard)\"",
        ]),
        &POSIX,
        "Bash",
        EvaluationDecision::Allow,
    );
    assert!(misses.is_empty(), "denied:\n{}", misses.join("\n"));
}
