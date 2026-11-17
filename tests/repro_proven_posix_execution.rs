//! Known positional arguments and variables that execute commands, tested
//! through both hook protocols. Commands are scanned, never executed.

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
            "session_id": "sess-eval",
            "transcript_path": "/tmp/claude/transcript.jsonl",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_use_id": "toolu_eval",
        }),
        // `turn_id` selects Codex's protocol.
        Protocol::Codex => serde_json::json!({
            "session_id": "019dd11d-b795-7261-a9cb-9b85a5dadf15",
            "turn_id": "turn-eval",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.5",
            "permission_mode": "default",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_use_id": "call_eval",
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

fn assert_both(decision: &str, commands: &[&str]) {
    for command in commands {
        for protocol in [Protocol::Claude, Protocol::Codex] {
            assert_eq!(
                hook_decision(protocol, command),
                decision,
                "{protocol:?}: {command:?}"
            );
        }
    }
}

#[test]
fn proven_command_arguments_and_source_are_judged() {
    assert_both(
        "deny",
        &[
            r#"f() { "$@"; }; f git reset --hard"#,
            r#"f() { $*; }; f git reset --hard"#,
            r#"f() { "$*" reset --hard; }; f git"#,
            r#"f() { exec "$@"; }; f git reset --hard"#,
            r#"f() { command "$@"; }; f git reset --hard"#,
            "f() {\n  \"$@\"\n}; f git reset --hard",
            r#"echo() { "$@"; }; echo git reset --hard"#,
            r#"set -- git reset --hard; "$@""#,
            r#"x='git reset --hard'; bash <<< "$x""#,
            r#"x='git reset --hard'; . /dev/stdin <<< "$x""#,
        ],
    );
}

#[test]
fn harmless_and_unknown_commands_keep_current_policy() {
    assert_both(
        "allow",
        &[
            r#"f() { "$@"; }; f ls"#,
            r#"retry() { "$@"; }; retry make"#,
            r#"f() { printf '%s' "$@"; }; f 'git reset --hard'"#,
            r#"f() { "$@"; }; f 'git reset --hard'"#,
            r#"set -- git status; "$@""#,
            r#"x='git status'; bash <<< "$x""#,
            r#"x='git status'; . /dev/stdin <<< "$x""#,
            r#"trap "$1" EXIT"#,
            r#"source "$1""#,
            r#""$@""#,
            // A quoted $* combines multiple words into one executable name.
            r#"f() { "$*"; }; f git reset --hard"#,
        ],
    );
    assert_both("deny", &[r#"eval "$*""#]);
}
