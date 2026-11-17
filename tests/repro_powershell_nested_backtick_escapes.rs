//! A nested `powershell -Command "..."` payload in double quotes is an
//! expandable string: the parent decodes `` `n `` / `` `r `` to line breaks
//! before the child reads it, so the text after the escape is a new statement
//! in the child. dcg read the payload spelled, so the second statement hid.

use destructive_command_guard::evaluator::evaluate_command_with_pack_order_at_path_in_dialect;
use destructive_command_guard::normalize::ShellDialect;
use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::{Config, EvaluationDecision, LayeredAllowlist};
use std::io::Write;
use std::process::{Command, Stdio};

const HOOK_TEST_TIMEOUT_MS: &str = "30000";

/// The child runs `git reset --hard` / `git branch -D` as a second statement
/// (Windows PowerShell 5.1, harmless analogue measured on the desktop).
const CHILD_RUNS_IT: &[&str] = &[
    "powershell -Command \"echo a`ngit reset --hard\"",
    "powershell -Command \"echo a`rgit reset --hard\"",
    "pwsh -Command \"echo a`rgit reset --hard\"",
    "pwsh -c \"echo a`ngit reset --hard\"",
    "powershell.exe -NoProfile -Command \"echo a`n`ngit reset --hard\"",
    "powershell -Command \"echo a`r`ngit branch -D doomed\"",
    "powershell -Command \"echo a`ngit reset --hard`necho done\"",
    "powershell -Command \"echo a``;`ngit reset --hard\"",
    // A bare word decodes the same escapes (Windows PowerShell 5.1 measured
    // `` `r `` in a bare word; PowerShell 7.5 measured `` `n ``, `` `r ``,
    // `` `t ``): `` ` `` before a space joins the words into one payload.
    "powershell -Command echo`ngit` reset` --hard",
    "powershell -Command echo`rgit` reset` --hard",
    "pwsh -c echo`ngit` branch` -D` doomed",
    // cmd.exe splits on the tab a bare or quoted `` `t `` becomes.
    "cmd /c git`treset`t--hard",
    "cmd /c \"git`treset`t--hard\"",
    // PowerShell 6+ reads `` `u{hex} `` as that code point.
    "pwsh -Command \"echo a`u{a}git reset --hard\"",
    "pwsh -Command \"echo a; `u{67}it reset --hard\"",
];

/// Single-quoted payloads keep the backtick literal; a doubled backtick or an
/// escaped quote is data; plain escapes with nothing destructive stay allowed.
const HARMLESS: &[&str] = &[
    "powershell -Command 'echo a`ngit reset --hard'",
    "powershell -Command \"echo a``ngit reset --hard\"",
    "powershell -Command \"echo a`ngit status\"",
    "powershell -Command \"echo a`tb\"",
    "powershell -Command \"echo `\"hi`\"\"",
    "powershell -Command echo`ta`nb",
    // `` `u `` that is not `` `u{hex} `` is the letter (5.1), or a parse
    // error that runs nothing (6+).
    "pwsh -Command \"echo a`ugit reset --hard\"",
    "pwsh -Command \"echo a`u{zz}git reset --hard\"",
];

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
            "session_id": "sess-ps-cr",
            "transcript_path": "/tmp/claude/transcript.jsonl",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "toolu_ps_cr",
        }),
        // `turn_id` selects Codex's protocol.
        Protocol::Codex => serde_json::json!({
            "session_id": "019dd11d-b795-7261-a9cb-9b85a5dadf15",
            "turn_id": "turn-ps-cr",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.5",
            "permission_mode": "default",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "call_ps_cr",
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

/// The PowerShell tool label, in both hook formats.
#[test]
fn powershell_tool_decodes_backtick_escapes_in_nested_command_payloads() {
    for protocol in [Protocol::Claude, Protocol::Codex] {
        for command in CHILD_RUNS_IT {
            assert_eq!(
                hook_decision(protocol, "PowerShell", command),
                "deny",
                "{protocol:?}: {command:?}"
            );
        }
        for command in HARMLESS {
            assert_eq!(
                hook_decision(protocol, "PowerShell", command),
                "allow",
                "{protocol:?}: {command:?}"
            );
        }
    }
}

/// Codex labels every command `Bash`; on Windows that resolves to PowerShell
/// or the PowerShell-or-POSIX union.
#[cfg(windows)]
#[test]
fn codex_bash_label_on_windows_decodes_backtick_escapes_in_nested_payloads() {
    for command in CHILD_RUNS_IT {
        assert_eq!(
            hook_decision(Protocol::Codex, "Bash", command),
            "deny",
            "{command:?}"
        );
    }
}

#[test]
fn powershell_and_unknown_dialects_decode_backtick_escapes_in_nested_payloads() {
    for dialect in [ShellDialect::PowerShell, ShellDialect::Unknown] {
        for command in CHILD_RUNS_IT {
            assert_eq!(
                decision_in(command, dialect),
                EvaluationDecision::Deny,
                "{dialect:?}: {command:?}"
            );
        }
    }
    for command in HARMLESS {
        assert_eq!(
            decision_in(command, ShellDialect::PowerShell),
            EvaluationDecision::Allow,
            "{command:?}"
        );
    }
}
