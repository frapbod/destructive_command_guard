//! cmd.exe reads a leading `@` as echo suppression, so dcg decoded
//! `@($x) + [scriptblock]::Create('git reset --hard').Invoke()` as the cmd.exe
//! command `($x) + …`. Under the Unknown dialect (generic hook labels, and
//! Codex's `Bash` label on Windows) that one launcher reading counted as the
//! whole command, and the passes that judge the PowerShell reading, where
//! `@( … )` is an array subexpression and the script block runs, were skipped.
//! A second statement (`@($x); …`) made a segment no dialect read as a
//! launcher and so hid the gap.

use destructive_command_guard::evaluator::evaluate_command_with_pack_order_at_path_in_dialect;
use destructive_command_guard::normalize::ShellDialect;
use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::{Config, EvaluationDecision, LayeredAllowlist};
use std::io::Write;
use std::process::{Command, Stdio};

const HOOK_TEST_TIMEOUT_MS: &str = "30000";

/// Each ran `git reset --hard` in sandboxed PowerShell 7.5
/// (`scripts/shell-truth pwsh`, fake git), Nov 18 2026; Bash ran nothing.
const RUNS_IT: &[&str] = &[
    "@($x) + [scriptblock]::Create('git reset --hard').Invoke()",
    "@(1).Count + [scriptblock]::Create('git reset --hard').Invoke().Count",
    "@{a=1} + [scriptblock]::Create('git reset --hard').Invoke()",
    "@($x) + [scriptblock]::Create(\"git reset --hard\").InvokeReturnAsIs()",
];

/// None of these ran `git reset --hard` in sandboxed PowerShell 7.5 or Bash.
const HARMLESS: &[&str] = &[
    "@(1, 2).ForEach({ $_ * 2 })",
    "@('a').ForEach('ToUpper')",
    "@($x) + [scriptblock]::Create('git status').Invoke()",
    "@{a=1}",
    "@($x).Count",
    // A Bash extglob.
    "ls @(*.txt|*.md)",
];

/// Harmless in PowerShell 7.5 too. The Unknown dialect denies it, as it
/// denies `('git reset --hard').Count` on base 9a712556 (its POSIX reading
/// takes the quoted text as a command), so it is checked in the PowerShell
/// dialect only.
const HARMLESS_IN_POWERSHELL: &[&str] = &["@('git reset --hard').Count"];

/// cmd.exe's own `@` prefix keeps its meaning. These are checked in the Cmd
/// dialect: with the Windows packs on, the Unknown dialect denies them, as
/// the PowerShell dialect does on base 9a712556. In PowerShell 7.5 `@word` in
/// command position is a parse error that runs nothing.
const CMD_AT_HARMLESS: &[&str] = &["@echo off", "@git status"];

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
            "session_id": "sess-cmd-at",
            "transcript_path": "/tmp/claude/transcript.jsonl",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "toolu_cmd_at",
        }),
        // `turn_id` selects Codex's protocol.
        Protocol::Codex => serde_json::json!({
            "session_id": "019dd11d-b795-7261-a9cb-9b85a5dadf15",
            "turn_id": "turn-cmd-at",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.5",
            "permission_mode": "default",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "call_cmd_at",
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

/// A tool label that names no shell is the Unknown dialect, and the
/// PowerShell label is PowerShell, in both hook formats.
#[test]
fn hook_judges_powershell_reading_of_cmd_at_prefix() {
    for protocol in [Protocol::Claude, Protocol::Codex] {
        for tool_name in ["Shell", "PowerShell"] {
            for command in RUNS_IT {
                assert_eq!(
                    hook_decision(protocol, tool_name, command),
                    "deny",
                    "{protocol:?} {tool_name}: {command:?}"
                );
            }
            for command in HARMLESS {
                assert_eq!(
                    hook_decision(protocol, tool_name, command),
                    "allow",
                    "{protocol:?} {tool_name}: {command:?}"
                );
            }
        }
        for command in HARMLESS_IN_POWERSHELL {
            assert_eq!(
                hook_decision(protocol, "PowerShell", command),
                "allow",
                "{protocol:?}: {command:?}"
            );
        }
        for command in CMD_AT_HARMLESS {
            assert_eq!(
                hook_decision(protocol, "cmd", command),
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
fn codex_bash_label_on_windows_judges_cmd_at_prefix() {
    for command in RUNS_IT {
        assert_eq!(
            hook_decision(Protocol::Codex, "Bash", command),
            "deny",
            "{command:?}"
        );
    }
    for command in HARMLESS {
        assert_eq!(
            hook_decision(Protocol::Codex, "Bash", command),
            "allow",
            "{command:?}"
        );
    }
}

#[test]
fn powershell_and_unknown_dialects_judge_cmd_at_prefix() {
    for dialect in [ShellDialect::PowerShell, ShellDialect::Unknown] {
        for command in RUNS_IT {
            assert_eq!(
                decision_in(command, dialect),
                EvaluationDecision::Deny,
                "{dialect:?}: {command:?}"
            );
        }
        for command in HARMLESS {
            assert_eq!(
                decision_in(command, dialect),
                EvaluationDecision::Allow,
                "{dialect:?}: {command:?}"
            );
        }
    }
    for command in HARMLESS_IN_POWERSHELL {
        assert_eq!(
            decision_in(command, ShellDialect::PowerShell),
            EvaluationDecision::Allow,
            "{command:?}"
        );
    }
    for command in CMD_AT_HARMLESS {
        assert_eq!(
            decision_in(command, ShellDialect::Cmd),
            EvaluationDecision::Allow,
            "{command:?}"
        );
    }
}

/// cmd.exe's `@` prefix still decodes the command it suppresses.
#[test]
fn cmd_at_prefix_still_judges_its_command() {
    for dialect in [ShellDialect::Cmd, ShellDialect::Unknown] {
        assert_eq!(
            decision_in("@git reset --hard", dialect),
            EvaluationDecision::Deny,
            "{dialect:?}"
        );
    }
}
