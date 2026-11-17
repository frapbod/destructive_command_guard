//! PowerShell ends a line at a lone carriage return (CR, U+000D), as at a line
//! feed. dcg's shared readers end a line at a line feed only, as POSIX shells
//! do, so `echo a<CR>git reset --hard` looked like one `echo` and the reset
//! passed. Codex on Windows runs every command with `powershell.exe -Command`.

use destructive_command_guard::evaluator::evaluate_command_with_pack_order_at_path_in_dialect;
use destructive_command_guard::normalize::ShellDialect;
use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::{Config, EvaluationDecision, LayeredAllowlist};
use std::io::Write;
use std::process::{Command, Stdio};

const HOOK_TEST_TIMEOUT_MS: &str = "30000";

/// Commands that run `git reset --hard` or `git branch -D` in PowerShell.
/// Windows PowerShell 5.1 ran each with a stand-in `git` function that only
/// printed its arguments, and the stand-in printed them.
const POWERSHELL_RUNS_IT: &[&str] = &[
    "echo a\rgit reset --hard",
    "echo \"a/\"\rgit reset --hard",
    "echo \"a\\\"\rgit reset --hard",
    "echo a\r& 'git' reset --hard",
    "echo a\r& \"git\" reset --hard",
    "# note\rgit reset --hard",
    "echo a\r(git reset --hard)",
    "$x = @\"\rbody\r\"@\rgit reset --hard",
    "<# a\rb #>\rgit reset --hard",
    "echo --% a\rgit reset --hard",
    "echo a\rGIT reset --hard",
    "echo a\rgit reset --hard\recho done",
    "Write-Output x\rgit branch -D doomed",
];

/// The same characters where PowerShell runs nothing destructive: the CR is
/// string data, a backtick continues the line, or the character ends no line
/// (NEL, U+2028, U+2029, VT, FF; measured on Windows PowerShell 5.1).
const HARMLESS: &[&str] = &[
    "echo a\rgit status",
    "Write-Output \"x\rgit reset --hard\"",
    "git commit -m \"line one\rline two\"",
    "echo a`\rgit reset --hard",
    "$x = @\"\rgit reset --hard\r\"@\rWrite-Output $x",
    "echo a\u{85}git reset --hard",
    "echo a\u{2028}git reset --hard",
    "echo a\u{2029}git reset --hard",
    "echo a\u{b}git reset --hard",
    "echo a\u{c}git reset --hard",
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

/// The PowerShell tool label, in both hook formats, on every host.
#[test]
fn powershell_tool_ends_lines_at_lone_carriage_returns_both_protocols() {
    for protocol in [Protocol::Claude, Protocol::Codex] {
        for command in POWERSHELL_RUNS_IT {
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

/// Codex labels every command `Bash`. On Windows the hook resolves that label
/// to PowerShell or the PowerShell-or-POSIX union, which must deny what
/// PowerShell runs.
#[cfg(windows)]
#[test]
fn codex_bash_label_on_windows_ends_lines_at_lone_carriage_returns() {
    for command in POWERSHELL_RUNS_IT {
        assert_eq!(
            hook_decision(Protocol::Codex, "Bash", command),
            "deny",
            "{command:?}"
        );
    }
    for command in [
        "echo a\rgit status",
        "Write-Output \"x\rgit reset --hard\"",
        "git commit -m \"line one\rline two\"",
    ] {
        assert_eq!(
            hook_decision(Protocol::Codex, "Bash", command),
            "allow",
            "{command:?}"
        );
    }
}

/// The dialects that may be PowerShell: the proven one and the union a
/// generic adapter (and Codex on Windows) gets.
#[test]
fn powershell_and_unknown_dialects_end_lines_at_lone_carriage_returns() {
    for dialect in [ShellDialect::PowerShell, ShellDialect::Unknown] {
        for command in POWERSHELL_RUNS_IT {
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

/// Bash, dash and zsh read a lone CR as a byte of the word around it, so on
/// a proven POSIX shell (and the `Bash` label off Windows) `echo` prints the
/// rest and nothing else runs.
#[test]
fn posix_shells_read_a_lone_carriage_return_as_a_word_byte() {
    for command in [
        "echo a\rgit reset --hard",
        "echo \"a/\"\rgit reset --hard",
        "echo a\rgit reset --hard\recho done",
    ] {
        assert_eq!(
            decision_in(command, ShellDialect::Posix),
            EvaluationDecision::Allow,
            "{command:?}"
        );
        if cfg!(not(windows)) {
            for protocol in [Protocol::Claude, Protocol::Codex] {
                assert_eq!(
                    hook_decision(protocol, "Bash", command),
                    "allow",
                    "{protocol:?}: {command:?}"
                );
            }
        }
    }
}
