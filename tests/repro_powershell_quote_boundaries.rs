//! PowerShell has no backslash escape: `"C:\temp\"` is a complete string, and
//! the backtick escapes instead. dcg's scanners read quotes the POSIX way, so
//! `Write-Output "C:\temp\"; git reset --hard` looked like one string and the
//! reset passed. Codex on Windows runs every command with
//! `powershell.exe -Command`.

use destructive_command_guard::evaluator::evaluate_command_with_pack_order_at_path_in_dialect;
use destructive_command_guard::normalize::ShellDialect;
use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::{Config, EvaluationDecision, LayeredAllowlist};
use std::io::Write;
use std::process::{Command, Stdio};

const HOOK_TEST_TIMEOUT_MS: &str = "30000";

/// Commands whose middle part PowerShell runs. powershell.exe 5.1 ran a
/// harmless analogue of each (the middle command printed a marker).
const POWERSHELL_RUNS_THE_RESET: &[&str] = &[
    r#"Write-Output "C:\temp\"; git reset --hard; Write-Output "x""#,
    r#"echo "a\"; git reset --hard; echo "x""#,
    r#"cd "C:\Users\kaita\repo\"; git reset --hard; echo "done""#,
    r#"git -C "C:\Users\kaita\repo\" reset --hard"#,
    r#"git log --grep "C:\x\"; git reset --hard; echo "x""#,
    r#"echo "a\" | git reset --hard; echo "x""#,
    "echo \"a\\\"\ngit reset --hard\necho \"x\"",
    r"echo a\; git reset --hard",
    r#"Write-Output "a\$(git reset --hard)""#,
    r#"Write-Output `"; git reset --hard; Write-Output "x""#,
    "Write-Output @\"\na\"\n\"@\ngit reset --hard\necho \"x\"",
    r#"Write-Output "C:\temp\"; Remove-Item -Recurse -Force .\victim; Write-Output "x""#,
];

/// Ordinary PowerShell with the same quoting, which must stay allowed.
const HARMLESS: &[&str] = &[
    r#"Write-Output "C:\temp\""#,
    r#"cd "C:\x\"; git status"#,
    r#"git -C "C:\Users\kaita\repo\" status"#,
    r#"Get-ChildItem "C:\Users\kaita\repo\" -Recurse | Select-Object Name"#,
    r#"git commit -m "fix C:\path\ handling""#,
    r"Write-Output 'it''s'; git status",
    "Write-Output @'\nit's \"quoted\"\n'@ | Set-Content notes.txt",
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
            "session_id": "sess-ps-quote",
            "transcript_path": "/tmp/claude/transcript.jsonl",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "toolu_ps_quote",
        }),
        // `turn_id` selects Codex's protocol.
        Protocol::Codex => serde_json::json!({
            "session_id": "019dd11d-b795-7261-a9cb-9b85a5dadf15",
            "turn_id": "turn-ps-quote",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.5",
            "permission_mode": "default",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "call_ps_quote",
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
fn powershell_tool_reads_powershell_quotes_both_protocols() {
    for protocol in [Protocol::Claude, Protocol::Codex] {
        for command in POWERSHELL_RUNS_THE_RESET {
            assert_eq!(
                hook_decision(protocol, "PowerShell", command),
                "deny",
                "{protocol:?}: {command:?}"
            );
        }
        // A backtick escape is ordinary PowerShell (the Unknown union reads
        // it as an unparseable POSIX substitution, so it is checked here).
        for command in HARMLESS
            .iter()
            .chain(&[r#"Write-Output "a`tb"; git status"#])
        {
            assert_eq!(
                hook_decision(protocol, "PowerShell", command),
                "allow",
                "{protocol:?}: {command:?}"
            );
        }
    }
}

/// Codex labels every command `Bash`. On Windows the hook resolves that label
/// to the PowerShell-or-POSIX union, which must deny what PowerShell runs.
#[cfg(windows)]
#[test]
fn codex_bash_label_on_windows_reads_powershell_quotes() {
    for command in POWERSHELL_RUNS_THE_RESET {
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

/// The dialects that may be PowerShell: the proven one and the union a
/// generic adapter (and Codex on Windows) gets.
#[test]
fn powershell_and_unknown_dialects_read_powershell_quotes() {
    for dialect in [ShellDialect::PowerShell, ShellDialect::Unknown] {
        for command in POWERSHELL_RUNS_THE_RESET {
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
}

/// Bash reads `\"` inside double quotes as an escaped quote, so on a proven
/// POSIX shell these print text and run nothing.
#[test]
fn posix_dialect_keeps_backslash_escapes() {
    for command in [
        r#"echo "a\"; git reset --hard; echo "x""#,
        r#"cd "C:\Users\kaita\repo\"; git reset --hard; echo "done""#,
    ] {
        assert_eq!(
            decision_in(command, ShellDialect::Posix),
            EvaluationDecision::Allow,
            "{command:?}"
        );
    }
}
