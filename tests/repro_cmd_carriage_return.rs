//! cmd.exe ignores CR bytes in command-line text before parsing it.

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

#[test]
fn direct_cmd_and_nested_payloads() {
    for command in [
        "gi\rt reset --hard",
        "echo a&gi\rt reset --hard",
        "gi\rt status",
    ] {
        let expected = if command.ends_with("status") {
            EvaluationDecision::Allow
        } else {
            EvaluationDecision::Deny
        };
        for dialect in [ShellDialect::Cmd, ShellDialect::Unknown] {
            assert_eq!(
                decision_in(command, dialect),
                expected,
                "{dialect:?}: {command:?}"
            );
        }
    }
    for command in [
        "cmd /c \"gi\rt reset --hard\"",
        "cmd.exe /d /k \"echo a&gi\rt reset --hard\"",
        "cmd /c \"g^\ri^t reset --hard\"",
        "cmd /c \"echo ok&gi\rt reset --hard\"",
    ] {
        for dialect in [
            ShellDialect::Cmd,
            ShellDialect::Unknown,
            ShellDialect::PowerShell,
            ShellDialect::Posix,
        ] {
            assert_eq!(
                decision_in(command, dialect),
                EvaluationDecision::Deny,
                "{dialect:?}: {command:?}"
            );
        }
    }
}

#[test]
fn cmd_hook_protocols() {
    for protocol in [Protocol::Claude, Protocol::Codex] {
        for command in [
            "gi\rt reset --hard",
            "echo a&gi\rt reset --hard",
            "cmd /c \"gi\rt reset --hard\"",
        ] {
            assert_eq!(
                hook_decision(protocol, "cmd", command),
                "deny",
                "{protocol:?}: {command:?}"
            );
        }
        for command in ["gi\rt status", "echo \"gi\rt reset --hard\""] {
            assert_eq!(
                hook_decision(protocol, "cmd", command),
                "allow",
                "{protocol:?}: {command:?}"
            );
        }
    }
}

#[test]
fn cmd_payload_hooks_in_other_shells_and_safe_data() {
    for protocol in [Protocol::Claude, Protocol::Codex] {
        for tool in ["Bash", "PowerShell", "cmd"] {
            for command in [
                "cmd /c \"gi\rt reset --hard\"",
                "cmd /k \"echo a&gi\rt reset --hard\"",
            ] {
                assert_eq!(
                    hook_decision(protocol, tool, command),
                    "deny",
                    "{protocol:?} {tool}: {command:?}"
                );
            }
            for command in [
                "cmd /c \"gi\rt status\"",
                "cmd /c \"echo gi\rt reset --hard\"",
            ] {
                assert_eq!(
                    hook_decision(protocol, tool, command),
                    "allow",
                    "{protocol:?} {tool}: {command:?}"
                );
            }
        }
    }
    for dialect in [ShellDialect::Posix, ShellDialect::PowerShell] {
        assert_eq!(
            decision_in("echo 'gi\rt reset --hard'", dialect),
            EvaluationDecision::Allow
        );
    }
}

/// A POSIX shell keeps a CR inside an unquoted word, so `cmd.exe /c
/// gi<CR>t reset --hard` from bash (WSL) hands cmd `gi<CR>t`, which cmd
/// reads as `git`. The same holds for a PowerShell host: it ends a line at
/// the CR. Unquoted, the words must keep their CR for those readings.
#[test]
fn unquoted_posix_words_keep_cr_for_windows_launchers() {
    for command in [
        "cmd.exe /c gi\rt reset --hard",
        "cmd.exe /d /c gi\rt reset --hard",
        "cmd.exe /c gi\rt\\ reset\\ --hard",
        "pwsh -Command echo a\rgit reset --hard",
    ] {
        for dialect in [ShellDialect::Posix, ShellDialect::Unknown] {
            assert_eq!(
                decision_in(command, dialect),
                EvaluationDecision::Deny,
                "{dialect:?}: {command:?}"
            );
        }
        for protocol in [Protocol::Claude, Protocol::Codex] {
            assert_eq!(
                hook_decision(protocol, "Bash", command),
                "deny",
                "{protocol:?}: {command:?}"
            );
        }
    }
    for command in [
        "cmd.exe /c gi\rt status",
        "cmd.exe /c echo gi\rt reset --hard",
        "echo gi\rt reset --hard",
    ] {
        for dialect in [ShellDialect::Posix, ShellDialect::Unknown] {
            assert_eq!(
                decision_in(command, dialect),
                EvaluationDecision::Allow,
                "{dialect:?}: {command:?}"
            );
        }
        for protocol in [Protocol::Claude, Protocol::Codex] {
            assert_eq!(
                hook_decision(protocol, "Bash", command),
                "allow",
                "{protocol:?}: {command:?}"
            );
        }
    }
}

/// `Start-Process cmd -ArgumentList '/c gi<CR>t reset --hard'` runs cmd with
/// that command line, and cmd removes the CR. A comma list runs the same
/// line: Start-Process joins it with spaces.
#[test]
fn start_process_cmd_argument_lists_with_cr() {
    for command in [
        "Start-Process cmd -ArgumentList '/c gi\rt reset --hard'",
        "Start-Process -FilePath cmd.exe -ArgumentList '/c gi\rt reset --hard' -Wait",
        "Start-Process cmd -ArgumentList '/c', 'gi\rt reset --hard'",
        "Start-Process cmd -ArgumentList '/c', 'git reset --hard'",
        "Start-Process cmd -ArgumentList @(\"/c\", \"gi\rt reset --hard\")",
    ] {
        for dialect in [ShellDialect::PowerShell, ShellDialect::Unknown] {
            assert_eq!(
                decision_in(command, dialect),
                EvaluationDecision::Deny,
                "{dialect:?}: {command:?}"
            );
        }
        for protocol in [Protocol::Claude, Protocol::Codex] {
            for tool in ["PowerShell", "Bash"] {
                assert_eq!(
                    hook_decision(protocol, tool, command),
                    "deny",
                    "{protocol:?} {tool}: {command:?}"
                );
            }
        }
    }
    for command in [
        "Start-Process cmd -ArgumentList '/c gi\rt status'",
        "Start-Process cmd -ArgumentList '/c', 'gi\rt status'",
        "Start-Process cmd -ArgumentList '/c', 'echo gi\rt reset --hard'",
    ] {
        for dialect in [ShellDialect::PowerShell, ShellDialect::Unknown] {
            assert_eq!(
                decision_in(command, dialect),
                EvaluationDecision::Allow,
                "{dialect:?}: {command:?}"
            );
        }
        for protocol in [Protocol::Claude, Protocol::Codex] {
            for tool in ["PowerShell", "Bash"] {
                assert_eq!(
                    hook_decision(protocol, tool, command),
                    "allow",
                    "{protocol:?} {tool}: {command:?}"
                );
            }
        }
    }
}
