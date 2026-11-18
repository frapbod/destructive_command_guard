//! PowerShell's dot-source operator `.` invokes a command the way the call
//! operator `&` does. Sandboxed PowerShell 7.5 (`scripts/shell-truth pwsh`,
//! Nov 17 2026) ran `git reset --hard` for `. git reset --hard`,
//! `. 'git' reset --hard`, `. "git" reset --hard`, `$r=. git reset --hard`,
//! `Get-Date | . git reset --hard`, `try { . git reset --hard } catch {}` and
//! `& { . git reset --hard }`, and `. Remove-Item -Recurse -Force victim`
//! deleted `victim`. dcg judged the `&` forms and let the dot forms pass.
//! Dot-sourcing a script (`. ./x.ps1`, `. $profile`) and a `.` inside
//! arguments stay allowed.

use destructive_command_guard::evaluator::evaluate_command_with_pack_order_at_path_in_dialect;
use destructive_command_guard::normalize::ShellDialect;
use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::{Config, EvaluationDecision, LayeredAllowlist};
use std::io::Write;
use std::process::{Command, Stdio};

const HOOK_TEST_TIMEOUT_MS: &str = "30000";

/// PowerShell runs the destructive command in each of these.
const POWERSHELL_RUNS_IT: &[&str] = &[
    ". git reset --hard",
    ". 'git' reset --hard",
    ". \"git\" reset --hard",
    ".  git reset --hard",
    ". GIT reset --hard",
    ". git.exe reset --hard",
    ". 'C:\\Program Files\\Git\\cmd\\git.exe' reset --hard",
    "echo a; . git reset --hard",
    "echo a\n. git reset --hard",
    "Write-Output x | . git reset --hard",
    "(. git reset --hard)",
    "if ($true) { . git reset --hard }",
    "try { . git reset --hard } catch {}",
    "& { . git reset --hard }",
    "$r = . git reset --hard",
    "$r=. git reset --hard",
    ". git branch -D doomed",
    ". git push --force origin main",
    ". Remove-Item -Recurse -Force C:\\Users\\kaita",
    ". 'Remove-Item' -Recurse -Force C:\\Users\\kaita",
    "Get-ChildItem x | . Remove-Item -Recurse -Force",
    ". rm -Recurse -Force C:\\Users\\kaita",
    "powershell -NoProfile -Command \". 'git' reset --hard\"",
    "powershell -NoProfile -Command \". Remove-Item -Recurse -Force C:\\Users\\kaita\"",
    "& git reset --hard",
];

/// Dot-sourcing a script, a harmless command, and `.` as data.
const HARMLESS: &[&str] = &[
    ". ./script.ps1",
    ". $profile",
    ". $PROFILE.CurrentUserAllHosts",
    ". .\\defs.ps1",
    ". .\\venv\\Scripts\\Activate.ps1",
    ". 'C:\\tools\\Remove-Item-Helpers.ps1'",
    ". \"$PSScriptRoot\\helpers.ps1\"",
    ". $env:USERPROFILE\\env.ps1",
    "$x = . .\\get-config.ps1",
    "ls . ; . .\\a.ps1",
    ". { Get-Date }",
    ". git status",
    ". git reset --soft HEAD~1",
    ". 'git' status",
    "$c = 'git'; . $c status",
    "echo . git reset --hard",
    "git add .",
    "git log -- .",
    "Write-Output \"x . git reset --hard\"",
    "git commit -m 'fix. git reset --hard is bad'",
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
            "session_id": "sess-ps-dot",
            "transcript_path": "/tmp/claude/transcript.jsonl",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "toolu_ps_dot",
        }),
        // `turn_id` selects Codex's protocol.
        Protocol::Codex => serde_json::json!({
            "session_id": "019dd11d-b795-7261-a9cb-9b85a5dadf15",
            "turn_id": "turn-ps-dot",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.5",
            "permission_mode": "default",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "call_ps_dot",
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
fn powershell_tool_judges_the_dot_source_operator_both_protocols() {
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

/// The dialects that may be PowerShell: the proven one and the union a
/// generic adapter (Windows Codex) gets.
#[test]
fn powershell_and_unknown_dialects_judge_the_dot_source_operator() {
    for dialect in [ShellDialect::PowerShell, ShellDialect::Unknown] {
        for command in POWERSHELL_RUNS_IT {
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

/// `.git` is one command name, not the operator: PowerShell 7.5 reported
/// that no command `.git` exists.
#[test]
fn a_dot_joined_to_the_word_is_not_the_operator() {
    assert_eq!(
        decision_in(".git reset --hard", ShellDialect::PowerShell),
        EvaluationDecision::Allow
    );
}

/// In a POSIX shell `. git` sources a file named git; it never runs git.
#[test]
fn posix_dot_builtin_is_not_a_git_invocation() {
    assert_eq!(
        decision_in(". git reset --hard", ShellDialect::Posix),
        EvaluationDecision::Allow
    );
}
