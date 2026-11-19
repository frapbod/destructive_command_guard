//! PowerShell reads a braced variable name (`${…}`) as literal text up to
//! the first `}` not escaped by a backtick, bare or in an expandable string:
//! a quote, `#`, `;` or `$(` in it is part of the name. dcg's PowerShell
//! readers read a quote there as opening a string, which hid the rest of the
//! command, so `${a'b} = 1; git reset --hard` passed in the PowerShell
//! dialect.

use destructive_command_guard::evaluator::evaluate_command_with_pack_order_at_path_in_dialect;
use destructive_command_guard::normalize::ShellDialect;
use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::{Config, EvaluationDecision, LayeredAllowlist};
use std::io::Write;
use std::process::{Command, Stdio};

const HOOK_TEST_TIMEOUT_MS: &str = "30000";

/// Each runs `git reset --hard` (or `Remove-Item -Recurse -Force`) in
/// sandboxed PowerShell 7.5 (`scripts/shell-truth pwsh`, fake git), Nov 18
/// and 19 2026.
const RUNS_IT: &[&str] = &[
    "${a'b} = 1; git reset --hard",
    "${a\"b} = 1; git reset --hard",
    "${a'b}; git reset --hard",
    "${a\"b}; git reset --hard",
    "Write-Output ${a'b}; git reset --hard",
    "${a'b} | Out-Null; git reset --hard",
    "${a'b}\ngit reset --hard",
    "${a'b} = 1; $ExecutionContext.InvokeCommand.InvokeScript('git reset --hard')",
    // PR #31's member-form reader is fed by the same tokenizer.
    "${a'b} = 'o'; $ExecutionContext.InvokeCommand | % -OutVariable ${a'b} InvokeScript 'git reset --hard'",
    // From card t_b993ced4 (PR #12): a POSIX-style default holds the quote.
    "echo ${x:- #it's}; git reset --hard",
    "echo ${x:- it's}; git reset --hard",
    // Any expression or position can hold the name.
    "$(${a'b}); git reset --hard",
    "(${a'b}); git reset --hard",
    "& { ${a'b} }; git reset --hard",
    "${a'b}.Length; git reset --hard",
    "[string]${a'b}; git reset --hard",
    "$y = ${a'b}; git reset --hard",
    "Write-Output ${a'b} && git reset --hard",
    "Write-Output x${a'b}; git reset --hard",
    "${a'b'c}; git reset --hard",
    "${'}; git reset --hard",
    "${\"}; git reset --hard",
    "${env:a'b}; git reset --hard",
    "${function:a'b} = { 1 }; git reset --hard",
    "if (${a'b}) { 1 }; git reset --hard",
    "@(${a'b}); git reset --hard",
    "Write-Output @{k=${a'b}}; git reset --hard",
    "Write-Output ${a'b}; Remove-Item -Recurse -Force .\\victim",
    "Write-Output ${a'b} # it's\ngit reset --hard",
    // A backtick escapes a `}` inside the name; `$$` is a variable of its own,
    // and an escaped backtick leaves the `$` that opens the name.
    "${a`}'b}; git reset --hard",
    "Write-Output $$${a'b}; git reset --hard",
    "Write-Output ``${a'b}; git reset --hard",
    // A here-string header, a smart quote and other syntax bytes in the name.
    "${a@'\n}; git reset --hard",
    "${a\u{2019}b}; git reset --hard",
    "${a$(b}; git reset --hard",
    "${a(b}; git reset --hard",
    "${a[b}; git reset --hard",
    "${a|b}; git reset --hard",
    // In an expandable string the name runs to its `}` too.
    "Write-Output \"${a\"b}\"; git reset --hard",
    "$x = @\"\n${a\"b}\n\"@; git reset --hard",
    // In a script string and a child shell's payload.
    "iex '${a''b}; git reset --hard'",
    "pwsh -c '${a''b} = 1; git reset --hard'",
];

/// Harmless in sandboxed PowerShell 7.5 (no `git reset`), and allowed in the
/// PowerShell and Unknown dialects.
const HARMLESS: &[&str] = &[
    "${a\"b} = 1; git status",
    "Write-Output '${a; git reset --hard}'",
    "Write-Output \"${a; git reset --hard}\"",
    "Write-Output ${env:ProgramFiles(x86)}",
    "Get-ChildItem \"${env:ProgramFiles(x86)}\\Git\"",
];

/// Harmless in sandboxed PowerShell 7.5 and allowed in the PowerShell
/// dialect. The Unknown dialect also reads them as POSIX text, where the
/// quote is unclosed or `;` ends a command, and does not allow them on base
/// d95833b3 either.
const HARMLESS_IN_POWERSHELL: &[&str] = &[
    "${a'b} = 1; git status",
    "$x = \"${a'b}\"; git status",
    "Write-Output ${a'b}",
    "Write-Output ${a';git reset --hard'}",
    "Write-Output ${a'b} 'git reset --hard'",
    "echo ${x:- it's}",
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
            "session_id": "sess-ps-braced",
            "transcript_path": "/tmp/claude/transcript.jsonl",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "toolu_ps_braced",
        }),
        // `turn_id` selects Codex's protocol.
        Protocol::Codex => serde_json::json!({
            "session_id": "019dd11d-b795-7261-a9cb-9b85a5dadf15",
            "turn_id": "turn-ps-braced",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.5",
            "permission_mode": "default",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "call_ps_braced",
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
fn powershell_tool_reads_braced_variable_names() {
    for protocol in [Protocol::Claude, Protocol::Codex] {
        for command in RUNS_IT {
            assert_eq!(
                hook_decision(protocol, "PowerShell", command),
                "deny",
                "{protocol:?}: {command:?}"
            );
        }
        for command in HARMLESS.iter().chain(HARMLESS_IN_POWERSHELL) {
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
fn codex_bash_label_on_windows_reads_braced_variable_names() {
    for command in RUNS_IT {
        assert_eq!(
            hook_decision(Protocol::Codex, "Bash", command),
            "deny",
            "{command:?}"
        );
    }
}

#[test]
fn powershell_and_unknown_dialects_read_braced_variable_names() {
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
}
