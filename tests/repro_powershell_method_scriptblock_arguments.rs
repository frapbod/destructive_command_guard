//! A script block passed to a method call ran unjudged in the PowerShell
//! dialect: `(1).ForEach({ git reset --hard })` runs the block once per
//! element, and so do `.Where`, the bare `.ForEach{ … }` form and .NET
//! methods that take a delegate (`[regex]::Replace`, `List.Sort`). A
//! `$b = { … }` variable passed to a method or invoked later was not
//! followed either. The Unknown dialect denied most rows only because its
//! POSIX reading took `{ git reset --hard }` for a brace group.

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
    "$x = 1; $x.ForEach({ git reset --hard })",
    "(1).ForEach({ git reset --hard })",
    "(1..2).ForEach({ git reset --hard })",
    "(1,2).Where({ git reset --hard })",
    "$a = @(1).ForEach({ git reset --hard })",
    "(1).ForEach{ git reset --hard }",
    "(1).Where{ git reset --hard }",
    "(1).ForEach{git reset --hard}",
    "(1).ForEach({ git reset --hard }, 'x')",
    "(1).Where({ git reset --hard }, 'First')",
    "(1).Where({ git reset --hard }, 'Until', 1)",
    "(1). ForEach({ git reset --hard })",
    "(1).<# c #>ForEach({ git reset --hard })",
    "(1).ForEach(<# c #>{ git reset --hard })",
    "(1).ForEach(`\n{ git reset --hard })",
    "(1).ForEach(\n{ git reset --hard })",
    "(1).'ForEach'({ git reset --hard })",
    "(1).\"ForEach\"({ git reset --hard })",
    "(1).FOREACH({ git reset --hard })",
    "(1)?.ForEach({ git reset --hard })",
    "$m = 'ForEach'; (1).$m({ git reset --hard })",
    "(1).$('ForEach')({ git reset --hard })",
    "(1).ForEach(({ git reset --hard }))",
    "(1).ForEach([scriptblock]{ git reset --hard })",
    "(1).ForEach((Write-Output { git reset --hard }))",
    "[regex]::Replace('a', 'a', { git reset --hard })",
    "[regex]::new('a').Replace('a', { git reset --hard })",
    "$l = [System.Collections.Generic.List[int]]::new(); $l.Add(2); $l.Add(1); $l.Sort({ git reset --hard; 0 })",
    "$l = [System.Collections.Generic.List[int]]::new(); $l.Add(2); $l.Add(1); $l.Sort{ git reset --hard; 0 }",
    "$x = (1).ForEach({ git reset --hard }).Count",
    "Write-Output (1).ForEach({ git reset --hard })",
    "$h = @{a=1}; $h.Keys.ForEach({ git reset --hard })",
    "(1).ForEach({ (2).Where({ git reset --hard }) })",
    "(1).ForEach({ & { git reset --hard } })",
    "(1).ForEach{ git reset --hard } | Out-Null",
    "Get-Item . | ForEach-Object { $_ }; (1).ForEach({ git reset --hard })",
    "$b = { git reset --hard }; (1).ForEach($b)",
    "$b = { git reset --hard }; (1).Where($b)",
    "$b = { git reset --hard }; (1).ForEach( $b )",
    "${b} = { git reset --hard }; (1).ForEach(${b})",
    "$script:b = { git reset --hard }; (1).ForEach($script:b)",
    "[scriptblock]$b = { git reset --hard }; (1).ForEach($b)",
    "$b = { git reset --hard }; [regex]::Replace('a', 'a', $b)",
    "$b = { git reset --hard }; $b.Invoke()",
    "$b = { git reset --hard }; $r = $b.Invoke()",
    "$b = [scriptblock]::Create('git reset --hard'); $r = $b.Invoke()",
    "$b = { git reset --hard }; $b.InvokeReturnAsIs()",
    "$b = { git reset --hard }; Invoke-Command $b",
    "$b = { git reset --hard }; Invoke-Command -ScriptBlock $b",
    "$b = { git reset --hard }; 1 | % $b",
    "$b = { git reset --hard }; . $b",
];

/// Each ran `git reset --hard` in PowerShell 7.5 too. Under the Unknown
/// dialect a leading `@(` is read as cmd.exe's `@` prefix and the PowerShell
/// passes are skipped; PR #32 fixes that. Until it merges they are checked
/// with the PowerShell dialect and label only.
const RUNS_IT_AT_PREFIX: &[&str] = &[
    "@(1).ForEach({ git reset --hard })",
    "@(1).Where({ git reset --hard })",
    "@(1).ForEach{ git reset --hard }",
];

/// None of these ran `git reset --hard` in PowerShell 7.5 or Bash.
const HARMLESS: &[&str] = &[
    "@(1, 2).ForEach({ $_ * 2 })",
    "(1..3).Where({ $_ -gt 1 })",
    "@('a').ForEach('ToUpper')",
    "(1).ForEach('ToString')",
    "$x = 1; $x.ForEach({ git status })",
    "(1).ForEach({ git status })",
    "$b = { git status }; (1).ForEach($b)",
    "$b = { git status }; $b.Invoke()",
    "Write-Output '(1).ForEach({ git reset --hard })'",
];

/// Harmless in PowerShell 7.5 and Bash as well. The Unknown dialect denies
/// them on base 9a712556 too (its POSIX reading takes `{ git reset --hard }`
/// for a brace group), so they are checked in the PowerShell dialect only.
/// The last three are PowerShell parse errors that run nothing.
const HARMLESS_IN_POWERSHELL: &[&str] = &[
    "$b = { git reset --hard }",
    "$b = { git reset --hard }; $b = 'x'; (1).ForEach({ $_ })",
    "$h = @{}; $h.Add('k', @{ a = { git reset --hard } }); $h.Count",
    "(1).ForEach ({ git reset --hard })",
    "(1).ForEach { git reset --hard }",
    "(1) .ForEach({ git reset --hard })",
];

/// These run nothing in PowerShell 7.5: `List.Add` stores the block and
/// `String.Replace` converts it to text. dcg cannot tell those methods from
/// one that runs its argument (the object's type is unknown), so a script
/// block in any method's arguments is judged as running. The cost is a denial
/// when such a stored block holds a destructive command.
const DENIED_THOUGH_NOT_RUN: &[&str] = &[
    "$l = [System.Collections.Generic.List[object]]::new(); $l.Add({ git reset --hard }); $l.Count",
    "$l = [System.Collections.Generic.List[object]]::new(); $l.Add{ git reset --hard }; $l.Count",
    "'x'.Replace('x', { git reset --hard })",
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
            "session_id": "sess-method-scriptblock",
            "transcript_path": "/tmp/claude/transcript.jsonl",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "toolu_method_scriptblock",
        }),
        // `turn_id` selects Codex's protocol.
        Protocol::Codex => serde_json::json!({
            "session_id": "019dd11d-b795-7261-a9cb-9b85a5dadf15",
            "turn_id": "turn-method-scriptblock",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.5",
            "permission_mode": "default",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "call_method_scriptblock",
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

fn assert_hook(protocol: Protocol, tool_name: &str, commands: &[&str], expected: &str) {
    for command in commands {
        assert_eq!(
            hook_decision(protocol, tool_name, command),
            expected,
            "{protocol:?} {tool_name}: {command:?}"
        );
    }
}

fn assert_dialect(dialect: ShellDialect, commands: &[&str], expected: EvaluationDecision) {
    for command in commands {
        assert_eq!(
            decision_in(command, dialect),
            expected,
            "{dialect:?}: {command:?}"
        );
    }
}

/// A tool label that names no shell is the Unknown dialect, and the
/// PowerShell label is PowerShell, in both hook formats.
#[test]
fn hook_judges_script_blocks_passed_to_methods() {
    for protocol in [Protocol::Claude, Protocol::Codex] {
        for tool_name in ["Shell", "PowerShell"] {
            assert_hook(protocol, tool_name, RUNS_IT, "deny");
            assert_hook(protocol, tool_name, HARMLESS, "allow");
        }
        assert_hook(protocol, "PowerShell", RUNS_IT_AT_PREFIX, "deny");
        assert_hook(protocol, "PowerShell", HARMLESS_IN_POWERSHELL, "allow");
        assert_hook(protocol, "PowerShell", DENIED_THOUGH_NOT_RUN, "deny");
    }
}

/// Codex labels every command `Bash`; on Windows that resolves to PowerShell
/// or the PowerShell-or-POSIX union.
#[cfg(windows)]
#[test]
fn codex_bash_label_on_windows_judges_script_blocks_passed_to_methods() {
    assert_hook(Protocol::Codex, "Bash", RUNS_IT, "deny");
    assert_hook(Protocol::Codex, "Bash", HARMLESS, "allow");
}

#[test]
fn powershell_and_unknown_dialects_judge_script_blocks_passed_to_methods() {
    for dialect in [ShellDialect::PowerShell, ShellDialect::Unknown] {
        assert_dialect(dialect, RUNS_IT, EvaluationDecision::Deny);
        assert_dialect(dialect, HARMLESS, EvaluationDecision::Allow);
    }
    assert_dialect(
        ShellDialect::PowerShell,
        RUNS_IT_AT_PREFIX,
        EvaluationDecision::Deny,
    );
    assert_dialect(
        ShellDialect::PowerShell,
        HARMLESS_IN_POWERSHELL,
        EvaluationDecision::Allow,
    );
    assert_dialect(
        ShellDialect::PowerShell,
        DENIED_THOUGH_NOT_RUN,
        EvaluationDecision::Deny,
    );
}
