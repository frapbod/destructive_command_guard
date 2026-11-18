//! PowerShell separates words on every Unicode `White_Space` character except
//! the line breaks, not only on ASCII space, tab and form feed. dcg read
//! `git<VT>reset<VT>--hard` (and the U+00A0, U+3000, ... spellings) as one
//! word, so the PowerShell dialect allowed it. Separately, Windows PowerShell
//! 5.1 (`powershell.exe`) reads its first non-switch argument as `-Command`,
//! and the host takes `/` and the Unicode dashes as switch prefixes; dcg read
//! `powershell "git reset --hard"` and `pwsh /c "..."` as no launcher at all.
//! Windows PowerShell 5.1 also skips empty arguments and takes `/-c` and
//! `--c` as `-Command`; pwsh does neither.

use destructive_command_guard::evaluator::evaluate_command_with_pack_order_at_path_in_dialect;
use destructive_command_guard::normalize::ShellDialect;
use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::{Config, EvaluationDecision, LayeredAllowlist};
use std::io::Write;
use std::process::{Command, Stdio};

const HOOK_TEST_TIMEOUT_MS: &str = "30000";

/// PowerShell runs the destructive command in each (PowerShell 7.5 measured
/// in the sandbox for the separators and the `/c`, en/em dash and `' -c'`
/// switch spellings; the positional `powershell` form is Windows PowerShell
/// 5.1's documented default parameter, unmeasured here).
const RUNS_IT: &[&str] = &[
    "git\u{b}reset\u{b}--hard",
    "echo a; git\u{b}reset --hard",
    "git\u{a0}reset\u{a0}--hard",
    "git\u{3000}reset\u{3000}--hard",
    "git\u{2028}reset --hard",
    "git\u{85}reset --hard",
    "git\u{1680}reset --hard",
    "git\u{202f}reset\u{202f}--hard",
    "git\u{2003}reset --hard",
    "Remove-Item\u{a0}-Recurse\u{a0}-Force C:\\src",
    // A comment after one of these spaces still ends at the line break.
    "echo a\u{3000}# it's here\ngit reset --hard",
    "echo a\u{b}# it's here\ngit reset --hard",
    // The escapes PR #18 decodes become the same separators.
    "powershell -Command \"git`vreset`v--hard\"",
    "powershell -Command \"git`v reset --hard\"",
    "pwsh -Command \"git`u{a0}reset`u{a0}--hard\"",
    "pwsh -Command \"git`u{3000}reset`u{3000}--hard\"",
    "iex \"git`vreset`v--hard\"",
    "powershell -Command \"git\u{a0}reset\u{a0}--hard\"",
    // Windows PowerShell 5.1's first non-switch argument is `-Command`.
    "powershell \"git reset --hard\"",
    "powershell git reset --hard",
    "powershell 'git reset --hard'",
    "powershell -NoProfile \"git reset --hard\"",
    "powershell.exe -NoProfile -ExecutionPolicy Bypass \"git reset --hard\"",
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe \"git reset --hard\"",
    "powershell -WindowStyle Hidden \"git reset --hard\"",
    "powershell \"echo a; git reset --hard\"",
    "powershell -nologo git push --force",
    "powershell \"Remove-Item -Recurse -Force C:\\src\"",
    "powershell\u{a0}\"git reset --hard\"",
    "cmd /c powershell \"git reset --hard\"",
    // `/` and the Unicode dashes are switch prefixes; the host trims.
    "powershell /c \"git reset --hard\"",
    "powershell /NoLogo /NoProfile \"git clean -fdx\"",
    "pwsh /c \"git reset --hard\"",
    "pwsh /Command \"git reset --hard\"",
    "pwsh \u{2013}c \"git reset --hard\"",
    "pwsh \u{2014}Command \"git reset --hard\"",
    "pwsh \" -c\" \"git reset --hard\"",
    // Windows PowerShell 5.1 skips an argument that is empty after trimming,
    // and after any switch prefix (`/` included) drops one more dash of any
    // kind. Source: PowerShell's ConsoleHost `CommandLineParameterParser.
    // ParseHelper` at tag v6.0.0-alpha.9 (the 5.1-lineage parser), lines
    // 338-342 and 357-362. Unmeasured on real 5.1 (no sandboxed route).
    "powershell \"\" -c \"git reset --hard\"",
    "powershell \" \" -c \"git reset --hard\"",
    "powershell '' -NoProfile -Command 'git reset --hard'",
    "powershell /-c \"git reset --hard\"",
    "powershell /-Command \"git reset --hard\"",
    "powershell /\u{2013}c \"git reset --hard\"",
    "powershell -\u{2013}Command \"git reset --hard\"",
    "powershell --c \"git reset --hard\"",
    "powershell \"\" /-NoProfile \"git reset --hard\"",
];

/// A separator inside quotes is data; characters PowerShell does not split on
/// stay in the word; pwsh's positional argument is a script path; plain
/// positional commands with nothing destructive stay allowed.
const HARMLESS: &[&str] = &[
    "Write-Host \"a\u{a0}b\"",
    "echo \"git\u{a0}reset\u{a0}--hard\"",
    "git commit -m 'git\u{b}reset\u{b}--hard'",
    "git commit -m \"docs: avoid git\u{a0}reset --hard\"",
    "git\u{200b}reset\u{200b}--hard",
    "git\u{a0}status",
    "Get-ChildItem\u{a0}-Recurse",
    // The quote is inside a comment, not an open string.
    "Write-Output a\u{3000}# it's here",
    "pwsh \"git reset --hard\"",
    "pwsh \"file.ps1\"",
    "pwsh ./build.ps1 -Verbose",
    "pwsh /tmp/build.ps1 -x",
    "pwsh -File script.ps1",
    "pwsh \u{2013}NoProfile ./b.ps1",
    "powershell .\\build.ps1 -Configuration Release",
    "powershell -ExecutionPolicy Bypass -File .\\x.ps1",
    "powershell \"Get-ChildItem\"",
    "powershell -NoProfile -NonInteractive Get-Process",
    "powershell \"Write-Host git reset --hard\"",
    "powershell Write-Output \"git reset --hard\"",
    "powershell \"git status; git log -1\"",
    "powershell /NoLogo /NoProfile \"Get-Date\"",
    "powershell -Version 5.1 Get-Date",
    // pwsh 7.5 reads an empty argument as `-File ''` (an error, measured) and
    // drops a second dash only when it repeats the first, so `/-c` is a
    // script path (`GetSwitchKey`, v7.5.0 line 699).
    "pwsh \"\" -c \"git reset --hard\"",
    "pwsh /-c \"git reset --hard\"",
    "powershell \"\" -c \"Get-Date\"",
    "powershell /-NoProfile \"Get-Date\"",
    "powershell --version",
    "pwsh --version",
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
            "session_id": "sess-ps-ws",
            "transcript_path": "/tmp/claude/transcript.jsonl",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "toolu_ps_ws",
        }),
        // `turn_id` selects Codex's protocol.
        Protocol::Codex => serde_json::json!({
            "session_id": "019dd11d-b795-7261-a9cb-9b85a5dadf15",
            "turn_id": "turn-ps-ws",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.5",
            "permission_mode": "default",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "call_ps_ws",
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
fn powershell_tool_splits_words_on_unicode_spaces_and_reads_positional_commands() {
    for protocol in [Protocol::Claude, Protocol::Codex] {
        for command in RUNS_IT {
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
fn codex_bash_label_on_windows_splits_words_on_unicode_spaces() {
    for command in RUNS_IT {
        assert_eq!(
            hook_decision(Protocol::Codex, "Bash", command),
            "deny",
            "{command:?}"
        );
    }
}

#[test]
fn powershell_and_unknown_dialects_split_words_on_unicode_spaces() {
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
}

/// Bash does not split on these characters: the POSIX reading keeps them in
/// the word.
#[test]
fn posix_dialect_keeps_unicode_spaces_inside_words() {
    for command in [
        "git\u{b}reset\u{b}--hard",
        "git\u{a0}reset\u{a0}--hard",
        "git\u{3000}reset\u{3000}--hard",
    ] {
        assert_eq!(
            decision_in(command, ShellDialect::Posix),
            EvaluationDecision::Allow,
            "{command:?}"
        );
    }
}
