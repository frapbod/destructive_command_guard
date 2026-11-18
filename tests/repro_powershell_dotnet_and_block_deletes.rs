//! PowerShell deletes a directory tree through .NET with no cmdlet or program
//! name: Visual Basic's `FileSystem.DeleteDirectory`, `[Directory]::Delete`
//! after `using namespace System.IO`, and `<DirectoryInfo>.Delete(1)`. The
//! Windows filesystem reader knew only `[IO.Directory]::Delete` and
//! `.Delete($true)`. Off Windows, the Unknown reading also never ran that
//! reader for a `.NET` statement (no Windows shape turned the `windows.*`
//! packs on), and never offered a block passed to `ForEach-Object` to
//! `core.filesystem`, whose `Remove-Item` reader no keyword selects.
//! Rows from card t_02cc8a24.

use destructive_command_guard::evaluator::evaluate_command_with_pack_order_at_path_in_dialect;
use destructive_command_guard::normalize::ShellDialect;
use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::{Config, EvaluationDecision, LayeredAllowlist};
use std::io::Write;
use std::process::{Command, Stdio};

const HOOK_TEST_TIMEOUT_MS: &str = "30000";

/// Each deleted a directory with a child in sandboxed PowerShell 7.5
/// (`scripts/shell-truth --json pwsh`, `Test-Path` False afterwards),
/// Nov 18 2026; measured on a relative path, written here with `C:\Users`.
const DELETES: &[&str] = &[
    r"[Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory('C:\Users', 'DeleteAllContents')",
    r"[Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory('C:\Users', [Microsoft.VisualBasic.FileIO.DeleteDirectoryOption]::DeleteAllContents)",
    r"Add-Type -AssemblyName Microsoft.VisualBasic; [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory('C:\Users', 'DeleteAllContents')",
    "using namespace Microsoft.VisualBasic.FileIO\n[FileSystem]::DeleteDirectory('C:\\Users', 'DeleteAllContents')",
    r"[microsoft.visualbasic.fileio.filesystem]::deletedirectory('C:\Users', 'deleteallcontents')",
    r"$null = [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory('C:\Users', 'DeleteAllContents')",
    r"$o = 'DeleteAllContents'; [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory('C:\Users', $o)",
    // Removes an empty directory (measured); reviewed like
    // `[IO.Directory]::Delete($path)`.
    r"[Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory('C:\empty', 'ThrowIfDirectoryNonEmpty')",
    "using namespace System.IO\n[Directory]::Delete('C:\\Users', $true)",
    r"[IO.Directory]::Delete('C:\Users', $true)",
    r"[System.IO.Directory]::Delete('C:\Users',$true)",
    r"[IO.DirectoryInfo]::new('C:\Users').Delete($true)",
    r"(Get-Item C:\Users).Delete(1)",
    r"(Get-Item C:\Users).Delete('true')",
    r"1 | ForEach-Object { Remove-Item -Recurse -Force C:\Users }",
    r"$x | ForEach-Object { Remove-Item -Recurse -Force C:\Users }",
    r"1 | % { Remove-Item -Recurse -Force C:\Users }",
    r"1 | Where-Object { Remove-Item -Recurse -Force C:\Users }",
    r"1 | ForEach-Object { Remove-Item -Recurse C:\Users }",
    r"{ Remove-Item -Recurse -Force C:\Users }.Invoke()",
    r"{ Remove-Item -Recurse -Force C:\Users }.InvokeReturnAsIs()",
];

/// Their measured harmless twins: each left the directory in place.
const HARMLESS: &[&str] = &[
    r"[Microsoft.VisualBasic.FileIO.FileSystem]::CopyDirectory('C:\Users', 'd2')",
    r"[IO.Directory]::Exists('C:\Users')",
    "[IO.Path]::Combine('a','b')",
    r"1 | ForEach-Object { Get-Item C:\Users }",
    r"{ Get-ChildItem C:\Users }.Invoke()",
];

/// Harmless in PowerShell (measured: pwsh 7.5 only previewed). The Unknown
/// reading denies it on base too once the `windows.*` packs are on (the
/// Windows host): that reading's `remove-item-recurse-force` regex does not
/// see `-WhatIf` after `1 |`.
const HARMLESS_IN_POWERSHELL: &[&str] =
    &[r"1 | ForEach-Object { Remove-Item -Recurse -Force C:\Users -WhatIf }"];

/// One file each (measured). dcg allows `Remove-Item <file>`, so their .NET
/// spellings are allowed too.
const ONE_FILE: &[&str] = &[
    r"[IO.File]::Delete('C:\x.txt')",
    r"(Get-Item C:\x.txt).Delete()",
    r"[Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile('C:\x.txt')",
];

/// POSIX text that looks like a type literal or a block, for the Bash label:
/// none is a PowerShell statement.
const POSIX_HARMLESS: &[&str] = &[
    "grep -n '[IO.Directory]::Delete' src/a.rs",
    "echo \"[IO.Path]::Combine\"",
    "[ -f x ] && echo ok",
    "[[ $a == b ]] && echo ok",
    "find . -name '*.tmp' -exec ls {} \\;",
    "f() { echo hi; }; f",
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
            "session_id": "sess-ps-dotnet-deletes",
            "transcript_path": "/tmp/claude/transcript.jsonl",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "toolu_ps_dotnet_deletes",
        }),
        // `turn_id` selects Codex's protocol.
        Protocol::Codex => serde_json::json!({
            "session_id": "019dd11d-b795-7261-a9cb-9b85a5dadf15",
            "turn_id": "turn-ps-dotnet-deletes",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.5",
            "permission_mode": "default",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "call_ps_dotnet_deletes",
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

/// The default packs a non-Windows host enables for an unproven payload:
/// no `windows.*` pack.
fn decision_in(command: &str, dialect: ShellDialect) -> EvaluationDecision {
    let enabled: std::collections::HashSet<String> = ["core.git", "core.filesystem"]
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

/// The PowerShell label, and a label that names no shell (the Unknown
/// dialect), in both hook formats.
#[test]
fn hooks_judge_dotnet_and_block_deletes() {
    for protocol in [Protocol::Claude, Protocol::Codex] {
        for tool in ["PowerShell", "Shell"] {
            for command in DELETES {
                assert_eq!(
                    hook_decision(protocol, tool, command),
                    "deny",
                    "{protocol:?} {tool}: {command:?}"
                );
            }
            for command in HARMLESS.iter().chain(ONE_FILE) {
                assert_eq!(
                    hook_decision(protocol, tool, command),
                    "allow",
                    "{protocol:?} {tool}: {command:?}"
                );
            }
        }
        for command in HARMLESS_IN_POWERSHELL {
            assert_eq!(
                hook_decision(protocol, "PowerShell", command),
                "allow",
                "{protocol:?} PowerShell: {command:?}"
            );
        }
        for command in POSIX_HARMLESS {
            assert_eq!(
                hook_decision(protocol, "Bash", command),
                "allow",
                "{protocol:?} Bash: {command:?}"
            );
        }
    }
}

/// With no `windows.*` pack, the Unknown reading still offers a block body
/// to `core.filesystem`'s `Remove-Item` reader, as it does the bare statement.
#[test]
fn unknown_reading_offers_blocks_to_core_filesystem() {
    for command in [
        r"Remove-Item -Recurse -Force C:\Users",
        r"1 | ForEach-Object { Remove-Item -Recurse -Force C:\Users }",
        r"$x | ForEach-Object { Remove-Item -Recurse -Force C:\Users }",
        r"1 | % { Remove-Item -Recurse -Force C:\Users }",
    ] {
        assert_eq!(
            decision_in(command, ShellDialect::Unknown),
            EvaluationDecision::Deny,
            "{command:?}"
        );
    }
    for command in [
        r"1 | ForEach-Object { Get-Item C:\Users }",
        "1..3 | ForEach-Object { $_ * 2 }",
    ] {
        assert_eq!(
            decision_in(command, ShellDialect::Unknown),
            EvaluationDecision::Allow,
            "{command:?}"
        );
    }
}
