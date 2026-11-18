//! `Start-Process` binds its parameters as any PowerShell cmdlet does (names,
//! unique prefixes, aliases, any order, positions 0 and 1) and joins its
//! argument list with spaces. A program other than a shell splits that line
//! into argv by Windows' rules, so `Start-Process git -ArgumentList
//! 'reset','--hard'` runs `git reset --hard`. Bindings and argv were measured
//! with PowerShell 7.5 (Start-Process's own parameter metadata, and a real
//! Start-Process of a recording program in the shell-truth sandbox).

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
            "session_id": "sess-start-process",
            "transcript_path": "/tmp/claude/transcript.jsonl",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "toolu_start_process",
        }),
        // `turn_id` selects Codex's protocol.
        Protocol::Codex => serde_json::json!({
            "session_id": "019dd11d-b795-7261-a9cb-9b85a5dadf15",
            "turn_id": "turn-start-process",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.5",
            "permission_mode": "default",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "call_start_process",
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

fn decision_with(command: &str, dialect: ShellDialect, packs: &[&str]) -> EvaluationDecision {
    let enabled: std::collections::HashSet<String> =
        packs.iter().map(|pack| (*pack).to_string()).collect();
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

/// Each command must get `expected` in the PowerShell and Unknown dialects
/// and from both hook protocols with the PowerShell and Bash tools.
fn assert_everywhere(commands: &[&str], expected: EvaluationDecision) {
    let hook_expected = if expected == EvaluationDecision::Deny {
        "deny"
    } else {
        "allow"
    };
    for command in commands {
        for dialect in [ShellDialect::PowerShell, ShellDialect::Unknown] {
            assert_eq!(
                decision_in(command, dialect),
                expected,
                "{dialect:?}: {command:?}"
            );
        }
        for protocol in [Protocol::Claude, Protocol::Codex] {
            for tool in ["PowerShell", "Bash"] {
                assert_eq!(
                    hook_decision(protocol, tool, command),
                    hook_expected,
                    "{protocol:?} {tool}: {command:?}"
                );
            }
        }
    }
}

/// The card's case: a comma list to a program that is not a shell. Each
/// runs `git reset --hard` (or another denied git command).
#[test]
fn comma_lists_to_other_programs_are_their_argv() {
    assert_everywhere(
        &[
            "Start-Process git -ArgumentList 'reset','--hard'",
            "Start-Process git -ArgumentList 'reset','--hard' -Wait -NoNewWindow",
            "Start-Process git -ArgumentList 'reset', '--hard'",
            "Start-Process git -ArgumentList @('reset','--hard')",
            "Start-Process git -ArgumentList '\"reset\"','--hard'",
            "Start-Process 'C:\\Program Files\\Git\\cmd\\git.exe' -ArgumentList 'reset','--hard'",
            "Start-Process git.exe -NoNewWindow -Wait -ArgumentList 'reset','--hard'",
            "Start-Process -FilePath:git -ArgumentList:@('reset','--hard')",
            "Start-Process git -ArgumentList 'clean','-fdx'",
            "Start-Process git -ArgumentList 'push','--force','origin','main'",
            "Start-Process git -ArgumentList 'reset','--hard',$rest",
            "$p = Start-Process git -ArgumentList 'reset','--hard' -PassThru",
            "& { Start-Process git -ArgumentList 'reset','--hard' }",
        ],
        EvaluationDecision::Deny,
    );
    assert_everywhere(
        &[
            "Start-Process git -ArgumentList 'status'",
            "Start-Process git -ArgumentList 'log','--oneline'",
            "Start-Process git -ArgumentList 'reset','--soft','HEAD~1'",
            // One argv word: git is asked for a command named "reset --hard".
            "Start-Process git -ArgumentList '\"reset --hard\"'",
            "Start-Process python -ArgumentList '-m','http.server','8000'",
            "Start-Process -FilePath 'C:\\tools\\build.exe' -ArgumentList '--out','C:\\work\\out' -Wait",
            "Start-Process notepad 'C:\\x\\notes.txt'",
            "Start-Process msedge -ArgumentList 'https://example.com/?a=1&b=2'",
        ],
        EvaluationDecision::Allow,
    );
}

/// Spellings from the review of PR #8: each binds `cmd` and
/// `/c git reset --hard` as PowerShell binds them.
#[test]
fn parameters_bind_by_name_prefix_alias_and_position() {
    let x = "git reset --hard";
    let dangerous: Vec<String> = [
        "Start-Process cmd '/c {X}'",
        "Start-Process -FilePath cmd '/c {X}'",
        "Start-Process cmd -A '/c {X}'",
        "Start-Process cmd -Arg '/c {X}'",
        "Start-Process cmd -NoNewWindow -ArgumentList '/c {X}'",
        "Start-Process -FilePath cmd -Verb RunAs -ArgumentList '/c {X}'",
        "Start-Process -Wait cmd -ArgumentList '/c {X}'",
        "Start-Process -ArgumentList '/c {X}' -FilePath cmd",
        "Start-Process -ArgumentList '/c {X}' cmd",
        "start cmd -ArgumentList '/c {X}'",
        "saps cmd '/c {X}'",
        "Start-Process -Path cmd -ArgumentList '/c {X}'",
        "Start-Process cmd -ArgumentList ('/c {X}')",
        "Start-Process -Ver RunAs cmd '/c {X}'",
        "Start-Process -- cmd '/c {X}'",
        "Start-Process -ArgumentList reset,--hard -FilePath git",
        "saps git reset,--hard",
        "start git -Args reset,--hard",
        "Microsoft.PowerShell.Management\\Start-Process git reset,--hard",
        "Start-Process -C $cred git reset,--hard",
    ]
    .iter()
    .map(|form| form.replace("{X}", x))
    .collect();
    let dangerous: Vec<&str> = dangerous.iter().map(String::as_str).collect();
    assert_everywhere(&dangerous, EvaluationDecision::Deny);
    assert_everywhere(
        &[
            "start cmd -ArgumentList '/c dir'",
            "Start-Process cmd -ArgumentList '/c', 'echo', 'reset', '--hard'",
            "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -Command Get-Service'",
            "npm start",
            "yarn start --port 3000",
            "docker start web",
            "systemctl start nginx",
            "echo start the build",
            // PowerShell stops: `-W` is ambiguous. Nothing starts.
            "Start-Process -W git reset,--hard",
        ],
        EvaluationDecision::Allow,
    );
}

/// A program that is not a literal (`$env:ComSpec`) may be a shell: its
/// line is read as each shell reads it.
#[test]
fn dynamic_programs_are_read_as_shells() {
    assert_everywhere(
        &["Start-Process -FilePath $env:ComSpec -ArgumentList '/c git reset --hard'"],
        EvaluationDecision::Deny,
    );
    assert_everywhere(
        &[
            "Start-Process -FilePath $env:ComSpec -ArgumentList '/c dir'",
            "Start-Process $tool -ArgumentList 'reset','--hard'",
        ],
        EvaluationDecision::Allow,
    );
}

/// The scp download and local-copy cases of the transfer pack's own
/// Start-Process reading stay allowed now that the argv is read too: a
/// `C:\work\…` operand is a Windows path, not host `C`.
#[test]
fn scp_argv_keeps_windows_paths() {
    let packs = [
        "core.git",
        "core.filesystem",
        "careful_company_running_windows",
    ];
    for command in [
        "Start-Process scp.exe -ArgumentList \"outside.example:/incoming/report.csv\",\"C:\\work\\report.csv\"",
        "Start-Process scp.exe -ArgumentList \"C:\\work\\report.csv\",\"D:\\archive\\report.csv\" -Wait",
        "Start-Process scp.exe -ArgumentList @(\"outside.example:/incoming/report.csv\",\"C:\\work\\report.csv\") -Wait",
    ] {
        for dialect in [ShellDialect::PowerShell, ShellDialect::Unknown] {
            assert_eq!(
                decision_with(command, dialect, &packs),
                EvaluationDecision::Allow,
                "{dialect:?}: {command:?}"
            );
        }
    }
    let upload = "Start-Process scp.exe -ArgumentList \"C:\\work\\report.csv\",\"outside.example:/incoming/\" -Wait";
    assert_eq!(
        decision_with(upload, ShellDialect::PowerShell, &packs),
        EvaluationDecision::Deny,
        "{upload:?}"
    );
}
