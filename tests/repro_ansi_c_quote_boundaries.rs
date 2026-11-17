// `${IFS:0:1}` in the shell commands below is not a format argument.
#![allow(clippy::literal_string_with_formatting_args)]

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

fn payload(protocol: Protocol, command: &str, cwd: &std::path::Path) -> serde_json::Value {
    match protocol {
        Protocol::Claude => serde_json::json!({
            "session_id": "sess-ifs",
            "transcript_path": "/tmp/claude/transcript.jsonl",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_use_id": "toolu_ifs",
        }),
        // `turn_id` selects Codex's protocol.
        Protocol::Codex => serde_json::json!({
            "session_id": "019dd11d-b795-7261-a9cb-9b85a5dadf15",
            "turn_id": "turn-ifs",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.5",
            "permission_mode": "default",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_use_id": "call_ifs",
        }),
    }
}

/// What the agent reads: "allow" for empty stdout, else the decision.
/// Panics unless the hook exited 0 with no stack overflow.
fn hook_decision(protocol: Protocol, command: &str) -> String {
    hook_verdict(protocol, command).0
}

/// The decision, as [`hook_decision`], and the reason the hook gave.
fn hook_verdict(protocol: Protocol, command: &str) -> (String, String) {
    let temp = tempfile::tempdir().expect("temp dir");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let payload = payload(protocol, command, temp.path()).to_string();
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
    assert!(
        !stderr.contains("overflowed its stack"),
        "{protocol:?}: the hook overflowed its stack on {command:?}\nstderr: {stderr}"
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{protocol:?}: the hook must exit with a verdict, not die ({:?}) on {command:?}\nstderr: {stderr}",
        out.status
    );
    if stdout.trim().is_empty() {
        return ("allow".to_string(), String::new());
    }
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("{protocol:?}: stdout is not one JSON value ({e}): {stdout}"));
    let output = &parsed["hookSpecificOutput"];
    (
        output["permissionDecision"]
            .as_str()
            .unwrap_or("<missing>")
            .to_string(),
        output["permissionDecisionReason"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    )
}

fn assert_both(decision: &str, commands: &[&str]) {
    for command in commands {
        for protocol in [Protocol::Claude, Protocol::Codex] {
            assert_eq!(
                hook_decision(protocol, command),
                decision,
                "{protocol:?}: {command:?}"
            );
        }
    }
}

#[test]
fn ansi_c_quote_boundaries_both_protocols() {
    assert_both(
        "deny",
        &[
            r"echo $'a\'b'; git reset --hard",
            "echo $'a\\'b'\ngit reset --hard",
            r"echo $'\''; git reset --hard",
            r"echo $'a\'b' && git reset --hard",
            r"echo $'a\'b' || git reset --hard",
            r"echo $'a\'b' | git reset --hard",
            r"echo $'a\'b' & git reset --hard",
            r"echo $'a\'b'; git${IFS}reset${IFS}--hard",
            r#"bash -c "echo \$'a\\'b'; git reset --hard""#,
            "bash <<'EOF'\necho $'a\\'b'; git reset --hard\nEOF",
            r"f() { echo $'a\'b'; git reset --hard; }; f",
            r"(echo $'a\'b'; git reset --hard)",
        ],
    );
    assert_both(
        "allow",
        &[
            r"echo $'a\'b'; git status",
            r"echo 'a\'; git status",
            r"printf '%s' $'it\'s fine'",
            r"echo \$'a\'; git status",
        ],
    );
}

/// `$$` is the shell's process id, so `$$'` opens a plain quote: Bash 3.2 and
/// 5.2 run the middle command of each of these. An odd run of `$` before the
/// quote (`$$$'`) is the process id followed by an ANSI-C string.
#[test]
fn process_id_before_a_quote_is_not_ansi_c() {
    assert_both(
        "deny",
        &[
            r"echo $$'a\'; git reset --hard; echo 'x'",
            "echo $$'a\\'\ngit reset --hard\necho 'x'",
            r"echo $$'a\' && rm -rf ~; echo 'x'",
            r"echo $$'a\' && git reset --hard && echo 'x'",
            r"echo $$$$'a\'; git reset --hard; echo 'x'",
            r"x=$(echo $$'a\'; git reset --hard; echo 'x')",
            r"echo $$$'a\'b'; git reset --hard",
        ],
    );
    assert_both("allow", &[r"echo $$'a\'; git status; echo 'x'"]);
}

/// PowerShell (what Codex runs on Windows) and dash (`/bin/sh` on Debian)
/// read `$'` as a literal `$` and a plain quote, so `$'a\'` ends at the
/// backslash and the next command runs. The hook denies what either reading
/// runs. Measured: dash and powershell.exe ran the middle command; Bash
/// refused the whole line (unterminated quote).
#[test]
fn plain_dollar_quote_reading_both_protocols() {
    assert_both(
        "deny",
        &[
            r"echo $'a\'; git reset --hard; echo 'x'",
            r#"sh -c "echo \$'a\\'; git reset --hard; echo 'x'""#,
            r"echo $'C:\temp\'; git reset --hard; echo 'done'",
            // Bash's own reading still decides this one.
            r"echo $'a\'b'; git reset --hard",
            // Destructive text inside the ANSI-C string is a command in the
            // plain reading: accepted as a false positive, as every earlier
            // build denied it too.
            r"echo $'a\'b; git reset --hard'",
        ],
    );
    assert_both(
        "allow",
        &[
            r"echo $'a\'; git status; echo 'x'",
            r"printf $'a\n'; git status",
        ],
    );
}

fn evaluate_all_packs(command: &str, dialect: ShellDialect) -> EvaluationDecision {
    let enabled: std::collections::HashSet<String> = REGISTRY
        .all_pack_ids()
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

/// A Windows Codex "Bash" payload is evaluated as `Unknown` (or PowerShell),
/// and desktop Codex runs it with `powershell.exe -Command`. There `$'` is a
/// literal `$` and a plain quote: `Write-Output $'a\'; Write-Output '[RUN]'`
/// printed `[RUN]` on the desktop.
#[test]
fn powershell_reading_of_dollar_quote_under_unknown_and_powershell() {
    for dialect in [
        ShellDialect::Unknown,
        ShellDialect::PowerShell,
        ShellDialect::Posix,
    ] {
        for command in [
            r"Write-Output $'a\'; git reset --hard; Write-Output 'x'",
            r"echo $'C:\temp\'; git reset --hard; echo 'done'",
        ] {
            assert_eq!(
                evaluate_all_packs(command, dialect),
                EvaluationDecision::Deny,
                "{dialect:?}: {command:?}"
            );
        }
        let harmless = r"Write-Output $'a\'; git status; Write-Output 'x'";
        assert_eq!(
            evaluate_all_packs(harmless, dialect),
            EvaluationDecision::Allow,
            "{dialect:?}: {harmless:?}"
        );
    }
}
