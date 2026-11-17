//! A foreach declaration is not a command, even when its collection is an array.
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

const ALLOW: &[&str] = &[
    r"foreach($n in @(1)) { $s=1 }; & 'C:\x\python.exe' -v",
    r"foreach($n in @(1)) { $s=1 }; & python -m unittest discover -v",
    r"foreach($n in @('one','two')) { Write-Output $n }; & python -v",
    r"foreach($n in @(1)) { echo 1 }; & python -p t.py",
    r"foreach ($item in @(1,2)) { $s=1 }; & python -s tests",
    r"foreach($n in @(1)) { foreach($m in @(2)) { echo $m } }; & python -v",
    r"foreach($n in @(1)) { $s=1 }; python -m unittest -v",
    r"if (1) { $s=1 }; & python -v",
];
const DENY: &[&str] = &[
    r"foreach($n in @(1)) { Remove-Item -Recurse -Force ./victim }; & python -v",
    r"foreach($n in @(1)) { & $cmd -r ./victim }; & python -v",
    r"foreach($n in $(Remove-Item -Recurse -Force ./victim)) { echo $n }; & python -v",
    r"foreach($n in @(& $cmd -r ./victim)) { echo $n }; & python -v",
    r"foreach($n in @(Remove-Item -Recurse -Force ./victim)) { echo $n }; & python -v",
    r"foreach($n in @(1)) { echo $n }; & $cmd -r ./victim",
    r"& $cmd @args",
    r"& $cmd @('-r','./victim')",
    r"& $cmd -r ./victim",
];
#[test]
fn powershell_foreach_and_invocations_in_both_protocols() {
    for protocol in [Protocol::Claude, Protocol::Codex] {
        for command in ALLOW {
            assert_eq!(
                hook_decision(protocol, "PowerShell", command),
                "allow",
                "{protocol:?}: {command:?}"
            );
        }
        for command in DENY {
            assert_eq!(
                hook_decision(protocol, "PowerShell", command),
                "deny",
                "{protocol:?}: {command:?}"
            );
        }
    }
}
#[test]
fn powershell_foreach_dialect_preserves_dangerous_commands() {
    for command in ALLOW {
        assert_eq!(
            decision_in(command, ShellDialect::PowerShell),
            EvaluationDecision::Allow,
            "{command:?}"
        );
    }
    for command in DENY {
        assert_eq!(
            decision_in(command, ShellDialect::PowerShell),
            EvaluationDecision::Deny,
            "{command:?}"
        );
    }
}
