//! Hook-level regressions: `eval`, brace lists, `trap`, `PROMPT_COMMAND` and
//! `alias` bodies are judged inside function bodies and case arms, as they
//! are on their own, in a subshell or after `then`.

use std::io::Write;
use std::process::{Command, Stdio};

const HOOK_TEST_TIMEOUT_MS: &str = "30000";

#[derive(Clone, Copy, Debug)]
enum Protocol {
    Claude,
    Codex,
}

fn payload(
    protocol: Protocol,
    command: &str,
    cwd: &std::path::Path,
    tool_name: &str,
) -> serde_json::Value {
    match protocol {
        Protocol::Claude => serde_json::json!({
            "session_id": "sess-deferred",
            "transcript_path": "/tmp/claude/transcript.jsonl",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "toolu_deferred",
        }),
        // `turn_id` selects Codex's protocol.
        Protocol::Codex => serde_json::json!({
            "session_id": "019dd11d-b795-7261-a9cb-9b85a5dadf15",
            "turn_id": "turn-deferred",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.5",
            "permission_mode": "default",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "call_deferred",
        }),
    }
}

/// What the agent reads: "allow" for empty stdout, else the decision.
fn hook_decision(protocol: Protocol, command: &str, tool_name: &str) -> String {
    let temp = tempfile::tempdir().expect("temp dir");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let payload = payload(protocol, command, temp.path(), tool_name).to_string();
    let mut child = Command::new(env!("CARGO_BIN_EXE_dcg"))
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
        "{protocol:?}: the hook must exit with a verdict ({:?}) on {command:?}\nstderr: {stderr}",
        out.status
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

/// Every command under both protocols and both tool labels: `Bash` (a POSIX
/// shell) and `Shell` (a shell dcg cannot name, read in every dialect).
fn assert_all(decision: &str, commands: &[String]) {
    let mut wrong = Vec::new();
    for command in commands {
        for tool in ["Bash", "Shell"] {
            for protocol in [Protocol::Claude, Protocol::Codex] {
                let actual = hook_decision(protocol, command, tool);
                if actual != decision {
                    wrong.push(format!("{tool} {protocol:?} {actual}: {command}"));
                }
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "expected {decision}:\n{}",
        wrong.join("\n")
    );
}

/// `inner` as a function body and as a case arm.
fn in_bodies(inner: &[&str]) -> Vec<String> {
    inner
        .iter()
        .flat_map(|x| {
            [
                format!("f() {{ {x}; }}; f"),
                format!("case a in a) {x};; esac"),
            ]
        })
        .collect()
}

#[test]
fn deferred_and_brace_readings_are_judged_in_function_bodies_and_case_arms() {
    // Bash 3.2 and 5, zsh and Linux bash run the destructive command in each
    // (scripts/shell-truth, t_6c63e222); dash runs the eval and trap forms.
    assert_all(
        "deny",
        &in_bodies(&[
            "eval 'git reset --hard'",
            "git reset {--hard,HEAD}",
            "rm {-rf,~}",
            "{git,reset,--hard}",
            r#"trap "git reset --hard" EXIT"#,
            r#"PROMPT_COMMAND="git reset --hard""#,
            "git restore --staged {.,-W}",
        ]),
    );
}

#[test]
fn deferred_readings_are_judged_in_other_body_shapes() {
    assert_all(
        "deny",
        &[
            "function f { eval 'git reset --hard'; }; f".to_string(),
            "f() ( rm {-rf,~} ); f".to_string(),
            "case a in (a) eval 'git reset --hard';; esac".to_string(),
            "case b in a) :;; b) rm {-rf,~};; esac".to_string(),
            "case a in a|b) trap 'git reset --hard' EXIT;; esac".to_string(),
            "f() { cd /tmp && eval 'git reset --hard'; }; f".to_string(),
            "f() { if true; then eval 'git reset --hard'; fi; }; f".to_string(),
            // An alias body is judged where it is defined, as at top level.
            "case a in a) alias x='git reset --hard';; esac".to_string(),
        ],
    );
}

#[test]
fn harmless_lists_and_handlers_in_bodies_stay_allowed() {
    assert_all(
        "allow",
        &[
            "f() { mkdir -p src/{a,b}; }; f".to_string(),
            "f() { git add {a,b}.txt; }; f".to_string(),
            "case a in a) cp f{,.bak};; esac".to_string(),
            "f() { eval 'git status'; }; f".to_string(),
            "case a in a) trap 'echo bye' EXIT;; esac".to_string(),
            "case a in a) PROMPT_COMMAND='history -a';; esac".to_string(),
            "f() { git log {--oneline,-3}; }; f".to_string(),
        ],
    );
}
