//! Hook-level regressions for quoted executable words inside shell groups.

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
            "session_id": "sess-var",
            "transcript_path": "/tmp/claude/transcript.jsonl",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_use_id": "toolu_var",
        }),
        // `turn_id` selects Codex's protocol.
        Protocol::Codex => serde_json::json!({
            "session_id": "019dd11d-b795-7261-a9cb-9b85a5dadf15",
            "turn_id": "turn-var",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.5",
            "permission_mode": "default",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_use_id": "call_var",
        }),
    }
}

/// What the agent reads: "allow" for empty stdout, else the decision.
fn hook_decision(protocol: Protocol, command: &str) -> String {
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

fn assert_both(decision: &str, commands: &[&str]) {
    let mut wrong = Vec::new();
    for command in commands {
        for protocol in [Protocol::Claude, Protocol::Codex] {
            let actual = hook_decision(protocol, command);
            if actual != decision {
                wrong.push(format!("{protocol:?} {actual}: {command}"));
            }
        }
    }
    assert!(wrong.is_empty(), "expected {decision}:\n{}", wrong.join("\n"));
}

#[test]
fn quoted_executables_in_shell_groups_are_judged() {
    assert_both("deny", &[
        r#"( "git" reset --hard )"#,
        r#"("git" reset --hard)"#,
        r#"f() { "git" reset --hard; }; f"#,
        r#"f() { "rm" -rf ~/; }; f"#,
        r#"( git reset --hard )"#,
        r#"( "rm" -rf ~/ )"#,
        r#"{ "git" reset --hard; }"#,
        r#"f() { git reset --hard; }; f"#,
        r#"X=t; ( "gi${X}" reset --hard )"#,
        r#"X=t; f() { "gi${X}" reset --hard; }; f"#,
        // t_49339710 review round 5: Bash runs `git` here.
        r#"f(){ "${IFS}it" reset --hard; }; IFS=g; f"#,
        r#"f(){ "git" reset --hard; }; f"#,
        r#"f(){ 'git' reset --hard; }; f"#,
        r#"f(){ g"it" reset --hard; }; f"#,
        // t_416fd788 review round 4: case arms are compound bodies too.
        r#"case a in a) "git" reset --hard;; esac"#,
        r#"X=gi; case a in a) "${X}t" reset --hard;; esac"#,
        r#"X=git; case a in a) $X reset --hard;; esac"#,
        r#"X=git; case a in a) "$X" reset --hard;; esac"#,
        r#"case a in a) git reset --hard;; esac"#,
    ]);
}

#[test]
fn safe_quoted_shell_groups_remain_allowed() {
    assert_both("allow", &[
        r#"( "git" status )"#,
        r#"f() { "git" status; }; f"#,
        r#"f() { "rm" ./unimportant; }; f"#,
        r#"{ "git" status; }"#,
        r#"( printf '%s' '"git" reset --hard' )"#,
        r#"f() { printf '%s' '"rm" -rf ~/'; }; f"#,
        r#"printf '%s' '( "git" reset --hard )'"#,
        r#"case a in a) "git" status;; esac"#,
        r#"case a in a) printf '%s' '"git" reset --hard';; esac"#,
    ]);
}
