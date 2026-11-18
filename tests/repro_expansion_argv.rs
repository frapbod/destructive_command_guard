//! Hook-level regressions: argv that parameter expansions and command
//! substitution output supply is judged as the argv it becomes.
//!
//! Bash runs `rm -rf ~/zz` for `rm ${X:--rf ~/zz}` when `X` is unset, and
//! `git reset --hard` for `git reset $(echo --hard)`; `scripts/shell-truth`
//! measured each deny case below with fake `git` and `rm` in bash 3.2,
//! bash 5, sh, dash, linux-bash and linux-dash. Only dcg reads these
//! strings; this test does not execute their shell source.

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
    command: &str,
    cwd: &std::path::Path,
    tool_name: &str,
) -> serde_json::Value {
    match protocol {
        Protocol::Claude => serde_json::json!({
            "session_id": "sess-var",
            "transcript_path": "/tmp/claude/transcript.jsonl",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
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
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "call_var",
        }),
    }
}

fn hook_decision_with_tool(protocol: Protocol, command: &str, tool_name: &str) -> String {
    let temp = tempfile::tempdir().expect("temp dir");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let payload = payload(protocol, command, temp.path(), tool_name).to_string();
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

fn assert_tools(decision: &str, commands: &[&str]) {
    let mut wrong = Vec::new();
    for command in commands {
        for tool in ["Bash", "Shell"] {
            for protocol in [Protocol::Claude, Protocol::Codex] {
                let actual = hook_decision_with_tool(protocol, command, tool);
                if actual != decision {
                    wrong.push(format!("{protocol:?} {tool} {actual}: {command}"));
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

#[test]
#[allow(clippy::literal_string_with_formatting_args)]
fn expansion_operands_supply_judged_argv() {
    assert_tools(
        "deny",
        &[
            r"rm ${X:--rf ~/zz}",
            r"rm ${X:--r -f ~/zz}",
            r#"rm "${X:--rf}" ~/zz"#,
            r"rm ${X:+-rf} ~/zz",
            r"rm -r${X}f ~/zz",
            r"rm -${X:-r}f ~/zz",
            r"rm -i ${X:--rf} ~/zz",
            r"rm -ri ${X:+-f} ~/zz",
            r"( rm ${X:--rf ~/zz} )",
            r"bash -c 'rm ${X:--rf ~/zz}'",
            r#"git reset "${X:---hard}""#,
            r"git clean -${X}fd",
            r"f() { git clean -${X}fd; }; f",
            r#"git restore --staged ${X:-. -"W"$Z}"#,
            r"git restore --staged . -${Y}W",
            r"git restore --staged . ${Y:--}W",
            r"git restore --staged . -${Y:-W}",
            r#"git restore --staged . ""${Y:--W}"#,
            r"git restore --staged . ${X:+.}${Y:--W}",
            "git restore --staged ${X:-. \"a\nb\" -W}",
        ],
    );
    assert_tools(
        "allow",
        &[
            r"rm ${X:-/tmp/zz/file}",
            r#"rm "${X:--rf}""#,
            r"rm -- ${X:--rf}",
            r"rm -f ${X:-a b}",
            r"rm $FILES",
            r"git reset ${X:-HEAD~1}",
            r"git log -${N:-5}",
            r"git restore --staged -${Y}p .",
            r"git restore --staged . ${Y:-src}",
            r"git status ${X:---short}",
            r#"git commit -m "${MSG:---hard}""#,
            r"echo -${Y}W",
        ],
    );
}

#[test]
fn command_substitution_output_is_judged_argv() {
    assert_tools(
        "deny",
        &[
            r"git reset $(echo --hard)",
            r"git reset `echo --hard`",
            r"git reset $(echo --hard HEAD~1)",
            r"git reset $(echo --hard) && echo done",
            r"git restore --staged . $(echo -W)",
            r"git restore --staged . `echo -W`",
            r"git restore --staged . $(echo${IFS}-W)",
            r"git restore --staged . `echo${IFS}-W`",
            r"rm $(echo -rf ~/zz)",
            r"rm $(echo -rf /etc)",
        ],
    );
    assert_tools(
        "allow",
        &[
            r"git log $(echo --oneline)",
            r"git log $(echo -n --oneline)",
            r"git log $(echo HEAD~1)",
            r"echo $(echo --hard)",
            r#"git commit -m "$(echo --hard)""#,
            r"git restore --staged $(git diff --name-only --cached)",
            r"git diff $(git merge-base HEAD main)",
            r#"rm "$(echo ~/x)""#,
        ],
    );
}
