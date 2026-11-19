//! An `eval` that opens a one-line function body, a case arm, or a `time`
//! or `coproc` command, under both hook protocols.
//!
//! The eval collector read the first word of each segment as the command, so
//! in `echo() { eval "$*"; }; echo 'git reset --hard'` it read `echo()` and
//! never saw the eval. Bash runs the function's eval with the call's
//! arguments: a fake `git` that only prints its argv receives `reset --hard`.
//! Any function name has the same effect; `echo` and `printf` are not
//! special, and their argument masking is not the cause (`f 'git reset
//! --hard'` after `f() { eval "$*"; }` was allowed as well). The same eval on
//! its own line, after `if`/`then`/`{`, or after `;` was already denied.
//!
//! The collector also stopped at `command -p`, `command --`, `builtin --`, a
//! chain of those wrappers, or a redirection before `eval`; Bash runs eval
//! after each of them. `command -v`/`-V` only describe eval and stay allowed.

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
            "session_id": "sess-eval",
            "transcript_path": "/tmp/claude/transcript.jsonl",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_use_id": "toolu_eval",
        }),
        // `turn_id` selects Codex's protocol.
        Protocol::Codex => serde_json::json!({
            "session_id": "019dd11d-b795-7261-a9cb-9b85a5dadf15",
            "turn_id": "turn-eval",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.5",
            "permission_mode": "default",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_use_id": "call_eval",
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
fn eval_that_opens_a_function_body_or_case_arm_is_judged() {
    assert_both(
        "deny",
        &[
            // The reported shapes: an output command replaced by a function.
            r#"echo() { eval "$*"; }; echo 'git reset --hard'"#,
            r#"echo() { eval "$*"; }; echo 'wrangler delete worker'"#,
            r#"printf() { eval "$*"; }; printf 'git reset --hard'"#,
            r#"echo() { eval "$*"; }; x=$(echo 'git reset --hard')"#,
            r#"bash -c 'echo() { eval "$*"; }; echo "git reset --hard"'"#,
            // Any name and every function spelling.
            r#"f() { eval "$*"; }; f 'git reset --hard'"#,
            r#"f() { eval "$*"; }; f git reset --hard"#,
            r#"f () { eval "$*"; }; f 'git reset --hard'"#,
            r#"function echo { eval "$*"; }; echo 'git reset --hard'"#,
            r#"function f() { eval "$*"; }; f 'git reset --hard'"#,
            r#"f() ( eval "$*" ); f 'git reset --hard'"#,
            r#"f() { builtin eval "$*"; }; f 'git reset --hard'"#,
            r#"f() { command eval "$*"; }; f 'git reset --hard'"#,
            r#"echo() { command -p eval "$*"; }; echo 'git reset --hard'"#,
            r#"echo() { command -- eval "$*"; }; echo 'git reset --hard'"#,
            r#"echo() { builtin -- eval "$*"; }; echo 'git reset --hard'"#,
            r#"echo() { command builtin eval "$*"; }; echo 'git reset --hard'"#,
            r#"echo() { 2>/dev/null eval "$*"; }; echo 'git reset --hard'"#,
            r#"x='git reset --hard'; 2>/dev/null eval "$x""#,
            r#"f() { command -p eval "$*"; }; f 'git reset --hard'"#,
            r#"f() { builtin -- eval "$*"; }; f 'git reset --hard'"#,
            r#"f() { command 2>&1 -p eval "$*"; }; f 'git reset --hard'"#,
            // A line continuation between the name and `()`.
            "echo \\\n () \\\n { eval \"$*\"; }; echo 'git reset --hard'",
            r#"f() { X=1 eval "$*"; }; f 'git reset --hard'"#,
            // A static payload is judged as the command it is.
            "f() { eval 'git reset --hard'; }; f",
            // Other syntax that shares a segment with the command it runs.
            r#"case x in x) eval "$y";; esac"#,
            r#"time eval "$y""#,
            r#"time -p eval "$y""#,
            "time eval 'git reset --hard'",
            r#"coproc eval "$y""#,
        ],
    );
}

#[test]
fn harmless_function_bodies_and_output_stay_allowed() {
    assert_both(
        "allow",
        &[
            "echo 'git reset --hard'",
            "printf '%s\\n' 'git reset --hard'",
            "f() { eval 'echo hi'; }; f",
            "f() { echo 'git reset --hard'; }; f",
            r#"echo() { command echo "$@"; }; echo 'git reset --hard'"#,
            "case x in x) echo 'git reset --hard';; esac",
            "time echo hi",
            "time eval 'echo hi'",
            // Introspection names eval without running it.
            "command -v eval",
            "command -V eval",
            "command -pv eval",
            "command -p -v eval >/dev/null && echo ok",
            "x=$(command -v eval)",
            // A redirection before an output command does not make its data run.
            "echo 2>/dev/null eval 'git reset --hard'",
            "2>/dev/null echo 'git reset --hard'",
            "2>/dev/null eval 'echo hi'",
        ],
    );
}

/// The trap reader read the segment's words with redirections in them, so a
/// redirection before `trap` or before its handler hid the handler. Every
/// shell sets the trap and runs the handler on exit.
#[test]
fn a_redirection_does_not_hide_a_trap_handler() {
    assert_both(
        "deny",
        &[
            "2>/dev/null trap 'git reset --hard' EXIT",
            "trap 2>/dev/null 'git reset --hard' EXIT",
            "f() { 2>/dev/null trap 'git reset --hard' EXIT; }; f",
        ],
    );
    assert_both(
        "allow",
        &[
            "2>/dev/null trap 'echo bye' EXIT",
            "trap 'echo bye' EXIT 2>/dev/null",
            "echo 2>/dev/null trap 'git reset --hard' EXIT",
        ],
    );
}

/// A heredoc operator before the command word left its delimiter as the
/// command word when the segment held the operator line without the body (or
/// the heredoc had no body), so `eval` and `trap` were not read. Every shell
/// runs the eval or the trap handler.
#[test]
fn a_heredoc_operator_does_not_hide_eval_or_trap() {
    assert_both(
        "deny",
        &[
            "<<EOF eval 'git reset --hard'\nhi\nEOF",
            "x='git reset --hard'; <<EOF eval \"$x\"\nhi\nEOF",
            "x='git reset --hard'; <<'EOF' eval \"$x\"\nhi\nEOF",
            "x='git reset --hard'; 0<<EOF eval \"$x\"\nhi\nEOF",
            "x='git reset --hard'; <<-EOF eval \"$x\"\n\thi\n\tEOF",
            "x='git reset --hard'; 2>/dev/null <<EOF eval \"$x\"\nhi\nEOF",
            "x='git reset --hard'; <<EOF command eval \"$x\"\nhi\nEOF",
            "x='git reset --hard'; command <<EOF eval \"$x\"\nhi\nEOF",
            "x='git reset --hard'; <<EOF command -p eval \"$x\"\nhi\nEOF",
            "x='git reset --hard'; <<EOF eval \"$x\"",
            "echo() {\n<<EOF eval \"$*\"\nhi\nEOF\n}\necho 'git reset --hard'",
            "<<EOF trap 'git reset --hard' EXIT\nhi\nEOF",
            "f() {\n<<EOF trap 'git reset --hard' EXIT\nhi\nEOF\n}\nf",
        ],
    );
    assert_both(
        "allow",
        &[
            "<<EOF echo eval 'git reset --hard'\nhi\nEOF",
            "<<EOF eval 'echo hi'\nhi\nEOF",
            "<<EOF echo 'git reset --hard'\nhi\nEOF",
            "<<EOF trap 'echo bye' EXIT\nhi\nEOF",
        ],
    );
}
