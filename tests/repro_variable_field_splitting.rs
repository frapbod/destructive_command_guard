//! Proven variable values are field-split and quote-removed where they are
//! used, under both hook protocols.
//!
//! Parameter expansion happens before field splitting and quote removal, so
//! a literal value can change which command runs without any word of the
//! source spelling it. Bash 5.2 runs `git reset --hard` for each of
//! `X=" "; git${X}reset${X}--hard`, `X=$IFS; git${X}reset${X}--hard` and
//! `X=gi; "${X}t" reset --hard`. 0.16.0 allowed all three: the executable
//! model only reads a command word that is exactly one reference, and only
//! the rm classifier consulted the deny-only value splice.

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
fn proven_whitespace_values_split_the_command_word() {
    assert_both(
        "deny",
        &[
            r#"X=" "; git${X}reset${X}--hard"#,
            r"X=' '; git${X}reset${X}--hard",
            r#"X=" "; git$X'reset'$X--hard"#,
            r"X=$'\x20'; git${X}reset${X}--hard",
            // A value copied from the default IFS.
            r"X=$IFS; git${X}reset${X}--hard",
            r#"X="$IFS"; git${X}reset${X}--hard"#,
            r"X=${IFS}; git${X}reset${X}--hard",
            // A custom IFS splits on its own characters.
            r"IFS=x; X=x; git${X}reset${X}--hard",
            // Sequencing, rebinding and nesting that keep the binding.
            r#"X=" " && git${X}reset${X}--hard"#,
            r#"X=" "; cd /tmp; git${X}reset${X}--hard"#,
            r#"X=a; X=" "; git${X}reset${X}--hard"#,
            r#"export X=" "; git${X}reset${X}--hard"#,
            r#"X=" " Y=1; git${X}reset${X}--hard"#,
            r#"X=" "; (git${X}reset${X}--hard)"#,
            r#"X=" "; if true; then git${X}reset${X}--hard; fi"#,
            r#"X=" "; echo ok | git${X}reset${X}--hard"#,
            r#"X=" "; bash -c "git${X}reset${X}--hard""#,
            r#"X=" "; rm${X}-rf${X}/"#,
            // Bash indirection and namerefs (t_49339710 review, Bash 5.2/5.3:
            // `declare -n r=IFS; printf "[%s]" a${r}b` prints `[a][b]`).
            r"v=IFS; git${!v}reset${!v}--hard",
            r"declare -n r=IFS; git${r}reset${r}--hard",
            r#"X=" "; v=X; git${!v}reset${!v}--hard"#,
            r#"X=" "; declare -n r=X; git${r}reset${r}--hard"#,
        ],
    );
}

#[test]
fn quoted_composition_of_a_proven_value_forms_the_command_word() {
    assert_both(
        "deny",
        &[
            r#"X=gi; "${X}t" reset --hard"#,
            r#"X=gi; "$X"t reset --hard"#,
            r#"X=gi; Y=t; "$X$Y" reset --hard"#,
            r#"X=g; Y="${X}i"; "${Y}t" reset --hard"#,
        ],
    );
}

#[test]
fn proven_argument_values_reach_their_rules() {
    assert_both(
        "deny",
        &[
            // An unquoted value that splits into several arguments, and a
            // value glued to a literal.
            r#"X="reset --hard"; git $X"#,
            r#"X=" --hard"; git reset$X"#,
        ],
    );
}

#[test]
fn quoting_empty_ifs_and_data_keep_values_whole() {
    assert_both(
        "allow",
        &[
            // Inside double quotes the value is one word: no git runs.
            r#"X=" "; "git${X}reset${X}--hard""#,
            // An empty IFS performs no field splitting.
            r#"IFS=; X=" "; git${X}reset${X}--hard"#,
            // Single quotes and escapes do not expand.
            r#"X=" "; echo 'git${X}reset${X}--hard'"#,
            r#"X=" "; echo git\${X}reset\${X}--hard"#,
            // The value is data for these commands.
            r#"X="git reset --hard"; echo "$X""#,
            r#"X=gi; echo "${X}t reset --hard""#,
            r#"X=" "; printf "%s\n" git${X}reset${X}--hard"#,
            r#"MSG="rm -rf /"; git commit -m "$MSG""#,
            // An assignment word is not split.
            r#"X=" "; Y=git${X}reset${X}--hard; echo "$Y""#,
            // Harmless commands assembled the same way.
            r#"X=" "; git${X}status"#,
            r#"X=gi; "${X}t" status"#,
            r"X=gi; ${X}t log --oneline",
            r#"B=main; git checkout "$B" && git pull"#,
            r"F=out.txt; cat $F | wc -l",
        ],
    );
}
