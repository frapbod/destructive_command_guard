//! Unknown executable values with visible git mutation syntax.
#![allow(clippy::literal_string_with_formatting_args)] // shell `${…}`, not a format

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
    let mut failures = Vec::new();
    for command in commands {
        for protocol in [Protocol::Claude, Protocol::Codex] {
            let actual = hook_decision(protocol, command);
            if actual != decision {
                failures.push(format!(
                    "{protocol:?}: {command:?}: expected {decision}, got {actual}"
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn literal_git_mutation_after_unknown_executable() {
    // `X` is unset in the command: an earlier command in a persistent shell
    // may have exported it. Quoted, it is one field of the same value.
    assert_both(
        "deny",
        &[
            r#""$X" reset --hard"#,
            r#""${X}t" reset --hard"#,
            r#""${X:-git}" reset --hard"#,
            r#"'g'"$X" reset --hard"#,
            r#""$X" clean -fdx"#,
            r#""$X" push --force origin main"#,
            r#"sudo "$X" reset --hard"#,
            r"$X reset --hard",
            r"g${X}t reset --hard",
        ],
    );
}

#[test]
fn only_a_binding_before_the_use_keeps_the_name_known() {
    // Later text, flags, comments and quoted mentions of the name do not
    // bind it before the use.
    assert_both(
        "deny",
        &[
            r#""$D" branch -D main"#,
            r#""$X" reset --hard; X=1"#,
            r#""$X" reset --hard # X"#,
            r#"echo "GIT is $GIT"; "$GIT" reset --hard"#,
            r#""$GIT" reset --hard origin/main && echo "GIT reset done""#,
        ],
    );
}

#[test]
fn literal_last_path_component_names_the_program() {
    assert_both(
        "deny",
        &[
            r#""$X/bin/git" reset --hard"#,
            r#""$HOMEBREW_PREFIX/bin/git" reset --hard"#,
            r#""$X"/bin/git reset --hard"#,
            r#""$X/bin/rm" -rf /"#,
            r#""$X/bin/git" -c core.pager=cat reset --hard"#,
            r#""$X/bin/git" -c user.name=x push --force origin main"#,
            r#""$X/bin/git" -C /r -c a=b reset --hard"#,
            r#""$X/bin/git" clean -fdx -e node_modules"#,
            r#""$X/bin/git" -p reset --hard"#,
        ],
    );
    assert_both(
        "allow",
        &[
            r#""$X/bin/python" -c "print(1)""#,
            r#""$X/bin/bash" -c "echo hi""#,
        ],
    );
}

#[test]
fn unquoted_unknown_values_can_split_a_composite_executable() {
    assert_both(
        "deny",
        &[
            r"git${X}reset${X}--hard",
            r"git${X}clean${X}-fdx",
            r"git${X}push${X}--force",
            r"git${X:+ }reset${X:+ }--hard",
            r"/usr/bin/git${X}reset${X}--hard",
            r"sudo git${X}reset${X}--hard",
            r"if true; then git${X}reset${X}--hard; fi",
            r"rm${X}-rf${X}/",
        ],
    );
}

#[test]
fn wrapper_command_names_are_judged() {
    assert_both(
        "deny",
        &[
            r#"X=git; sudo "$X" reset --hard"#,
            r#"X=git; env "$X" reset --hard"#,
            r#"X=git; env -i "$X" reset --hard"#,
            r#"X=git; exec "$X" reset --hard"#,
            r#"X=git; nohup "$X" reset --hard"#,
            r#"X=git; nice "$X" reset --hard"#,
            r#"X=git; timeout 5 "$X" reset --hard"#,
            r#"X=git; doas "$X" reset --hard"#,
            r#"X=git; xargs "$X" reset --hard"#,
            r#"X=git; command -p "$X" reset --hard"#,
            r#"X=git; sudo -u root "$X" reset --hard"#,
            r#"Y=git; X=$Y; sudo "$X" reset --hard"#,
        ],
    );
}

#[test]
fn wrapper_harmless_controls() {
    assert_both(
        "allow",
        &[
            r#"X=git; sudo "$X" status"#,
            r#"X=echo; sudo "$X" harmless"#,
            r#"X=echo; sudo "$X" reset --hard"#,
            r#"X=printf; "$X" reset --hard"#,
            r#"X=not_git; "${X}t" reset --hard"#,
            r#"X=git; sudo "$X" clean -n"#,
        ],
    );
}

#[test]
fn shell_scope_preserves_possible_git_bindings() {
    assert_both("deny", &[r#"X=gi; ( "${X}t" reset --hard )"#]);
}

#[test]
fn shell_scope_harmless_controls() {
    assert_both(
        "allow",
        &[
            r"X=' '; ( X=a ); git${X}status",
            r"IFS=; X=' '; git${X}reset${X}--hard",
            r"X=a; git${X}reset${X}--hard",
            // A name the command binds belongs to the binding proof.
            r"X=a; false && { X=' '; }; git${X}reset${X}--hard",
            // An `eval` body is judged without the bindings around it.
            r#"git() { :; }; X=gi; eval '"${X}t" reset --hard'"#,
        ],
    );
}

#[test]
fn unknown_and_inert_shapes_remain_allowed() {
    // #273/#281: an unknown program with no literal Git evidence.
    assert_both(
        "allow",
        &[
            r#""$X" "$Y""#,
            r#""$BIN" run "$ARG""#,
            r"$cmd $arg",
            r#""$@""#,
            r#"exec "$@""#,
            r"echo 'git${X}reset${X}--hard'",
            r#""git${X}reset${X}--hard""#,
            r#"git"${Y}"reset"${Y}"--hard"#,
            r#""$X" status"#,
            r#""$X" clean -n"#,
            r"git${X}status",
            r#""$EDITOR" README.md"#,
            r#""$VIRTUAL_ENV/bin/python" -m pip install -e ."#,
            r#""$HOME/bin/tool" reset --hard"#,
            r"$HOME/.local/bin/dcg --version",
            // #538: the documented flowctl handle stays data.
            r#""$FLOWCTL" gate receipt --command "git reset --hard""#,
        ],
    );
}
