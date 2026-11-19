//! Hook-level regressions: every reader judges a command inside a function
//! body or a case arm as it judges the command on its own, in a subshell or
//! after `then`: `eval`, brace lists, `trap`, `PROMPT_COMMAND`, `alias`,
//! process substitution, sed `e`, tar's command options, launchers, the
//! working directory and quoted executable paths.

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

/// `inner` in each body shape: one-line and multi-line function and case,
/// `function NAME { …; }` and a case arm inside a function.
fn in_every_body(inner: &[&str]) -> Vec<String> {
    inner
        .iter()
        .flat_map(|x| {
            [
                format!("f() {{ {x}; }}; f"),
                format!("case a in a) {x};; esac"),
                format!("f() {{\n  {x}\n}}\nf"),
                format!("case a in\n  a)\n    {x}\n    ;;\nesac"),
                format!("function f {{ {x}; }}; f"),
                format!("f() {{ case a in a) {x};; esac; }}; f"),
            ]
        })
        .collect()
}

#[test]
fn every_segment_reader_is_judged_in_function_bodies_and_case_arms() {
    // Each denies on its own. Linux bash, bash 5 and dash run the process
    // substitution (bash only), launcher, sed and tar bodies with the plain
    // form's argv (scripts/shell-truth, t_6c63e222 review round 1).
    assert_all(
        "deny",
        &in_every_body(&[
            "bash <(echo 'git reset --hard')",
            "source <(echo 'rm -rf ~')",
            ". <(echo 'git reset --hard')",
            "sed 'e rm -rf /' file.txt",
            "sed -e 's|x|rm -rf /|e' file.txt",
            "sed -n '1e git reset --hard' notes.txt",
            "tar -xf a.tar --to-command='rm -rf ~'",
            "tar -cf /dev/null --checkpoint=1 --checkpoint-action=exec='git reset --hard' .",
            "b''ash -c 'git reset --hard'",
            "cd ~/.ssh && rm id_rsa",
            "cd /home/user/.ssh; echo k >>authorized_keys",
            "mkfs.ext4 /dev/sda1",
            r#""C:/Program Files/Git/bin/git.exe" reset --hard"#,
            r#""C:\Program Files\Git\bin\git.exe" reset --hard"#,
            "$(echo git reset --hard)",
            "cp /dev/null ~/.bashrc",
        ]),
    );
}

#[test]
fn a_quoted_executable_path_after_a_reserved_word_is_judged() {
    let git = r#""C:/Program Files/Git/bin/git.exe" reset --hard"#;
    assert_all(
        "deny",
        &[
            format!("{{ {git}; }}"),
            format!("if true; then {git}; fi"),
            format!("while true; do {git}; break; done"),
            format!("if {git}; then :; fi"),
            format!("! {git}"),
            r#"{ "/usr/bin/git" reset --hard; }"#.to_string(),
        ],
    );
}

#[test]
fn harmless_commands_in_every_body_stay_allowed() {
    assert_all(
        "allow",
        &in_every_body(&[
            "sed 's/a/b/' file.txt",
            "tar -xf a.tar",
            "bash -c 'git status'",
            "cat <(echo hi)",
            "diff <(sort a) <(sort b)",
            "cd src && ls",
            "cd ~/.ssh && ls",
            r#""C:/Program Files/Git/bin/git.exe" status"#,
            "$(echo git status)",
        ]),
    );
}

/// Reading a body at its command must not lose what the segment around it
/// carries: a group's redirect writes the file (`( … ) >> FILE`), and an
/// assignment in a subshell or branch does not bind the parent shell. A
/// version that narrowed every segment allowed each of these.
#[test]
fn group_redirects_and_binding_scopes_survive_body_reading() {
    assert_all(
        "deny",
        &[
            "(echo k) >> ~/.ssh/authorized_keys",
            "(cat /dev/null) > ~/.bashrc",
            "(printf x) > /etc/passwd",
            "(sed 's/a/b/' f) > ~/.ssh/config",
            "(cmd.exe /c echo hi) > ~/.bashrc",
            r#"(D=/tmp/ok); rm -rf "$D""#,
            r#"if test -n "$C"; then D=/tmp/build; fi; rm -rf "$D""#,
            r#"(S=/tmp/d); echo hi > "$S/x""#,
        ]
        .map(String::from),
    );
    assert_all(
        "allow",
        &[
            "(echo hi) > /tmp/x",
            "X=a; false && { X=' '; }; git${X}reset${X}--hard",
            "X=a; if false; then { X=' '; }; fi; git${X}reset${X}--hard",
        ]
        .map(String::from),
    );
}
