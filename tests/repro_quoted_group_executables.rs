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

/// What the agent reads: "allow" for empty stdout, else the decision.
fn hook_decision(protocol: Protocol, command: &str) -> String {
    hook_decision_with_tool(protocol, command, "Bash")
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
    assert!(
        wrong.is_empty(),
        "expected {decision}:\n{}",
        wrong.join("\n")
    );
}

#[test]
fn quoted_executables_in_shell_groups_are_judged() {
    assert_both(
        "deny",
        &[
            r#"( "git" reset --hard )"#,
            r#"("git" reset --hard)"#,
            r#"f() { "git" reset --hard; }; f"#,
            r#"f() { "rm" -rf ~/; }; f"#,
            r"( git reset --hard )",
            r#"( "rm" -rf ~/ )"#,
            r#"{ "git" reset --hard; }"#,
            r"f() { git reset --hard; }; f",
            r#"X=t; ( "gi${X}" reset --hard )"#,
            r#"X=t; f() { "gi${X}" reset --hard; }; f"#,
            // t_49339710 review round 5: Bash runs `git` here.
            r#"f(){ "${IFS}it" reset --hard; }; IFS=g; f"#,
            r#"f(){ "git" reset --hard; }; f"#,
            r"f(){ 'git' reset --hard; }; f",
            r#"f(){ g"it" reset --hard; }; f"#,
            // t_416fd788 review round 4: case arms are compound bodies too.
            r#"case a in a) "git" reset --hard;; esac"#,
            r#"X=gi; case a in a) "${X}t" reset --hard;; esac"#,
            r"X=git; case a in a) $X reset --hard;; esac",
            r#"X=git; case a in a) "$X" reset --hard;; esac"#,
            r"case a in a) git reset --hard;; esac",
            r#"case a in (a) "git" reset --hard;; esac"#,
            r#"case a in b|a) "git" reset --hard;; esac"#,
            r#"f () ( "git" reset --hard ); f"#,
            r#"function f { "git" reset --hard; }; f"#,
            r#"( "git" reset --hard ) >/dev/null"#,
            r#"if true; then ( "git" reset --hard ); fi"#,
            r#"( "git" reset --hard ) 2>&1"#,
            r#"( "git" reset --hard ) > /dev/null 2>&1"#,
            r#"if ( "git" reset --hard ); then :; fi"#,
            r#"( ( "git" reset --hard ) )"#,
            // t_25afdc20 review round 1: the subshell's `)` can close a `(`
            // from an earlier segment or follow a case pattern, Bash accepts
            // closing reserved words after it, and `time` times a subshell.
            r#"( cd /tmp && "git" reset --hard )"#,
            r#"(cd /tmp; "git" reset --hard)"#,
            r#"( : | "git" reset --hard )"#,
            r#"( cd /tmp && "git" reset --hard ) >/dev/null"#,
            r#"f() ( cd /tmp && "git" reset --hard ); f"#,
            r#"X=t; ( cd /tmp && "gi${X}" reset --hard )"#,
            r#"( cd /tmp || "git" reset --hard )"#,
            r#"(cd /tmp && "git" reset --hard) | cat"#,
            r#"case a in a) ( "git" reset --hard ) ;; esac"#,
            r#"case a in a) ( "git" reset --hard );; esac"#,
            r#"case a in a) f() ( "git" reset --hard ); f;; esac"#,
            r#"if ( "git" reset --hard ) then :; fi"#,
            r#"while ( "git" reset --hard ) do :; done"#,
            r#"until ( "git" reset --hard ) do :; done"#,
            r#"{ ( "git" reset --hard ) }"#,
            r#"for i in 1; do ( "git" reset --hard ) done"#,
            r#"select x in a; do ( "git" reset --hard ) done"#,
            r#"if true; then ( "git" reset --hard ) fi"#,
            r#"if true; then :; else ( "git" reset --hard ) fi"#,
            r#"X=t; if ( "gi${X}" reset --hard ) then :; fi"#,
            r#"time ( "git" reset --hard )"#,
            r#"time -p ( "git" reset --hard )"#,
            r#"{ time ( "git" reset --hard ); }"#,
            r#"! time ( "git" reset --hard )"#,
            r#"time ! ( "git" reset --hard )"#,
        ],
    );
}

#[test]
#[allow(clippy::literal_string_with_formatting_args)]
fn parameter_expansion_parentheses_are_not_group_closes() {
    assert_both(
        "deny",
        &[
            r"git checkout ${x:+)} -- .",
            r"git checkout ${x:-)} -- .",
            r"git reset ${x//)} --hard",
            r"git push ${x:+)} --force origin main",
            r"rm ${x:+)} -rf /tmp/zz",
            r"git clean ${x:+)} -fdx",
            r"git stash ${x:+)} clear",
            r#"( cd /tmp && "git" reset ${x:+(} --hard )"#,
        ],
    );
    assert_both(
        "allow",
        &[
            r"git restore ${x:+)} --staged .",
            r"git stash ${x:-pop} clear",
            r"git status ${x:+)}",
            r"git commit -m '${x:+)} git reset --hard'",
            r"printf '%s' 'git reset ${x:+)} --hard'",
        ],
    );
}

#[test]
fn quoted_git_groups_with_unknown_shell_are_judged() {
    for protocol in [Protocol::Claude, Protocol::Codex] {
        for command in [
            r#"{ g"it" reset --hard; }"#,
            r#"f() { g"it" reset --hard; }; f"#,
            r#"f(){ gi"t" reset --hard; }; f"#,
            r"f(){ g\it reset --hard; }; f",
            r#"function f { g"it" reset --hard; }; f"#,
            r#"f(){ g"it" push --force origin main; }; f"#,
            r#"if true; then g"it" reset --hard; fi"#,
            r#"cat <( cd /tmp && "git" reset --hard )"#,
            r"git push ${x:+)} --force origin main",
            r"git reset ${x//)} --hard",
            r"git clean ${x:+)} -fdx",
            r"git stash ${x:+)} clear",
        ] {
            assert_eq!(
                hook_decision_with_tool(protocol, command, "Shell"),
                "deny",
                "{protocol:?}: {command}"
            );
        }
        assert_eq!(
            hook_decision_with_tool(protocol, r#"f(){ g"it" status; }; f"#, "Shell"),
            "allow"
        );
    }
}

#[test]
fn safe_quoted_shell_groups_remain_allowed() {
    assert_both(
        "allow",
        &[
            r#"( "git" status )"#,
            r#"f() { "git" status; }; f"#,
            r#"f() { "rm" ./unimportant; }; f"#,
            r#"{ "git" status; }"#,
            r#"( printf '%s' '"git" reset --hard' )"#,
            r#"f() { printf '%s' '"rm" -rf ~/'; }; f"#,
            r#"printf '%s' '( "git" reset --hard )'"#,
            r#"case a in a) "git" status;; esac"#,
            r#"case a in a) printf '%s' '"git" reset --hard';; esac"#,
            r#"( cd /tmp && "git" status ) >/dev/null"#,
            r#"( "git" commit -m "reset --hard" )"#,
            r#"f() { "git" log; }; f"#,
            r#"( git commit -m "reset --hard" )"#,
            // PowerShell conditions: POSIX rejects a word after a subshell's
            // `)`, so these are not subshells (Windows judges both dialects).
            r"if ($n -ge 96 -and $n -le 107) { 'x' }",
            r"while ($n -lt 3 -and $m) { $n++ }",
            r#"(git commit -m "reset --hard")"#,
            r#"( "git" log --grep "reset --hard" ) | cat"#,
            r#"printf '%s\n' 'a) "git" reset --hard'"#,
            r"if (git diff --quiet) then echo clean; fi",
            r#"(cd /tmp && "git" status)"#,
            r#"(cd /tmp && git commit -m "reset --hard")"#,
            r#"for f in *.txt; do (wc -l "$f") done"#,
            r"while (true) do sleep 1; done",
            r#"(cd /tmp && grep -r "git reset --hard" .)"#,
            r#"time -p ( "git" status )"#,
            r"echo $(cd /tmp; git status) foo",
        ],
    );
}

/// t_25afdc20 review round 4: a flag inside an unquoted expansion's operand
/// reaches Git when the parameter is unset (`${X:-. -"W"}` runs
/// `git restore --staged . -W`, which discards worktree changes). A safe
/// exemption must hold under every reading of such a word, in a plain
/// command and inside a subshell, function body or case arm alike. Only dcg
/// reads these strings; this test does not execute their shell source.
#[test]
#[allow(clippy::literal_string_with_formatting_args)]
fn expansion_operands_cannot_grant_core_git_exemptions() {
    let unsafe_commands = [
        r#"git restore --staged ${X:-. -"W"}"#,
        r"git restore --staged ${X:-. -\W}",
        r"git restore --staged ${X:-. -'W'}",
        r#"git restore --staged ${X:-. --work"tree"}"#,
        r#"git restore -S ${X:-. -"W"}"#,
        r#"git restore --staged ${X:=. -"W"}"#,
        r#"git restore --staged ${X-. -"W"}"#,
        r#"X=; git restore --staged ${X:-. -"W"}"#,
        r#"cd /tmp && git restore --staged ${X:-. -"W"}"#,
        r#"git restore --staged ${X:-. -"W"} && echo ok"#,
        r#"git restore --staged ${X:-. -"W"} ${Y}"#,
        r"git restore --staged ${X:--W}",
        r#"git restore --staged ${X:+-"W"} ."#,
        r#"git restore --staged . ${X:+--"worktree"}"#,
        r#"git restore --staged ${X:-. -"W"$Z}"#,
        r#"bash -c 'git restore --staged ${X:-. -"W"}'"#,
        r#"( git restore --staged ${X:-. -"W"} )"#,
        r#"f() { git restore --staged ${X:-. -"W"}; }; f"#,
        r#"case a in a) git restore --staged ${X:-. -"W"};; esac"#,
    ];
    let safe_commands = [
        r"git restore --staged ${X:-a b}",
        r"git restore --staged ${FILES}",
        r"git restore --staged ${X:-src docs}",
        r"git restore --staged ${X:-.} ${Y:-src}",
        r"git clean -n ${X:-a b}",
        r"git clean -n ${FILES}",
        r"git checkout -b ${X:-a b}",
        r"( git restore --staged ${X:-src docs} )",
        r"f() { git clean -n ${FILES}; }; f",
    ];
    assert_both("deny", &unsafe_commands);
    assert_both("allow", &safe_commands);
    let mut wrong = Vec::new();
    for protocol in [Protocol::Claude, Protocol::Codex] {
        for command in unsafe_commands {
            let actual = hook_decision_with_tool(protocol, command, "Shell");
            if actual != "deny" {
                wrong.push(format!("{protocol:?} Shell {actual}: {command}"));
            }
        }
        for command in safe_commands {
            let actual = hook_decision_with_tool(protocol, command, "Shell");
            if actual != "allow" {
                wrong.push(format!("{protocol:?} Shell {actual}: {command}"));
            }
        }
    }
    assert!(wrong.is_empty(), "unknown shell:\n{}", wrong.join("\n"));
}
