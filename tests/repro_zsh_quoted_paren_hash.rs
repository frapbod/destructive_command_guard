//! zsh reads a `#` after a blank (or a `|`) inside a glob or case-pattern
//! group as data, so the rest of the line runs. A `)` in quotes, `$'…'`, a
//! backquote or `${…}` closes no group: measured with `scripts/shell-truth`
//! (zsh 5.9, with and without `interactivecomments`), zsh runs
//! `git reset --hard` for `ls (a")" #); git reset --hard`, while bash, sh,
//! dash and pwsh run nothing. dcg used to count that quoted `)`, read the
//! `#` as a comment and allow the line.

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
            "session_id": "sess-zsh-quoted-paren",
            "transcript_path": "/tmp/claude/transcript.jsonl",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "toolu_zsh_quoted_paren",
        }),
        // `turn_id` selects Codex's protocol.
        Protocol::Codex => serde_json::json!({
            "session_id": "019dd11d-b795-7261-a9cb-9b85a5dadf15",
            "turn_id": "turn-zsh-quoted-paren",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.5",
            "permission_mode": "default",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "call_zsh_quoted_paren",
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
    let enabled: std::collections::HashSet<String> = ["core.git", "core.filesystem"]
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

/// Checks each command in its dialects and in both hook formats with
/// `tool`, and reports every miss at once.
fn expect_everywhere(
    commands: &[String],
    dialects: &[ShellDialect],
    tool: &str,
    want: EvaluationDecision,
) -> Vec<String> {
    let hook_want = if want == EvaluationDecision::Deny {
        "deny"
    } else {
        "allow"
    };
    let mut misses = Vec::new();
    for command in commands {
        for &dialect in dialects {
            let got = decision_in(command, dialect);
            if got != want {
                misses.push(format!("{dialect:?}: {command:?} -> {got:?}"));
            }
        }
        for protocol in [Protocol::Claude, Protocol::Codex] {
            let got = hook_decision(protocol, tool, command);
            if got != hook_want {
                misses.push(format!("{protocol:?} {tool}: {command:?} -> {got}"));
            }
        }
    }
    misses
}

fn strings(commands: &[&str]) -> Vec<String> {
    commands
        .iter()
        .map(|command| (*command).to_string())
        .collect()
}

const POSIX: [ShellDialect; 2] = [ShellDialect::Posix, ShellDialect::Unknown];

/// A quoted `)` inside a glob or case-pattern group does not end the group,
/// so the `#` after it is data to zsh and the command after the group runs.
#[test]
fn a_quoted_paren_in_a_glob_or_case_group_does_not_hide_the_rest_of_the_line() {
    let misses = expect_everywhere(
        &strings(&[
            r#"ls (a")" #); git reset --hard"#,
            r"ls (a')' #); git reset --hard",
            r"ls (a$')' #); git reset --hard",
            r#"ls (a")"|#); git reset --hard"#,
            r#"ls (a")"| #); git reset --hard"#,
            "ls (a\")\"\t#); git reset --hard",
            r#"ls ("a)" #); git reset --hard"#,
            r"ls (a${x%)} #); git reset --hard",
            r#"case x in (a")" #) ;; esac; git reset --hard"#,
            r#"case x in (a")"|#)) ;; esac; git reset --hard"#,
            r#"ls (a")" #); git push --force origin main"#,
            r#"ls (a")" #); git clean -fdx"#,
            r#"ls (a")" #) || git reset --hard"#,
        ]),
        &POSIX,
        "Bash",
        EvaluationDecision::Deny,
    );
    assert!(misses.is_empty(), "allowed:\n{}", misses.join("\n"));
}

/// The same inside a shell payload, a substitution and after a comment
/// whose quote opens nothing.
#[test]
fn a_quoted_paren_in_a_group_is_read_in_payloads_and_after_comments() {
    let misses = expect_everywhere(
        &strings(&[
            r#"zsh -c 'ls (a")" #); git reset --hard'"#,
            r"x=$(ls (a')' #); git reset --hard)",
            "echo hi # it's\nls (a\")\" #); git reset --hard",
            r#"echo "$(ls (a')' #); git reset --hard)""#,
        ]),
        &POSIX,
        "Bash",
        EvaluationDecision::Deny,
    );
    assert!(misses.is_empty(), "allowed:\n{}", misses.join("\n"));
}

/// A comment outside every group is read as before, and a `#` read as data
/// inside a group hides nothing on the next line.
#[test]
fn comments_outside_groups_stay_comments() {
    let misses = expect_everywhere(
        &strings(&[
            "ls (a\")\" #)\ngit status",
            r#"ls (a")" #)"#,
            r#"case x in (a")" #) ;; esac; git status"#,
            "echo $(date) # git reset --hard",
            r#"echo $(echo ")") # git reset --hard"#,
            r#"echo ")" # git reset --hard"#,
        ]),
        &POSIX,
        "Bash",
        EvaluationDecision::Allow,
    );
    assert!(misses.is_empty(), "denied:\n{}", misses.join("\n"));
}
