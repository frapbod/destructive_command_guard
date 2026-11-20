//! A heredoc, here-string or pipe is the stdin of the command it feeds, and
//! some of those commands run it as source that dcg did not read:
//!
//! - `. /dev/stdin` and `source /dev/stdin` (also `/dev/fd/0`,
//!   `/proc/self/fd/0`, behind `builtin`) run it in the consumer's own shell.
//!   `echo 'git reset --hard' | source /dev/stdin` runs `git reset --hard` in
//!   Linux bash, macOS bash 3.2 and 5.3 and zsh; `| . /dev/stdin` also in
//!   dash; `source /dev/stdin <<'EOF'` and `<<<` do too (`scripts/shell-truth`,
//!   fake git).
//! - A program word the shell expands (`env $A sh`) can become options or
//!   assignments before the shell: with `A=X=git`, `echo 'git reset --hard' |
//!   /usr/bin/env $A /bin/sh` runs `git reset --hard` in Linux bash and dash.
//! - cmd.exe reads its stdin as commands when it runs bare, with `/k`, or
//!   through a nested `cmd /c cmd`; a heredoc or here-string into it was read
//!   only as Bash.

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

fn payload(protocol: Protocol, command: &str, cwd: &std::path::Path) -> serde_json::Value {
    match protocol {
        Protocol::Claude => serde_json::json!({
            "session_id": "sess-stdin-redirect-consumers",
            "transcript_path": "/tmp/claude/transcript.jsonl",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_use_id": "toolu_stdin_redirect_consumers",
        }),
        // `turn_id` selects Codex's protocol.
        Protocol::Codex => serde_json::json!({
            "session_id": "019dd11d-b795-7261-a9cb-9b85a5dadf16",
            "turn_id": "turn-stdin-redirect-consumers",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.5",
            "permission_mode": "default",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_use_id": "call_stdin_redirect_consumers",
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
        .env("DCG_PACKS", "core.git,core.filesystem,windows.filesystem")
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

/// Checks each command in `dialects` and in both hook formats, and reports
/// every miss at once.
fn misses(commands: &[&str], dialects: &[ShellDialect], want: EvaluationDecision) -> Vec<String> {
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
            let got = hook_decision(protocol, command);
            if got != hook_want {
                misses.push(format!("{protocol:?}: {command:?} -> {got}"));
            }
        }
    }
    misses
}

const POSIX: [ShellDialect; 2] = [ShellDialect::Posix, ShellDialect::Unknown];

/// A shell that sources its stdin runs a pipe, heredoc or here-string as its
/// own source.
#[test]
fn stdin_sourced_by_the_shell_itself_is_shell_source() {
    let misses = misses(
        &[
            "echo 'git reset --hard' | source /dev/stdin",
            "echo 'git reset --hard' | . /dev/stdin",
            "echo 'git reset --hard' | source /dev/fd/0",
            "echo 'git reset --hard' | . /proc/self/fd/0",
            "echo 'git reset --hard' | source -- /dev/stdin",
            "printf '%s\\n' 'git reset --hard' | builtin source /dev/stdin",
            "printf '%s\\n' 'git reset --hard' | command . /dev/stdin",
            "{ echo '\"$X\" reset --hard'; } | source /dev/stdin",
            "source /dev/stdin <<'EOF'\ngit reset --hard\nEOF",
            ". /dev/stdin <<'EOF'\ngit reset --hard\nEOF",
            "source /dev/stdin <<EOF\ngit reset --hard\nEOF",
            "source /dev/stdin <<EOF\n$X reset --hard\nEOF",
            "builtin . /dev/stdin <<'EOF'\nrm -rf ~/\nEOF",
            "source /dev/stdin <<< 'git reset --hard'",
            ". /dev/fd/0 <<< \"git reset --hard\"",
        ],
        &POSIX,
        EvaluationDecision::Deny,
    );
    assert!(misses.is_empty(), "misses:\n{}", misses.join("\n"));
}

/// An expanded program word may turn into options or assignments before a
/// shell word, so that shell reads the stdin.
#[test]
fn stdin_into_a_shell_after_an_expanded_program_word_is_shell_source() {
    let misses = misses(
        &[
            "echo 'git reset --hard' | env $A sh",
            "A=X=git; echo 'git reset --hard' | env $A sh",
            "echo 'git reset --hard' | env \"$A\" bash",
            "echo 'git reset --hard' | env -u X $A sh",
            "echo 'git reset --hard' | $W bash -s",
            "env $A sh <<'EOF'\ngit reset --hard\nEOF",
            "env $A /bin/sh <<< 'git reset --hard'",
        ],
        &POSIX,
        EvaluationDecision::Deny,
    );
    assert!(misses.is_empty(), "misses:\n{}", misses.join("\n"));
}

/// cmd.exe runs the lines it reads from stdin when it runs bare, with `/k`,
/// or as a nested `cmd /c cmd`; a value the parent substitutes into them is
/// unknown, as a cmd variable is.
#[test]
fn stdin_into_cmd_is_read_as_cmd() {
    let misses = misses(
        &[
            r#"cmd.exe <<< "rd /s /q C:\x""#,
            "cmd.exe <<EOF\nrd /s /q C:\\x\nEOF",
            "cmd <<'EOF'\nrd /s /q C:\\x\nEOF",
            r#"cmd.exe /c cmd <<< "rd /s /q C:\x""#,
            r#"cmd /c cmd /q <<< "rd /s /q C:\x""#,
            r#"cmd /c "cmd /q" <<< "rd /s /q C:\x""#,
            r#"cmd /k echo hi <<< "rd /s /q C:\x""#,
            r#"echo "rd /s /q C:\x" | cmd /c cmd"#,
            r#"echo "rd /s /q C:\x" | cmd /k echo hi"#,
            r#"cmd.exe <<< "$X""#,
            r#"cmd /c cmd <<< "$X""#,
            r#"cmd /c cmd<<<"$X""#,
            r#"X='rd /s /q C:\x'; cmd /c cmd <<< "$X""#,
        ],
        &POSIX,
        EvaluationDecision::Deny,
    );
    assert!(misses.is_empty(), "misses:\n{}", misses.join("\n"));
}

/// The same consumers with harmless source, data readers of the same stdin,
/// and programs that do not read it stay allowed.
#[test]
fn harmless_stdin_and_data_readers_stay_allowed() {
    let misses = misses(
        &[
            "echo 'git status' | source /dev/stdin",
            "echo 'echo hi' | . /dev/stdin",
            "source /dev/stdin <<'EOF'\ngit status\nEOF",
            ". /dev/stdin <<< 'echo hi'",
            "echo 'git reset --hard' | cat /dev/stdin",
            "echo 'git reset --hard' | grep source /dev/stdin",
            "cat /dev/stdin <<'EOF'\ngit reset --hard\nEOF",
            "echo 'git reset --hard' | source ./setup.sh",
            "echo 'git status' | env $A sh",
            "echo 'git reset --hard' | env $A cat",
            "echo 'git reset --hard' | $PAGER",
            r#"cmd.exe <<< "dir C:\x""#,
            "cmd.exe <<EOF\necho hi\nEOF",
            r#"echo "dir" | cmd.exe"#,
            r#"cmd /c cmd <<< "dir C:\x""#,
            r#"cmd /c dir <<< "rd /s /q C:\x""#,
        ],
        &POSIX,
        EvaluationDecision::Allow,
    );
    assert!(misses.is_empty(), "misses:\n{}", misses.join("\n"));
}
