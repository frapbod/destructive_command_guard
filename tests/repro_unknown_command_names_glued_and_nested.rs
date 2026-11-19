//! An unknown variable in a command name, read the way the shell can run it.
//!
//! - Glued between quoted literal text (`'gi'${V}'t'`, `"gi"${V}"t"`,
//!   `g'i'${V}t`): with `V` unset or empty the shell runs `git` (measured
//!   with Linux bash and dash and macOS bash and zsh, fake `git`; each ran
//!   `git reset --hard`). The unknown-name view read such a word only as a
//!   field break (`gi t`), never as the one word an empty value leaves.
//! - In a shell source the command starts (`bash -c '"$X" reset --hard'`,
//!   a heredoc body, an ssh payload): the view ran only for the command as
//!   sent, so the child's own unknown names were read as literal text,
//!   while `"$X" reset --hard` sent directly is denied. The same held for
//!   an eval body and for source a shell reads from a pipe.
//! - A name the parent shell binds without exporting it is unset in the
//!   child (`V=x; bash -c 'gi"${V}"t reset --hard'` runs `git`), so the
//!   child reads it empty; one the parent may export is unknown there.
//! - ANSI-C and locale quotes (`$'gi'${V}$'t'`) and references that keep
//!   part of the value (`${V#x}`, `${V/x/}`) glue the same way, and the
//!   command name may follow a subshell's `(`, a function declaration, a
//!   case arm or a `$(` in an assignment.

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
            "session_id": "sess-unknown-command-names",
            "transcript_path": "/tmp/claude/transcript.jsonl",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_use_id": "toolu_unknown_command_names",
        }),
        // `turn_id` selects Codex's protocol.
        Protocol::Codex => serde_json::json!({
            "session_id": "019dd11d-b795-7261-a9cb-9b85a5dadf16",
            "turn_id": "turn-unknown-command-names",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.5",
            "permission_mode": "default",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_use_id": "call_unknown_command_names",
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

/// Quotes around the literal text of a command name do not hide a glued
/// unknown value: the word is read split and unsplit.
#[test]
#[allow(clippy::literal_string_with_formatting_args)]
fn unknown_values_glued_between_quoted_text_are_read_unsplit_too() {
    let misses = misses(
        &[
            r"'gi'${V}'t' reset --hard",
            r#""gi"${V}"t" reset --hard"#,
            r"g'i'${V}t reset --hard",
            r"'gi'$V't' reset --hard",
            r"'g'${V}'it' reset --hard",
            r"'gi'${V:-}'t' reset --hard",
            r"'git'${V}'reset'${V}'--hard'",
            r"sudo 'gi'${V}'t' reset --hard",
            r"cd /tmp && 'gi'${V}'t' reset --hard",
            r"'r'${V}'m' -rf /",
            r"IFS=; 'gi'${V}'t' reset --hard",
            r"$'gi'${V}$'t' reset --hard",
            r#"$"gi"${V}$"t" reset --hard"#,
            r"'gi'${V#x}'t' reset --hard",
            r"'gi'${V%x}'t' reset --hard",
            r"'gi'${V/x/}'t' reset --hard",
            r#"gi"${V#x}"t reset --hard"#,
            r#"'gi'"${V#x}"'t' reset --hard"#,
            r"gi${V/x/}t reset --hard",
        ],
        &POSIX,
        EvaluationDecision::Deny,
    );
    assert!(misses.is_empty(), "misses:\n{}", misses.join("\n"));
}

/// A shell source the command starts has unknown names of its own, read as
/// they are in the command as sent.
#[test]
fn a_child_shells_own_unknown_names_are_read_like_the_commands() {
    let misses = misses(
        &[
            r#"bash -c '"$X" reset --hard'"#,
            r#"bash -c 'gi"${X}"t reset --hard'"#,
            r#"bash -c "'gi'\${V}'t' reset --hard""#,
            r#"bash -c 'echo ok; "$X" reset --hard'"#,
            r"bash -c 'git${X}reset${X}--hard'",
            r#"sh -c '"$X" reset --hard'"#,
            r#"sudo bash -c '"$X" reset --hard'"#,
            r#"ssh host '"$X" reset --hard'"#,
            "bash <<'EOF'\n\"$X\" reset --hard\nEOF",
            "bash <<'EOF'\n'gi'${V}'t' reset --hard\nEOF",
            r#"bash -c 'bash -c "\"\$X\" reset --hard"'"#,
            // The parent hands the child its value: not the parent's name.
            r#"X=git bash -c '"$X" reset --hard'"#,
            r#"env X=git bash -c '"$X" reset --hard'"#,
            r#"X=git; export X; bash -c '"$X" reset --hard'"#,
            "export X=' '; bash <<'EOF'\ngit${X}reset${X}--hard\nEOF",
        ],
        &POSIX,
        EvaluationDecision::Deny,
    );
    assert!(misses.is_empty(), "misses:\n{}", misses.join("\n"));
}

/// A name the parent shell binds without exporting it is unset in the child
/// shell; one exported from a group or subshell is the child's unknown.
#[test]
fn a_name_the_parent_does_not_export_is_unset_in_the_child() {
    let misses = misses(
        &[
            r#"V=x; /bin/bash -c 'gi"${V}"t reset --hard'"#,
            r#"V=x; bash -c "'gi'\${V}'t' reset --hard""#,
            "V=; bash <<'EOF'\n'gi'${V}'t' reset --hard\nEOF",
            r#"read V; bash -c 'gi"${V}"t reset --hard'"#,
            r#"for V in a; do :; done; bash -c 'gi"${V}"t reset --hard'"#,
            r#"(export X=git; bash -c '"$X" reset --hard')"#,
            r#"{ export X=git; bash -c '"$X" reset --hard'; }"#,
        ],
        &POSIX,
        EvaluationDecision::Deny,
    );
    assert!(misses.is_empty(), "misses:\n{}", misses.join("\n"));
}

/// An eval body runs in this shell and a shell reading a pipe is a child:
/// both get the unknown-name view.
#[test]
fn eval_bodies_and_piped_shell_source_read_unknown_names() {
    let misses = misses(
        &[
            r#"eval '"$X" reset --hard'"#,
            r#"eval "'gi'\${V}'t' reset --hard""#,
            r"X=' '; eval 'git${X}reset${X}--hard'",
            r#"echo '"$X" reset --hard' | sh"#,
            r#"printf '%s\n' "'gi'\${V}'t' reset --hard" | sh"#,
            r#"X=git; export X; echo '"$X" reset --hard' | /bin/sh"#,
        ],
        &POSIX,
        EvaluationDecision::Deny,
    );
    assert!(misses.is_empty(), "misses:\n{}", misses.join("\n"));
}

/// The command name after syntax that opens a body, and in a command
/// substitution an assignment runs.
#[test]
fn command_names_after_body_syntax_read_unknown_names() {
    let misses = misses(
        &[
            r#"( "$X" reset --hard )"#,
            r#"("$X" reset --hard)"#,
            r"('gi'${V}'t' reset --hard)",
            r"( git${X}reset${X}--hard )",
            r"echo ok && ( 'gi'${V}'t' reset --hard )",
            r"x=$('gi'${V}'t' reset --hard)",
            r#"f() { "$X" reset --hard; }; f"#,
            r"f() { 'gi'${V}'t' reset --hard; }; f",
            r#"case a in a) "$X" reset --hard;; esac"#,
            r#"bash -c 'f() { "$X" reset --hard; }; f'"#,
        ],
        &POSIX,
        EvaluationDecision::Deny,
    );
    assert!(misses.is_empty(), "misses:\n{}", misses.join("\n"));
}

/// Harmless commands with the same shapes stay allowed, and a name the
/// parent binds without exporting it is empty in the child (decided in
/// `repro_variable_field_splitting::values_the_shell_does_not_use_there_are_not_read`).
#[test]
fn harmless_unknown_command_names_stay_allowed() {
    let mut found = misses(
        &[
            r"'git'${V}'status'",
            r#""gi"${V}"t" status"#,
            r"'ec'${V}'ho' hi",
            r#"bash -c '"$X" status'"#,
            r#"bash -c 'cd "$HOME" && ls'"#,
            r#"bash -c '"$VIRTUAL_ENV/bin/python" -m pytest'"#,
            r#"ssh host '"$HOME/bin/deploy" --dry-run'"#,
            "bash <<'EOF'\n\"$EDITOR\" notes.txt\nEOF",
            "X=' '; bash <<'EOF'\ngit${X}reset${X}--hard\nEOF",
            r#"X=git bash -c '"$X" status'"#,
            r#"X=git; bash -c '"$X" reset --hard'"#,
            r"X=' '; echo 'git${X}reset${X}--hard' | bash",
            r"'gi'${V#x}'t' status",
            r#"( "$X" status )"#,
            r"x=$('ec'${V}'ho' hi)",
            r#"f() { "$EDITOR" notes.txt; }; f"#,
            r#"case a in a) "$X" status;; esac"#,
            r#"eval '"$X" status'"#,
            r#"echo '"$EDITOR" notes.txt' | sh"#,
        ],
        &POSIX,
        EvaluationDecision::Allow,
    );
    // The Unknown dialect's Windows filesystem reading denies a `$'…'`
    // command word as unresolved syntax (on the base too), so this one is
    // checked as POSIX only.
    found.extend(misses(
        &[r"$'ec'${V}$'ho' hi"],
        &[ShellDialect::Posix],
        EvaluationDecision::Allow,
    ));
    assert!(found.is_empty(), "misses:\n{}", found.join("\n"));
}
