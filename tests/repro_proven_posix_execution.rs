//! Known positional arguments and variables that execute commands, tested
//! through both hook protocols. Commands are scanned, never executed.

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
fn proven_command_arguments_and_source_are_judged() {
    assert_both(
        "deny",
        &[
            r#"f() { "$@"; }; f git reset --hard"#,
            r"f() { $*; }; f git reset --hard",
            r#"f() { "$*" reset --hard; }; f git"#,
            r#"f() { exec "$@"; }; f git reset --hard"#,
            r#"f() { command "$@"; }; f git reset --hard"#,
            "f() {\n  \"$@\"\n}; f git reset --hard",
            r#"echo() { "$@"; }; echo git reset --hard"#,
            r#"set -- git reset --hard; "$@""#,
            r#"x='git reset --hard'; bash <<< "$x""#,
            r#"x='git reset --hard'; . /dev/stdin <<< "$x""#,
        ],
    );
}

/// The cases from the design review, measured allowed before this change.
#[test]
fn function_frames_and_positional_bindings_are_judged() {
    assert_both(
        "deny",
        &[
            r#"run() { echo "+ $*"; "$@"; }; run git reset --hard"#,
            r#"f() { "$1" "${@:2}"; }; f git reset --hard"#,
            r#"f() { shift; "$@"; }; f x git reset --hard"#,
            r#"f() { local a=$1; shift; "$a" "$@"; }; f git reset --hard"#,
            r#"f() { "$@"; }; g() { f "$@"; }; g git reset --hard"#,
            r#"function f { "$@"; }; f git reset --hard"#,
            r#"f() ( "$@" ); f git reset --hard"#,
            r#"set -- git reset --hard; exec "$@""#,
            r#"x=git; f() { "$@"; }; f "$x" reset --hard"#,
            r#"retry() { "$@"; }; retry git push --force "$branch""#,
            r"x='git reset --hard'; bash <<< $x",
            r#"x='git reset --hard'; bash <<< "${x}""#,
            r#"x='git reset --hard'; bash -s <<< "$x""#,
            r#"X='git reset --hard'; bash <<< " $X""#,
        ],
    );
}

#[test]
fn frames_do_not_leak_or_run_before_their_definition() {
    assert_both(
        "allow",
        &[
            r#"f() { :; }; f git reset --hard; "$@""#,
            r#"f git reset --hard; f() { "$@"; }"#,
            r#"f() { "$@"; }; f "$x""#,
            r#"x='git reset --hard'; cat <<< "$x""#,
            r#"x='git reset --hard'; grep -q foo <<< "$x""#,
            r#"f() { "$@"; }; f echo git reset --hard"#,
            r#"set -- git reset --hard; shift 3; "$@""#,
            r#"retry() { "$@" || retry "$@"; }; retry make"#,
            r#"mk() { make "$@"; }; mk -j4 all"#,
            r#"log() { echo "+ $*"; }; log git reset --hard"#,
            r#"set -e; set -o pipefail; "$@""#,
        ],
    );
}

#[test]
fn harmless_and_unknown_commands_keep_current_policy() {
    assert_both(
        "allow",
        &[
            r#"f() { "$@"; }; f ls"#,
            r#"retry() { "$@"; }; retry make"#,
            r#"f() { printf '%s' "$@"; }; f 'git reset --hard'"#,
            r#"f() { "$@"; }; f 'git reset --hard'"#,
            r#"set -- git status; "$@""#,
            r#"x='git status'; bash <<< "$x""#,
            r#"x='git status'; . /dev/stdin <<< "$x""#,
            r#"trap "$1" EXIT"#,
            r#"source "$1""#,
            r#""$@""#,
            // A quoted $* combines multiple words into one executable name.
            r#"f() { "$*"; }; f git reset --hard"#,
        ],
    );
    assert_both("deny", &[r#"eval "$*""#]);
}

/// A handler a function frame or `set --` proves (review of PR #13, round
/// 2): the deferred trap reading and the here-string receiver see the value.
/// Unknown handlers keep the policy above.
#[test]
fn proven_trap_and_stdin_handlers_are_judged() {
    assert_both(
        "deny",
        &[
            r#"echo() { trap "$*" EXIT; }; echo 'git reset --hard'"#,
            r#"echo() { 2>/dev/null trap "$*" EXIT; }; echo 'git reset --hard'"#,
            r#"set -- 'git reset --hard'; trap "$1" EXIT"#,
            r#"f() { source /dev/stdin <<< "$1"; }; f 'git reset --hard'"#,
            // The review of #43: a handler a frame binds as a quoted argument.
            r#"f() { trap "$1" EXIT; }; f 'git reset --hard'"#,
            r#"f() { trap -- "${1}" EXIT; }; f 'git reset --hard'"#,
        ],
    );
    assert_both(
        "allow",
        &[
            r#"f() { trap "$*" EXIT; }; f 'echo done'"#,
            r#"f() { trap "$*" EXIT; }; f "$x""#,
            r#"f() { trap "$1" EXIT; }; f 'rm -f /tmp/x.lock'"#,
        ],
    );
}

/// A whole quoted or bare argument with a proven plain value (PR #2 "Not
/// covered", fixed upstream in 18687c83): the second deny-only reading.
#[test]
fn proven_plain_argument_values_are_judged() {
    assert_both(
        "deny",
        &[
            r#"x=--hard; git reset "$x""#,
            r"x=--hard; git reset $x",
            r#"x=-f; git push "$x""#,
            r#"x=--force; git push origin "$x""#,
            r#"x=-D; git branch "$x" main"#,
            r#"x=--hard; f() { git reset "$1"; }; f "$x""#,
        ],
    );
    assert_both(
        "allow",
        &[
            r#"x=--soft; git reset "$x""#,
            r#"x=main; git push origin "$x""#,
            r#"x=--hard; echo "$x""#,
            r#"x=--hard; printf '%s\n' "$x" > notes.txt"#,
            r#"x=-la; ls "$x""#,
            // A quoted value with spaces is one word of data here.
            r#"msg='git reset --hard'; echo "$msg""#,
            r#"msg='git reset --hard'; git commit -m "$msg""#,
            r#"x='git reset --hard'; grep -F "$x" notes.txt"#,
        ],
    );
}

/// Implementation review of PR #15: a positional change that is prefixed,
/// quoted, conditional or in a loop around the use proves nothing, so the
/// unknown command word is judged as on the base. Each row runs Git in Bash.
#[test]
fn unread_positional_changes_leave_parameters_unknown() {
    assert_both(
        "deny",
        &[
            r#"set -- ls; builtin set -- git; "$1" reset --hard"#,
            r#"set -- ls; command set -- git; "$1" reset --hard"#,
            r#"set -- ls; \set -- git; "$1" reset --hard"#,
            r#"set -- ls; 'set' -- git; "$1" reset --hard"#,
            r#"set -- ls; X=1 set -- git; "$1" reset --hard"#,
            r#"set -- ls; >/dev/null set -- git; "$1" reset --hard"#,
            r#"set -- ls; command eval "set -- git"; "$1" reset --hard"#,
            r#"set -- ls; builtin eval "set -- git"; "$1" reset --hard"#,
            r#"set -- ls; builtin source ./x; "$1" reset --hard"#,
            r#"set -- git; [ -n "$Y" ] && set -- ls; "$1" reset --hard"#,
            r#"set -- git; if [ -n "$Y" ]; then set -- ls; fi; "$1" reset --hard"#,
            r#"set -- git; case "$Y" in a) set -- ls;; esac; "$1" reset --hard"#,
            r#"set -- git; while false; do set -- ls; done; "$1" reset --hard"#,
            r#"set -- git; for i in $Y; do set -- ls; done; "$1" reset --hard"#,
            r#"set -- x git; [ -n "$Y" ] && shift; "$2" reset --hard"#,
            r#"set -- x x git; for i in 1 2; do shift; done; "$1" reset --hard"#,
            r#"set -- ls git; for i in 1 2; do "$1" reset --hard; shift; done"#,
            r#"set -- ls; for i in 1 2; do "$1" reset --hard; set -- git; done"#,
        ],
    );
    assert_both("allow", &[r#"set -- ls; for i in 1 2; do "$1" -la; done"#]);
}

/// Review round 3 of PR #15: whatever the positional proof gets wrong, the
/// reading that leaves positional parameters as written is judged too, so
/// the base's denial of an unknown command word stays. Each row runs Git in
/// the shell named.
#[test]
fn positional_proof_never_removes_a_base_denial() {
    assert_both(
        "deny",
        &[
            // Redirections and line continuations among `set` words
            // (bash, dash, zsh).
            r#"set -- >/dev/null git; "$1" reset --hard"#,
            r#"set -- 2>/dev/null git; "$1" reset --hard"#,
            r#"set -- ls 2>/dev/null git; "$2" reset --hard"#,
            r#"set -- ls 3>&1 git; "$2" reset --hard"#,
            "set -- \\\n git; \"$1\" reset --hard",
            "set -- ls \\\n git; \"$2\" reset --hard",
            // A `set` or `shift` that is not the builtin.
            r#"set -- git; set() { :; }; set -- ls; "$1" reset --hard"#,
            r#"set -- git; function set { :; }; set -- ls; "$1" reset --hard"#,
            r#"set -- git ls; shift() { :; }; shift; "$1" reset --hard"#,
            r#"set -- git; enable -n set; set -- ls; "$1" reset --hard"#,
            "set -- git\nshopt -s expand_aliases\nalias set=:\nset -- ls\n\"$1\" reset --hard",
            "set -- git\nalias set=:\nset -- ls\n\"$1\" reset --hard",
            // Traps that change positionals (bash, zsh).
            r#"set -- ls; trap 'set -- git' ERR; false; "$1" reset --hard"#,
            r#"set -- ls; trap 'set -- git' DEBUG; "$1" reset --hard"#,
            r#"trap 'set -- git' DEBUG; set -- ls; "$1" reset --hard"#,
            r#"trap 'set -- git' ERR; set -- ls; false; "$1" reset --hard"#,
            r#"set -- x git; trap shift ERR; false; "$1" reset --hard"#,
            r#"set -- ls git; trap 'shift' ERR; false; "$1" reset --hard"#,
            // The last pipeline stage in the current shell (zsh; Bash lastpipe).
            r#"set -- ls; : | set -- git; "$1" reset --hard"#,
            r#"set -- ls git; : | shift; "$1" reset --hard"#,
            r#"set -- ls; true | { set -- git; }; "$1" reset --hard"#,
            r#"shopt -s lastpipe; set -- ls; : | set -- git; "$1" reset --hard"#,
            // Changes only zsh makes.
            r#"set -- ls; argv=(git); "$1" reset --hard"#,
            r#"set -- ls; argv[1]=git; "$1" reset --hard"#,
            r#"set -- ls; noglob set -- git; "$1" reset --hard"#,
            r#"set -- ls; nocorrect set -- git; "$1" reset --hard"#,
            // Denied as on the base: the unknown-name reading does not trust
            // the positional proof.
            r#"set -- git; set -- ls; "$1" reset --hard"#,
            r#"set -- git; { set -- ls; }; "$1" reset --hard"#,
            r#"IFS=,; set -- git reset --hard; "$*""#,
        ],
    );
}

/// Call sites from the same review: a call in a subshell, after `time` or
/// with assignment words runs the body, and `cmd="$*"` copies the joined
/// parameters.
#[test]
fn calls_in_subshells_after_time_and_with_assignments_are_judged() {
    assert_both(
        "deny",
        &[
            r#"f() { "$@"; }; (f git reset --hard)"#,
            r#"f() { "$@"; }; time f git reset --hard"#,
            r#"f() { "$@"; }; X=1 f git reset --hard"#,
            r#"f() { local cmd="$*"; $cmd; }; f git reset --hard"#,
            r#"run() { cmd="$*"; $cmd; }; run git reset --hard"#,
            // Review round 3: redirections, a quoted name, `time` with
            // assignment words.
            r#"f() { "$@"; }; >/dev/null f git reset --hard"#,
            r#"f() { "$@"; }; X=1 >/dev/null f git reset --hard"#,
            r#"f() { "$@"; }; "f" git reset --hard"#,
            r#"f() { "$@"; }; \f git reset --hard"#,
            r#"f() { "$@"; }; time X=1 f git reset --hard"#,
            r#"f() { "$@"; }; f git reset --hard 2>/dev/null"#,
        ],
    );
    assert_both(
        "allow",
        &[
            r#"f() { "$@"; }; (f ls -la)"#,
            r#"f() { "$@"; }; time f make"#,
            r#"f() { "$@"; }; X=1 f ls"#,
            r#"f() { local cmd="$*"; $cmd; }; f ls -la"#,
            r#"f() { "$@"; }; >/dev/null f make"#,
            r#"f() { "$@"; }; "f" ls"#,
            r#"f() { "$@"; }; time X=1 f make test"#,
        ],
    );
}
