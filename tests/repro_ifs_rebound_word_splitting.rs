//! Field splitting by a rebound `IFS`, and the #628 hook crash, under both
//! hook protocols.
//!
//! An unquoted `$IFS` expansion yields only characters of `IFS`, and field
//! splitting treats every one of them as a separator. So after `IFS=x`,
//! `git${IFS}reset${IFS}--hard` runs `git reset --hard` (Bash 5.2:
//! `IFS=x; printf '[%s]' a${IFS}b` prints `[a][b]`). 0.16.0 only expanded
//! `$IFS` when the command never assigned it, and allowed every command
//! below that assigns it.
//!
//! The #628 shapes crashed the 0.16.0 hook with a stack overflow and no
//! output, which Claude Code and Codex both treat as a non-blocking error:
//! the command ran. Each case runs the built binary as each agent does and
//! asserts a verdict, never a crash.

// `${IFS:0:1}` in the shell commands below is not a format argument.
#![allow(clippy::literal_string_with_formatting_args)]

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
            "session_id": "sess-ifs",
            "transcript_path": "/tmp/claude/transcript.jsonl",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_use_id": "toolu_ifs",
        }),
        // `turn_id` selects Codex's protocol.
        Protocol::Codex => serde_json::json!({
            "session_id": "019dd11d-b795-7261-a9cb-9b85a5dadf15",
            "turn_id": "turn-ifs",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.5",
            "permission_mode": "default",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_use_id": "call_ifs",
        }),
    }
}

/// What the agent reads: "allow" for empty stdout, else the decision.
/// Panics unless the hook exited 0 with no stack overflow.
fn hook_decision(protocol: Protocol, command: &str) -> String {
    hook_verdict(protocol, command).0
}

/// The decision, as [`hook_decision`], and the reason the hook gave.
fn hook_verdict(protocol: Protocol, command: &str) -> (String, String) {
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
    assert!(
        !stderr.contains("overflowed its stack"),
        "{protocol:?}: the hook overflowed its stack on {command:?}\nstderr: {stderr}"
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{protocol:?}: the hook must exit with a verdict, not die ({:?}) on {command:?}\nstderr: {stderr}",
        out.status
    );
    if stdout.trim().is_empty() {
        return ("allow".to_string(), String::new());
    }
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("{protocol:?}: stdout is not one JSON value ({e}): {stdout}"));
    let output = &parsed["hookSpecificOutput"];
    (
        output["permissionDecision"]
            .as_str()
            .unwrap_or("<missing>")
            .to_string(),
        output["permissionDecisionReason"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    )
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
fn rebound_ifs_splitting_denies_under_both_protocols() {
    assert_both(
        "deny",
        &[
            "IFS=x; git${IFS}reset${IFS}--hard",
            "IFS=x;git${IFS}reset${IFS}--hard",
            "IFS=x; git$IFS'reset'$IFS--hard",
            "IFS=,; git${IFS}reset${IFS}--hard",
            "IFS=$'\\n'; git${IFS}reset${IFS}--hard",
            "IFS=\"$CUSTOM\"; git${IFS}reset${IFS}--hard",
            // A prefix assignment does not change this command's expansion:
            // the shell's own IFS (default whitespace) splits it.
            "IFS=x git${IFS}reset${IFS}--hard",
            "export IFS=x; git${IFS}reset${IFS}--hard",
            "IFS=x; IFS=y; git${IFS}reset${IFS}--hard",
            "IFS=''; IFS=x; git${IFS}reset${IFS}--hard",
            "IFS=x\ngit${IFS}reset${IFS}--hard",
            "(IFS=x; git${IFS}reset${IFS}--hard)",
            "if true; then IFS=x; git${IFS}reset${IFS}--hard; fi",
            "IFS=x; true | git${IFS}reset${IFS}--hard",
            "IFS=x; git${IFS}clean${IFS}-fdx",
            "IFS=x; rm${IFS}-rf${IFS}~",
            "bash -c 'IFS=x; git${IFS}reset${IFS}--hard'",
            // Derived values are characters of IFS too.
            "git${IFS:0:1}reset${IFS:0:1}--hard",
            "IFS=x; git${IFS::1}reset${IFS::1}--hard",
            "git${IFS%??}reset${IFS%??}--hard",
            // Empty or unset IFS joins, and a quoted literal value is inserted.
            "IFS=; gi${IFS}t reset --hard",
            "IFS=t; \"gi${IFS}\" reset --hard",
            // Quote characters that do not open a quote must not hide a use.
            "echo \"'\"; git${IFS}reset${IFS}--hard",
            "echo 'a\\'; git${IFS}reset${IFS}--hard",
            "echo hi # it's\ngit${IFS}reset${IFS}--hard",
            "cat <<EOF\nit's\nEOF\ngit${IFS}reset${IFS}--hard",
            // `${IFS[0]}`, `${IFS[@]}` and `${IFS[*]}` are the value.
            "git${IFS[0]}reset${IFS[0]}--hard",
            "git${IFS[@]}reset${IFS[@]}--hard",
            "git${IFS[*]}reset${IFS[*]}--hard",
            "IFS=x; git${IFS[0]}reset${IFS[0]}--hard",
            "git${IFS[0]:0:1}reset${IFS[0]:0:1}--hard",
            // Case changes, transforms and substitutions keep IFS characters.
            "git${IFS^^}reset${IFS^^}--hard",
            "git${IFS,}reset${IFS,}--hard",
            "git${IFS~~}reset${IFS~~}--hard",
            "git${IFS@U}reset${IFS@U}--hard",
            "IFS=,; git${IFS^}reset${IFS^}--hard",
            "git${IFS/q/z}reset${IFS/q/z}--hard",
            "git${IFS//q/z}reset${IFS//q/z}--hard",
            // One use empty and another not, in the same command.
            "gi${IFS:9}t${IFS:0:1}reset${IFS:0:1}--hard",
            "gi${IFS#???}t${IFS::1}reset${IFS::1}--hard",
            "r${IFS:9}m${IFS:0:1}-rf${IFS:0:1}~",
            // A quoted slice of a literal value is that slice.
            "IFS=xt; \"gi${IFS:1:1}\" reset --hard",
            // `+=` appends to the value in force.
            "IFS+=t; \"gi${IFS:3}\" reset --hard",
            // After `unset IFS` or a valueless local in a function, `+=`
            // starts from nothing and `${IFS-word}` is the word.
            "unset IFS; IFS+=g; \"${IFS}it\" reset --hard",
            "unset -v IFS; IFS+=g; \"${IFS}it\" reset --hard",
            "IFS=x; unset IFS; IFS+=g; \"${IFS}it\" reset --hard",
            "unset IFS; IFS+=gi; \"${IFS}t\" reset --hard",
            "f(){ local IFS; IFS+=g; \"${IFS}it\" reset --hard; }; f",
            "f(){ declare IFS; IFS+=g; \"${IFS}it\" reset --hard; }; f",
            "unset IFS; IFS+=xt; \"gi${IFS:1}\" reset --hard",
            "unset IFS; \"gi${IFS:-t}\" reset --hard",
            "unset IFS; \"gi${IFS-t}\" reset --hard",
            // A pattern that matches the empty value replaces it.
            "IFS=; gi${IFS//*/t} reset --hard",
            "IFS=; gi${IFS/*/t} reset --hard",
            "IFS=; \"gi${IFS//*/t}\" reset --hard",
            // `$IFS` is element 0 of the array.
            "IFS=(g x); \"${IFS}it\" reset --hard",
            "IFS=(g); \"${IFS}it\" reset --hard",
            "declare -a IFS=(g); \"${IFS}it\" reset --hard",
            "IFS=g; IFS+=(x); \"${IFS}it\" reset --hard",
            "IFS[0]=g; \"${IFS}it\" reset --hard",
            // A declaration that makes no unset local leaves the value.
            "f(){ IFS=g; declare -p IFS; \"${IFS}it\" reset --hard; }; f",
            "f(){ IFS=g; declare -p IFS >/dev/null; \"${IFS}it\" reset --hard; }; f",
            "f(){ IFS=g; typeset -p IFS >/dev/null; \"${IFS}it\" reset --hard; }; f",
            "f(){ IFS=g; declare -f IFS >/dev/null; \"${IFS}it\" reset --hard; }; f",
            "f(){ IFS=g; declare -F IFS >/dev/null; \"${IFS}it\" reset --hard; }; f",
            "f(){ IFS=g; local -p IFS >/dev/null; \"${IFS}it\" reset --hard; }; f",
            "f(){ IFS=g; declare -I IFS; \"${IFS}it\" reset --hard; }; f",
            "f(){ IFS=g; local -I IFS; \"${IFS}it\" reset --hard; }; f",
            "shopt -s localvar_inherit; f(){ IFS=g; local IFS; \"${IFS}it\" reset --hard; }; f",
            "f(){ IFS=g; local IFS=$IFS; \"${IFS}it\" reset --hard; }; f",
            // A write need not happen where it is written, or at all.
            "IFS=g; (unset IFS); \"${IFS}it\" reset --hard",
            "IFS=g; : $(unset IFS); \"${IFS}it\" reset --hard",
            "IFS=g; true | unset IFS; \"${IFS}it\" reset --hard",
            "IFS=g; IFS=x true; \"${IFS}it\" reset --hard",
            "IFS=g; IFS=x \"${IFS}it\" reset --hard",
            "IFS=g; (IFS=x); \"${IFS}it\" reset --hard",
            "IFS=g; : $(IFS=x); \"${IFS}it\" reset --hard",
            "IFS=g; : <(IFS=x); \"${IFS}it\" reset --hard",
            "IFS=g; true | { IFS=x; }; \"${IFS}it\" reset --hard",
            "IFS=g; true | IFS=x; \"${IFS}it\" reset --hard",
            "IFS=g; IFS=x & wait; \"${IFS}it\" reset --hard",
            "IFS=g; { IFS=x; } & wait; \"${IFS}it\" reset --hard",
            "IFS=g; f(){ IFS=x; }; \"${IFS}it\" reset --hard",
            "IFS=g; if false; then IFS=x; fi; \"${IFS}it\" reset --hard",
            "IFS=g; false && IFS=x; \"${IFS}it\" reset --hard",
            "IFS=g; case a in b) IFS=x;; esac; \"${IFS}it\" reset --hard",
            "for i in 1 2; do \"${IFS}it\" reset --hard; IFS=g; done",
            "unset IFS; (IFS=x); IFS+=g; \"${IFS}it\" reset --hard",
            "f(){ IFS+=g; }; unset IFS; f; \"${IFS}it\" reset --hard",
            // A reading write applies once for each place it is written, and
            // any number of times in a loop or a function body.
            "unset IFS; IFS+=-; IFS+=-; git reset \"${IFS}hard\"",
            "IFS=; IFS+=-; IFS+=-; git reset \"${IFS}hard\"",
            "IFS[0]=; IFS[0]+=-; IFS[0]+=-; git reset \"${IFS}hard\"",
            "bash -c 'unset IFS; IFS+=-; IFS+=-; git reset \"${IFS}hard\"'",
            "IFS=; for i in 1 2; do IFS+=-; done; git reset \"${IFS}hard\"",
            "f(){ IFS+=-; }; IFS=; f; f; git reset \"${IFS}hard\"",
            "IFS=; while [ ${#IFS} -lt 2 ]; do IFS+=-; done; git reset \"${IFS}hard\"",
            "IFS=; until [ ${#IFS} -ge 2 ]; do IFS+=-; done; git reset \"${IFS}hard\"",
            // Bash runs the lines before a syntax error; without a clean
            // parse a use that needs a value cannot be checked.
            "IFS=g; \"${IFS}it\" reset --hard\n)",
            "IFS=g; \"${IFS}it\" reset --hard\n;;",
            "unset IFS; IFS+=g; \"${IFS}it\" reset --hard\n)",
            "IFS=x; git${IFS}reset${IFS}--hard\n)",
            // More combinations than dcg checks.
            "echo${IFS:0}a${IFS:1}b${IFS:2}c${IFS:3}d${IFS:4}e${IFS:5}f",
        ],
    );
}

#[test]
fn harmless_ifs_uses_stay_allowed_under_both_protocols() {
    assert_both(
        "allow",
        &[
            "IFS=x; echo${IFS}hi",
            "IFS=x; git${IFS}status",
            "IFS=x; git${IFS}log${IFS}--oneline",
            "IFS=, read -r a b <<< \"1,2\"; echo \"$a\"",
            "while IFS= read -r line; do echo \"$line\"; done < file.txt",
            "IFS=x; echo \"git${IFS}reset${IFS}--hard\"",
            "IFS=x; printf '%s\\n' git${IFS}reset${IFS}--hard",
            "IFS=x; grep '$IFS' file.txt",
            "IFS=$'\\n'; for f in $(ls); do echo \"$f\"; done",
            "OLDIFS=$IFS; IFS=,; set -- $csv; IFS=$OLDIFS; echo \"$1\"",
            "echo${IFS}hello",
            "ls${IFS}-la",
            "git status",
            "printf '%s' \"$IFS\" | od -c",
            "echo \"${IFS@Q}\" ${#IFS} ${IFS:+set}",
            "IFS=x; echo ${IFS^^}",
            "echo \"$IFS\" \"$IFS\" \"$IFS\"",
            "git${IFS[0]}status",
            "git${IFS^^}log${IFS^^}--oneline",
            "echo a$IFS b$IFS c$IFS d$IFS e$IFS f$IFS g",
            "declare IFS; IFS+=g; \"${IFS}it\" reset --hard",
            "f(){ local IFS=,; echo \"$*\"; }; f a b",
            "old=$IFS; unset IFS; read -r a b; IFS=$old; echo \"$a\"",
            "IFS=x true; \"${IFS}it\" reset --hard",
            "old=$IFS; IFS=,; echo \"${arr[*]}\"; IFS=$old",
            "while IFS=: read -r a b; do echo \"$a\"; done < /etc/passwd",
            "f(){ declare -p IFS; }; f",
            // Counted appends stay within the value cap.
            "IFS+=,; echo \"$IFS\"",
            "IFS=; IFS+=,; IFS+=,; echo \"$IFS\"",
            "for i in 1 2; do IFS=,; echo \"$IFS\"; done",
        ],
    );
}

/// Thousands of distinct IFS writes and uses pass the value and view caps
/// early: the command is denied as unverified, quickly, instead of
/// enumerating every value. A release build answers each in under 0.1 s;
/// the bound leaves room for a loaded test machine.
#[test]
fn many_ifs_writes_and_uses_stay_bounded_under_both_protocols() {
    let writes = (0..1_500)
        .map(|i| format!("IFS=v{i}; IFS+=a{i}; "))
        .collect::<Vec<_>>()
        .concat();
    let uses = (0..1_500)
        .map(|i| format!("\"${{IFS:{i}}}x\" "))
        .collect::<Vec<_>>()
        .concat();
    let commands = [
        format!("{writes}echo {uses}"),
        format!("{writes}echo \"${{IFS}}\""),
        format!("echo {uses}"),
    ];
    for command in &commands {
        assert!(command.len() < 64 * 1024, "{}", command.len());
        for protocol in [Protocol::Claude, Protocol::Codex] {
            let started = std::time::Instant::now();
            let decision = hook_decision(protocol, command);
            let elapsed = started.elapsed();
            assert_eq!(decision, "deny", "{protocol:?}: {}", &command[..40]);
            assert!(
                elapsed < std::time::Duration::from_secs(2),
                "{protocol:?}: took {elapsed:?}"
            );
        }
    }
}

/// Glob patterns in IFS operators that made a recursive, backtracking
/// matcher overflow the 1 MiB Windows main-thread stack (one frame per `*`)
/// or run for minutes, past Codex's 600 s hook timeout. Either way the
/// agent ran the command. Each must get the reset's own denial, quickly.
#[test]
fn ifs_glob_patterns_stay_bounded_under_both_protocols() {
    let stars = "*".repeat(20_000);
    let backtracking = format!(
        "IFS={}; echo ${{IFS#{}b}}; git reset --hard",
        "a".repeat(44),
        "*a".repeat(16)
    );
    assert_eq!(backtracking.len(), 113);
    let commands = [
        format!("echo ${{IFS#{stars}}}; git reset --hard"),
        format!("echo ${{IFS%%{stars}}}; git reset --hard"),
        format!("echo ${{IFS//{stars}/x}}; git reset --hard"),
        backtracking,
    ];
    for command in &commands {
        for protocol in [Protocol::Claude, Protocol::Codex] {
            let started = std::time::Instant::now();
            let (decision, reason) = hook_verdict(protocol, command);
            let elapsed = started.elapsed();
            assert_eq!(decision, "deny", "{protocol:?}: {}", &command[..40]);
            assert!(
                reason.contains("reset-hard") || reason.contains("reset --hard"),
                "{protocol:?}: the reset's own rule must deny, not a time budget: {reason}"
            );
            assert!(
                elapsed < std::time::Duration::from_secs(10),
                "{protocol:?}: took {elapsed:?}"
            );
        }
    }
}

/// The #628 shapes under Codex as well as Claude Code. Each crashed 0.16.0.
#[test]
fn heredoc_recursion_shapes_get_a_verdict_under_both_protocols() {
    assert_both(
        "allow",
        &[
            "P=x; $P; python3 - <<'EOF'\nprint('SAFE')\nEOF",
            "echo hi ); python3 - <<'EOF'\nprint(1)\nEOF",
            "{ echo hi; python3 - <<'EOF'\nprint(1)\nEOF",
        ],
    );
    assert_both(
        "deny",
        &[
            "P=x; $P; python3 - <<'EOF'\nimport shutil\nshutil.rmtree('/Users/x/proj')\nEOF",
            "{ echo hi; ruby - <<'RB'\nrequire 'fileutils'; FileUtils.rm_rf('/Users/x/proj')\nRB",
        ],
    );
    // Some shapes have no harmless verdict to pin, only "never crash".
    for command in [
        "; node - <<'JS'\nconsole.log(1)\nJS",
        "{ echo hi; ruby - <<'RB'\nputs 1\nRB",
    ] {
        for protocol in [Protocol::Claude, Protocol::Codex] {
            hook_decision(protocol, command);
        }
    }
}
