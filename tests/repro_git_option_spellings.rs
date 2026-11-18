//! Hook-level regressions: a `core.git` safe pattern's flag evidence must be
//! what Git's parse-options reads, not one spelling of it.
//!
//! Git reads `-SW` as `-S -W`, `--wor` as `--worktree`, `-ein` as `-e in` and
//! a later `--no-dry-run` over an earlier `-n`. Each deny case below discarded
//! uncommitted work or untracked files in a throwaway repository with Git
//! 2.39.5 while dcg allowed it. dcg executes no command text here.

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
            "session_id": "sess-opt",
            "transcript_path": "/tmp/claude/transcript.jsonl",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "toolu_opt",
        }),
        // `turn_id` selects Codex's protocol.
        Protocol::Codex => serde_json::json!({
            "session_id": "019dd11d-b795-7261-a9cb-9b85a5dadf15",
            "turn_id": "turn-opt",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.5",
            "permission_mode": "default",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "call_opt",
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

/// Every command gets `decision` under both protocols, from the `Bash` tool
/// (POSIX dialect) and the `Shell` tool (unknown dialect).
fn assert_all(decision: &str, commands: &[&str]) {
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

#[test]
fn restore_staged_with_a_worktree_flag_git_reads_is_denied() {
    assert_all(
        "deny",
        &[
            "git restore --staged . -SW",
            "git restore --staged -SW .",
            "git restore -SW --staged .",
            "git restore --staged -qW .",
            "git restore -S -qW src",
            "git restore --staged -Ws HEAD .",
            "git restore --staged --wor .",
            "git restore --staged --worktre .",
            "git restore --staged --w .",
            "git restore -S --wo src",
            "git -C repo restore --staged . -SW",
            "git-restore --staged --wor .",
            // Already denied; kept as controls.
            "git restore -SW .",
            "git restore --staged --worktree .",
            "git restore --staged -W .",
        ],
    );
}

#[test]
fn restore_staged_alone_stays_allowed() {
    assert_all(
        "allow",
        &[
            "git restore --staged .",
            "git restore -S src",
            "git restore . --staged",
            "git restore --staged --no-worktree .",
            "git restore --staged -sHEAD .",
            "git restore --staged -sWIP .",
            "git restore --staged --source=HEAD src",
        ],
    );
}

#[test]
fn branch_creation_with_force_is_denied() {
    assert_all(
        "deny",
        &[
            "git checkout -b x -f",
            "git checkout -b x --force",
            "git checkout -b x --forc",
            "git checkout -b x --f",
            "git checkout -b x -qf",
            "git checkout -b x origin/main -f",
            "git checkout --orphan x -f",
            "git checkout --orphan x --fo",
            // Already denied; kept as controls.
            "git checkout -fb x",
            "git checkout --forc .",
        ],
    );
}

#[test]
fn branch_creation_without_force_stays_allowed() {
    assert_all(
        "allow",
        &[
            "git checkout -b feature",
            "git checkout -b feature origin/main",
            "git checkout -b fix-f",
            "git checkout -b feature/force",
            "git checkout -b x --no-force",
            "git checkout -b x -f --no-force",
            "git checkout -b x --track origin/x",
            "git checkout -b x --no-track origin/x",
            "git checkout --orphan gh-pages",
        ],
    );
}

#[test]
fn clean_dry_run_that_git_does_not_read_is_denied() {
    assert_all(
        "deny",
        &[
            "git clean -f -ein",
            "git clean -fein",
            "git clean -f -e -n",
            "git clean -n --no-dry-run -f",
            "git clean -fn --no-d",
            "git clean -fn --no-dry-ru",
            "git clean -Xf",
            "git clean -dXf",
            "git clean -n --no-dry-run -Xf",
            "git clean -n -Xdf --no-dry-run",
            // Already denied; kept as controls.
            "git clean --forc -d",
            "git clean -fdx",
        ],
    );
}

#[test]
fn clean_dry_run_stays_allowed() {
    assert_all(
        "allow",
        &[
            "git clean -n",
            "git clean -nd",
            "git clean -fn",
            "git clean -nf",
            "git clean -f --dry-run",
            "git clean -n -e foo",
            "git clean -dn -e '*.f'",
            "git clean -f -e foo -n",
            "git clean -X -n",
            "git clean -nX",
            "git clean -Xn",
            "git clean -Xnf",
            "git clean -Xn -f",
        ],
    );
}

#[test]
fn rm_and_update_ref_spellings_git_reads_are_denied() {
    assert_all(
        "deny",
        &[
            "git rm -f --cached --no-cached t",
            "git rm -f --dry-run --no-dry-run t",
            "git rm -fn --no-dry-run t",
            "git rm -fn --no-d t",
            "git update-ref -dmreason refs/heads/x",
            // Already denied; kept as controls.
            "git rm -f t",
            "git update-ref -d refs/heads/x",
        ],
    );
    assert_all(
        "allow",
        &[
            "git rm --cached t",
            "git rm -f --cached t",
            "git rm -n -f t",
            "git rm -r --cached .",
            "git update-ref refs/heads/x HEAD",
            "git update-ref -m reason refs/heads/x HEAD",
            "git update-ref -md refs/heads/x HEAD",
        ],
    );
}

#[test]
fn windows_spellings_are_read_the_same_way() {
    let mut wrong = Vec::new();
    for (tool, command, decision) in [
        ("PowerShell", r"git restore --staged . -SW", "deny"),
        (
            "PowerShell",
            r"& 'C:\Program Files\Git\cmd\git.exe' restore --staged --wor .",
            "deny",
        ),
        ("PowerShell", r"C:\x\git.exe checkout -b x -f", "deny"),
        ("PowerShell", r"git.exe clean -f -ein", "deny"),
        ("Shell", r"C:\x\git restore --staged . -SW", "deny"),
        // `--%` is PowerShell's stop-parsing token: the rest reaches Git as
        // plain words. The Shell label may be PowerShell; Bash's Git refuses
        // `--%`, so denying there costs nothing.
        ("Shell", r"git --% restore --staged . -SW", "deny"),
        ("Shell", r"git --% checkout -b x -f", "deny"),
        ("PowerShell", r"git --% restore --staged . -SW", "deny"),
        ("PowerShell", r"git --% checkout -b x -f", "deny"),
        ("Shell", r"git --% restore --staged .", "allow"),
        ("Shell", r"git --% checkout -b feature", "allow"),
        (
            "PowerShell",
            r"& 'C:\Program Files\Git\cmd\git.exe' restore --staged .",
            "allow",
        ),
        (
            "PowerShell",
            r"git.exe checkout -b feature origin/main",
            "allow",
        ),
        ("PowerShell", r"git clean -nd", "allow"),
    ] {
        for protocol in [Protocol::Claude, Protocol::Codex] {
            let actual = hook_decision(protocol, command, tool);
            if actual != decision {
                wrong.push(format!(
                    "{tool} {protocol:?} {actual} (want {decision}): {command}"
                ));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
