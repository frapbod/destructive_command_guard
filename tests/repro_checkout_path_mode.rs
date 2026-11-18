//! Hook-level regressions: `git checkout` restores paths whenever paths
//! follow `--`, two operands are given or `--pathspec-from-file` names them,
//! with any options first.
//!
//! Each deny case below overwrote an uncommitted edit in a throwaway
//! repository with Git 2.39.5 while dcg allowed it (`git checkout -q other
//! -- f` read two words before `--`, where `checkout-ref-discard` took one).
//! dcg executes no command text here.

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
            "session_id": "sess-co",
            "transcript_path": "/tmp/claude/transcript.jsonl",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "toolu_co",
        }),
        // `turn_id` selects Codex's protocol.
        Protocol::Codex => serde_json::json!({
            "session_id": "019dd11d-b795-7261-a9cb-9b85a5dadf15",
            "turn_id": "turn-co",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.5",
            "permission_mode": "default",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "call_co",
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
fn checkout_paths_after_options_are_denied() {
    assert_all(
        "deny",
        &[
            "git checkout -q other -- f",
            "git checkout --quiet other -- f",
            "git checkout --no-overlay other -- f",
            "git checkout --recurse-submodules other -- f",
            "git checkout --conflict=merge other -- f",
            "git checkout --conflict merge other -- f",
            "git checkout -q -q -- f",
            "git checkout --quiet --progress -- f",
            "git -C repo checkout -q other -- f",
            "git-checkout -q other -- f",
            "git checkout other f",
            "git checkout -q other f",
            "git checkout other --pathspec-from-file=list",
            "git checkout --pathspec-from-file=list other",
            "git checkout -q other --pathspec-from-file list",
            // `-m` is `--merge` here, not a commit message flag.
            "git checkout -m -- f",
            "git checkout -m other f",
            "git checkout -qm other f",
            "git checkout -q -m other f",
            "git checkout other -m f",
            "git restore -m f",
            "git restore -ms other f",
            // Global options written as `--name=value` or quoted.
            "git --git-dir=.git checkout -m other f",
            "git --work-tree=. checkout -m other f",
            "git --git-dir=.git checkout -qm other f",
            "git --git-dir=.git checkout -m -- f",
            "git --git-dir=.git checkout other -m f",
            "git --namespace=x checkout -m other f",
            "git --exec-path=/x checkout -m other f",
            "git --config-env=a=B checkout -m other f",
            "git --bogus=x checkout -m other f",
            "git -C . --git-dir=.git checkout -m other f",
            "git \"--git-dir=.git\" checkout -m other f",
            // `git show <ref>:<path>` redirected onto `<path>`, options first.
            "git show --quiet other:f > f",
            "git show -m other:f > f",
            // Already denied; kept as controls.
            "git checkout other -- f",
            "git checkout -- f",
            "git checkout -q -- f",
        ],
    );
}

#[test]
fn branch_switches_and_creation_stay_allowed() {
    assert_all(
        "allow",
        &[
            "git checkout -b x origin/main",
            "git checkout -q main",
            "git checkout main",
            "git checkout -q -b x origin/main",
            "git checkout --detach HEAD~1",
            "git checkout -b feature",
            "git checkout -q main --",
            "git checkout --orphan gh-pages",
            "git checkout --track origin/feature",
            "git checkout -q --recurse-submodules main",
            "git checkout --conflict merge main",
            "git checkout main 2>/dev/null",
            "git checkout -",
            "git checkout -m main",
            "git switch -m main",
            "git commit -m \"fix checkout other f\"",
            "git commit -m \"git checkout other -- f\"",
            "git --git-dir=.git checkout -m main",
            "git --git-dir=.git commit -m \"git checkout other -- f\"",
            "git show other:f > g",
            "git show -m HEAD",
        ],
    );
}
