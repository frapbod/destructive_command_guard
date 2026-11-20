//! A POSIX shell reads a program from the text piped into it, from cmd and
//! PowerShell too: Git for Windows puts `sh` and `bash` on PATH, and
//! `bash.exe` in System32 is WSL's. The PowerShell reading never read that
//! text, so `echo 'git reset --hard' | sh` passed there, and under Unknown
//! (a Codex `Bash` payload on Windows) only the POSIX reading saw it.
//! PowerShell computes the text first: `echo "git reset --hard $PWD" | sh`
//! hands sh `git reset --hard <path>`, and `echo a b` writes `a` and `b` on
//! two lines. Measured with pwsh 7.5 piping into /bin/sh and /bin/bash
//! (`scripts/shell-truth`, fake git).

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
            "session_id": "sess-ps-pipe-posix",
            "transcript_path": "/tmp/claude/transcript.jsonl",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "toolu_ps_pipe_posix",
        }),
        // `turn_id` selects Codex's protocol.
        Protocol::Codex => serde_json::json!({
            "session_id": "019dd11d-b795-7261-a9cb-9b85a5dadf15",
            "turn_id": "turn-ps-pipe-posix",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.5",
            "permission_mode": "default",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "call_ps_pipe_posix",
        }),
    }
}

/// What the agent reads: "allow" for empty stdout, else the decision.
/// `config` is the text of a dcg config file for the run, if any.
fn hook_decision(
    protocol: Protocol,
    tool_name: &str,
    command: &str,
    config: Option<&str>,
) -> String {
    let temp = tempfile::tempdir().expect("temp dir");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let payload = payload(protocol, tool_name, command, temp.path()).to_string();
    let mut process = Command::new(dcg_binary());
    process
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
        .stderr(Stdio::piped());
    if let Some(config) = config {
        let path = temp.path().join("config.toml");
        std::fs::write(&path, config).unwrap();
        process.env("DCG_CONFIG", &path);
    }
    let mut child = process.spawn().expect("spawn dcg");
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

/// Checks each command in its dialects and in both hook formats with
/// `tool`, and reports every miss at once.
fn expect_everywhere(
    commands: &[&str],
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
            let got = hook_decision(protocol, tool, command, None);
            if got != hook_want {
                misses.push(format!("{protocol:?} {tool}: {command:?} -> {got}"));
            }
        }
    }
    misses
}

const PS: [ShellDialect; 2] = [ShellDialect::PowerShell, ShellDialect::Unknown];

/// Each of these runs `git reset --hard` in /bin/sh or /bin/bash from pwsh
/// 7.5 (the `| sh` rows ran as `| /bin/sh`; the WSL rows are read the same
/// way, not measured).
#[test]
fn text_powershell_pipes_into_a_posix_shell_is_its_program() {
    let misses = expect_everywhere(
        &[
            "echo 'git reset --hard' | sh",
            r#"echo "git reset --hard" | bash"#,
            r#"Write-Output "git reset --hard" | bash"#,
            r#""git reset --hard" | bash"#,
            "'git reset' + ' --hard' | sh",
            r#""gi$()t reset --hard" | sh"#,
            "@'\ngit reset --hard\n'@ | sh",
            r#"echo "git reset --hard" "x" | sh"#,
            "echo 'git reset --hard' | /bin/sh",
            "echo 'git reset --hard' | sh -s",
            r#"echo 'git reset --hard' | C:\Windows\System32\bash.exe"#,
            "echo 'git reset --hard' | wsl",
            "echo 'git reset --hard' | wsl.exe -d Ubuntu",
            "echo 'git reset --hard' | wsl -e sh",
            "echo 'git reset --hard' | wsl -- bash -s",
        ],
        &PS,
        "PowerShell",
        EvaluationDecision::Deny,
    );
    assert!(misses.is_empty(), "misses:\n{}", misses.join("\n"));
}

/// A value PowerShell expands in the piped text is an unknown value of the
/// shell, where it lands: `$x = 'git'; "$x reset --hard" | sh` runs git,
/// and a path or any other value after `git reset --hard` is still that
/// command (pwsh 7.5).
#[test]
fn values_powershell_expands_in_the_piped_text_are_unknown_shell_text() {
    let misses = expect_everywhere(
        &[
            r#"echo "git reset --hard $PWD" | sh"#,
            r#"echo "git reset --hard $Y" | sh"#,
            r#"echo "git reset --hard $x" | bash"#,
            r#""git reset --hard $PWD" | bash"#,
            r#"$x = 'git'; "$x reset --hard" | sh"#,
            r#"echo "git reset --hard $env:USERPROFILE" | sh"#,
            r#"echo "git reset --hard $($PWD.Path)" | sh"#,
            r#"echo "$x" | sh"#,
            "$x | sh",
            r#"echo "git reset --hard $PWD" | C:\Windows\System32\bash.exe"#,
        ],
        &PS,
        "PowerShell",
        EvaluationDecision::Deny,
    );
    assert!(misses.is_empty(), "misses:\n{}", misses.join("\n"));
}

/// Kai's desktop warns on `heredoc.posix:pipeline-consumer` (a POSIX-reading
/// false alarm on PowerShell here-strings), and a Codex `Bash` payload on
/// Windows is read under Unknown. The POSIX reading of
/// `echo "git reset --hard $PWD" | sh` is only that rule, so the PowerShell
/// reading must judge the command itself.
#[test]
fn the_powershell_reading_judges_the_command_where_the_posix_rule_only_warns() {
    const WARN: &str = "[policy.rules]\n\"heredoc.posix:pipeline-consumer\" = \"warn\"\n";
    let mut misses = Vec::new();
    for command in [
        r#"echo "git reset --hard $PWD" | sh"#,
        r#"echo "git reset --hard $Y" | sh"#,
        r#"echo "git reset --hard $x" | bash"#,
        r#"$x = 'git'; "$x reset --hard" | sh"#,
    ] {
        // `runTerminalCommand` is read under Unknown on every host.
        let got = hook_decision(Protocol::Claude, "runTerminalCommand", command, Some(WARN));
        if got != "deny" {
            misses.push(format!(
                "Unknown with the desktop policy: {command:?} -> {got}"
            ));
        }
    }
    assert!(misses.is_empty(), "misses:\n{}", misses.join("\n"));
}

/// cmd's `echo` writes the rest of its line, so the piped text is that
/// line.
#[test]
fn text_cmd_pipes_into_a_posix_shell_is_its_program() {
    let misses = expect_everywhere(
        &[
            "echo git reset --hard | sh",
            "echo git reset --hard | bash.exe",
            "echo git reset --hard | wsl",
        ],
        &[ShellDialect::Cmd],
        "cmd",
        EvaluationDecision::Deny,
    );
    assert!(misses.is_empty(), "misses:\n{}", misses.join("\n"));
}

/// PowerShell writes each argument on its own line (`echo git reset --hard |
/// sh` runs `git` alone), a backslash is no escape inside its double quotes,
/// and a shell given a program of its own does not run the pipe (pwsh 7.5).
#[test]
fn harmless_text_and_consumers_stay_allowed() {
    let powershell_only = expect_everywhere(
        &[
            "echo git reset --hard | sh",
            "echo 'git reset' '--hard' | sh",
            r#"echo "ls $PWD" | sh"#,
            r#"echo "\"\$X\" reset --hard $PWD" | sh"#,
        ],
        &[ShellDialect::PowerShell],
        "PowerShell",
        EvaluationDecision::Allow,
    );
    let everywhere = expect_everywhere(
        &[
            "echo 'git status' | sh",
            "echo 'ls -la' | bash",
            "echo 'git reset --hard' | sh -c 'wc -l'",
            "echo 'git reset --hard' | wsl ls",
            "echo 'git reset --hard' | findstr git",
            "echo hi | Out-File x.txt",
        ],
        &PS,
        "PowerShell",
        EvaluationDecision::Allow,
    );
    assert!(
        powershell_only.is_empty() && everywhere.is_empty(),
        "PowerShell misses:\n{}\nmisses:\n{}",
        powershell_only.join("\n"),
        everywhere.join("\n")
    );
}
