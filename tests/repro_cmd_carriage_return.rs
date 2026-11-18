//! cmd.exe ignores CR bytes in command-line text before parsing it.

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
            "session_id": "sess-ps-quote",
            "transcript_path": "/tmp/claude/transcript.jsonl",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "toolu_ps_quote",
        }),
        // `turn_id` selects Codex's protocol.
        Protocol::Codex => serde_json::json!({
            "session_id": "019dd11d-b795-7261-a9cb-9b85a5dadf15",
            "turn_id": "turn-ps-quote",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.5",
            "permission_mode": "default",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "call_ps_quote",
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

#[test]
fn direct_cmd_and_nested_payloads() {
    for command in [
        "gi\rt reset --hard",
        "echo a&gi\rt reset --hard",
        "gi\rt status",
    ] {
        let expected = if command.ends_with("status") {
            EvaluationDecision::Allow
        } else {
            EvaluationDecision::Deny
        };
        for dialect in [ShellDialect::Cmd, ShellDialect::Unknown] {
            assert_eq!(
                decision_in(command, dialect),
                expected,
                "{dialect:?}: {command:?}"
            );
        }
    }
    for command in [
        "cmd /c \"gi\rt reset --hard\"",
        "cmd.exe /d /k \"echo a&gi\rt reset --hard\"",
        "cmd /c \"g^\ri^t reset --hard\"",
        "cmd /c \"echo ok&gi\rt reset --hard\"",
    ] {
        for dialect in [
            ShellDialect::Cmd,
            ShellDialect::Unknown,
            ShellDialect::PowerShell,
            ShellDialect::Posix,
        ] {
            assert_eq!(
                decision_in(command, dialect),
                EvaluationDecision::Deny,
                "{dialect:?}: {command:?}"
            );
        }
    }
}

#[test]
fn cmd_hook_protocols() {
    for protocol in [Protocol::Claude, Protocol::Codex] {
        for command in [
            "gi\rt reset --hard",
            "echo a&gi\rt reset --hard",
            "cmd /c \"gi\rt reset --hard\"",
        ] {
            assert_eq!(
                hook_decision(protocol, "cmd", command),
                "deny",
                "{protocol:?}: {command:?}"
            );
        }
        for command in ["gi\rt status", "echo \"gi\rt reset --hard\""] {
            assert_eq!(
                hook_decision(protocol, "cmd", command),
                "allow",
                "{protocol:?}: {command:?}"
            );
        }
    }
}

#[test]
fn cmd_payload_hooks_in_other_shells_and_safe_data() {
    for protocol in [Protocol::Claude, Protocol::Codex] {
        for tool in ["Bash", "PowerShell", "cmd"] {
            for command in [
                "cmd /c \"gi\rt reset --hard\"",
                "cmd /k \"echo a&gi\rt reset --hard\"",
            ] {
                assert_eq!(
                    hook_decision(protocol, tool, command),
                    "deny",
                    "{protocol:?} {tool}: {command:?}"
                );
            }
            for command in [
                "cmd /c \"gi\rt status\"",
                "cmd /c \"echo gi\rt reset --hard\"",
            ] {
                assert_eq!(
                    hook_decision(protocol, tool, command),
                    "allow",
                    "{protocol:?} {tool}: {command:?}"
                );
            }
        }
    }
    for dialect in [ShellDialect::Posix, ShellDialect::PowerShell] {
        assert_eq!(
            decision_in("echo 'gi\rt reset --hard'", dialect),
            EvaluationDecision::Allow
        );
    }
}

/// A POSIX shell keeps a CR inside an unquoted word, so `cmd.exe /c
/// gi<CR>t reset --hard` from bash (WSL) hands cmd `gi<CR>t`, which cmd
/// reads as `git`. The same holds for a PowerShell host: it ends a line at
/// the CR. Unquoted, the words must keep their CR for those readings.
#[test]
fn unquoted_posix_words_keep_cr_for_windows_launchers() {
    for command in [
        "cmd.exe /c gi\rt reset --hard",
        "cmd.exe /d /c gi\rt reset --hard",
        "cmd.exe /c gi\rt\\ reset\\ --hard",
        "pwsh -Command echo a\rgit reset --hard",
    ] {
        for dialect in [ShellDialect::Posix, ShellDialect::Unknown] {
            assert_eq!(
                decision_in(command, dialect),
                EvaluationDecision::Deny,
                "{dialect:?}: {command:?}"
            );
        }
        for protocol in [Protocol::Claude, Protocol::Codex] {
            assert_eq!(
                hook_decision(protocol, "Bash", command),
                "deny",
                "{protocol:?}: {command:?}"
            );
        }
    }
    for command in [
        "cmd.exe /c gi\rt status",
        "cmd.exe /c echo gi\rt reset --hard",
        "echo gi\rt reset --hard",
    ] {
        for dialect in [ShellDialect::Posix, ShellDialect::Unknown] {
            assert_eq!(
                decision_in(command, dialect),
                EvaluationDecision::Allow,
                "{dialect:?}: {command:?}"
            );
        }
        for protocol in [Protocol::Claude, Protocol::Codex] {
            assert_eq!(
                hook_decision(protocol, "Bash", command),
                "allow",
                "{protocol:?}: {command:?}"
            );
        }
    }
}

/// `Start-Process cmd -ArgumentList '/c gi<CR>t reset --hard'` runs cmd with
/// that command line, and cmd removes the CR. A comma list runs the same
/// line: Start-Process joins it with spaces.
#[test]
fn start_process_cmd_argument_lists_with_cr() {
    for command in [
        "Start-Process cmd -ArgumentList '/c gi\rt reset --hard'",
        "Start-Process -FilePath cmd.exe -ArgumentList '/c gi\rt reset --hard' -Wait",
        "Start-Process cmd -ArgumentList '/c', 'gi\rt reset --hard'",
        "Start-Process cmd -ArgumentList '/c', 'git reset --hard'",
        "Start-Process cmd -ArgumentList @(\"/c\", \"gi\rt reset --hard\")",
    ] {
        for dialect in [ShellDialect::PowerShell, ShellDialect::Unknown] {
            assert_eq!(
                decision_in(command, dialect),
                EvaluationDecision::Deny,
                "{dialect:?}: {command:?}"
            );
        }
        for protocol in [Protocol::Claude, Protocol::Codex] {
            for tool in ["PowerShell", "Bash"] {
                assert_eq!(
                    hook_decision(protocol, tool, command),
                    "deny",
                    "{protocol:?} {tool}: {command:?}"
                );
            }
        }
    }
    for command in [
        "Start-Process cmd -ArgumentList '/c gi\rt status'",
        "Start-Process cmd -ArgumentList '/c', 'gi\rt status'",
        "Start-Process cmd -ArgumentList '/c', 'echo gi\rt reset --hard'",
    ] {
        for dialect in [ShellDialect::PowerShell, ShellDialect::Unknown] {
            assert_eq!(
                decision_in(command, dialect),
                EvaluationDecision::Allow,
                "{dialect:?}: {command:?}"
            );
        }
        for protocol in [Protocol::Claude, Protocol::Codex] {
            for tool in ["PowerShell", "Bash"] {
                assert_eq!(
                    hook_decision(protocol, tool, command),
                    "allow",
                    "{protocol:?} {tool}: {command:?}"
                );
            }
        }
    }
}

/// The line Start-Process rebuilds is the target's own command line. For
/// cmd it is read as cmd reads it: `&` is cmd's operator, CR is removed and
/// `C:\Windows\System32\cmd.exe` stays a path to cmd. The argument list is
/// one grammar: blanks before a comma do not end it, and an element after a
/// comma may start with `-` (PowerShell passes `--hard` on).
#[test]
fn start_process_lines_read_in_the_target_dialect() {
    for command in [
        "Start-Process cmd -ArgumentList '/c echo ok&gi\rt reset --hard'",
        "Start-Process cmd -ArgumentList '/c echo ok','&gi\rt reset --hard'",
        "Start-Process C:\\Windows\\System32\\cmd.exe -ArgumentList '/c gi\rt reset --hard'",
        "Start-Process C:\\Windows\\System32\\cmd.exe -ArgumentList '/c', 'gi\rt reset --hard'",
        "Start-Process cmd -ArgumentList '/c echo ok' , '&git reset --hard'",
        "Start-Process cmd -ArgumentList '/c echo ok' , '&gi\rt reset --hard'",
        "Start-Process cmd -ArgumentList '/c', 'git', reset, --hard",
        "Start-Process cmd -ArgumentList '/c', 'gi\rt', reset, --hard",
        "Start-Process cmd -ArgumentList @('/c' , 'git reset --hard')",
        // A PowerShell host's comma list is joined too (t_a7d98548 review).
        "Start-Process -FilePath pwsh -ArgumentList '-Command', 'git reset --hard'",
        "Start-Process -FilePath powershell -ArgumentList '-Command', 'git reset --hard'",
        "Start-Process powershell.exe -ArgumentList '-NoProfile', '-Command', 'git reset --hard'",
    ] {
        for dialect in [ShellDialect::PowerShell, ShellDialect::Unknown] {
            assert_eq!(
                decision_in(command, dialect),
                EvaluationDecision::Deny,
                "{dialect:?}: {command:?}"
            );
        }
        for protocol in [Protocol::Claude, Protocol::Codex] {
            assert_eq!(
                hook_decision(protocol, "PowerShell", command),
                "deny",
                "{protocol:?}: {command:?}"
            );
        }
    }
    for command in [
        "Start-Process cmd -ArgumentList @('/c' , 'echo SAFE')",
        "Start-Process cmd -ArgumentList '/c' , 'dir'",
        "Start-Process cmd -ArgumentList '/c echo ok&gi\rt status'",
        "Start-Process C:\\Windows\\System32\\cmd.exe -ArgumentList '/c dir'",
        "Start-Process cmd -ArgumentList '/c', 'echo', reset, --hard",
        "Start-Process -FilePath pwsh -ArgumentList '-Command', 'git status'",
    ] {
        for dialect in [ShellDialect::PowerShell, ShellDialect::Unknown] {
            assert_eq!(
                decision_in(command, dialect),
                EvaluationDecision::Allow,
                "{dialect:?}: {command:?}"
            );
        }
        for protocol in [Protocol::Claude, Protocol::Codex] {
            assert_eq!(
                hook_decision(protocol, "PowerShell", command),
                "allow",
                "{protocol:?}: {command:?}"
            );
        }
    }
}

/// A `cmd /c` payload found inside another command (a subshell, `if`, `for`,
/// `xargs`, `wsl`) is cmd's own command text: cmd removes the CR, so
/// `gi<CR>t reset --hard` runs `git reset --hard`. The POSIX reading ends the
/// word at the CR; the payload is also read as Cmd.
#[test]
fn cmd_payloads_inside_other_commands_are_read_as_cmd() {
    for command in [
        "(cmd.exe /c gi\rt reset --hard)",
        "if true; then cmd.exe /c gi\rt reset --hard; fi",
        "for i in 1; do cmd.exe /c gi\rt reset --hard; done",
        "xargs cmd.exe /c gi\rt reset --hard < /dev/null",
        "wsl cmd.exe /c gi\rt reset --hard",
        "wsl.exe -e cmd.exe /c gi\rt reset --hard",
        "wsl -- cmd.exe /c gi\rt reset --hard",
    ] {
        for dialect in [ShellDialect::Posix, ShellDialect::Unknown] {
            assert_eq!(
                decision_in(command, dialect),
                EvaluationDecision::Deny,
                "{dialect:?}: {command:?}"
            );
        }
        for protocol in [Protocol::Claude, Protocol::Codex] {
            assert_eq!(
                hook_decision(protocol, "Bash", command),
                "deny",
                "{protocol:?}: {command:?}"
            );
        }
    }
    for command in [
        "Start-Process wsl -ArgumentList 'cmd.exe /c gi\rt reset --hard'",
        "Start-Process wsl -ArgumentList '-e cmd.exe /c gi\rt reset --hard'",
        "Start-Process wsl -ArgumentList '-e', 'cmd.exe /c gi\rt reset --hard'",
    ] {
        for dialect in [ShellDialect::PowerShell, ShellDialect::Unknown] {
            assert_eq!(
                decision_in(command, dialect),
                EvaluationDecision::Deny,
                "{dialect:?}: {command:?}"
            );
        }
        for protocol in [Protocol::Claude, Protocol::Codex] {
            assert_eq!(
                hook_decision(protocol, "PowerShell", command),
                "deny",
                "{protocol:?}: {command:?}"
            );
        }
    }
    for command in [
        "(cmd.exe /c gi\rt status)",
        "for i in 1; do cmd.exe /c gi\rt status; done",
    ] {
        for dialect in [ShellDialect::Posix, ShellDialect::Unknown] {
            assert_eq!(
                decision_in(command, dialect),
                EvaluationDecision::Allow,
                "{dialect:?}: {command:?}"
            );
        }
        for protocol in [Protocol::Claude, Protocol::Codex] {
            assert_eq!(
                hook_decision(protocol, "Bash", command),
                "allow",
                "{protocol:?}: {command:?}"
            );
        }
    }
    let command = "Start-Process wsl -ArgumentList 'cmd.exe /c gi\rt status'";
    for dialect in [ShellDialect::PowerShell, ShellDialect::Unknown] {
        assert_eq!(
            decision_in(command, dialect),
            EvaluationDecision::Allow,
            "{dialect:?}: {command:?}"
        );
    }
    for protocol in [Protocol::Claude, Protocol::Codex] {
        assert_eq!(
            hook_decision(protocol, "PowerShell", command),
            "allow",
            "{protocol:?}: {command:?}"
        );
    }
}

/// In PowerShell, `` `r `` inside a double-quoted string is a CR. Passed to
/// cmd, that CR is removed, so `cmd /c "gi`rt reset --hard"` runs
/// `git reset --hard`. Needs both the backtick decode (#18) and the Cmd CR
/// reading.
#[test]
fn powershell_backtick_r_in_a_cmd_payload() {
    for command in [
        "cmd /c \"gi`rt reset --hard\"",
        "cmd.exe /d /c \"echo ok&gi`rt reset --hard\"",
    ] {
        for dialect in [ShellDialect::PowerShell, ShellDialect::Unknown] {
            assert_eq!(
                decision_in(command, dialect),
                EvaluationDecision::Deny,
                "{dialect:?}: {command:?}"
            );
        }
        for protocol in [Protocol::Claude, Protocol::Codex] {
            assert_eq!(
                hook_decision(protocol, "PowerShell", command),
                "deny",
                "{protocol:?}: {command:?}"
            );
        }
    }
    // The harmless twin allows in PowerShell. Unknown is not checked: its
    // POSIX reading sees an unterminated backtick substitution and denies
    // with `heredoc.shell:launcher-unverified`, before and after this change.
    let command = "cmd /c \"gi`rt status\"";
    assert_eq!(
        decision_in(command, ShellDialect::PowerShell),
        EvaluationDecision::Allow,
        "PowerShell: {command:?}"
    );
    for protocol in [Protocol::Claude, Protocol::Codex] {
        assert_eq!(
            hook_decision(protocol, "PowerShell", command),
            "allow",
            "{protocol:?}: {command:?}"
        );
    }
}

/// A `cmd /c` call inside another command hands cmd only its own words: they
/// end where the outer shell ends the command (`;`, `&&`, `|`, `)`), and the
/// outer shell resolves their quotes and escapes first. A later quoted `&`
/// is the outer shell's data, not cmd's separator, and a later `cmd /c` is
/// not nested inside the first.
#[test]
fn cmd_call_inside_another_command_ends_where_its_shell_ends_it() {
    // Bash joins the escaped words into one argument; cmd gets
    // `gi<CR>t reset --hard` (or `git reset --hard`) and runs it.
    for command in [
        "(cmd.exe /c gi\rt\\ reset\\ --hard)",
        "(cmd.exe /c git\\ reset\\ --hard)",
    ] {
        for dialect in [ShellDialect::Posix, ShellDialect::Unknown] {
            assert_eq!(
                decision_in(command, dialect),
                EvaluationDecision::Deny,
                "{dialect:?}: {command:?}"
            );
        }
        for protocol in [Protocol::Claude, Protocol::Codex] {
            assert_eq!(
                hook_decision(protocol, "Bash", command),
                "deny",
                "{protocol:?}: {command:?}"
            );
        }
    }
    let nine_ps = (0..9)
        .map(|n| format!("$v{n} = (cmd /c echo {n})"))
        .collect::<Vec<_>>()
        .join("; ");
    for command in [
        "cmd /c ver; Write-Output 'a & git reset --hard'",
        "(cmd /c ver); Write-Output 'a & git reset --hard'",
        nine_ps.as_str(),
    ] {
        assert_eq!(
            decision_in(command, ShellDialect::PowerShell),
            EvaluationDecision::Allow,
            "PowerShell: {command:?}"
        );
        for protocol in [Protocol::Claude, Protocol::Codex] {
            assert_eq!(
                hook_decision(protocol, "PowerShell", command),
                "allow",
                "{protocol:?}: {command:?}"
            );
        }
    }
    let nine_posix = (0..9)
        .map(|n| format!("(cmd.exe /c echo {n})"))
        .collect::<Vec<_>>()
        .join("; ");
    for command in [
        "cmd.exe /c ver; echo 'a & git reset --hard'",
        nine_posix.as_str(),
    ] {
        assert_eq!(
            decision_in(command, ShellDialect::Posix),
            EvaluationDecision::Allow,
            "Posix: {command:?}"
        );
        for protocol in [Protocol::Claude, Protocol::Codex] {
            assert_eq!(
                hook_decision(protocol, "Bash", command),
                "allow",
                "{protocol:?}: {command:?}"
            );
        }
    }
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

fn with_cr(commands: &[&str]) -> Vec<String> {
    commands
        .iter()
        .map(|command| command.replace("<CR>", "\r"))
        .collect()
}

/// Every `cmd /c` call the scanner finds gets a Cmd reading, also when the
/// launcher reader cannot verify it:
/// - the call is inside a quoted argument of a program that runs it (the
///   program gets the argument's value, which holds the call);
/// - cmd expands a variable in it (`%CD%`, `!…!`): the commands written
///   beside the variable are still judged.
#[test]
fn cmd_calls_the_launcher_reader_cannot_verify_still_get_a_cmd_reading() {
    let posix = [ShellDialect::Posix, ShellDialect::Unknown];
    let ps = [ShellDialect::PowerShell, ShellDialect::Unknown];
    let mut misses = expect_everywhere(
        &with_cr(&[
            "tmux new-session -d 'cmd.exe /c gi<CR>t reset --hard'",
            "tmux new-session -d \"cmd.exe /c gi<CR>t reset --hard\"",
            "tmux new-session -d 'echo start; cmd.exe /c gi<CR>t reset --hard'",
            "tmux send-keys 'cmd.exe /c gi<CR>t reset --hard' Enter",
            "watchexec 'cmd.exe /c gi<CR>t reset --hard'",
            "npx concurrently 'cmd.exe /c gi<CR>t reset --hard'",
            "git rebase --exec 'cmd.exe /c gi<CR>t reset --hard' HEAD~1",
            "xterm -e 'cmd.exe /c gi<CR>t reset --hard'",
            "nodemon --exec 'cmd.exe /c gi<CR>t reset --hard'",
            "(cmd.exe /c \"gi<CR>t reset --hard & echo %CD%\")",
            "(cmd.exe /c \"gi<CR>t clean -fdx %CD%\")",
            "(cmd.exe /c \"gi<CR>t reset --hard & echo done!!\")",
            "if true; then cmd.exe /c \"echo %DATE%&gi<CR>t reset --hard\"; fi",
            "for i in 1; do cmd.exe /c \"gi<CR>t reset --hard & echo %USERNAME%\"; done",
            "xargs cmd.exe /c \"gi<CR>t reset --hard & echo %CD%\" < /dev/null",
            "wsl cmd.exe /c \"gi<CR>t reset --hard & echo %CD%\"",
            "(cmd.exe /c gi<CR>t reset --hard \\& echo %CD%)",
        ]),
        &posix,
        "Bash",
        EvaluationDecision::Deny,
    );
    misses.extend(expect_everywhere(
        &with_cr(&[
            "schtasks /create /tn x /sc once /st 00:00 /tr \"cmd /c gi<CR>t reset --hard\"",
            "Start-Process wsl -ArgumentList 'cmd.exe /c \"gi<CR>t reset --hard & echo %CD%\"'",
        ]),
        &ps,
        "PowerShell",
        EvaluationDecision::Deny,
    ));
    misses.extend(expect_everywhere(
        &with_cr(&[
            "tmux new-session -d 'cmd.exe /c gi<CR>t status'",
            "(cmd.exe /c echo %PATH%)",
            "echo 'cmd /c gi<CR>t reset --hard'",
            "git commit -m \"docs: cmd /c gi<CR>t reset --hard\"",
            "grep -n 'cmd /c gi<CR>t reset' notes.md",
        ]),
        &[ShellDialect::Posix],
        "Bash",
        EvaluationDecision::Allow,
    ));
    assert!(
        misses.is_empty(),
        "{} misses:\n{}",
        misses.len(),
        misses.join("\n")
    );
}

/// A quoted cmd program name (`"cmd.exe" /c …`, `& 'C:\…\cmd.exe' /c …`) is
/// a cmd call wherever it stands, as it is at the start of a command.
#[test]
fn quoted_cmd_program_names_are_cmd_calls() {
    let posix = [ShellDialect::Posix, ShellDialect::Unknown];
    let ps = [ShellDialect::PowerShell, ShellDialect::Unknown];
    let mut misses = expect_everywhere(
        &with_cr(&[
            "(\"cmd.exe\" /c gi<CR>t reset --hard)",
            "('cmd.exe' /c \"gi<CR>t reset --hard\")",
            "(\"cmd.exe\" /c git reset --hard)",
            "('cmd.exe' /c \"git reset --hard\")",
        ]),
        &posix,
        "Bash",
        EvaluationDecision::Deny,
    );
    misses.extend(expect_everywhere(
        &with_cr(&[
            "(& 'C:\\Windows\\System32\\cmd.exe' /c \"gi<CR>t reset --hard\")",
            "(& 'cmd.exe' /c \"gi<CR>t reset --hard\")",
        ]),
        &ps,
        "PowerShell",
        EvaluationDecision::Deny,
    ));
    misses.extend(expect_everywhere(
        &with_cr(&["(& 'C:\\Windows\\System32\\cmd.exe' /c \"gi<CR>t status\")"]),
        &[ShellDialect::PowerShell],
        "PowerShell",
        EvaluationDecision::Allow,
    ));
    misses.extend(expect_everywhere(
        &with_cr(&[
            "(\"cmd.exe\" /c gi<CR>t status)",
            "('cmd.exe' /c \"git status\")",
        ]),
        &[ShellDialect::Posix],
        "Bash",
        EvaluationDecision::Allow,
    ));
    assert!(
        misses.is_empty(),
        "{} misses:\n{}",
        misses.len(),
        misses.join("\n")
    );
}

/// A cmd call at the start of an option value (`--exec=cmd.exe /c …`,
/// `--exec='cmd.exe /c …'`) is read from its `cmd` word, as the scanner's
/// POSIX reading of the same call is.
#[test]
fn cmd_calls_at_the_start_of_an_option_value() {
    let posix = [ShellDialect::Posix, ShellDialect::Unknown];
    let ps = [ShellDialect::PowerShell, ShellDialect::Unknown];
    // Each form with a CR and its CR-free twin.
    let twins = |forms: &[&str]| -> Vec<String> {
        forms
            .iter()
            .flat_map(|form| [form.replace("<CR>", "\r"), form.replace("<CR>", "")])
            .collect()
    };
    let mut misses = expect_everywhere(
        &twins(&[
            "nodemon --exec='cmd.exe /c gi<CR>t reset --hard'",
            "nodemon --exec=\"cmd.exe /c gi<CR>t reset --hard\"",
            "npx nodemon --exec='cmd.exe /c gi<CR>t reset --hard'",
            "git rebase --exec='cmd.exe /c gi<CR>t reset --hard' HEAD~1",
            "git rebase --exec=\"cmd.exe /c gi<CR>t reset --hard\" HEAD~1",
            "nodemon --exec=cmd.exe /c gi<CR>t reset --hard",
        ]),
        &posix,
        "Bash",
        EvaluationDecision::Deny,
    );
    misses.extend(expect_everywhere(
        &twins(&[
            "nodemon --exec=\"cmd /c gi<CR>t reset --hard\"",
            "npx nodemon --exec='cmd /c gi<CR>t reset --hard'",
            "git rebase --exec=\"cmd /c gi<CR>t reset --hard\" HEAD~1",
        ]),
        &ps,
        "PowerShell",
        EvaluationDecision::Deny,
    ));
    misses.extend(expect_everywhere(
        &with_cr(&[
            "nodemon --exec='cmd.exe /c gi<CR>t status'",
            "git rebase --exec='cmd.exe /c cargo test' HEAD~3",
        ]),
        &[ShellDialect::Posix],
        "Bash",
        EvaluationDecision::Allow,
    ));
    misses.extend(expect_everywhere(
        &with_cr(&["nodemon --exec=\"cmd /c gi<CR>t status\""]),
        &[ShellDialect::PowerShell],
        "PowerShell",
        EvaluationDecision::Allow,
    ));
    assert!(
        misses.is_empty(),
        "{} misses:\n{}",
        misses.len(),
        misses.join("\n")
    );
}
