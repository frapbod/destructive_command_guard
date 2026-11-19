//! cmd.exe reads the text after `/C` or `/K` with its own quote rule
//! (`cmd /?`; ReactOS cmd's `GetCmdLineCommand`): when the text starts with
//! a quote, cmd removes that quote and the last one and runs the rest, unless
//! (without `/S`) exactly two quotes enclose whitespace, no special character
//! and the name of an executable file. So `cmd /c '"git reset --hard"'` in
//! PowerShell, which hands cmd `"git reset --hard"`, runs git. dcg reads such
//! a payload as written and with the quotes removed; deny wins.
//!
//! cmd also looks for its switches anywhere on its command line (ReactOS
//! cmd's `Initialize` scans every `/`), so a word that is not a switch before
//! `/C` does not end them (`cmd foo /c git reset --hard`). What Windows
//! cmd.exe does there is not measured, so dcg fails closed.

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
            "session_id": "sess-cmd-switch-quotes",
            "transcript_path": "/tmp/claude/transcript.jsonl",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "toolu_cmd_switch_quotes",
        }),
        // `turn_id` selects Codex's protocol.
        Protocol::Codex => serde_json::json!({
            "session_id": "019dd11d-b795-7261-a9cb-9b85a5dadf15",
            "turn_id": "turn-cmd-switch-quotes",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.5",
            "permission_mode": "default",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "call_cmd_switch_quotes",
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

const PS: [ShellDialect; 2] = [ShellDialect::PowerShell, ShellDialect::Unknown];

const POSIX: [ShellDialect; 2] = [ShellDialect::Posix, ShellDialect::Unknown];

/// cmd's own reading only: no hook tool runs commands in cmd.
fn cmd_misses(commands: &[&str], want: EvaluationDecision) -> Vec<String> {
    commands
        .iter()
        .filter_map(|command| {
            let got = decision_in(command, ShellDialect::Cmd);
            (got != want).then(|| format!("Cmd: {command:?} -> {got:?}"))
        })
        .collect()
}

fn assert_no_misses(groups: &[Vec<String>]) {
    let misses: Vec<&String> = groups.iter().flatten().collect();
    assert!(
        misses.is_empty(),
        "misses:\n{}",
        misses
            .iter()
            .map(|miss| miss.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// A payload that reaches cmd with a leading quote: PowerShell hands cmd
/// the double quotes inside single quotes, and after `--%` as typed.
#[test]
fn a_quoted_cmd_payload_is_read_as_cmd_strips_its_quotes() {
    let powershell = expect_everywhere(
        &strings(&[
            r#"cmd /c '"git reset --hard"'"#,
            r#"cmd /c --% "git reset --hard""#,
            r#"cmd /s /c '"git reset --hard"'"#,
            r#"cmd /k '"git reset --hard"'"#,
            r#"cmd /d /q /c '"git reset --hard"'"#,
            r#"cmd.exe /c '"git reset --hard"'"#,
            r#"& cmd /c '"git reset --hard"'"#,
            r#"cmd /c '  "git reset --hard"'"#,
            r#"cmd /c '"git reset --hard'"#,
            r#"cmd /c '"git reset --hard" & echo x'"#,
            r#"cmd /c '"git reset --hard & echo x"'"#,
            r#"cmd /c '"git reset --hard" & rem'"#,
            r#"cmd /c '"echo "x" & git reset --hard"'"#,
            r#"cmd /c '"echo a" "b & git reset --hard"'"#,
            r#"cmd /c '"if 1==1 git reset --hard"'"#,
            r#"cmd /c '"git reset --hard"' 2>&1"#,
            r#"cmd /c '"git reset --hard"' | Out-Null"#,
            r#"(cmd /c '"git reset --hard"')"#,
            r#"$r = cmd /c '"git reset --hard"'"#,
        ]),
        &PS,
        "PowerShell",
        EvaluationDecision::Deny,
    );
    let posix = expect_everywhere(
        &strings(&[
            r#"cmd.exe /c '"git reset --hard"'"#,
            r#"cmd.exe /s /c '"git reset --hard"'"#,
            r#"cmd.exe //c '"git reset --hard"'"#,
            r#"bash -c "cmd.exe /c '\"git reset --hard\"'""#,
            r#"xargs cmd.exe /c '"git reset --hard"'"#,
            r#"wsl cmd.exe /c '"git reset --hard"'"#,
            r#"(cmd.exe /c '"git reset --hard"')"#,
        ]),
        &POSIX,
        "Bash",
        EvaluationDecision::Deny,
    );
    let cmd = cmd_misses(
        &[
            r#"cmd /c ""git reset --hard"""#,
            r#"cmd /s /c ""git reset --hard"""#,
            r#"cmd /c "  "git reset --hard"""#,
            r#"call cmd /c ""git reset --hard"""#,
            r#"if 1==1 cmd /c ""git reset --hard"""#,
        ],
        EvaluationDecision::Deny,
    );
    assert_no_misses(&[powershell, posix, cmd]);
}

/// A word that is not a switch before `/C`, `/K` or `/R` fails closed.
#[test]
fn a_word_that_is_not_a_switch_before_slash_c_fails_closed() {
    let powershell = expect_everywhere(
        &strings(&[
            r"cmd foo /c git reset --hard",
            r"cmd .y /c git reset --hard",
            r"cmd '--%' -x.y /c git reset --hard",
            r#"cmd "" /c git reset --hard"#,
            r"cmd /d foo /k git reset --hard",
            r"cmd foo /r git reset --hard",
            r"cmd foo/c git reset --hard",
            r"cmd.exe foo /C git reset --hard",
        ]),
        &PS,
        "PowerShell",
        EvaluationDecision::Deny,
    );
    let posix = expect_everywhere(
        &strings(&[
            r"cmd.exe foo /c git reset --hard",
            r"cmd.exe foo //c git reset --hard",
        ]),
        &POSIX,
        "Bash",
        EvaluationDecision::Deny,
    );
    let cmd = cmd_misses(
        &[
            r"cmd foo /c git reset --hard",
            r"cmd .y /c git reset --hard",
        ],
        EvaluationDecision::Deny,
    );
    assert_no_misses(&[powershell, posix, cmd]);
}

/// Payloads whose quoted program path cmd keeps, or whose quotes hide
/// nothing, stay allowed, and so does cmd with no command.
#[test]
fn quoted_program_paths_and_harmless_payloads_stay_allowed() {
    let powershell = expect_everywhere(
        &strings(&[
            r#"cmd /c "\"C:\Program Files\x\y.exe\" arg""#,
            r#"cmd /c '"C:\Program Files\x\y.exe" arg'"#,
            r#"cmd /c '"C:\Program Files\x\y.exe" "a b"'"#,
            r#"cmd /c '"C:\Program Files\Git\bin\git.exe" status'"#,
            r#"cmd /c '""C:\Program Files\Git\bin\git.exe" status"'"#,
            r#"cmd /c '"echo hi"'"#,
            r#"cmd /c '"where git"'"#,
            r#"cmd /c '"dir" /b'"#,
            r#"cmd /c '"npm" run build'"#,
            r#"cmd /c start "" "https://example.com""#,
            r#"cmd.exe /c "set FOO=1&& npm run build""#,
            r"cmd /c ver",
            r"cmd",
            r"cmd /d",
            r"cmd foo",
        ]),
        &[ShellDialect::PowerShell],
        "PowerShell",
        EvaluationDecision::Allow,
    );
    let posix = expect_everywhere(
        &strings(&[
            r#"cmd.exe /c '"C:\Program Files\Git\bin\git.exe" status'"#,
            r#"cmd.exe /c "where git""#,
            r#"cmd.exe /c 'echo "a b"'"#,
            r"cmd.exe build.bat",
        ]),
        &[ShellDialect::Posix],
        "Bash",
        EvaluationDecision::Allow,
    );
    let cmd = cmd_misses(
        &[
            r#"cmd /c ""C:\Program Files\Git\bin\git.exe" status""#,
            r#"cmd /s /c ""C:\Program Files\x\y.exe" "a b"""#,
            r#"cmd /c "where git""#,
            r#"cmd /c ""dir"""#,
        ],
        EvaluationDecision::Allow,
    );
    assert_no_misses(&[powershell, posix, cmd]);
}
