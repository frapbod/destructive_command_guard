//! PowerShell continues a statement on the next line after a line that ends
//! with an operator: `'git reset' +` LF `' --hard' | iex` and
//! `'git reset {0}' -f` LF `'--hard' | iex` run `git reset --hard` (pwsh 7.5,
//! measured in the sandbox for every RUNS_IT row, with fake `git`; the
//! Remove-Item rows deleted a real directory there). Every binary operator
//! does this, in any case and with a Unicode dash, and so do unary
//! operators, member access, the ternary and null-coalescing operators and
//! a backtick before the line break; comments and blank lines between the
//! operator and the next code change nothing, and so does a `<<` in a
//! PowerShell comment or string (smart quotes included), where a POSIX shell
//! would read a heredoc.
//!
//! dcg's readers end a statement at every line break outside brackets: the
//! pipeline source of `iex` was `' --hard'`, a harmless string, while the
//! one-line spelling `'git reset' + ' --hard' | iex` was denied. dcg now
//! also reads a command that may be PowerShell with each such line break
//! (and the comment before it) spelled as blanks, through the whole
//! evaluator, and the denial wins. In command mode only `,` and the
//! backtick continue (`Write-Output a +` LF `git reset --hard` runs the
//! reset); the original reading still judges those lines one by one.

use destructive_command_guard::evaluator::evaluate_command_with_pack_order_at_path_in_dialect;
use destructive_command_guard::normalize::ShellDialect;
use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::{Config, EvaluationDecision, LayeredAllowlist};
use std::io::Write;
use std::process::{Command, Stdio};

const HOOK_TEST_TIMEOUT_MS: &str = "30000";

/// pwsh 7.5 runs `git reset --hard` for each (sandboxed, fake `git`).
const RUNS_IT: &[&str] = &[
    // The card's rows.
    "'git reset' +\n' --hard' | iex",
    "'git reset {0}' -f\n'--hard' | iex",
    "$c = 'git reset' +\n' --hard' | iex",
    "$c='git reset' +\n' --hard' | iex",
    "$c=@(1,2); $c[ 0 ] = 'git reset' +\n' --hard' | iex",
    "@{a = 'git reset' +\n' --hard' | iex}",
    // Every binary operator that builds text, any case, a Unicode dash.
    "'git reset {0}' -F\n'--hard' | iex",
    "'git reset {0}' \u{2013}f\n'--hard' | iex",
    "'git','reset','--hard' -join\n' ' | iex",
    "'git','reset','--hard' -JOIN\n' ' | Invoke-Expression",
    "'git reset X' -replace\n'X','--hard' | iex",
    "'git reset --hard; ' *\n1 | iex",
    "('git','reset','--hard' -join ' ') -split\n';' | iex",
    "'git reset' +\n' --hard' | Invoke-Expression",
    "'git' +\n' reset' +\n' --hard' | iex",
    // Whatever stands between the operator and the next code.
    "'git reset' + # c\n' --hard' | iex",
    "'git reset' + # it's\n' --hard' | iex",
    "'git reset' + <# c #>\n' --hard' | iex",
    "'git reset' +\n\n' --hard' | iex",
    "'git reset' +\n  # c\n' --hard' | iex",
    "'git reset' +\r\n' --hard' | iex",
    "'git reset' +\r' --hard' | iex",
    "'git reset'+\n' --hard'|iex",
    "'git reset' + `\n' --hard' | iex",
    "'git reset' `\n+ ' --hard' | iex",
    // Unary operators, member access, ternary, null-coalescing.
    "-join\n('git reset',' --hard') | iex",
    "'git reset --hard '.\nTrim() | iex",
    "[string]::\nConcat('git reset', ' --hard') | iex",
    "($true ?\n'git reset --hard' : 'x') | iex",
    "($null ??\n'git reset --hard') | iex",
    // Wherever the statement stands.
    "Write-Output a; 'git reset' +\n' --hard' | iex",
    "if ($true -and\n'x') { }; 'git reset' +\n' --hard' | iex",
    "& { 'git reset' +\n' --hard' | iex }",
    "1 | % { 'git reset' +\n' --hard' | iex }",
    "iex ('git reset' +\n' --hard')",
    "$c = 'git reset' +\n' --hard'; iex $c",
    "$c = 'git reset'; $c +=\n' --hard'; iex $c",
    "[scriptblock]::Create('git reset' +\n' --hard').Invoke()",
    "icm ([scriptblock]::Create('git reset' +\n' --hard'))",
    // A `<<` in a PowerShell comment or string opens no heredoc.
    "'git reset' + <#\nx <<X\n#>\n' --hard' | iex",
    "'git reset' + <#\n<<X\n#>\n' --hard' | iex",
    "'git reset' + <#\ncat <<'X'\n#>\n' --hard' | iex",
    "'git reset' + \u{2018}<<X\u{2019}*0 +\n' --hard' | iex",
    "'git reset' + # <<X\n' --hard' | iex",
    "'git reset' + \u{201c}<<X\u{201d}*0 +\n' --hard' | iex",
    "'git reset' + @\u{2018}\n<<X\n\u{2019}@*0 +\n' --hard' | iex",
    "'git reset' + @'\n<<X\n'@*0 +\n' --hard' | iex",
    "'git reset' + 'it\u{2018}\u{2019}s <<X'*0 +\n' --hard' | iex",
    // A member chain or a number literal before a glued operator.
    "@{a='git reset'}.a+\n' --hard' | iex",
    "@{a='git reset {0}'}.a-f\n'--hard' | iex",
    "(@{a='git reset'}).a+\n' --hard' | iex",
    "[string]'git reset'+[string]::Empty+\n' --hard' | iex",
    "pwsh -c \"@{a='git reset'}.a+\n' --hard' | iex\"",
    "'git reset' * 1L+\n' --hard' | iex",
    "'git reset' * 0x1+\n' --hard' | iex",
    "'git reset' * 1e0+\n' --hard' | iex",
    "'git reset' * 1d+\n' --hard' | iex",
    "'git reset' * (1)*1+\n' --hard' | iex",
    "'git reset' * 1*1+\n' --hard' | iex",
    "'git reset' + ''*1kb+\n' --hard' | iex",
    "'git reset'.Trim()+\n' --hard' | iex",
    "'git reset' * 0b1+\n' --hard' | iex",
    "'git reset' * 1uy+\n' --hard' | iex",
    "'git reset' * 1E0+\n' --hard' | iex",
    "$a=@{b='git reset'}; $a.b+\n' --hard' | iex",
    "'git reset' * 1e-0+\n' --hard' | iex",
    // Command mode: the line ends, and the next line is its own command.
    "Write-Output a +\ngit reset --hard",
    "Write-Output a -f\ngit reset --hard",
    // pwsh deleted a real directory with these spellings.
    "'Remove-Item -Recurse' +\n' -Force C:\\Users' | iex",
    "$c = 'Remove-Item -Recurse -Force {0}' -f\n'C:\\Users' | iex",
];

/// pwsh 7.5 runs nothing dangerous for each.
const HARMLESS: &[&str] = &[
    "'git status' +\n' --short' | iex",
    "$c = 'a' +\n'b'; Write-Output $c",
    "$total = 1 +\n2 +\n3; Write-Output $total",
    "Write-Output ('a' +\n'b')",
    "Write-Output a +\ngit status",
    "Get-ChildItem |\nSelect-Object Name",
    "Get-ChildItem\n| Select-Object Name",
    "cd ..\ngit status",
    "git add .\ngit status",
    "$x = 'git reset --hard' +\n' is dangerous'; Write-Output $x",
    "Write-Output 'git reset' +\n' --hard'",
    "md5sum <<EOF\ngit reset --hard /\nEOF",
    "Write-Output \u{2018}a +\ngit reset --hard\u{2019}",
    "Write-Output @\u{2018}\ngit reset +\n\u{2019}@\ngit status",
    "Write-Output @\u{2018}\nx\n'@\ngit status",
    "Write-Output \u{201c}a`\u{201d} +\ngit reset --hard\u{201d}",
];

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
            "session_id": "sess-ps-continue",
            "transcript_path": "/tmp/claude/transcript.jsonl",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "toolu_ps_continue",
        }),
        // `turn_id` selects Codex's protocol.
        Protocol::Codex => serde_json::json!({
            "session_id": "019dd11d-b795-7261-a9cb-9b85a5dadf15",
            "turn_id": "turn-ps-continue",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.5",
            "permission_mode": "default",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "call_ps_continue",
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

/// The PowerShell tool label (PowerShell) and an unlabeled shell tool
/// (Unknown), in both hook formats.
#[test]
fn hooks_read_a_line_that_continues_after_an_operator_as_one_statement() {
    for protocol in [Protocol::Claude, Protocol::Codex] {
        for tool in ["PowerShell", "exec_command"] {
            for command in RUNS_IT {
                assert_eq!(
                    hook_decision(protocol, tool, command),
                    "deny",
                    "{protocol:?} {tool}: {command:?}"
                );
            }
            for command in HARMLESS {
                assert_eq!(
                    hook_decision(protocol, tool, command),
                    "allow",
                    "{protocol:?} {tool}: {command:?}"
                );
            }
        }
    }
}

#[test]
fn powershell_and_unknown_dialects_read_a_line_that_continues_after_an_operator() {
    for dialect in [ShellDialect::PowerShell, ShellDialect::Unknown] {
        for command in RUNS_IT {
            assert_eq!(
                decision_in(command, dialect),
                EvaluationDecision::Deny,
                "{dialect:?}: {command:?}"
            );
        }
        for command in HARMLESS {
            assert_eq!(
                decision_in(command, dialect),
                EvaluationDecision::Allow,
                "{dialect:?}: {command:?}"
            );
        }
    }
}
