//! Windows PowerShell 5.1 (`powershell.exe`) knows fewer host switches than
//! pwsh, and it starts the command string at the first argument it does not
//! recognize. dcg read `powershell` with pwsh's switch list, so it skipped
//! `-WorkingDirectory "x; git reset --hard"` as an option and its value, and
//! never judged the command 5.1 runs. 5.1 also accepts a switch only from a
//! minimum abbreviation, first match wins (`-NoP` is NoProfile, `-conf` is not
//! a switch).
//!
//! Source: PowerShell's ConsoleHost `CommandLineParameterParser.ParseHelper`
//! and `MatchSwitch` at tag v6.0.0-alpha.7 (the 5.1-lineage parser, before
//! pwsh-only switches were added). Measured with PowerShell 7.5 in the
//! sandbox: the command strings `-WorkingDirectory x; git reset --hard` and
//! `-SettingsFile x; git reset --hard` each run `git reset --hard` after a
//! not-found error. Unmeasured on real 5.1 (no sandboxed route).

use destructive_command_guard::evaluator::evaluate_command_with_pack_order_at_path_in_dialect;
use destructive_command_guard::normalize::ShellDialect;
use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::{Config, EvaluationDecision, LayeredAllowlist};
use std::io::Write;
use std::process::{Command, Stdio};

const HOOK_TEST_TIMEOUT_MS: &str = "30000";

/// Windows PowerShell 5.1 runs the destructive command in each.
const RUNS_IT: &[&str] = &[
    // pwsh-only value options are the start of the 5.1 command string.
    "powershell -WorkingDirectory \"x; git reset --hard\"",
    "powershell -SettingsFile \"x; git reset --hard\"",
    "powershell -ConfigurationFile \"x; git reset --hard\"",
    "powershell -CustomPipeName \"x; git reset --hard\"",
    "powershell -Work \"x; git reset --hard\"",
    "powershell.exe -NoProfile -WorkingDirectory \"x; git reset --hard\"",
    "powershell /WorkingDirectory \"x; git reset --hard\"",
    "powershell -WorkingDirectory x \"; git clean -fdx\"",
    "powershell -Login \"x; git reset --hard\"",
    // Abbreviations below 5.1's minimum are not switches either.
    "powershell -conf \"x; git reset --hard\"",
    "powershell -non \"x; git reset --hard\"",
    // Known 5.1 switches, including its own abbreviations, still lead to the
    // command that follows.
    "powershell -NoP -c \"git reset --hard\"",
    "powershell -nop -w hidden -c \"git reset --hard\"",
    "powershell -ep Bypass -c \"git reset --hard\"",
    "powershell -ec ZwBpAHQAIAByAGUAcwBlAHQAIAAtAC0AaABhAHIAZAA=",
    "powershell -Config x -c \"git reset --hard\"",
    "powershell -sta -noni \"git reset --hard\"",
    // Switches 5.1 reads but dcg does not model are never the command, for
    // any prefix: 5.1 keeps parsing after `/imp`, and the later -c runs.
    "powershell /imp -c \"git reset --hard\"",
    "powershell /ImportSystemModules -c \"git reset --hard\"",
    "powershell /-imp -c \"git reset --hard\"",
    "powershell /ea AAAA -c \"git reset --hard\"",
    "powershell /encodedarguments AAAA -c \"git reset --hard\"",
    "powershell /s -c \"git reset --hard\"",
    "powershell /so -c \"git reset --hard\"",
    "powershell /nam -c \"git reset --hard\"",
    "powershell /PSConsoleFile x.psc1 -c \"git reset --hard\"",
    "powershell -NoProfile /imp -Command \"git reset --hard\"",
    "powershell -imp -c \"git reset --hard\"",
    "powershell --imp -c \"git reset --hard\"",
    // ... and never prove that the host leaves piped input alone.
    "echo \"git reset --hard\" | powershell /imp -c -",
    "echo \"git reset --hard\" | powershell /imp",
    // pwsh knows -WorkingDirectory; its command is still judged.
    "pwsh -WorkingDirectory C:\\ -c \"git reset --hard\"",
];

/// Ordinary launches stay allowed.
const HARMLESS: &[&str] = &[
    "pwsh -WorkingDirectory C:\\ ./b.ps1",
    "pwsh -SettingsFile s.json -c \"Get-Date\"",
    "powershell -ExecutionPolicy Bypass -File .\\x.ps1",
    "powershell -NoP -c \"Get-Date\"",
    "powershell -nop -w hidden -c \"Get-Date\"",
    "powershell -ep Bypass -NoProfile -File .\\x.ps1",
    "powershell -ec RwBlAHQALQBEAGEAdABlAA==",
    "powershell -noni -nol -noe -c \"Get-Date\"",
    "powershell -sta -c \"Get-Date\"",
    "powershell -Config Microsoft.PowerShell -c \"Get-Date\"",
    "powershell -v 2 -c \"Get-Date\"",
    "powershell /?",
    "powershell /nop /c \"Get-Date\"",
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
            "session_id": "sess-ps-host",
            "transcript_path": "/tmp/claude/transcript.jsonl",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "toolu_ps_host",
        }),
        // `turn_id` selects Codex's protocol.
        Protocol::Codex => serde_json::json!({
            "session_id": "019dd11d-b795-7261-a9cb-9b85a5dadf16",
            "turn_id": "turn-ps-host",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.5",
            "permission_mode": "default",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "call_ps_host",
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

/// The PowerShell tool label, in both hook formats.
#[test]
fn powershell_tool_reads_windows_powershell_switches() {
    for protocol in [Protocol::Claude, Protocol::Codex] {
        for command in RUNS_IT {
            assert_eq!(
                hook_decision(protocol, "PowerShell", command),
                "deny",
                "{protocol:?}: {command:?}"
            );
        }
        for command in HARMLESS {
            assert_eq!(
                hook_decision(protocol, "PowerShell", command),
                "allow",
                "{protocol:?}: {command:?}"
            );
        }
    }
}

#[test]
fn powershell_and_unknown_dialects_read_windows_powershell_switches() {
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

/// Git Bash (MSYS2) rewrites a native program's argument before it starts:
/// a word that starts with `//` loses one `/` (its escape for Windows
/// switches), and a word that starts with one `/` becomes a Windows path
/// (`C:/Program Files/Git/...`). WSL and Linux pass both unchanged, and dcg
/// cannot tell them apart in the POSIX dialect, so it judges both readings.
/// Source: `find_path_start_and_type` in msys2-runtime's
/// `winsup/cygwin/msys2_path_conv.cc` (tag msys2-3.6.5). Real Git Bash
/// argument conversion is unmeasured here.
const GIT_BASH_RUNS_IT: &[&str] = &[
    // `//c` reaches the host as `/c`, which is -Command.
    "powershell //c \"git reset --hard\"",
    "powershell //Command \"git reset --hard\"",
    "powershell.exe -NoProfile //c \"git reset --hard\"",
    "powershell //nop //c \"git reset --hard\"",
    "powershell //imp -c \"git reset --hard\"",
    "pwsh //c \"git reset --hard\"",
    "pwsh -NoProfile //Command 'git reset --hard'",
    "powershell \" //c\" \"git reset --hard\"",
    // A single `/` value switch becomes a path, so 5.1 starts the command
    // string there instead of skipping a value.
    "powershell /ep \"x; git reset --hard\"",
    "powershell /WindowStyle \"x; git reset --hard\"",
    // Unchanged under WSL: the word is the start of the command string.
    "powershell //ep \"x; git reset --hard\"",
    "powershell //WorkingDirectory \"x; git reset --hard\"",
    // Piped input reaches the host's -Command - or -File -.
    "echo \"git reset --hard\" | powershell //c -",
    "echo \"git reset --hard\" | pwsh //File -",
    // Payload words are converted too: the nested host gets `/c`.
    "cmd //c powershell //c \"git reset --hard\"",
    "cmd //c pwsh //c \"git reset --hard\"",
    "cmd //c powershell -NoProfile //Command \"git reset --hard\"",
    "cmd //c powershell //c git reset --hard",
    "powershell -c powershell //c \"git reset --hard\"",
    "pwsh -c powershell //c \"git reset --hard\"",
    "powershell //c powershell //c \"git reset --hard\"",
    // Git Bash makes cmd's `/c` a path, whose reading by cmd.exe dcg does
    // not model; it keeps the switch reading, so the converted payload is
    // judged as well.
    "cmd /c powershell //c \"git reset --hard\"",
];

/// Ordinary Git Bash launches stay allowed.
const GIT_BASH_HARMLESS: &[&str] = &[
    "powershell //nop //c \"Get-Date\"",
    "pwsh //c \"Get-Date\"",
    "pwsh -NoProfile -File ./b.ps1",
    "powershell -File /c/Users/x/b.ps1",
    "powershell //c \"git status\"",
];

/// Nested launches that stay allowed under the Bash label and the POSIX
/// dialect. The Unknown dialect already denies `cmd //c` (an unknown cmd
/// switch in its Cmd reading), before and after this change.
const GIT_BASH_NESTED_HARMLESS: &[&str] = &[
    "cmd //c powershell //c Get-Date",
    "cmd //c powershell -c Get-Date",
    // One word: Git Bash converts only a word that starts with `/`, so the
    // inner powershell gets `//c`, the start of a harmless command string.
    "cmd //c \"powershell //c git reset --hard\"",
];

/// The Bash tool label in both hook formats: Claude Code on Windows runs it
/// in Git Bash.
#[test]
fn bash_tool_reads_git_bash_powershell_arguments() {
    for protocol in [Protocol::Claude, Protocol::Codex] {
        for command in GIT_BASH_RUNS_IT {
            assert_eq!(
                hook_decision(protocol, "Bash", command),
                "deny",
                "{protocol:?}: {command:?}"
            );
        }
        for command in GIT_BASH_HARMLESS.iter().chain(GIT_BASH_NESTED_HARMLESS) {
            assert_eq!(
                hook_decision(protocol, "Bash", command),
                "allow",
                "{protocol:?}: {command:?}"
            );
        }
    }
}

#[test]
fn posix_and_unknown_dialects_read_git_bash_powershell_arguments() {
    for dialect in [ShellDialect::Posix, ShellDialect::Unknown] {
        for command in GIT_BASH_RUNS_IT {
            assert_eq!(
                decision_in(command, dialect),
                EvaluationDecision::Deny,
                "{dialect:?}: {command:?}"
            );
        }
        for command in GIT_BASH_HARMLESS {
            assert_eq!(
                decision_in(command, dialect),
                EvaluationDecision::Allow,
                "{dialect:?}: {command:?}"
            );
        }
    }
    for command in GIT_BASH_NESTED_HARMLESS {
        assert_eq!(
            decision_in(command, ShellDialect::Posix),
            EvaluationDecision::Allow,
            "{command:?}"
        );
    }
}

/// Real PowerShell passes `//c` to a nested host unchanged, which starts a
/// harmless command string there: the PowerShell label and dialect do not
/// apply Git Bash's conversion to payload words.
#[test]
fn powershell_outer_shell_keeps_nested_double_slash_words() {
    let command = "powershell -c powershell //c \"git reset --hard\"";
    for protocol in [Protocol::Claude, Protocol::Codex] {
        assert_eq!(
            hook_decision(protocol, "PowerShell", command),
            "allow",
            "{protocol:?}"
        );
    }
    assert_eq!(
        decision_in(command, ShellDialect::PowerShell),
        EvaluationDecision::Allow
    );
}

/// Git Bash or WSL starting powershell.exe: the outer shell is POSIX.
#[test]
fn posix_dialect_reads_windows_powershell_switches() {
    for command in [
        "powershell -WorkingDirectory \"x; git reset --hard\"",
        "powershell -SettingsFile \"x; git reset --hard\"",
        "powershell.exe -Work 'x; git reset --hard'",
        "powershell /imp -c 'git reset --hard'",
        "powershell /PSConsoleFile x.psc1 -c 'git reset --hard'",
        "echo 'git reset --hard' | powershell /imp -c -",
        "echo 'git reset --hard' | powershell /imp",
    ] {
        assert_eq!(
            decision_in(command, ShellDialect::Posix),
            EvaluationDecision::Deny,
            "{command:?}"
        );
    }
}

/// pwsh's own switch list (`core_powershell_switch` in src/evaluator.rs,
/// from `CommandLineParameterParser.ParseHelper` at v7.5.4 to v7.7.0): its
/// short aliases (`-wd`, `-ep`, `-ec`, `-of`, `-if`, `-cwa`) and minimum
/// abbreviations, first match wins. pwsh reads each after `/` as well and
/// keeps parsing, so the later -Command runs. dcg read an unknown `/name` as
/// the script path and judged nothing after it. Measured with pwsh 7.5.0 in
/// the sandbox: `/wd .`, `/ep Bypass`, `/ex Bypass`, `/of text`, `/if text`,
/// `/inp text`, `/in`, `/cus x`, `/noe`, `/l` before `-c 'git reset --hard'`,
/// and `/cwa 'git reset --hard'`, `/ec <base64>`, `/e <base64>`, each ran
/// `git reset --hard`.
const PWSH_RUNS_IT: &[&str] = &[
    "pwsh /wd x -c \"git reset --hard\"",
    "pwsh -NoProfile /wd . -c \"git reset --hard\"",
    "pwsh /wo x -c \"git reset --hard\"",
    "pwsh /ep Bypass -c \"git reset --hard\"",
    "pwsh /ex Bypass -c \"git reset --hard\"",
    "pwsh /ec ZwBpAHQAIAByAGUAcwBlAHQAIAAtAC0AaABhAHIAZAA=",
    "pwsh -NoProfile /e ZwBpAHQAIAByAGUAcwBlAHQAIAAtAC0AaABhAHIAZAA=",
    "pwsh /of text -c \"git reset --hard\"",
    "pwsh /if text -c \"git reset --hard\"",
    "pwsh /inp text -c \"git reset --hard\"",
    "pwsh /in -c \"git reset --hard\"",
    "pwsh /cus x -c \"git reset --hard\"",
    "pwsh /config x -c \"git reset --hard\"",
    "pwsh /settings s.json -c \"git reset --hard\"",
    "pwsh /noe /l /noprofileloadtime -c \"git reset --hard\"",
    "pwsh -NoP -c \"git reset --hard\"",
    // Windows-only pwsh switches (a script path on Linux and macOS).
    "pwsh /to x /utc 2026-01-01T00:00:00Z -c \"git reset --hard\"",
    // Switches pwsh reads but dcg does not model fail closed for every
    // prefix: `-CommandWithArgs` runs its first argument, the server modes
    // read a protocol stream.
    "pwsh /cwa \"git reset --hard\"",
    "pwsh /CommandWithArgs \"git reset --hard\"",
    "pwsh /ea AAAA -c \"git reset --hard\"",
    "pwsh /s -c \"git reset --hard\"",
    "pwsh /so -c \"git reset --hard\"",
    "pwsh /nam -c \"git reset --hard\"",
    "pwsh /sshs -c \"git reset --hard\"",
    // Piped input reaches the -Command -.
    "echo \"git reset --hard\" | pwsh /wd x -c -",
    // The outer shell removes its redirects before pwsh starts, wherever
    // they stand, so they are no switch, switch value or script path
    // (measured with bash 5.2 and pwsh 7.5 as the outer shell:
    // `pwsh -nop 2>/dev/null /c`, `/wd 2>/dev/null .`, `/ep 2>/dev/null
    // Bypass`, `-nop > out.txt /c`, `-nop 2>&1 /c` and `/wd 2>&1 .` each ran
    // the command). cmd removes `2>nul` the same way (documented).
    "pwsh -nop 2>/dev/null /c \"git reset --hard\"",
    "pwsh 2>/dev/null /c \"git reset --hard\"",
    "pwsh /wd 2>/dev/null x -c \"git reset --hard\"",
    "pwsh /wd x 2>/dev/null -c \"git reset --hard\"",
    "pwsh /wd >/dev/null x -c \"git reset --hard\"",
    "pwsh /ep 2>/dev/null Bypass -c \"git reset --hard\"",
    "pwsh /ec 2>/dev/null ZwBpAHQAIAByAGUAcwBlAHQAIAAtAC0AaABhAHIAZAA=",
    "pwsh -nop 2>&1 /c \"git reset --hard\"",
    "pwsh -nop 2>nul /c \"git reset --hard\"",
    "pwsh -nop 2> out.txt /c \"git reset --hard\"",
    "cmd /c pwsh /wd 2>nul x -c \"git reset --hard\"",
];

/// Ordinary pwsh launches stay allowed, including abbreviations dcg used to
/// refuse as ambiguous (`-nop`, `-w`). `/Foo` and `/cu` match no pwsh
/// switch, so pwsh reads them as the script path and runs nothing after
/// them (measured: `pwsh /Foo -c 'git reset --hard'` and
/// `pwsh /cu x -c 'git reset --hard'` ran nothing).
const PWSH_HARMLESS: &[&str] = &[
    "pwsh /wd C:/ -c \"Get-Date\"",
    "pwsh -NoProfile -File ./b.ps1",
    "pwsh /Foo",
    "pwsh /Foo -c \"git reset --hard\"",
    "pwsh /cu x -c \"git reset --hard\"",
    "pwsh -nop -c \"Get-Date\"",
    "pwsh -w hidden -c \"Get-Date\"",
    "pwsh /ep Bypass -File ./b.ps1",
    "pwsh /ec RwBlAHQALQBEAGEAdABlAA==",
    "pwsh /of text /if text -c \"Get-Date\"",
    "pwsh /?",
    "pwsh -nop 2>/dev/null -c Get-Date",
    "pwsh /wd x 2>/dev/null -c Get-Date",
    "pwsh -NoProfile -File ./b.ps1 2>/dev/null",
    // A quoted operator is an argument.
    "pwsh /wd '2>x' -c Get-Date",
];

/// Both hook formats, under the PowerShell and the Bash tool labels.
#[test]
fn hooks_read_pwsh_switch_aliases() {
    for protocol in [Protocol::Claude, Protocol::Codex] {
        for tool in ["PowerShell", "Bash"] {
            for command in PWSH_RUNS_IT {
                assert_eq!(
                    hook_decision(protocol, tool, command),
                    "deny",
                    "{protocol:?} {tool}: {command:?}"
                );
            }
            for command in PWSH_HARMLESS {
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
fn every_dialect_reads_pwsh_switch_aliases() {
    for dialect in [
        ShellDialect::PowerShell,
        ShellDialect::Unknown,
        ShellDialect::Posix,
    ] {
        for command in PWSH_RUNS_IT {
            assert_eq!(
                decision_in(command, dialect),
                EvaluationDecision::Deny,
                "{dialect:?}: {command:?}"
            );
        }
        for command in PWSH_HARMLESS {
            assert_eq!(
                decision_in(command, dialect),
                EvaluationDecision::Allow,
                "{dialect:?}: {command:?}"
            );
        }
    }
}

/// A pwsh launched by a POSIX shell can run a process-substitution file. dcg
/// matched only the exact `-File` spelling there, so `pwsh -f <(...)` and
/// `pwsh <(...)` were allowed. Measured with pwsh 7.5.0 under bash 5.2 in the
/// sandbox: `-f`, `/f`, `-File`, `/wd . -f`, `-nop -noni`, a bare
/// `<(...)` and `-ec <value> <(...)` each ran the substituted
/// `git reset --hard`, and so did a -Command that embeds the path
/// (`-c 'iex ([IO.File]::ReadAllText("'<(...)'"))'`).
const PWSH_PROCESS_SUBSTITUTION_RUNS_IT: &[&str] = &[
    "pwsh -f <(echo \"git reset --hard\")",
    "pwsh /f <(echo \"git reset --hard\")",
    "pwsh -File <(echo \"git reset --hard\")",
    "pwsh /wd x -f <(echo \"git reset --hard\")",
    "pwsh <(echo \"git reset --hard\")",
    "pwsh -NoProfile <(echo \"git reset --hard\")",
    "pwsh -nop -noni <(echo \"git reset --hard\")",
    "pwsh -f <(echo \"git reset --hard\") extra",
    "pwsh 2>/dev/null -f <(echo \"git reset --hard\")",
    "pwsh -ec RwBlAHQALQBEAGEAdABlAA== <(echo \"git reset --hard\")",
    "pwsh -c 'iex ([IO.File]::ReadAllText(\"'<(echo \"git reset --hard\")'\"))'",
    "powershell -File <(echo \"git reset --hard\")",
    // Outer-shell redirects at a switch or value position (measured:
    // `-f 2>/dev/null <(...)`, `-f > out.txt <(...)`, `-wd 2>/dev/null x
    // <(...)` and `-nop 2>/dev/null < <(...)` each ran the text).
    "pwsh -wd 2>/dev/null x <(echo \"git reset --hard\")",
    "pwsh -wd 2>/dev/null x -f <(echo \"git reset --hard\")",
    "pwsh -f 2>/dev/null <(echo \"git reset --hard\")",
    "pwsh -f > out.txt <(echo \"git reset --hard\")",
    "pwsh -File >/dev/null <(echo \"git reset --hard\")",
    "pwsh -nop -f 2>&1 <(echo \"git reset --hard\")",
    "pwsh -nop 2>/dev/null < <(echo \"git reset --hard\")",
    "pwsh -ep Bypass 2>/dev/null < <(echo \"git reset --hard\")",
    "pwsh 2>/dev/null < <(echo \"git reset --hard\")",
    // A POSIX redirect glued to an argument leaves the argument
    // (`/wd>/dev/null` reaches pwsh as `/wd`), and the rest of bash's
    // redirect family (measured).
    "pwsh /wd>/dev/null x -c \"git reset --hard\"",
    "pwsh /nop>/dev/null /c \"git reset --hard\"",
    "pwsh /wd >| out.txt . -c \"git reset --hard\"",
    "pwsh /wd &>/dev/null . -c \"git reset --hard\"",
    "pwsh /wd {fd}>/dev/null . -c \"git reset --hard\"",
];

/// The substituted text is judged as PowerShell source, so a harmless one
/// stays allowed, and a process substitution pwsh only takes as a switch
/// value runs nothing (measured: `pwsh -f <(echo Get-Date)` and
/// `pwsh -wd <(echo 'git reset --hard') -c Get-Date` ran no git).
const PWSH_PROCESS_SUBSTITUTION_HARMLESS: &[&str] = &[
    "pwsh -f <(echo Get-Date)",
    "pwsh <(echo Get-Date)",
    "pwsh /wd x -f <(echo Get-Date)",
    "pwsh -wd <(echo \"git reset --hard\") -c Get-Date",
    "pwsh -f <(echo Get-Date) 2>/dev/null",
];

/// Process substitution and these redirect spellings exist only in a POSIX
/// outer shell, so the Bash tool label in both hook formats, and the Unknown
/// and POSIX dialects.
#[test]
fn hooks_read_pwsh_process_substitution_files() {
    for protocol in [Protocol::Claude, Protocol::Codex] {
        for command in PWSH_PROCESS_SUBSTITUTION_RUNS_IT {
            assert_eq!(
                hook_decision(protocol, "Bash", command),
                "deny",
                "{protocol:?}: {command:?}"
            );
        }
        for command in PWSH_PROCESS_SUBSTITUTION_HARMLESS {
            assert_eq!(
                hook_decision(protocol, "Bash", command),
                "allow",
                "{protocol:?}: {command:?}"
            );
        }
    }
}

#[test]
fn posix_dialects_read_pwsh_process_substitution_files() {
    for dialect in [ShellDialect::Unknown, ShellDialect::Posix] {
        for command in PWSH_PROCESS_SUBSTITUTION_RUNS_IT {
            assert_eq!(
                decision_in(command, dialect),
                EvaluationDecision::Deny,
                "{dialect:?}: {command:?}"
            );
        }
        for command in PWSH_PROCESS_SUBSTITUTION_HARMLESS {
            assert_eq!(
                decision_in(command, dialect),
                EvaluationDecision::Allow,
                "{dialect:?}: {command:?}"
            );
        }
    }
}

/// PowerShell's own redirects, at the start of a word only, for streams 1-6
/// and `*`. Measured with pwsh 7.5 as the outer shell: `pwsh -nop 2>$null
/// /c`, `-nop *>$null /c` and `/wd 3>$null .` ran the command, while
/// `/wd 7>$null .` and `/wd>$null .` gave pwsh the arguments `7>` and `/wd>`
/// and ran nothing.
const PWSH_POWERSHELL_REDIRECT_RUNS_IT: &[&str] = &[
    "pwsh -nop 2>$null /c \"git reset --hard\"",
    "pwsh -nop *>$null /c \"git reset --hard\"",
    "pwsh /wd 3>$null . -c \"git reset --hard\"",
];

const PWSH_POWERSHELL_REDIRECT_HARMLESS: &[&str] = &[
    "pwsh /wd 7>$null . -c \"git reset --hard\"",
    "pwsh /wd>$null . -c \"git reset --hard\"",
];

#[test]
fn powershell_outer_shell_redirects_are_not_pwsh_arguments() {
    for protocol in [Protocol::Claude, Protocol::Codex] {
        for command in PWSH_POWERSHELL_REDIRECT_RUNS_IT {
            assert_eq!(
                hook_decision(protocol, "PowerShell", command),
                "deny",
                "{protocol:?}: {command:?}"
            );
        }
        for command in PWSH_POWERSHELL_REDIRECT_HARMLESS {
            assert_eq!(
                hook_decision(protocol, "PowerShell", command),
                "allow",
                "{protocol:?}: {command:?}"
            );
        }
    }
    for command in PWSH_POWERSHELL_REDIRECT_RUNS_IT {
        assert_eq!(
            decision_in(command, ShellDialect::PowerShell),
            EvaluationDecision::Deny,
            "{command:?}"
        );
    }
    for command in PWSH_POWERSHELL_REDIRECT_HARMLESS {
        assert_eq!(
            decision_in(command, ShellDialect::PowerShell),
            EvaluationDecision::Allow,
            "{command:?}"
        );
    }
}
