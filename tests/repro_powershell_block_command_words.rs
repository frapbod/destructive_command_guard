//! A PowerShell script block that runs starts a command at its first word:
//! `& { g"it" reset --hard }`, `if (1) { … }`, `foreach (…) { … }` and
//! `function f { … }; f` each run Git in powershell.exe 5.1, the shell Codex
//! uses on Windows. The POSIX reading of the same line sees `g"it"` as an
//! argument of `&`, `if` or `function` and never decodes it, so the union a
//! Windows Codex `Bash` payload gets allowed them. A quoted Git word with a
//! separator after it (`"git" reset --hard;`) was allowed in every dialect
//! but the union, which also hid a block body ending in `;`.

// Shell parameter expansions such as `${X:-word}` are case data here.
#![allow(clippy::literal_string_with_formatting_args)]

use destructive_command_guard::evaluator::evaluate_command_with_pack_order_at_path_in_dialect;
use destructive_command_guard::normalize::ShellDialect;
use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::{Config, EvaluationDecision, LayeredAllowlist};
use std::io::Write;
use std::process::{Command, Stdio};

const HOOK_TEST_TIMEOUT_MS: &str = "30000";

/// powershell.exe 5.1 ran a harmless analogue (`g"it" --version`) of the
/// shapes here: `function f { … }; f`, `& { … }`, `if (1) { … }` and
/// `function f { gi"t" … }; f` each printed Git's version.
const POWERSHELL_RUNS_GIT: &[&str] = &[
    r#"function f { g"it" reset --hard }; f"#,
    r#"function f { g"it" reset --hard; }; f"#,
    r#"function f { gi"t" reset --hard }; f"#,
    r#"function f { g"it" push --force origin main }; f"#,
    r#"& { g"it" reset --hard }"#,
    r#"& { g"it" reset --hard; }"#,
    r#"if (1) { g"it" reset --hard }"#,
    r#"foreach ($i in 1) { g"it" reset --hard }"#,
    r#"& { & { g"it" reset --hard } }"#,
    r#". { g"it" reset --hard }"#,
    r#"try { g"it" reset --hard } catch {}"#,
    r#"while ($true) { g"it" reset --hard; break }"#,
    r#"function global:f { g"it" reset --hard }; f"#,
    r#"function f($a) { g"it" reset --hard }; f 1"#,
    r#"filter f { g"it" reset --hard }; f"#,
    r#"Get-ChildItem | ForEach-Object { g"it" -C $_ reset --hard }"#,
    // One per kind of block that runs (each ran `g"it" --version` in
    // powershell.exe 5.1): the statement keywords, whose header may hold
    // any statement text and may be followed by a line break, a loop label,
    // switch clause conditions and actions, a script block's named blocks,
    // the function-like definitions, and class methods.
    r#"if (0) {} elseif (1) { g"it" reset --hard }"#,
    r#"if (0) {} else { g"it" reset --hard }"#,
    "if (0) {}\nelse\n{ g\"it\" reset --hard }",
    "if (1)\n{ g\"it\" reset --hard }",
    r#"if ((1..2 | % { $_ }).Count) { g"it" reset --hard }"#,
    r#"if (")" -eq ")") { g"it" reset --hard }"#,
    r#"switch (1) { 1 { g"it" reset --hard } }"#,
    r#"switch (1) { default { g"it" reset --hard } }"#,
    r#"switch (1) { { $_ -eq 1 } { g"it" reset --hard } }"#,
    r#"switch (1) { { g"it" reset --hard; $true } { } }"#,
    r#"switch -Regex ("a") { "a" { g"it" reset --hard } }"#,
    r#"for ($i=0; $i -lt 1; $i++) { g"it" reset --hard }"#,
    "for ($i=0; $i -lt 1; $i++)\n{ g\"it\" reset --hard }",
    r#"foreach ($i in @(1;2)) { g"it" reset --hard }"#,
    r#"while(1){ g"it" reset --hard; break }"#,
    r#":outer foreach ($i in 1) { g"it" reset --hard }"#,
    r#":l for (;;) { g"it" reset --hard; break }"#,
    r#"do { g"it" reset --hard } while ($false)"#,
    r#"do { g"it" reset --hard } until (1)"#,
    "try\n{ g\"it\" reset --hard } finally {}",
    r#"try { throw "x" } catch [System.Exception] { g"it" reset --hard }"#,
    r#"try {} finally { g"it" reset --hard }"#,
    r#"trap { g"it" reset --hard; continue } throw "x""#,
    r#"function f { begin {} process { g"it" reset --hard } end {} }; f"#,
    r#"1 | & { process { g"it" reset --hard } }"#,
    r#"& { begin { g"it" reset --hard } }"#,
    r#"& { end { g"it" reset --hard } }"#,
    r#"function f { [CmdletBinding()] param() dynamicparam { g"it" reset --hard } end {} }; f"#,
    "function f\n{ g\"it\" reset --hard }; f",
    r#"workflow w { g"it" reset --hard }; w"#,
    r#"configuration c { g"it" reset --hard }; c"#,
    r#"class C { static [void] m() { g"it" reset --hard } }; [C]::m()"#,
    r#"class C { C() { g"it" reset --hard } }; [C]::new()"#,
    r#"$null = & { g"it" reset --hard }"#,
    r#"1 | ForEach-Object -Begin { g"it" reset --hard } -Process { }"#,
    // Controls that were already denied.
    r#"g"it" reset --hard"#,
    "function f { git reset --hard }; f",
    r#"function f { & "git" reset --hard }; f"#,
    "& { git reset --hard }",
];

/// A partly quoted Git word with a separator after it. Bash and PowerShell
/// both run these.
const SEPARATOR_AFTER_QUOTED_GIT: &[&str] = &[
    r#"g"it" reset --hard;"#,
    r#"gi"t" push --force origin main;"#,
    r#"g"it" reset --hard ;"#,
];

/// Bash runs these; powershell.exe 5.1 refuses each line. It reads a leading
/// string as an expression (`"git" --version` is a parse error) and has no
/// trailing `&`.
const SEPARATOR_AFTER_QUOTED_GIT_BASH_ONLY: &[&str] = &[
    r#"g"it" reset --hard &"#,
    r#""git" reset --hard;"#,
    r#""git" push --force origin main;"#,
    r"'git' reset --hard;",
];

/// A command wrapper with a separator after the line. The whole-line reading
/// denied these before the single segment was read without its separator;
/// both readings are kept, deny wins.
const WRAPPED_GIT_BEFORE_A_SEPARATOR: &[&str] = &[
    "sudo git reset --hard;",
    "sudo git reset --hard ;",
    "sudo -u root git reset --hard;",
    "nice git reset --hard;",
    "sudo git clean -fdx;",
    "sudo git push --force;",
    "wsl git reset --hard;",
];

/// POSIX heredoc data that names a PowerShell block. Bash passes it to the
/// data sink, and PowerShell refuses `<<`, so neither runs it.
const BLOCK_TEXT_IN_HEREDOC_DATA: &[&str] = &[
    "cat > x.ps1 <<'EOF'\nif ($x) { git reset --hard }\nEOF",
    "cat > x.ps1 <<'EOF'\n& { git reset --hard }\nEOF",
    "cat > x.ps1 <<'EOF'\nfunction f { git reset --hard }; f\nEOF",
    "gh pr comment 9 --body-file - <<'EOF'\nPowerShell runs & { g\"it\" reset --hard }.\nEOF",
];

const HARMLESS: &[&str] = &[
    r#"function f { g"it" status }; f"#,
    r#"switch (1) { 1 { g"it" status } }"#,
    "for ($i=0; $i -lt 1; $i++) { git log -1 }",
    "class C { [void] m() { git status } }",
    "try\n{ git status } finally {}",
    "& { process { git status } }",
    "$h = @{ a = 1 }; switch (1) { 1 { $h } }",
    "sudo git status;",
    r#"& { g"it" log -1 }"#,
    "if ($x) { git status }",
    r#"foreach ($i in 1) { "reset --hard" }"#,
    r#"$sb = { Write-Output "git reset --hard" }"#,
    r"$sb = { Write-Output 'git reset --hard' }",
    r#"$sb = { Write-Output "git clean -fdx" }"#,
    r#"& { git commit -m "reset --hard" }"#,
    r#""git" status;"#,
    "git status;",
];

/// One quoted argument is one argv word, however many spaces it holds. The
/// Git view removed the quotes and joined the words with spaces, so the text
/// of one argument read as Git's own subcommand and flags. Bash runs none of
/// these as `git reset --hard` or `git clean -f`.
const QUOTED_TEXT_IN_ONE_ARGUMENT: &[&str] = &[
    r#"$sb = { Write-Output "git reset --hard" }"#,
    r"$sb = { Write-Output 'git reset --hard' }",
    r"$X 'reset --hard'",
    r#"git commit -m "x" "reset --hard""#,
    r#"git commit -m "fix: reset --hard bug""#,
    r#"git log --grep "reset --hard""#,
    r#"git stash push -m "clean -fdx later""#,
    r#"X=git; $X commit -m "reset --hard""#,
    r#"git clean -n -e "a b""#,
    r#"git clean -e "x y" -n"#,
];

/// POSIX only. Under `Unknown` the Git view is the raw text (the dialect may
/// be PowerShell), so the `-c` value's words still read as `reset --hard`
/// there. That over-deny predates this boundary (v0.16.0 and PR #9 block it
/// too) and errs safe; the Bash hook reads POSIX and allows it.
const QUOTED_TEXT_IN_ONE_ARGUMENT_POSIX: &[&str] = &[r#"git -c "a=b reset --hard" status"#];

/// The same boundary must not hide real Git syntax next to a quoted argument
/// with spaces, nor let its text supply a dry-run flag (`-e "-n foo"` is an
/// exclude pattern, so Git still cleans).
const GIT_NEXT_TO_QUOTED_TEXT: &[&str] = &[
    r#"git clean -e "-n foo" -fdx"#,
    r"git clean -e '-n foo' -fdx",
    r#"X=git; $X clean -e "-n foo" -fdx"#,
    r#"git clean -fdx -- "a b""#,
    r#"git -C "/tmp/a b" reset --hard"#,
    r#"git -c "user.name=A B" reset --hard"#,
    r#"git checkout -- "my file""#,
    r#"git branch -D "x y""#,
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
            "session_id": "sess-ps-block",
            "transcript_path": "/tmp/claude/transcript.jsonl",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "toolu_ps_block",
        }),
        // `turn_id` selects Codex's protocol.
        Protocol::Codex => serde_json::json!({
            "session_id": "019dd11d-b795-7261-a9cb-9b85a5dadf16",
            "turn_id": "turn-ps-block",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.5",
            "permission_mode": "default",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "call_ps_block",
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

fn assert_all(cases: &[&str], expected: &str, decide: impl Fn(&str) -> String, label: &str) {
    let misses: Vec<String> = cases
        .iter()
        .filter_map(|command| {
            let actual = decide(command);
            (actual != expected).then(|| format!("{label}: {command:?} -> {actual}"))
        })
        .collect();
    assert!(
        misses.is_empty(),
        "expected {expected}:\n{}",
        misses.join("\n")
    );
}

/// The PowerShell tool label, in both hook formats, on every host.
#[test]
fn powershell_tool_judges_block_command_words_both_protocols() {
    for protocol in [Protocol::Claude, Protocol::Codex] {
        let decide = |command: &str| hook_decision(protocol, "PowerShell", command);
        let label = format!("{protocol:?} PowerShell");
        assert_all(POWERSHELL_RUNS_GIT, "deny", decide, &label);
        assert_all(SEPARATOR_AFTER_QUOTED_GIT, "deny", decide, &label);
        assert_all(WRAPPED_GIT_BEFORE_A_SEPARATOR, "deny", decide, &label);
        assert_all(HARMLESS, "allow", decide, &label);
    }
}

/// The Bash label off Windows is POSIX: a separator after a quoted Git word
/// must not hide it there either.
#[test]
fn bash_tool_judges_quoted_git_before_a_separator_both_protocols() {
    for protocol in [Protocol::Claude, Protocol::Codex] {
        let decide = |command: &str| hook_decision(protocol, "Bash", command);
        let label = format!("{protocol:?} Bash");
        assert_all(SEPARATOR_AFTER_QUOTED_GIT, "deny", decide, &label);
        assert_all(SEPARATOR_AFTER_QUOTED_GIT_BASH_ONLY, "deny", decide, &label);
        assert_all(WRAPPED_GIT_BEFORE_A_SEPARATOR, "deny", decide, &label);
        assert_all(BLOCK_TEXT_IN_HEREDOC_DATA, "allow", decide, &label);
        assert_all(
            &[r#""git" status;"#, "git status;"],
            "allow",
            decide,
            &label,
        );
    }
}

/// Codex labels every command `Bash`. On Windows the hook resolves that label
/// to PowerShell or the PowerShell-or-POSIX union, which must deny what
/// PowerShell runs.
#[cfg(windows)]
#[test]
fn codex_bash_label_on_windows_judges_block_command_words() {
    let decide = |command: &str| hook_decision(Protocol::Codex, "Bash", command);
    assert_all(POWERSHELL_RUNS_GIT, "deny", decide, "Codex Bash on Windows");
    assert_all(
        SEPARATOR_AFTER_QUOTED_GIT,
        "deny",
        decide,
        "Codex Bash on Windows",
    );
    assert_all(
        WRAPPED_GIT_BEFORE_A_SEPARATOR,
        "deny",
        decide,
        "Codex Bash on Windows",
    );
    assert_all(
        BLOCK_TEXT_IN_HEREDOC_DATA,
        "allow",
        decide,
        "Codex Bash on Windows",
    );
    assert_all(HARMLESS, "allow", decide, "Codex Bash on Windows");
}

/// The dialects that may be PowerShell: the proven one and the union a
/// generic adapter (and Codex on Windows) gets.
#[test]
fn powershell_and_unknown_dialects_judge_block_command_words() {
    for dialect in [ShellDialect::PowerShell, ShellDialect::Unknown] {
        let decide = |command: &str| format!("{:?}", decision_in(command, dialect));
        let label = format!("{dialect:?}");
        assert_all(POWERSHELL_RUNS_GIT, "Deny", decide, &label);
        assert_all(SEPARATOR_AFTER_QUOTED_GIT, "Deny", decide, &label);
        assert_all(WRAPPED_GIT_BEFORE_A_SEPARATOR, "Deny", decide, &label);
        assert_all(HARMLESS, "Allow", decide, &label);
    }
    for dialect in [ShellDialect::Posix, ShellDialect::Unknown] {
        let decide = |command: &str| format!("{:?}", decision_in(command, dialect));
        let label = format!("{dialect:?}");
        assert_all(SEPARATOR_AFTER_QUOTED_GIT, "Deny", decide, &label);
        assert_all(SEPARATOR_AFTER_QUOTED_GIT_BASH_ONLY, "Deny", decide, &label);
        assert_all(WRAPPED_GIT_BEFORE_A_SEPARATOR, "Deny", decide, &label);
        assert_all(BLOCK_TEXT_IN_HEREDOC_DATA, "Allow", decide, &label);
    }
}

/// Windows PowerShell 5.1 ran harmless marker bodies in every one of these
/// layouts with LF, CRLF and lone CR. ScriptBlock literals remain inert.
fn multiline_control_cases() -> Vec<(String, bool)> {
    let layouts = [
        "if (1)\n{ BODY }",
        "if (\n1) { BODY }",
        "try\n{ BODY } catch { }",
        "foreach ($n in @(1))\n{ BODY }",
        "foreach(\n$n in @(1)) { BODY }",
        "foreach($n\nin @(1)) { BODY }",
        "foreach\n($n in @(1)) { BODY }",
        "while ($true)\n{ BODY; break }",
    ];
    let mut cases = Vec::new();
    for newline in ["\n", "\r\n", "\r"] {
        for layout in layouts {
            for (body, deny) in [
                ("git reset --hard", true),
                ("Remove-Item -Recurse -Force ./victim", true),
                ("Write-Output 1", false),
            ] {
                cases.push((layout.replace("BODY", body).replace('\n', newline), deny));
            }
        }
        for inert in [
            "$b = { git reset --hard }",
            "{ git reset --hard }",
            "$b = { if (1)\n{ git reset --hard } }",
        ] {
            cases.push((inert.replace('\n', newline), false));
        }
    }
    cases
}

#[test]
fn powershell_multiline_control_blocks_in_dialect_and_both_hook_protocols() {
    for (command, deny) in multiline_control_cases() {
        let expected = if deny {
            EvaluationDecision::Deny
        } else {
            EvaluationDecision::Allow
        };
        assert_eq!(
            decision_in(&command, ShellDialect::PowerShell),
            expected,
            "{command:?}"
        );
        for protocol in [Protocol::Claude, Protocol::Codex] {
            let expected = if deny { "deny" } else { "allow" };
            assert_eq!(
                hook_decision(protocol, "PowerShell", &command),
                expected,
                "{protocol:?}: {command:?}"
            );
        }
    }
}

/// Past the nesting depth the union's block gate fails closed, as the
/// PowerShell reading does.
#[test]
fn unknown_dialect_judges_deeply_nested_blocks() {
    for opener in ["& { ", "if (1) { "] {
        let command = format!(
            "{}g\"it\" reset --hard{}",
            opener.repeat(10),
            " }".repeat(10)
        );
        assert_eq!(
            decision_in(&command, ShellDialect::Unknown),
            EvaluationDecision::Deny,
            "{command}"
        );
    }
}

/// Expansions may produce several argv words, unlike a quoted literal. These
/// are shell source sent as hook data: this test never runs the commands.
#[test]
fn split_expansions_and_powershell_native_quote_boundaries() {
    let split = [
        "git reset ${X:-HEAD --hard}",
        "git reset ${X=HEAD --hard}",
        "git reset ${X:=HEAD --hard}",
        "git reset ${X:-HEAD  --hard}",
        "git reset ${X:-HEAD\t--hard}",
        "git reset ${X:-x} ${Y:-HEAD --hard}",
        "git push ${X:-origin main --force}",
        "git push origin ${X:-main --force}",
        "git checkout ${X:-HEAD -- .}",
        "cd /tmp && git reset ${X:-HEAD --hard}",
        "( git reset ${X:-HEAD --hard} )",
        "f() { git reset ${X:-HEAD --hard}; }; f",
        "git reset ${X:-\"HEAD\" --hard}",
        "git reset ${X:-'HEAD' --hard}",
        "git reset ${X:+HEAD --hard}",
        "git push ${X:+origin main --force}",
    ];
    let fixed_arguments = [
        r#"git reset "${X:-HEAD --hard}""#,
        r#"git commit -m "${X:-reset --hard}""#,
        r#"git commit -m "x" "reset --hard""#,
        r#"git log ${X:-"--grep=reset --hard"}"#,
    ];
    let powershell = [
        r#"git reset 'HEAD" --hard "--'"#,
        r#"git clean 'x" -fdx "y'"#,
        r#"git push 'origin" --force "main'"#,
        "git reset \"HEAD`\" --hard `\"--\"",
        r#"& git reset 'HEAD" --hard "--'"#,
        "git reset 'HEAD\" --hard \"--'; echo \"`$(\"",
    ];
    let posix = |command: &str| format!("{:?}", decision_in(command, ShellDialect::Posix));
    assert_all(&split, "Deny", posix, "POSIX expansion");
    assert_all(&fixed_arguments, "Allow", posix, "fixed POSIX argument");
    for protocol in [Protocol::Claude, Protocol::Codex] {
        let bash = |command: &str| hook_decision(protocol, "Bash", command);
        let ps = |command: &str| hook_decision(protocol, "PowerShell", command);
        assert_all(&split, "deny", bash, "unquoted POSIX expansion");
        assert_all(&fixed_arguments, "allow", bash, "fixed POSIX argument");
        assert_all(&powershell, "deny", ps, "PowerShell native argument");
        let nested = "bash -c 'git reset ${X:-HEAD --hard}'";
        assert_all(&[nested], "deny", ps, "nested POSIX under PowerShell");
        let cmd = |command: &str| hook_decision(protocol, "cmd", command);
        assert_all(&[nested], "deny", cmd, "nested POSIX under cmd");
    }
}

/// Text in an optional expansion is not proof that a safe flag reaches Git.
/// Only dcg reads these strings; this test does not execute their shell source.
#[test]
fn optional_expansion_cannot_grant_git_clean_dry_run_exemption() {
    let unsafe_commands = [
        "git clean -fdx ${X:-foo --dry-run}",
        "git clean -fdx ${X:+foo --dry-run}",
        "git clean -fdx ${X:-foo -n}",
        "( git clean -fdx ${X:-foo --dry-run} )",
    ];
    let safe_commands = [
        "git clean -n -fdx ${X:-foo}",
        "git clean --dry-run -fdx ${X:-foo}",
        "git clean -n ${FILES}",
        "git status ${X:-HEAD --hard}",
    ];
    let posix = |command: &str| format!("{:?}", decision_in(command, ShellDialect::Posix));
    assert_all(&unsafe_commands, "Deny", posix, "optional safe flag");
    assert_all(&safe_commands, "Allow", posix, "literal safe flag");
    for protocol in [Protocol::Claude, Protocol::Codex] {
        let bash = |command: &str| hook_decision(protocol, "Bash", command);
        assert_all(&unsafe_commands, "deny", bash, "optional safe flag");
        assert_all(&safe_commands, "allow", bash, "literal safe flag");
    }
}

/// A quoted argument with spaces stays one argument in the POSIX reading, and
/// in the union that adds it.
#[test]
fn quoted_argument_with_spaces_stays_one_word() {
    for dialect in [ShellDialect::Posix, ShellDialect::Unknown] {
        let decide = |command: &str| format!("{:?}", decision_in(command, dialect));
        let label = format!("{dialect:?}");
        assert_all(QUOTED_TEXT_IN_ONE_ARGUMENT, "Allow", decide, &label);
        assert_all(GIT_NEXT_TO_QUOTED_TEXT, "Deny", decide, &label);
    }
    let posix = |command: &str| format!("{:?}", decision_in(command, ShellDialect::Posix));
    assert_all(QUOTED_TEXT_IN_ONE_ARGUMENT_POSIX, "Allow", posix, "Posix");
    for protocol in [Protocol::Claude, Protocol::Codex] {
        let decide = |command: &str| hook_decision(protocol, "Bash", command);
        let label = format!("{protocol:?} Bash");
        assert_all(QUOTED_TEXT_IN_ONE_ARGUMENT, "allow", decide, &label);
        // Codex on a Windows host reads a Bash label as `Unknown`.
        if !cfg!(windows) {
            assert_all(QUOTED_TEXT_IN_ONE_ARGUMENT_POSIX, "allow", decide, &label);
        }
        assert_all(GIT_NEXT_TO_QUOTED_TEXT, "deny", decide, &label);
    }
}

/// An unquoted `${X:-word}`, `${X:=word}` or `${X:+word}` argument can give
/// its operand's fields as argv. Only dcg reads these strings.
#[test]
fn parameter_operand_fields_are_possible_git_argv() {
    let unsafe_commands = [
        "git clean ${X:--fdx}",
        "git clean ${X:--f -d -x}",
        "git push ${X:+--force} origin main",
        "git clean ${X:+-f -d -x}",
        "git stash ${X:-clear}",
        "git checkout ${X:--- .}",
        "git reset ${X:-x} ${Y:-HEAD --hard}",
    ];
    let safe_commands = [
        "git push ${X:+--dry-run} origin main",
        "git checkout ${BRANCH:-main}",
        "git log ${X:-\"--grep=reset --hard\"}",
    ];
    let posix = |command: &str| format!("{:?}", decision_in(command, ShellDialect::Posix));
    assert_all(&unsafe_commands, "Deny", posix, "operand fields");
    assert_all(&safe_commands, "Allow", posix, "harmless operand fields");
    for protocol in [Protocol::Claude, Protocol::Codex] {
        let bash = |command: &str| hook_decision(protocol, "Bash", command);
        assert_all(&unsafe_commands, "deny", bash, "operand fields");
        assert_all(&safe_commands, "allow", bash, "harmless operand fields");
    }
}
