//! PowerShell expands variables and subexpressions in a double-quoted or bare
//! argument before cmd.exe starts. Measured with pwsh 7.5 (fake `cmd` that
//! records its argv): `cmd /c "gi$('')t reset --hard"` hands cmd
//! `git reset --hard`, and `$x = 'a & git reset --hard'; cmd /c "echo $x"`
//! hands it `echo a & git reset --hard`.

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
            "session_id": "sess-ps-cmd-values",
            "transcript_path": "/tmp/claude/transcript.jsonl",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "toolu_ps_cmd_values",
        }),
        // `turn_id` selects Codex's protocol.
        Protocol::Codex => serde_json::json!({
            "session_id": "019dd11d-b795-7261-a9cb-9b85a5dadf15",
            "turn_id": "turn-ps-cmd-values",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.5",
            "permission_mode": "default",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "call_ps_cmd_values",
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

/// A value PowerShell computes inside a cmd payload is unknown cmd text: a
/// top-level `cmd /c` fails closed on it, as on `%CD%`, so a value that
/// joins or spells a command (`gi$('')t`, `$x`) or carries cmd operators
/// (`a & git reset --hard`) cannot pass.
#[test]
fn powershell_values_in_a_cmd_payload_are_unknown_cmd_text() {
    let misses = expect_everywhere(
        &strings(&[
            r#"cmd /c "gi$('')t reset --hard""#,
            r#"& cmd /c "gi$([char]13)t reset --hard""#,
            r#"cmd /c "gi${c}t reset --hard""#,
            r#"cmd /c "gi$c`t reset --hard""#,
            r#"cmd /c "gi$env:NOPE`t reset --hard""#,
            r#"cmd /c "$x reset --hard""#,
            r#"cmd /c "gi$('')t clean -fdx""#,
            r#"cmd /k "gi$('')t reset --hard""#,
            r#"cmd.exe /c "gi$('')t reset --hard""#,
            r#"& cmd.exe /d /s /c "gi$('')t reset --hard""#,
            r#"C:\Windows\System32\cmd.exe /c "gi$('')t reset --hard""#,
            r#"cmd /c "echo ok & gi$('')t reset --hard""#,
            r#"cmd /c gi"$('')"t reset --hard"#,
            r#"cmd /c "r$('')d /s /q C:\src""#,
            r#"$x = 'a & git reset --hard'; cmd /c "echo $x""#,
            r#"$x = Get-Content f.txt; cmd /c "echo $x""#,
            r#"cmd /c "echo $(Remove-Item -Recurse -Force C:\src)""#,
            r#"cmd /c "cmd /c $x""#,
            r#"(cmd /c "gi$('')t reset --hard")"#,
            r#"(cmd /c "echo $(Remove-Item -Recurse -Force C:\src)")"#,
            r#"Start-Process cmd -ArgumentList "/c gi$x`t reset --hard""#,
            r#"Start-Process cmd -ArgumentList '/c', "gi${x}t reset --hard""#,
            r#"$x = 'a & git reset --hard'; $r = cmd /c "echo $x""#,
        ]),
        &PS,
        "PowerShell",
        EvaluationDecision::Deny,
    );
    assert!(misses.is_empty(), "misses:\n{}", misses.join("\n"));
}

/// A splat or an array is a list of arguments PowerShell computes (`$a =
/// 'git','reset','--hard'; cmd /c @a` hands cmd `/c git reset --hard`), and
/// a value where cmd reads its switches can be `/c` and its payload (`$a =
/// '/c','git reset --hard'; cmd $a`). Measured with pwsh 7.5.
#[test]
fn powershell_lists_and_values_in_cmd_switches_are_unknown() {
    let misses = expect_everywhere(
        &strings(&[
            r"$a = 'git','reset','--hard'; cmd /c @a",
            r"$a = 'reset','--hard'; cmd /c git @a",
            r"cmd /c @('git','reset','--hard')",
            r"$a = '/c','git reset --hard'; cmd $a",
            r"$a = '/c','git reset --hard'; cmd @a",
            r"cmd /d $x",
            r#"cmd "$x""#,
            r"cmd.exe /d /s @a",
        ]),
        &PS,
        "PowerShell",
        EvaluationDecision::Deny,
    );
    assert!(misses.is_empty(), "misses:\n{}", misses.join("\n"));
}

/// An outer PowerShell expands its values in a PowerShell host's payload
/// before the host reads it: `$x = 'git reset --hard'; powershell -c "$x"`
/// runs git, and `powershell -c "Write-Output '$x'"` with `$x = "'; git
/// reset --hard; '"` hands the host `Write-Output ''; git reset --hard;
/// ''` (pwsh 7.5).
#[test]
fn powershell_values_in_a_powershell_host_payload_are_unknown_code() {
    let misses = expect_everywhere(
        &strings(&[
            r#"$x = 'git reset --hard'; powershell -c "$x""#,
            r#"pwsh -c "$x""#,
            r#"powershell -Command "$x""#,
            r"powershell -c $x",
            r"powershell $x",
            r#"$x = "'; git reset --hard; '"; powershell -c "Write-Output '$x'""#,
            r"$a = '-c','git reset --hard'; pwsh $a",
            r"pwsh @a",
            r"pwsh -NoProfile -c @a",
            r"pwsh -WorkingDirectory @a",
        ]),
        &[ShellDialect::PowerShell],
        "PowerShell",
        EvaluationDecision::Deny,
    );
    assert!(misses.is_empty(), "misses:\n{}", misses.join("\n"));
}

/// PowerShell performs the redirections written on the launcher call, so a
/// stream merge (`2>&1`, which its tokenizer splits at the `&`) does not end
/// the launcher reading: the payload is judged as without it.
#[test]
fn powershell_redirections_on_a_launcher_call_are_not_its_payload() {
    let deny = expect_everywhere(
        &strings(&[
            r#"$x = 'a & git reset --hard'; cmd /c "echo $x" 2>&1"#,
            r#"cmd /c "echo $x" *>&1"#,
            r#"cmd /c "dir %CD%" 2>&1"#,
            r#"cmd /k "echo %X%" *>&1"#,
            r#"cmd /c "git reset --hard" 2>&1"#,
            r#"cmd /c "git reset --hard" 2>$null"#,
            r#"pwsh -c "git reset --hard" 2>&1"#,
            r#"pwsh -c "$x" 2>&1"#,
        ]),
        &[ShellDialect::PowerShell],
        "PowerShell",
        EvaluationDecision::Deny,
    );
    let allow = expect_everywhere(
        &strings(&[
            r"cmd /c ver 2>$null",
            r"cmd /c ver 2>&1",
            r#"cmd /c "git status" 2>&1 | Out-Null"#,
            r"pwsh -NoProfile -c 'Get-Date' *> $null",
        ]),
        &[ShellDialect::PowerShell],
        "PowerShell",
        EvaluationDecision::Allow,
    );
    assert!(
        deny.is_empty() && allow.is_empty(),
        "deny misses:\n{}\nallow misses:\n{}",
        deny.join("\n"),
        allow.join("\n")
    );
}

/// The same rule makes a harmless-looking value fail closed: its text is not
/// known before PowerShell runs, exactly like the cmd variable beside it.
#[test]
fn harmless_powershell_values_fail_closed_like_cmd_variables() {
    let misses = expect_everywhere(
        &strings(&[
            r#"cmd /c "dir $PWD""#,
            r#"cmd /c "echo $env:USERNAME""#,
            r#"cmd /c "echo $($env:USERNAME)""#,
            r#"cmd /c "dir %CD%""#,
        ]),
        &[ShellDialect::PowerShell],
        "PowerShell",
        EvaluationDecision::Deny,
    );
    assert!(misses.is_empty(), "misses:\n{}", misses.join("\n"));
}

/// Text PowerShell does not expand reaches the program as written: single
/// quotes, a backtick-escaped `$`, a `$` before a blank, everything after
/// `--%`, a single-quoted Start-Process element and a single-quoted
/// PowerShell host payload. A `$` or `@` that starts no value stays text
/// (`"gi$@t"` and `"gi@(1)t"` reach cmd as written, pwsh 7.5).
#[test]
fn text_powershell_does_not_expand_stays_as_written() {
    let misses = expect_everywhere(
        &strings(&[
            r"cmd /c 'gi$('')t reset --hard'",
            r#"cmd /c "gi`$('')t status""#,
            r"cmd /c --% gi$('')t status",
            r#"cmd /c "echo cost $ 5""#,
            r#"cmd /c "git status""#,
            r#"Write-Output "gi$('')t reset --hard""#,
            r#"cmd /c "gi$@t status""#,
            r#"cmd /c "gi@(1)t status""#,
            r"Start-Process cmd -ArgumentList '/c', 'echo $x'",
            r"Start-Process cmd -ArgumentList '/c dir'",
            r"pwsh -c '$PSVersionTable.PSVersion'",
        ]),
        &[ShellDialect::PowerShell],
        "PowerShell",
        EvaluationDecision::Allow,
    );
    assert!(misses.is_empty(), "misses:\n{}", misses.join("\n"));
}

/// A `( … )`, `$( … )` or `@( … )` argument is an expression whose value
/// PowerShell hands the program, wherever it stands: `$a = '/c','git reset
/// --hard'; cmd ($a)` hands cmd `/c` `git reset --hard`, `$x = '&git'; cmd
/// /c ver $($x) reset --hard` hands it `/c ver &git reset --hard`, and `$a =
/// '-c','git reset --hard'; pwsh ($a)` runs git (pwsh 7.5). The tokenizer
/// ends a segment at the parenthesis, which dropped the word.
#[test]
fn parenthesized_arguments_to_a_launcher_are_powershell_values() {
    let deny = expect_everywhere(
        &strings(&[
            // Where cmd reads its switches.
            r"$a = '/c','git reset --hard'; cmd $($a)",
            r"$a = '/c','git reset --hard'; cmd ($a)",
            r"$a = '/c','git reset --hard'; cmd @($a)",
            r"$a = '/c','git reset --hard'; cmd.exe $(,$a)",
            r"cmd /d (Get-Content args.txt)",
            r"cmd $($x) /c ver",
            // In cmd's payload, after its first word.
            r"$x = '&git'; cmd /c ver $($x) reset --hard",
            r"$x = '&git'; cmd /c ver ($x) reset --hard",
            r"$x = '&git'; cmd /c ver ($x)reset --hard",
            r"$x = '&git'; cmd /c ver hi$($x) reset --hard",
            r"$x = '&git'; cmd /c ver `$($x) reset --hard",
            r"$a = 'reset','--hard'; cmd /c git @($a)",
            r"$x = '&git'; & cmd /c ver $($x) reset --hard 2>&1",
            r"cmd /c ver $(Get-Date)",
            r"$r = cmd /c ver ($x)",
            // Where a PowerShell host reads its options.
            r"$a = '-c','git reset --hard'; pwsh $($a)",
            r"$a = '-c','git reset --hard'; pwsh ($a)",
            r"pwsh @($a)",
            r"powershell -NoProfile ($a)",
            r"pwsh -NoProfile $(Get-Content args.txt)",
        ]),
        &PS,
        "PowerShell",
        EvaluationDecision::Deny,
    );
    // A launcher inside a group, or a group in the next statement, is not
    // an argument of the call.
    let allow = expect_everywhere(
        &strings(&[
            r"if (cmd /c ver) { 'x' }",
            r"Write-Output (cmd /c ver)",
            r"cmd /c ver; (Get-Date)",
            r"foreach ($l in (cmd /c dir)) { $l }",
            r#"cmd /c "echo (hi)""#,
            r"pwsh -File build.ps1 (Get-Date)",
        ]),
        &[ShellDialect::PowerShell],
        "PowerShell",
        EvaluationDecision::Allow,
    );
    assert!(
        deny.is_empty() && allow.is_empty(),
        "deny misses:\n{}\nallow misses:\n{}",
        deny.join("\n"),
        allow.join("\n")
    );
}

/// After PowerShell's `--%` cmd receives the rest of the line as written,
/// so a `--%` where cmd reads its switches still leads to `/c`: `cmd --% /c
/// git reset --hard` hands cmd `/c git reset --hard` (pwsh 7.5).
#[test]
fn stop_parsing_before_cmd_switches_keeps_the_payload() {
    let deny = expect_everywhere(
        &strings(&[
            r"cmd --% /c git reset --hard",
            r"cmd /d --% /c git reset --hard",
            r"cmd '--%' /c git reset --hard",
            r#"cmd --% /c "git reset --hard""#,
            r"cmd --% /c git reset --hard 2>&1",
            r"cmd --% /c echo %X%",
        ]),
        &PS,
        "PowerShell",
        EvaluationDecision::Deny,
    );
    let allow = expect_everywhere(
        &strings(&[
            r"cmd --% /c ver",
            r"cmd --% /c echo $x",
            r"cmd /d --% /c dir",
        ]),
        &[ShellDialect::PowerShell],
        "PowerShell",
        EvaluationDecision::Allow,
    );
    assert!(
        deny.is_empty() && allow.is_empty(),
        "deny misses:\n{}\nallow misses:\n{}",
        deny.join("\n"),
        allow.join("\n")
    );
}

/// Review round 3, item 1. Only a `--%` that does not start with a quote
/// stops PowerShell's parsing. A quoted `'--%'` or `"--%"` is dropped from
/// cmd's argv, and PowerShell still expands the values after it: `$x = 'a &
/// git reset --hard'; cmd '--%' /c "echo $x"` hands cmd `/c echo a & git
/// reset --hard`, and `Write-Output '--%'; git reset --hard` runs git
/// (pwsh 7.5, fake cmd and git).
#[test]
fn a_quoted_stop_parsing_token_does_not_stop_expansion() {
    let deny = expect_everywhere(
        &strings(&[
            r#"$x = 'a & git reset --hard'; cmd '--%' /c "echo $x""#,
            r#"$x = 'a & git reset --hard'; cmd "--%" /c "echo $x""#,
            r#"$x = 'a & git reset --hard'; cmd /d '--%' /c "echo $x""#,
            r#"$x = 'a & git reset --hard'; cmd '--%' /c "echo $x" 2>&1"#,
            r"$x = 'git reset --hard'; cmd '--%' /c $x",
            r"$a = '/c','git reset --hard'; cmd '--%' @a",
            r"$a = '/c','git reset --hard'; cmd '--%' $a",
            r"$x = 'git reset --hard'; cmd '--%' /c ($x)",
            r"$a = 'reset','--hard'; cmd '--%' /c git @a",
            r"$x = '&git'; cmd /c ver '--%' $x reset --hard",
            r"cmd '--%' /c git reset --hard",
            // Before a parameter word a quoted `'--%'` stops parsing like a
            // bare one: pwsh receives `$x` as written, not `-c` and the
            // value (pwsh 7.5). The host reader fails closed on a
            // stop-parsing token where it reads its options.
            r"$x = 'git reset --hard'; pwsh '--%' -c $x",
            r"$x = 'git reset --hard'; pwsh -NoProfile '--%' -c $x",
            // So it fails closed on a harmless payload too, as on `pwsh --%
            // -c 'Get-Date'`.
            r"pwsh '--%' -c 'Get-Date'",
        ]),
        &PS,
        "PowerShell",
        EvaluationDecision::Deny,
    );
    // The same misreading ended the statement's parsing: the next statement
    // was read as text.
    let deny_statements = expect_everywhere(
        &strings(&[
            r"Write-Output '--%'; git reset --hard",
            r"cmd '--%' /c ver; git reset --hard",
            r"git '--%' reset `--hard",
        ]),
        &[ShellDialect::PowerShell],
        "PowerShell",
        EvaluationDecision::Deny,
    );
    // A bare or backtick-spelled `--%` stops parsing: cmd receives `$x` and
    // `@a` as written.
    let allow = expect_everywhere(
        &strings(&[
            r#"$x = 'a & git reset --hard'; cmd --% /c "echo $x""#,
            r#"$x = 'a & git reset --hard'; cmd `--% /c "echo $x""#,
            r"$a = 'reset','--hard'; cmd --% /c git @a",
            r"Write-Output '--%'",
            r"git '--%' status",
            r"Write-Output '--%'; git status",
            r"pwsh '--%' 'Get-Date'",
        ]),
        &[ShellDialect::PowerShell],
        "PowerShell",
        EvaluationDecision::Allow,
    );
    assert!(
        deny.is_empty() && deny_statements.is_empty() && allow.is_empty(),
        "deny misses:\n{}\n{}\nallow misses:\n{}",
        deny.join("\n"),
        deny_statements.join("\n"),
        allow.join("\n")
    );
}

/// Review round 4. A quoted `'--%'` followed by a parameter word does stop
/// PowerShell's parsing: the parser peeks at the token after the quoted
/// string and enters verbatim mode when it is a parameter, which it drops
/// (`Parser.cs` `GetVerbatimCommandArgumentToken`). `cmd '--%' -x /c git
/// reset --hard` hands cmd `/c git reset --hard`, and `cmd '--%' -x /c ver #
/// & git status` hands it `/c ver # & git status`: no comment, no separator
/// (pwsh 7.5, fake cmd and git).
#[test]
fn a_quoted_stop_parsing_token_before_a_parameter_stops_parsing() {
    let deny = expect_everywhere(
        &strings(&[
            r"cmd '--%' -x /c git reset --hard",
            r#"cmd "--%" -x /c git reset --hard"#,
            r"cmd '--%' -x /c echo 'a & git reset --hard & '",
            r#"cmd '--%' -d /c "git reset --hard""#,
            r#"cmd '--%' -x /c "echo a & git reset --hard""#,
            r"cmd /d '--%' -x /c git reset --hard",
            r"cmd '--%'-x /c git reset --hard",
            "cmd '--%' \u{2013}x /c git reset --hard",
            r"cmd '--%' -x: /c git reset --hard",
            r"& cmd '--%' -x /c git reset --hard",
            r"cmd '--%' -NoProfile /c git reset --hard",
            // Verbatim text has no comments and no statement separators.
            r"cmd '--%' -x /c ver # & git reset --hard",
            r"cmd '--%' -x /c ver <# c #> & git reset --hard",
            // The parameter may follow a line continuation or a block
            // comment, and it ends before `.`, `(` and `,` and after `:`
            // (`-x.y` hands cmd `.y`), or takes the rest of a glued word.
            "cmd '--%' `\n -x /c ver # & git reset --hard",
            r"cmd '--%' <# c #> -x /c ver # & git reset --hard",
            r"cmd /c ver '--%' -x # & git reset --hard",
            r"cmd /c ver '--%' -x.y # & git reset --hard",
            r"cmd /c ver '--%' -x(1) # & git reset --hard",
            r"cmd /c ver '--%' -x:y # & git reset --hard",
            r"cmd /c ver '--%' -x,y # & git reset --hard",
            r"cmd /c ver '--%'-x/c # & git reset --hard",
            // Any program: git receives `reset --hard`.
            r"git '--%' -x reset --hard",
            // The host reads its options as written: fail closed.
            r#"pwsh '--%' -x -c "git reset --hard""#,
            r#"powershell -NoProfile '--%' -x -c "git reset --hard""#,
        ]),
        &PS,
        "PowerShell",
        EvaluationDecision::Deny,
    );
    // The Unknown reading allows `cmd /c rd /s /q C:\src` itself (base).
    let deny_ps = expect_everywhere(
        &strings(&[
            r"cmd '--%' -x /c rd /s /q C:\src",
            r"cmd /d '--%' -x /c ver # & rd /s /q C:\src",
        ]),
        &[ShellDialect::PowerShell],
        "PowerShell",
        EvaluationDecision::Deny,
    );
    let allow = expect_everywhere(
        &strings(&[
            r"cmd '--%' -x /c ver",
            r"cmd '--%' -x /c echo $x",
            // Verbatim text ends at a pipe or `&&`.
            r"cmd '--%' -x /c ver | Select-String x",
            // No parameter after the quoted marker: parsing goes on, and
            // `-x'y'`, `--x`, `-1` and `-` are not parameters.
            r"cmd '--%' /c ver # & git reset --hard",
            r"Write-Output '--%' --x # & git reset --hard",
            r"cmd '--%' -x'y' /c ver # & git reset --hard",
            r"cmd '--%' -1 /c ver # & git reset --hard",
            r"cmd '--%' - /c ver # & git reset --hard",
        ]),
        &[ShellDialect::PowerShell],
        "PowerShell",
        EvaluationDecision::Allow,
    );
    assert!(
        deny.is_empty() && deny_ps.is_empty() && allow.is_empty(),
        "deny misses:\n{}\n{}\nallow misses:\n{}",
        deny.join("\n"),
        deny_ps.join("\n"),
        allow.join("\n")
    );
}

/// Review round 5. PowerShell checks for a quoted `'--%'` only in its
/// command-argument loop. Where the string is an expression (a statement
/// start, after `=`, inside `( )`, in `if ( )`, an array or a method call),
/// the word after it is an operator and the line goes on: each row below
/// runs git (pwsh 7.5, fake git). dcg judges the line both ways, deny wins.
#[test]
fn a_quoted_stop_parsing_token_in_an_expression_does_not_stop_parsing() {
    let deny = expect_everywhere(
        &strings(&[
            r"'--%' -f 1; git reset --hard",
            r"$a = '--%' -f 1; git reset --hard",
            r"Write-Output ('--%' -replace 'x','y'); git reset --hard",
            r"if ('--%' -eq $x) { 1 }; git reset --hard",
            r"$a = '--%' -join ','; git reset --hard",
            r#""--%" -like '*'; git reset --hard"#,
            r"[string]'--%' -f 1; git reset --hard",
            r"@('--%' -f 1); git reset --hard",
            r"$h = @{a='--%' -f 1}; git reset --hard",
            r"$a = '--%' -split 'x'; git reset --hard",
            r"$b = '--%' -ne 'a'; git reset --hard",
            r"$a = 1, '--%' -f 1; git reset --hard",
            r"$a = '--%' -f 1 & git reset --hard",
            r"'--%' -f 1 && git reset --hard",
            r"$a = '--%' -f 1 | ForEach-Object { git reset --hard }",
            r"$a = '--%'-f 1; git reset --hard",
            r"$a = '--%' -match 'x'; git reset --hard",
            r"if ('--%' -match 'x') { git reset --hard }",
            r"while ('--%' -ne '--%') {}; git reset --hard",
            r"$x.Replace('--%' -f 1, 'y'); git reset --hard",
            r#"$a = '--%' -f 1; cmd /c "git reset --hard""#,
            r#"$x = 'a & git reset --hard'; $a = '--%' -f 1; cmd /c "echo $x""#,
            r"$a = '--%' -f 1; cmd /c git reset --hard",
            // Each marker is read both ways, one after the other.
            r"$a = '--%' -f 1; $b = '--%' -f 2; git reset --hard",
            r"$a = '--%' -f 1; cmd '--%' -x /c ver # & git reset --hard",
        ]),
        &PS,
        "PowerShell",
        EvaluationDecision::Deny,
    );
    let deny_ps = expect_everywhere(
        &strings(&[
            r"$a = '--%' -f 1; Remove-Item -Recurse -Force C:\src",
            r#"$s = "--%" -replace '%',''; Remove-Item -Recurse -Force C:\src"#,
            // As a command argument the marker starts verbatim text and git
            // does not run; read both ways, this denies (accepted over-deny).
            r"Write-Output '--%' -x; git reset --hard",
            r"Write-Output '--%' -f 1; git reset --hard",
            // cmd receives `/c echo ^& git reset --hard`, an escaped `&`; read
            // as an expression, `&` ends the statement.
            r"cmd /c echo '--%' -x ^& git reset --hard",
        ]),
        &[ShellDialect::PowerShell],
        "PowerShell",
        EvaluationDecision::Deny,
    );
    let allow = expect_everywhere(
        &strings(&[
            r"$a = '--%' -f 1; git status",
            r"'--%' -f 1",
            r"cmd '--%' -x /c ver",
            r"cmd '--%' -x /c ver | Select-String x",
        ]),
        &[ShellDialect::PowerShell],
        "PowerShell",
        EvaluationDecision::Allow,
    );
    assert!(
        deny.is_empty() && deny_ps.is_empty() && allow.is_empty(),
        "deny misses:\n{}\n{}\nallow misses:\n{}",
        deny.join("\n"),
        deny_ps.join("\n"),
        allow.join("\n")
    );
}

/// Review round 3, item 2. Under Unknown the segments are POSIX's, which
/// do not end where a PowerShell group starts, so a cmd call that starts a
/// statement inside `( … )` was never read as a launcher. Codex's `Bash`
/// tool on Windows runs PowerShell and reads these commands (they parse as
/// POSIX) in the Unknown dialect. `$x='&git'; $y = (cmd /c "ver $x reset
/// --hard")` hands cmd `/c ver &git reset --hard` (pwsh 7.5).
#[test]
fn the_unknown_reading_finds_launchers_inside_powershell_groups() {
    let deny = expect_everywhere(
        &strings(&[
            r#"$x='&git'; $y = (cmd /c "ver $x reset --hard")"#,
            r#"$x='&git'; (cmd /c "ver $x reset --hard")"#,
            r#"$x='&git'; (cmd /c "ver $x reset --hard").Length"#,
            r#"$x='&git'; @(cmd /c "ver $x reset --hard")"#,
            r#"$x='&git'; [string](cmd /c "ver $x reset --hard")"#,
            r#"$x='&git'; Write-Output ((cmd /c "ver $x reset --hard"))"#,
            r#"$x='&git'; if (cmd /c "ver $x reset --hard") { 1 }"#,
            r#"$x='&git'; while (cmd /c "ver $x reset --hard") { break }"#,
            r#"$x='&git'; foreach ($l in (cmd /c "ver $x reset --hard")) { $l }"#,
            r#"$x='&git'; -not (cmd /c "ver $x reset --hard")"#,
            r"$x='&git'; Write-Output (cmd /c ver $($x) reset --hard)",
            r"$x='&git'; $y = (cmd /c ver $x reset --hard)",
            r"$a='/c','ver','&git'; Write-Output (cmd @a reset --hard)",
            r#"$x='git reset --hard'; $y = (pwsh -c "$x")"#,
            r"$y = (cmd /c git reset --hard)",
        ]),
        &PS,
        "PowerShell",
        EvaluationDecision::Deny,
    );
    let allow_ps = expect_everywhere(
        &strings(&[
            r"if (cmd /c ver) { 1 }",
            r"$v = (cmd /c ver)",
            r"Write-Output (cmd /c ver)",
            r"$y = @(cmd /c dir)",
            r"foreach ($l in (cmd /c dir)) { $l }",
            r#"cmd.exe /c "echo (hi)""#,
            r"$r = (pwsh -NoProfile -c 'Get-Date')",
        ]),
        &PS,
        "PowerShell",
        EvaluationDecision::Allow,
    );
    // POSIX commands with groups keep their verdict.
    let allow_posix = expect_everywhere(
        &strings(&[
            r"echo $(date) (x)",
            r#"python -c "print(1)""#,
            r"git log --format='%h (%s)'",
            r"find . \( -name a -o -name b \) -print",
            r"(cd sub && make)",
        ]),
        &[ShellDialect::Unknown, ShellDialect::Posix],
        "Bash",
        EvaluationDecision::Allow,
    );
    assert!(
        deny.is_empty() && allow_ps.is_empty() && allow_posix.is_empty(),
        "deny misses:\n{}\nallow misses:\n{}\n{}",
        deny.join("\n"),
        allow_ps.join("\n"),
        allow_posix.join("\n")
    );
}
