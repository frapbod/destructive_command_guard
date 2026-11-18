//! PowerShell engine methods run a string as script, like `iex` and
//! `[scriptblock]::Create`: `$ExecutionContext.InvokeCommand.InvokeScript`
//! and `.NewScriptBlock` (also through `$ExecutionContext.SessionState`),
//! `[powershell]::Create().AddScript`, a runspace's `CreatePipeline` and
//! `CreateNestedPipeline`, a `Runspaces.Command` built with `isScript`,
//! `Parser::ParseInput`, and the `$( … )` inside `ExpandString`'s text.
//! dcg read their string argument as data, so
//! `$ExecutionContext.InvokeCommand.InvokeScript("git reset --hard")` passed
//! in the PowerShell dialect.

use destructive_command_guard::evaluator::evaluate_command_with_pack_order_at_path_in_dialect;
use destructive_command_guard::normalize::ShellDialect;
use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::{Config, EvaluationDecision, LayeredAllowlist};
use std::io::Write;
use std::process::{Command, Stdio};

const HOOK_TEST_TIMEOUT_MS: &str = "30000";

/// Each ran `git reset --hard` in sandboxed PowerShell 7.5
/// (`scripts/shell-truth pwsh`, fake git), Nov 18 2026.
const RUNS_IT: &[&str] = &[
    "$ExecutionContext.InvokeCommand.InvokeScript(\"git reset --hard\")",
    "$ExecutionContext.InvokeCommand.InvokeScript('git reset --hard')",
    "$ExecutionContext.InvokeCommand.NewScriptBlock(\"git reset --hard\").Invoke()",
    "$ExecutionContext.InvokeCommand.InvokeScript(\"git`vreset`v--hard\")",
    "$ExecutionContext.InvokeCommand.InvokeScript(\"git`treset`t--hard\")",
    "$ExecutionContext.InvokeCommand.InvokeScript(\"git`u{a0}reset`u{a0}--hard\")",
    "$ExecutionContext.InvokeCommand.InvokeScript(\"git status; git reset --hard\")",
    "$ExecutionContext.InvokeCommand.InvokeScript(('git ' + 'reset --hard'))",
    "[void]$ExecutionContext.InvokeCommand.InvokeScript('git reset --hard')",
    "$ExecutionContext.SessionState.InvokeCommand.InvokeScript('git reset --hard')",
    // The member name may be quoted, computed, or follow blank space or a
    // line break after the dot.
    "$ExecutionContext.InvokeCommand.'InvokeScript'('git reset --hard')",
    "$ExecutionContext.InvokeCommand.\"InvokeScript\"('git reset --hard')",
    "$ExecutionContext.InvokeCommand.(\"Invoke\"+\"Script\")('git reset --hard')",
    "$ExecutionContext.InvokeCommand. InvokeScript('git reset --hard')",
    "$ExecutionContext.InvokeCommand.\nInvokeScript('git reset --hard')",
    "$ExecutionContext.InvokeCommand?.InvokeScript('git reset --hard')",
    // Any expression can hold the object or the method.
    "$ic=$ExecutionContext.InvokeCommand; $ic.InvokeScript('git reset --hard')",
    "$m=$ExecutionContext.InvokeCommand.InvokeScript; $m.Invoke('git reset --hard')",
    "$ExecutionContext.InvokeCommand.InvokeScript.Invoke('git reset --hard')",
    // A name that is not static may be any of these methods.
    "$n='InvokeScript'; $ExecutionContext.InvokeCommand.$n('git reset --hard')",
    "$n='InvokeScript'; $ExecutionContext.InvokeCommand.${n}('git reset --hard')",
    "$n='InvokeScript'; $ExecutionContext.InvokeCommand.$n.Invoke('git reset --hard')",
    "$ExecutionContext.InvokeCommand.$('InvokeScript')('git reset --hard')",
    // ForEach-Object and the `.ForEach()` intrinsic call a member by name.
    // A statement may start with `@(` (rows from card t_e0f360c0, PR #32).
    "$x = $ExecutionContext.InvokeCommand; @($x).InvokeScript('git reset --hard')",
    "@($ExecutionContext.InvokeCommand).ForEach('InvokeScript', 'git reset --hard')",
    "$ExecutionContext.InvokeCommand | % InvokeScript 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | ForEach-Object -MemberName InvokeScript -ArgumentList 'git reset --hard'",
    "$ExecutionContext.InvokeCommand.ForEach('InvokeScript', 'git reset --hard')",
    "$a = @($ExecutionContext.InvokeCommand).ForEach('InvokeScript', 'git reset --hard')",
    "$ExecutionContext.InvokeCommand | % NewScriptBlock 'git reset --hard' | % Invoke",
    "[powershell]::Create() | % AddScript 'git reset --hard' | % Invoke",
    // Other overloads: extra arguments, and a script block to run.
    "$ExecutionContext.InvokeCommand.InvokeScript('git reset --hard', 1, 2)",
    "$ExecutionContext.InvokeCommand.InvokeScript($ExecutionContext.SessionState, {git reset --hard})",
    "$ExecutionContext.InvokeCommand.InvokeScript($false, {git reset --hard}, $null, $null)",
    "$ExecutionContext.InvokeCommand.InvokeScript($true, [scriptblock]::Create('git reset --hard'), $null, $null)",
    // Sources the static string reader does not take fail closed.
    "$ExecutionContext.InvokeCommand.InvokeScript(@'\ngit reset --hard\n'@)",
    "$ExecutionContext.InvokeCommand.InvokeScript(<#c#>'git reset --hard')",
    // NewScriptBlock builds a block that runs wherever it is invoked.
    "& $ExecutionContext.InvokeCommand.NewScriptBlock('git reset --hard')",
    "$sb=$ExecutionContext.InvokeCommand.NewScriptBlock('git reset --hard'); & $sb",
    // A PowerShell instance and a runspace pipeline run their script.
    "[powershell]::Create().AddScript('git reset --hard').Invoke()",
    "[System.Management.Automation.PowerShell]::Create().AddScript('git reset --hard').Invoke()",
    "$ps=[powershell]::Create(); [void]$ps.AddScript('git reset --hard'); $ps.Invoke()",
    "$p=[powershell]::Create(); $p.Commands.AddScript('git reset --hard'); $p.Invoke()",
    "[powershell]::Create().AddStatement().AddScript('git reset --hard').Invoke()",
    "$Host.Runspace.CreateNestedPipeline('git reset --hard', $false).Invoke()",
    "$r=[runspacefactory]::CreateRunspace(); $r.Open(); $p=$r.CreatePipeline('git reset --hard'); $p.Invoke()",
    // ExpandString runs the subexpressions in its text.
    "$ExecutionContext.InvokeCommand.ExpandString('$(git reset --hard)')",
    "$ExecutionContext.InvokeCommand.ExpandString(\"`$(git reset --hard)\")",
    "$ExecutionContext.InvokeCommand.ExpandString('a $(git reset --hard) b')",
    "$ExecutionContext.InvokeCommand.ExpandString('\"$(git reset --hard)\"')",
    // Inside a subexpression and a running block.
    "\"$($ExecutionContext.InvokeCommand.InvokeScript('git reset --hard'))\"",
    "& { $ExecutionContext.InvokeCommand.InvokeScript('git reset --hard') }",
    // A backtick line continuation after the dot.
    "$ExecutionContext.InvokeCommand.`\nInvokeScript('git reset --hard')",
    "$ExecutionContext.InvokeCommand.`\r\nInvokeScript('git reset --hard')",
    "$ic=$ExecutionContext.InvokeCommand; $ic.`\n  InvokeScript('git reset --hard')",
    // ForEach-Object binds positional words after -MemberName to -ArgumentList.
    "$ExecutionContext.InvokeCommand | ForEach-Object -MemberName InvokeScript 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % -MemberName InvokeScript 'git reset --hard'",
    "ForEach-Object -InputObject $ExecutionContext.InvokeCommand -MemberName:InvokeScript 'git reset --hard'",
    // ExpandString text with a line that would close a here-string early.
    "$ExecutionContext.InvokeCommand.ExpandString('x\n\"@\n''\n$(git reset --hard)\n''\n\"')",
    "$ExecutionContext.InvokeCommand.ExpandString(\"x`r`n`\"@`r`n'`r`n`$(git reset --hard)`r`n'`r`n`\"\")",
    // A pipeline made with no argument runs the script added to it.
    "$r=[runspacefactory]::CreateRunspace(); $r.Open(); $p=$r.CreatePipeline(); [void]$p.Commands.AddScript('git reset --hard'); [void]$p.Invoke()",
    // A Runspaces.Command built with isScript holds script that runs once added.
    "$ps=[powershell]::Create(); [void]$ps.Commands.AddCommand([System.Management.Automation.Runspaces.Command]::new('git reset --hard', $true)); [void]$ps.Invoke()",
    "$r=[runspacefactory]::CreateRunspace(); $r.Open(); $p=$r.CreatePipeline(); $p.Commands.Add([System.Management.Automation.Runspaces.Command]::new('git reset --hard', $true)); [void]$p.Invoke()",
    "$ps=[powershell]::Create(); [void]$ps.Commands.AddCommand([System.Management.Automation.Runspaces.Command]::new('git reset --hard', $true, $false)); [void]$ps.Invoke()",
    "$ps=[powershell]::Create(); [void]$ps.Commands.AddCommand([System.Management.Automation.Runspaces.Command]::new.Invoke('git reset --hard', $true)); [void]$ps.Invoke()",
    "using namespace System.Management.Automation.Runspaces\n$ps=[powershell]::Create(); [void]$ps.Commands.AddCommand([Command]::new('git reset --hard', $true)); [void]$ps.Invoke()",
    "$t=[System.Management.Automation.Runspaces.Command]; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($t::new('git reset --hard', $true)); [void]$ps.Invoke()",
    "$c = New-Object System.Management.Automation.Runspaces.Command('git reset --hard', $true); $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$c = New-Object System.Management.Automation.Runspaces.Command 'git reset --hard', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$c = New-Object -TypeName System.Management.Automation.Runspaces.Command -ArgumentList 'git reset --hard', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$c = New-Object -TypeName System.Management.Automation.Runspaces.Command -ArgumentList @('git reset --hard', $true); $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    // Parser.ParseInput builds an AST whose GetScriptBlock() runs it.
    "[System.Management.Automation.Language.Parser]::ParseInput('git reset --hard', [ref]$null, [ref]$null).GetScriptBlock().Invoke()",
    "$a=[System.Management.Automation.Language.Parser]::ParseInput('git reset --hard',[ref]$null,[ref]$null); & $a.GetScriptBlock()",
    "$p=[System.Management.Automation.Language.Parser]; $p::ParseInput('git reset --hard',[ref]$null,[ref]$null).GetScriptBlock().Invoke()",
    "using namespace System.Management.Automation.Language\n[Parser]::ParseInput('git reset --hard',[ref]$null,[ref]$null).GetScriptBlock().Invoke()",
    "[System.Management.Automation.Language.Parser]:: ParseInput('git reset --hard',[ref]$null,[ref]$null).GetScriptBlock().Invoke()",
    // An assembly-qualified or parenthesized type name is still that type.
    "$ps=[powershell]::Create(); [void]$ps.Commands.AddCommand([System.Management.Automation.Runspaces.Command, System.Management.Automation]::new('git reset --hard', $true)); [void]$ps.Invoke()",
    "$c = New-Object -TypeName 'System.Management.Automation.Runspaces.Command, System.Management.Automation' -ArgumentList 'git reset --hard', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$c = New-Object -TypeName ([System.Management.Automation.Runspaces.Command]) -ArgumentList 'git reset --hard', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$c = New-Object -TypeName ([System.Management.Automation.Runspaces.Command, System.Management.Automation]) -ArgumentList 'git reset --hard', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    // New-Object and `.Invoke` spread one array value into the constructor's
    // arguments; a value whose length is not visible may carry isScript.
    "$a = 'git reset --hard', $true; $c = New-Object System.Management.Automation.Runspaces.Command -ArgumentList $a; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$a = 'git reset --hard', $true; $c = New-Object System.Management.Automation.Runspaces.Command $a; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$a = 'git reset --hard', $true; $c = New-Object System.Management.Automation.Runspaces.Command($a); $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$a = 'git reset --hard', $true; $c = [System.Management.Automation.Runspaces.Command]::new.Invoke($a); $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$c = [System.Management.Automation.Runspaces.Command]::new.Invoke(@('git reset --hard', $true)); $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$c = [System.Management.Automation.Runspaces.Command]::new.Invoke(('git reset --hard', $true)); $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$c = New-Object System.Management.Automation.Runspaces.Command -ArgumentList ($a = 'git reset --hard', $true); $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$c = New-Object -TypeName System.Management.Automation.Runspaces.Command -ArgumentList $('git reset --hard', $true); $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    // A member or type name written as a group may hold blanks and commas.
    "$ExecutionContext.InvokeCommand | % -MemberName ('Invoke' + 'Script') 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | ForEach-Object ('Invoke' + 'Script') 'git reset --hard'",
    "$c = New-Object ([System.Management.Automation.Runspaces.Command, System.Management.Automation]) 'git reset --hard', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$c = New-Object -TypeName ('System.Management.Automation.Runspaces.Command, System.Management.Automation') -ArgumentList 'git reset --hard', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
];

/// None of these ran `git reset --hard` in sandboxed PowerShell 7.5.
const HARMLESS: &[&str] = &[
    "$ExecutionContext.InvokeCommand.InvokeScript(\"git status\")",
    "$n='InvokeScript'; $ExecutionContext.InvokeCommand.$n.Invoke(\"git status\")",
    "$ExecutionContext.InvokeCommand | % InvokeScript 'git status'",
    "Get-ChildItem | % Name",
    "Get-ChildItem | % { $_.Name }",
    "@(1, 2).ForEach({ $_ * 2 })",
    "@('a').ForEach('ToUpper')",
    "$ExecutionContext.InvokeCommand.NewScriptBlock('Write-Output ok')",
    "[powershell]::Create().AddScript('Get-Date').Invoke() | Out-Null",
    "$ExecutionContext.InvokeCommand.GetCommand('git', 'Application')",
    "Write-Output 'ExpandString InvokeScript NewScriptBlock AddScript'",
    "Write-Output '$ExecutionContext.InvokeCommand.InvokeScript(\"git reset --hard\")'",
    "Write-Output \"InvokeScript('git reset --hard')\"",
    "Write-Output 'use .InvokeScript() for x'",
    "Write-Output a.InvokeScript",
    "$r=[runspacefactory]::CreateRunspace(); $r.Open(); $p=$r.CreatePipeline(); [void]$p.Commands.AddScript('git status'); [void]$p.Invoke()",
    "$r=[runspacefactory]::CreateRunspace(); $r.Open(); $p=$r.CreatePipeline(); $p.Dispose()",
    "$ExecutionContext.InvokeCommand.NewScriptBlock()",
    "$ExecutionContext.InvokeCommand | ForEach-Object -MemberName InvokeScript 'git status'",
    "$ExecutionContext.InvokeCommand | % -MemberName InvokeScript 'git status'",
    "$ExecutionContext.InvokeCommand.ExpandString('a \"@ b')",
    "Get-ChildItem / | % -MemberName ('Na' + 'me') | Out-Null",
];

/// Harmless in PowerShell 7.5 too. The Unknown dialect denies these on base
/// 9a712556 and e94e3692 as well (its POSIX reading takes the quoted text as a command),
/// so they are checked in the PowerShell dialect only.
const HARMLESS_IN_POWERSHELL: &[&str] = &[
    // The second argument is data for the script's `$args`.
    "$ExecutionContext.InvokeCommand.InvokeScript(\"git status\", \"git reset --hard\")",
    // ExpandString keeps text as text, and an escaped or quoted `$( … )` too.
    "$ExecutionContext.InvokeCommand.ExpandString('git reset --hard')",
    "$ExecutionContext.InvokeCommand.ExpandString('`$(git reset --hard)')",
    "$ExecutionContext.InvokeCommand.ExpandString('$(\"git reset --hard\")')",
    // Script run as a Command or parsed AST, and a constructor of another type.
    "$r=[runspacefactory]::CreateRunspace(); $r.Open(); $p=$r.CreatePipeline(); $p.Commands.Add([System.Management.Automation.Runspaces.Command]::new('git status', $true)); [void]$p.Invoke()",
    "[System.Management.Automation.Language.Parser]::ParseInput('git status', [ref]$null, [ref]$null).GetScriptBlock().Invoke()",
    "$c = New-Object System.Management.Automation.Runspaces.Command('git status', $true); $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    // One argument is a command name, not script: this one is not found.
    "$ps=[powershell]::Create(); [void]$ps.Commands.AddCommand([System.Management.Automation.Runspaces.Command]::new('git reset --hard')); [void]$ps.Invoke()",
    "$w=New-Object System.Text.StringBuilder('git reset --hard', 100); $w.ToString()",
    // Other qualified type spellings, and a direct `::new` that passes the array
    // as one argument (a command name, not found).
    "$ps=[powershell]::Create(); [void]$ps.Commands.AddCommand([System.Management.Automation.Runspaces.Command, System.Management.Automation]::new('git status', $true)); [void]$ps.Invoke()",
    "$c = New-Object -TypeName ([System.Management.Automation.Runspaces.Command]) -ArgumentList 'git status', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$c = [System.Management.Automation.Runspaces.Command]::new.Invoke(@('git status', $true)); $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$a='git reset --hard',$true; $c=[System.Management.Automation.Runspaces.Command]::new($a); $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$c=[System.Management.Automation.Runspaces.Command]::new(@('git reset --hard',$true)); $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$c = New-Object System.Management.Automation.Runspaces.Command 'git reset --hard'; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$c = [System.Management.Automation.Runspaces.Command]::new.Invoke('git reset --hard'); $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$c = New-Object -TypeName ([System.Text.StringBuilder]) -ArgumentList 'git reset --hard', 100; $c.ToString()",
    "$ExecutionContext.InvokeCommand | % -MemberName ('Invoke' + 'Script') 'git status'",
    "$c = New-Object ([System.Text.StringBuilder]) 'git reset --hard', 100; $c.ToString()",
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
            "session_id": "sess-ps-engine",
            "transcript_path": "/tmp/claude/transcript.jsonl",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "toolu_ps_engine",
        }),
        // `turn_id` selects Codex's protocol.
        Protocol::Codex => serde_json::json!({
            "session_id": "019dd11d-b795-7261-a9cb-9b85a5dadf15",
            "turn_id": "turn-ps-engine",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.5",
            "permission_mode": "default",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "call_ps_engine",
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
fn powershell_tool_judges_engine_script_methods() {
    for protocol in [Protocol::Claude, Protocol::Codex] {
        for command in RUNS_IT {
            assert_eq!(
                hook_decision(protocol, "PowerShell", command),
                "deny",
                "{protocol:?}: {command:?}"
            );
        }
        for command in HARMLESS.iter().chain(HARMLESS_IN_POWERSHELL) {
            assert_eq!(
                hook_decision(protocol, "PowerShell", command),
                "allow",
                "{protocol:?}: {command:?}"
            );
        }
    }
}

/// Codex labels every command `Bash`; on Windows that resolves to PowerShell
/// or the PowerShell-or-POSIX union.
#[cfg(windows)]
#[test]
fn codex_bash_label_on_windows_judges_engine_script_methods() {
    for command in RUNS_IT {
        assert_eq!(
            hook_decision(Protocol::Codex, "Bash", command),
            "deny",
            "{command:?}"
        );
    }
}

#[test]
fn powershell_and_unknown_dialects_judge_engine_script_methods() {
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
    for command in HARMLESS_IN_POWERSHELL {
        assert_eq!(
            decision_in(command, ShellDialect::PowerShell),
            EvaluationDecision::Allow,
            "{command:?}"
        );
    }
}
