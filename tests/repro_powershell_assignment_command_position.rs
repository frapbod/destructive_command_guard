//! PowerShell runs the value of an assignment as a pipeline: `$c=iex 'git
//! reset --hard'`, `$null = Remove-Item -Recurse -Force .git`, `$c[ 0 ]=git
//! reset --hard` and `@{a=git reset --hard}` run their command (pwsh 7.5
//! measured in the sandbox for every RUNS_IT row; Windows PowerShell 5.1
//! parses assignments the same way). dcg's readers and packs each found a
//! statement's command by themselves: the tokenizer kept `$c=iex` as one
//! word, several readers wanted `$name =` as separate words, the filesystem
//! pack skipped every statement starting with `$name =`, and none read a
//! target with a blank inside (`$c[ 0 ]`, `$a, $b`) or a hashtable value.
//!
//! A deny-only PowerShell view now ends each assignment's target at its
//! operator (`$c=iex '…'` reads as `$c;iex '…'`), wherever the target stands,
//! so every reader and pack judges the value as a command. Only a value that
//! PowerShell parses in command mode (a bare word, `&` or `.`) is split off;
//! an expression (`$y=$x*2`, `$x = $(Get-Date)`) stays as written. Targets:
//! variables (`${c}`, `$env:C`, Unicode names), members (`.p`, `.'p'`, `.$n`,
//! `.$('p')`), indexes, type constraints, static properties, hashtable keys
//! and `(expr).p`; brackets and braced names may hold blanks (`$c[$i + 1]`,
//! `[Dictionary[string, int]]$c`, `${c d}`). A comment glued between target
//! and operator (`$c<#x#>=`) is not covered yet. An argument spelled like an
//! assignment has its value judged as a command too: `Write-Output $c=iex
//! 'git reset --hard'` denies, as `Write-Output $c = iex '…'` already did on
//! base, although PowerShell only prints it.

use destructive_command_guard::evaluator::evaluate_command_with_pack_order_at_path_in_dialect;
use destructive_command_guard::normalize::ShellDialect;
use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::{Config, EvaluationDecision, LayeredAllowlist};
use std::io::Write;
use std::process::{Command, Stdio};

const HOOK_TEST_TIMEOUT_MS: &str = "30000";

/// pwsh 7.5 runs `git reset --hard` for each (sandboxed, fake `git`).
const RUNS_IT: &[&str] = &[
    // Glued to the target, the value, or both (the card's row first).
    "$c=iex 'git reset --hard'",
    "$c =iex 'git reset --hard'",
    "$c=iex \"git reset --hard\"",
    "$c=Invoke-Expression 'git reset --hard'",
    "$c=iex 'git reset --hard'|Out-Null",
    "$c=iex 'git reset --hard' 2>&1",
    "$c=iex 'git reset --hard' # note",
    "<#x#>$c=iex 'git reset --hard'",
    "$c=iex 'Write-Output hi; git reset --hard'",
    // Every assignment operator and target shape.
    "$c+=iex 'git reset --hard'",
    "$c-=iex 'git reset --hard'",
    "$c*=iex 'git reset --hard'",
    "$c??=iex 'git reset --hard'",
    "[string]$c=iex 'git reset --hard'",
    "[string] $c=iex 'git reset --hard'",
    "[int[]]$c=iex 'git reset --hard; 1'",
    "${c}=iex 'git reset --hard'",
    "$global:c=iex 'git reset --hard'",
    "$env:C=iex 'git reset --hard'",
    "$a=$b=iex 'git reset --hard'",
    "$a = $b=iex 'git reset --hard'",
    "$a,$b=iex 'git reset --hard'",
    "$a, $b=iex 'git reset --hard'",
    "$c.p=iex 'git reset --hard'",
    "$c=@(1); $c[0]=iex 'git reset --hard'",
    "$h=@{}; $h['k']=iex 'git reset --hard'",
    "[System.Environment]::CurrentDirectory=iex 'git reset --hard'",
    "$c=@{a=iex 'git reset --hard'}",
    // Every statement start: separators, blocks, parentheses.
    "echo hi;$c=iex 'git reset --hard'",
    "echo hi\n$c=iex 'git reset --hard'",
    "$c=1 ; $d=2; $e=iex 'git reset --hard'",
    "if(1){$c=iex 'git reset --hard'}",
    "if (1) { $c=iex 'git reset --hard' }",
    "if(1){'a'}$c=iex 'git reset --hard'",
    "if(0){'a'}else{$c=iex 'git reset --hard'}",
    "foreach($i in 1){$c=iex 'git reset --hard'}",
    "try{$c=iex 'git reset --hard'}finally{}",
    "& {$c=iex 'git reset --hard'}",
    "while($c=iex 'git reset --hard'){break}",
    "for($c=iex 'git reset --hard';$false;){}",
    "Write-Output ($c=iex 'git reset --hard')",
    "Write-Output $($c=iex 'git reset --hard')",
    // Other commands after an assignment, glued or spaced: the script-block
    // consumers, `iex` forms and aliases read the command word there too.
    "$c=Invoke-Expression -Command 'git reset --hard'",
    "$c=iex('git reset --hard')",
    "$c=iex `\n'git reset --hard'",
    "$c=icm {git reset --hard}",
    "$c=.{git reset --hard}",
    "$c=ForEach-Object -InputObject 1 -Process {git reset --hard}",
    "$c=Start-Job {git reset --hard}|Wait-Job",
    "$c = icm {git reset --hard}",
    "$c = Start-Job {git reset --hard}|Wait-Job",
    "$c = iex('git reset --hard')",
    "[string] $c = icm {git reset --hard}",
    "$a, $b = icm {git reset --hard}",
    "$a = $b = icm {git reset --hard}",
    "if(1){$c = icm {git reset --hard}}",
    "$c=sal x iex; x 'git reset --hard'",
    "$c = Set-Alias x iex; x 'git reset --hard'",
    "sal x iex; $r=x 'git reset --hard'",
    "function f { git reset --hard }; $r=f",
    // Wherever the assignment stands: after `&`, and as the pipeline of
    // `return`, `throw` or `exit`.
    "Get-Date & $c=iex 'git reset --hard'",
    "Get-Date & $c+=iex 'git reset --hard'",
    "return $c=iex 'git reset --hard'",
    "throw $c=iex 'git reset --hard'",
    "exit $c=iex 'git reset --hard'",
    // Every hashtable key, not only the first.
    "@{a=1;b=iex 'git reset --hard'}",
    "$h=@{a=1;b=iex 'git reset --hard'}",
    "@{a=1\nb=iex 'git reset --hard'\n}",
    "@{ a = 1; 'b'=iex 'git reset --hard'}",
    "@{a=@{x=1};b=iex 'git reset --hard'}",
    // Unicode names, quoted and dynamic members, expression targets.
    "$c\u{e9}=iex 'git reset --hard'",
    "$\u{3a9}=iex 'git reset --hard'",
    "$c=@{}; $c.'p'=iex 'git reset --hard'",
    "$c=@{}; $c.\"p\"=iex 'git reset --hard'",
    "$c=@{}; $c.$('p')=iex 'git reset --hard'",
    "$c=@{}; $c.$('p') =iex 'git reset --hard'",
    "$c=@{}; $n='p'; $c.$n=iex 'git reset --hard'",
    "$c=@(1); $c[(0)]=iex 'git reset --hard'",
    "$o=[pscustomobject]@{p=1}; ($o).p=iex 'git reset --hard'",
    // PowerShell reads U+2013, U+2014 and U+2015 as `-`.
    "$c=1; $c\u{2013}=iex 'git reset --hard'",
    "$c=1; $c\u{2014}=iex 'git reset --hard'",
    "$c=1; $c\u{2015}=iex 'git reset --hard'",
    // A target's brackets or braced name with blanks inside span words.
    "$c=@(1,2); $i=0; $c[$i + 1]=iex 'git reset --hard'",
    "$c=@(1,2); $c[ 0 ]=iex 'git reset --hard'",
    "$c=@(1,2); $c[0 ]=iex 'git reset --hard'",
    "$c=@(1,2); $c[ 0 ] =iex 'git reset --hard'",
    "$c=@{}; $c[ 'a' ]=iex 'git reset --hard'",
    "$c=@(@{}); $c[ 0 ].p=iex 'git reset --hard'",
    "$c=@(1,2); $c[ 0 ]=$d=iex 'git reset --hard'",
    "$c=@(1,2); if(1){$c[ 0 ]=iex 'git reset --hard'}",
    "[System.Collections.Generic.Dictionary[string, int]]$c=iex 'git reset --hard'",
    "[System.Collections.Generic.Dictionary[string, int]] $c=iex 'git reset --hard'",
    "${c d}=iex 'git reset --hard'",
    // Any command in the value, glued or spaced, read by any reader or pack:
    // the filesystem pack's Remove-Item reader, the Windows launchers, and
    // direct commands after targets the readers did not take as words.
    "$null = Remove-Item -Recurse -Force .git",
    "$null=Remove-Item -Recurse -Force .git",
    "$c = Remove-Item -Recurse -Force C:\\Windows",
    "$c=Remove-Item -Recurse -Force $env:USERPROFILE\\.ssh",
    "$c=Remove-Item -LiteralPath C:\\x -Recurse -Force",
    "$c = ri -r -fo C:\\Users",
    "$c = rd -r -fo C:\\Users",
    "$c=del -Recurse -Force C:\\Users",
    "$c = cmd /c rd /s /q C:\\Users",
    "$c = powershell -c 'Remove-Item -Recurse -Force C:\\Windows'",
    "$c=@(1,2); $c[ 0 ]=git reset --hard",
    "$c=@(1,2); $c[ 0 ] = git reset --hard",
    "$c=@(1,2); $c[ 0 ]=icm {git reset --hard}",
    "$c=@(1,2); $i=0; $c[$i + 1]=git reset --hard",
    "$c=@{}; $c[ 'a' ]=git reset --hard",
    "$c=@{}; $c['a b']=git reset --hard",
    "$c=@(@{}); $c[ 0 ].p=git reset --hard",
    "$c=@{p=@(1)}; $c.p[ 0 ]=git reset --hard",
    "$c=@{}; $c.'p q'=git reset --hard",
    "[System.Collections.Generic.Dictionary[string, int]]$c=git reset --hard",
    "[int] [string] $c=git reset --hard",
    "$a, $b = git reset --hard",
    "$a, $b=git reset --hard",
    "[int] $a, $b=git reset --hard",
    "$c=1; (Get-Variable c).Value=git reset --hard",
    "[System.Environment]::CurrentDirectory=git reset --hard",
    "${c}=icm {git reset --hard}",
    "@{a=git reset --hard}",
    "@{a=1; b=git reset --hard}",
    "$c=@(1,2); if(1){$c[ 0 ]=git reset --hard}",
    "$c=@(1,2); function f {$c[ 0 ]=git reset --hard}; f",
    "$c=@(1,2); foreach($i in 1){$c[ 0 ]=git reset --hard}",
    "echo hi; $a, $b = git reset --hard",
    // Hashtable values, spaced or glued, typed or nested (card t_9c78e651).
    "$h = @{a = git reset --hard}",
    "@{a = git reset --hard}",
    "$h = @{a = 1; b = git reset --hard}",
    "$h = [ordered]@{a = git reset --hard}",
    "$h=@{a=git reset --hard}",
    "$h=[ordered]@{a=git reset --hard}",
    "$h = [pscustomobject]@{a = git reset --hard}",
    "$h = @{a = @{b = git reset --hard}}",
    "$p = @{a = git reset --hard}; Get-ChildItem @p",
    "$h = @{a = $(git reset --hard)}",
    "$h = @{a = (git reset --hard)}",
];

/// pwsh 7.5 runs no `git reset --hard` for any of these (sandboxed).
const HARMLESS: &[&str] = &[
    // The same shapes with a harmless value or data.
    "$c=iex 'git status'",
    "$c=iex 'git log -1'",
    "Get-Date & $c=git status",
    "return $c=git status",
    "$c\u{e9}=git status",
    "$c\u{e9} = git status",
    "@{a=1;b=git status}",
    "@{a=1\nb=git status\n}",
    "$c=@{}; $c.'p'=git status",
    "$c=@{}; $c.$('p')=git status",
    "$c=1; $c\u{2013}=1",
    "$c=@(1,2); $c[ 0 ]=git status",
    "$c=@(1,2); $i=0; $c[$i + 1]=git status",
    "$c=@(1,2); $c[ 0 ] =git status",
    "[System.Collections.Generic.Dictionary[string, int]]$c=@{}",
    "$c=@(1,2); $c[ 0 ] = git status",
    "$a, $b = git status",
    "@{a=git status}",
    "$null = Get-ChildItem",
    "$null=Remove-Item -WhatIf x",
    // A value in expression mode is not a command.
    "foreach($i in 1..3){ $y=$i*2 }",
    "if(1){$y=$x*2}",
    "$el=$('#x')",
    "$x = $(Get-Date)",
    "$x = @{a='git reset --hard'}; $x.a",
    "Get-Process | Select-Object -Property @{n='x';e={$_.Name}}",
    "$c=1; git status",
    "$c=$true",
    "$c=Get-Date",
    "$c=git status",
    "$c=git log --oneline",
    "$out=& git log -1 --format=%H",
    "$r=git status --porcelain; if($r){Write-Output dirty}",
    "$c==iex",
    "$env:GIT_DIR='x'; git status",
    "$env:PATH+=';C:\\tools'; git status",
    "$c=Write-Output 'git reset --hard'",
    "$c=[scriptblock]::Create('git status')",
    "$h=@{a=1;b='git reset --hard'}",
    "$x=Get-ChildItem -Recurse | Where-Object {$_.Length -gt 1}",
    "foreach($f in Get-ChildItem){$n=$f.Name; Write-Output $n}",
    "$i=0; while($i -lt 3){$i++}",
    "[void]$list.Add(1)",
    "$c = icm {git status}",
    "$c = Start-Job {git status}",
    "$x = 1 | % {git status}",
    "$c = Get-ChildItem | ForEach-Object { $_.Name }",
    "$r = Invoke-Command -ScriptBlock { Get-Date }",
    "$c = Set-Alias x Write-Output; x 'git reset --hard'",
    "$x = 5; sal y iex; y 'git status'",
];

/// Data the Unknown dialect already denies on the base commit through its
/// POSIX reading (unchanged here); PowerShell itself runs nothing.
const HARMLESS_IN_POWERSHELL: &[&str] = &[
    "$c='git reset --hard'",
    "$c=\"git reset --hard\"",
    "$c=@'\ngit reset --hard\n'@",
    "$c={git reset --hard}",
    "$msg='git reset --hard is dangerous'; Write-Output $msg",
    // A here-string value is data, not a command (the filesystem pack's
    // reason to skip assignments).
    "$text = @'\n[System.IO.Directory]::Delete($path, $true)\n'@; Write-Output $text",
    "$p = @{Path='.'; Recurse=$true}; Get-ChildItem @p",
];

/// Text PowerShell cannot parse (it runs none of it) that the Unknown dialect
/// allows on the base commit. The view must not turn PowerShell's parse
/// failure into an Unknown denial: the first row is a Node heredoc from real
/// Codex history, reduced (`()=>{…` in JavaScript).
const HARMLESS_IN_UNKNOWN: &[&str] = &["node <<'JS'\n)={\nJS", "x)={"];

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
            "session_id": "sess-ps-assign",
            "transcript_path": "/tmp/claude/transcript.jsonl",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "toolu_ps_assign",
        }),
        // `turn_id` selects Codex's protocol.
        Protocol::Codex => serde_json::json!({
            "session_id": "019dd11d-b795-7261-a9cb-9b85a5dadf15",
            "turn_id": "turn-ps-assign",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.5",
            "permission_mode": "default",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "call_ps_assign",
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
fn powershell_tool_judges_the_value_of_a_statement_leading_assignment() {
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

#[test]
fn powershell_and_unknown_dialects_judge_the_value_of_a_statement_leading_assignment() {
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
    for command in HARMLESS_IN_UNKNOWN {
        assert_eq!(
            decision_in(command, ShellDialect::Unknown),
            EvaluationDecision::Allow,
            "{command:?}"
        );
    }
}

/// Bash runs a command named `=iex` (or the value of `$c` followed by
/// `=iex`) here, not `iex`: the POSIX reading stays as it was.
#[test]
fn posix_dialect_keeps_reading_a_glued_dollar_word_as_one_word() {
    for command in ["$c=iex 'git reset --hard'", "$c+=iex 'git reset --hard'"] {
        assert_eq!(
            decision_in(command, ShellDialect::Posix),
            EvaluationDecision::Allow,
            "{command:?}"
        );
    }
}
