//! PowerShell engine methods run a string as script, like `iex` and
//! `[scriptblock]::Create`: `$ExecutionContext.InvokeCommand.InvokeScript`
//! and `.NewScriptBlock` (also through `$ExecutionContext.SessionState`),
//! `[powershell]::Create().AddScript`, a runspace's `CreatePipeline` and
//! `CreateNestedPipeline`, a `Runspaces.Command` built with `isScript`,
//! `Parser::ParseInput`, and the `$( … )` inside `ExpandString`'s text.
//! `[scriptblock]::Create` is read the same way, by any spelling.
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
    // A line break inside a grouped value or argument list does not end the
    // statement.
    "$c = New-Object -TypeName System.Management.Automation.Runspaces.Command -ArgumentList @(\n  'git reset --hard',\n  $true\n)\n$ps=[powershell]::Create()\n[void]$ps.Commands.AddCommand($c)\n[void]$ps.Invoke()",
    "$c = New-Object -TypeName System.Management.Automation.Runspaces.Command -ArgumentList @(\n  'git reset --hard'\n  $true\n)\n$ps=[powershell]::Create()\n[void]$ps.Commands.AddCommand($c)\n[void]$ps.Invoke()",
    "$c = New-Object -TypeName System.Management.Automation.Runspaces.Command -ArgumentList (\n  'git reset --hard',\n  $true\n)\n$ps=[powershell]::Create()\n[void]$ps.Commands.AddCommand($c)\n[void]$ps.Invoke()",
    "$c = New-Object System.Management.Automation.Runspaces.Command @(\n  'git reset --hard',\n  $true\n)\n$ps=[powershell]::Create()\n[void]$ps.Commands.AddCommand($c)\n[void]$ps.Invoke()",
    "$c = New-Object -TypeName (\n  [System.Management.Automation.Runspaces.Command]\n) -ArgumentList 'git reset --hard', $true\n$ps=[powershell]::Create()\n[void]$ps.Commands.AddCommand($c)\n[void]$ps.Invoke()",
    "$ExecutionContext.InvokeCommand | % -MemberName (\n'InvokeScript'\n) 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % -MemberName InvokeScript -ArgumentList (\n  'git reset --hard'\n)",
    "$ExecutionContext.InvokeCommand | % InvokeScript (\n  'git reset --hard'\n)",
    "$c = New-Object -TypeName System.Management.Automation.Runspaces.Command `\n    -ArgumentList 'git reset --hard', $true\n$ps=[powershell]::Create()\n[void]$ps.Commands.AddCommand($c)\n[void]$ps.Invoke()",
    "$c = New-Object `\n    -TypeName System.Management.Automation.Runspaces.Command `\n    -ArgumentList 'git reset --hard', $true\n$ps=[powershell]::Create()\n[void]$ps.Commands.AddCommand($c)\n[void]$ps.Invoke()",
    "$ExecutionContext.InvokeCommand | ForEach-Object -MemberName InvokeScript `\n    -ArgumentList 'git reset --hard'",
    "$ExecutionContext.InvokeCommand |\n  ForEach-Object -MemberName InvokeScript -ArgumentList 'git reset --hard'",
    "$c = [System.Management.Automation.Runspaces.Command]::new.Invoke(@(\n  'git reset --hard',\n  $true\n))\n$ps=[powershell]::Create()\n[void]$ps.Commands.AddCommand($c)\n[void]$ps.Invoke()",
    "$c = [System.Management.Automation.Runspaces.Command]::new(\n  'git reset --hard',\n  $true\n)\n$ps=[powershell]::Create()\n[void]$ps.Commands.AddCommand($c)\n[void]$ps.Invoke()",
    "$ExecutionContext.InvokeCommand.InvokeScript(\n  'git reset --hard'\n)",
    "$c = New-Object -TypeName (\n[System.Management.Automation.Runspaces.Command]\n) -ArgumentList 'git reset --hard', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    // A trailing comma carries the array, and the statement, to the next
    // line, past blank and comment lines.
    "$c = New-Object -ArgumentList 'git reset --hard',\n  $true -TypeName System.Management.Automation.Runspaces.Command\n$ps=[powershell]::Create()\n[void]$ps.Commands.AddCommand($c)\n[void]$ps.Invoke()",
    "$c = New-Object -ArgumentList 'git reset --hard',\n\n  $true -TypeName System.Management.Automation.Runspaces.Command\n$ps=[powershell]::Create()\n[void]$ps.Commands.AddCommand($c)\n[void]$ps.Invoke()",
    "$c = New-Object -ArgumentList 'git reset --hard',\n  # note\n  $true -TypeName System.Management.Automation.Runspaces.Command\n$ps=[powershell]::Create()\n[void]$ps.Commands.AddCommand($c)\n[void]$ps.Invoke()",
    "$ExecutionContext.InvokeCommand | % -ArgumentList 'git reset --hard',\n  'x' -MemberName InvokeScript",
    "$ExecutionContext.InvokeCommand | % -ArgumentList 'git reset --hard',\r\n  'x' -MemberName InvokeScript",
    // Text glued after a literal (an index, a member call, more elements) is
    // part of the value PowerShell evaluates.
    "$c = New-Object System.Management.Automation.Runspaces.Command ('git reset --hard'), $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$c = New-Object System.Management.Automation.Runspaces.Command -ArgumentList ('git status', 'git reset --hard', $true)[1,2]; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$c = New-Object System.Management.Automation.Runspaces.Command -ArgumentList @('git status', 'git reset --hard', $true)[1,2]; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$ExecutionContext.InvokeCommand | % InvokeScript ('git status', 'git reset --hard')[1]",
    "$ExecutionContext.InvokeCommand | % -MemberName InvokeScript -ArgumentList ('git status', 'git reset --hard')[-1]",
    "$ExecutionContext.InvokeCommand | % InvokeScript ('git status').Replace('status', 'reset --hard')",
    "$c = New-Object -TypeName ('System.Text.StringBuilder').Replace('Text.StringBuilder', 'Management.Automation.Runspaces.Command') -ArgumentList 'git reset --hard', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$c = New-Object -TypeName 'System.Text.StringBuilder'.Replace('Text.StringBuilder', 'Management.Automation.Runspaces.Command') -ArgumentList 'git reset --hard', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$ExecutionContext.InvokeCommand | % -MemberName ('NotIt').Replace('NotIt', 'InvokeScript') 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % 'NotIt'.Replace('NotIt', 'InvokeScript') 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % ('Trim', 'InvokeScript')[1] 'git reset --hard'",
    // The same, attached with `:` or before -ArgumentList; a blank before the
    // comma; typographic quotes.
    "$ExecutionContext.InvokeCommand | % -MemberName:('NotIt').Replace('NotIt', 'InvokeScript') 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % -MemberName 'NotIt'.Replace('NotIt', 'InvokeScript') -ArgumentList 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % InvokeScript ('git reset --hard') , 'x'",
    "$ExecutionContext.InvokeCommand | % InvokeScript \u{2018}git reset --hard\u{2019}",
    // A parameter placed before the name takes its value (review round 5,
    // runner rv6/truth.out and r5/truth*.out).
    "$ExecutionContext.InvokeCommand | % -ErrorAction Stop InvokeScript 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | ForEach-Object -PipelineVariable p InvokeScript 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % -OutVariable o InvokeScript 'git reset --hard'",
    "$c = New-Object -ErrorAction Stop System.Management.Automation.Runspaces.Command 'git reset --hard', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$c = New-Object -OutVariable o System.Management.Automation.Runspaces.Command -ArgumentList 'git reset --hard', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$ExecutionContext.InvokeCommand | % -Verbose InvokeScript 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % -ErrorAction:Stop InvokeScript 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % -Verbose: $false InvokeScript 'git reset --hard'",
    "ForEach-Object -InputObject $ExecutionContext.InvokeCommand -ErrorAction Stop InvokeScript 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % -ea Stop -ov o InvokeScript 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % -WarningAction SilentlyContinue, Stop InvokeScript 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % -PipelineVariable (\n'p') InvokeScript 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % –MemberName InvokeScript 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % -MemberName InvokeScript -ErrorAction Stop 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % InvokeScript 'git reset --hard' -ErrorAction Stop",
    "$ExecutionContext.InvokeCommand | % -OutBuffer (0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0) InvokeScript 'git reset --hard'",
    // ForEach-Object member names are wildcard patterns.
    "$ExecutionContext.InvokeCommand | % InvokeScr* 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % -MemberName Invoke?cript 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | ForEach-Object -MemberName 'Invoke[S]cript' -ArgumentList 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % *eScript 'git reset --hard'",
    "[powershell]::Create() | % AddScr* 'git reset --hard' | % Invoke",
    "$ExecutionContext.InvokeCommand | % [I]nvokeScript 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % 'I*Script' 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % Invoke[R-T]cript 'git reset --hard'",
    // A quoted or bare cmdlet name after the call or dot-source operator.
    "$c = & 'New-Object' System.Management.Automation.Runspaces.Command 'git reset --hard', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$ExecutionContext.InvokeCommand | & 'ForEach-Object' InvokeScript 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | & \"ForEach-Object\" -MemberName InvokeScript -ArgumentList 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | . 'ForEach-Object' InvokeScript 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | . ForEach-Object InvokeScript 'git reset --hard'",
    "$c = . 'New-Object' System.Management.Automation.Runspaces.Command 'git reset --hard', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    // A line continuation between an argument group and its comma.
    "$c = New-Object System.Management.Automation.Runspaces.Command ('git reset --hard') `\n, $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$c = New-Object System.Management.Automation.Runspaces.Command ('git reset --hard')`\n, $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    // A splat binds parameters dcg cannot see (review round 6, runner
    // rv7/truth*.out and r6/truth.out).
    "$p = @{ErrorAction = 'Stop'}; $ExecutionContext.InvokeCommand | % @p InvokeScript 'git reset --hard'",
    "$p = @{ErrorAction = 'Stop'}; $c = New-Object @p System.Management.Automation.Runspaces.Command 'git reset --hard', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$p = @{ErrorAction = 'Stop'}; $c = New-Object -TypeName System.Management.Automation.Runspaces.Command @p -ArgumentList 'git reset --hard', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    // A redirection and its target are not the name or an argument.
    "$ExecutionContext.InvokeCommand | % 2>$null InvokeScript 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % *>$null InvokeScript 'git reset --hard'",
    "$c = New-Object 2>$null System.Management.Automation.Runspaces.Command 'git reset --hard', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$ExecutionContext.InvokeCommand | % 2>&1 InvokeScript 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % -MemberName InvokeScript 2>$null 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % InvokeScript 2>$null 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % 3>$null InvokeScript 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % 2> $null InvokeScript 'git reset --hard'",
    "$c = New-Object System.Management.Automation.Runspaces.Command 2>$null 'git reset --hard', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$ExecutionContext.InvokeCommand | % 2>&1 -MemberName InvokeScript -ArgumentList 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % 2>>$null InvokeScript 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % *>&1 InvokeScript 'git reset --hard'",
    "$c = New-Object 2>&1 System.Management.Automation.Runspaces.Command 'git reset --hard', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$ExecutionContext.InvokeCommand | % -MemberName 2>$null InvokeScript 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % InvokeScript -ArgumentList 2>$null 'git reset --hard'",
    "$c = New-Object -TypeName System.Management.Automation.Runspaces.Command 2>&1 -ArgumentList 'git reset --hard', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$ExecutionContext.InvokeCommand | % 2>>$null InvokeScript 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % > $null InvokeScript 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % -ArgumentList 'git reset --hard' 2>&1 -MemberName InvokeScript",
    // A positional word before a named -MemberName or -TypeName is the
    // first argument.
    "$ExecutionContext.InvokeCommand | % 'git reset --hard' -MemberName InvokeScript",
    "$c = New-Object 'git reset --hard', $true -TypeName System.Management.Automation.Runspaces.Command; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$ExecutionContext.InvokeCommand | % -ArgumentList 'git reset --hard' InvokeScript",
    "$c = New-Object -ArgumentList 'git reset --hard', $true System.Management.Automation.Runspaces.Command; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$ExecutionContext.InvokeCommand | % 2>$null 'git reset --hard' -MemberName InvokeScript",
    // Wildcard names fold case beyond ASCII (KELVIN SIGN is `k`).
    "$ExecutionContext.InvokeCommand | % Invo\u{212a}eScr* 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % -MemberName 'Invo\u{212a}e*' -ArgumentList 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % '*\u{212a}eScript' 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % [I]nvo\u{212a}eScript 'git reset --hard'",
    // Review round 7 (runner rv8/truth*.out, r7/truth.out): every positional
    // element is an argument once the name is named, a redirection target is
    // one element, and a group of several elements followed by another
    // argument is one array argument.
    "$ExecutionContext.InvokeCommand | % 'git reset --hard' 'x' -MemberName InvokeScript",
    "$ExecutionContext.InvokeCommand | % 'git reset --hard' -ErrorAction Stop 'x' -MemberName InvokeScript",
    "$ExecutionContext.InvokeCommand | ForEach-Object 'git reset --hard' 'x' -MemberName:InvokeScript",
    "$ExecutionContext.InvokeCommand | % 'git reset --hard', 'x' 'y' -MemberName InvokeScript",
    "$ExecutionContext.InvokeCommand | % 2> ('x' + 'y') InvokeScript 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % 2> (Join-Path $HOME 'e.txt') InvokeScript 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % -MemberName InvokeScript 2> ('x' + 'y') 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % InvokeScript 2> ('x' + 'y') 'git reset --hard'",
    "$c = New-Object 2> ('x' + 'y') System.Management.Automation.Runspaces.Command 'git reset --hard', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$c = New-Object -TypeName 2> ('x' + 'y') System.Management.Automation.Runspaces.Command -ArgumentList 'git reset --hard', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$ExecutionContext.InvokeCommand | % 2> $('x' + 'y') InvokeScript 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % 2> \"x y\" InvokeScript 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % 'git reset --hard' 'x' -MemberName Invoke*",
    "$ExecutionContext.InvokeCommand | % 'git reset --hard' 'x' 2>$null -MemberName InvokeScript",
    "$ExecutionContext.InvokeCommand | % 2>('x' + 'y') InvokeScript 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % *> ('x' +\n 'y') InvokeScript 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % InvokeScript ('git', 'reset', '--hard') 'y'",
    "$ExecutionContext.InvokeCommand | % InvokeScript ('git', 'reset --hard') 'y'",
    "$ExecutionContext.InvokeCommand | % InvokeScript @('git', 'reset --hard') 'y'",
    "$ExecutionContext.InvokeCommand | % -MemberName InvokeScript ('git', 'reset --hard') 'y'",
    "$ExecutionContext.InvokeCommand | % ('git', 'reset --hard') 'y' -MemberName InvokeScript",
    "$ExecutionContext.InvokeCommand | % InvokeScript ('git', 'reset --hard') -ErrorAction Stop 'y'",
    "$ExecutionContext.InvokeCommand | % InvokeScript ('git reset --hard', 'x')",
    "$ExecutionContext.InvokeCommand | % InvokeScript 'git', 'reset --hard' 'y'",
    "$ExecutionContext.InvokeCommand | % 2> (Join-Path $HOME 'e.txt') -MemberName InvokeScript 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % -MemberName 2> ('x' + 'y') InvokeScript 'git reset --hard'",
    "$c = New-Object -TypeName System.Management.Automation.Runspaces.Command 2> ('x' + 'y') -ArgumentList 'git reset --hard', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$ExecutionContext.InvokeCommand | % InvokeScript 'git reset --hard' 2> ('x' + 'y')",
    "$ExecutionContext.InvokeCommand | % InvokeScript ('git reset --hard') 'y'",
    "$ExecutionContext.InvokeCommand | % 2>(Join-Path $HOME 'e.txt') InvokeScript 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % 2> <# c #> ('x' + 'y') InvokeScript 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % -MemberName InvokeScript 'git reset --hard' 'x' 'y'",
    // Review round 8 (runner rv9/truth*.out, r8/truth.out): only a bare
    // dash word is a parameter, and `--%` is not skipped.
    "$ExecutionContext.InvokeCommand | % InvokeScript 'git reset --hard' '-MemberName' 'x'",
    "$ExecutionContext.InvokeCommand | % InvokeScript 'git reset --hard' \"-MemberName\" 'x'",
    "$ExecutionContext.InvokeCommand | % InvokeScript 'git reset --hard' `-MemberName 'x'",
    "$ExecutionContext.InvokeCommand | % InvokeScript 'git reset --hard' -Member'Name' 'x'",
    "$ExecutionContext.InvokeCommand | % InvokeScript 'git reset --hard' '-Mem' Trim",
    "$ExecutionContext.InvokeCommand | % InvokeScript 'git reset --hard' '--%'",
    "$ExecutionContext.InvokeCommand | % InvokeScript 'git reset --hard' \"--%\"",
    "$c = New-Object System.Management.Automation.Runspaces.Command 'git reset --hard', '--%'; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$c = New-Object -TypeName System.Management.Automation.Runspaces.Command -ArgumentList 'git reset --hard', '--%'; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$ExecutionContext.InvokeCommand | % InvokeScript 'git reset --hard' -Member`Name x",
    "$ExecutionContext.InvokeCommand | % InvokeScript 'git reset --hard' -\"MemberName\" x",
    "$ExecutionContext.InvokeCommand | % InvokeScript 'git reset --hard' --% x",
    "$e = 'Stop'; $ExecutionContext.InvokeCommand | % -ErrorAction:$e InvokeScript 'git reset --hard'",
    "$o = 'o'; $ExecutionContext.InvokeCommand | % -OutVariable:$o InvokeScript 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % InvokeScript 'git reset --hard' -‘MemberName’ x",
    "$x = 'Name'; $ExecutionContext.InvokeCommand | % InvokeScript 'git reset --hard' -Member$x x",
    "$ExecutionContext.InvokeCommand | % InvokeScript 'git reset --hard' -Member\"Name\":x",
    "$e = 'Stop'; $c = New-Object -ErrorAction:$e System.Management.Automation.Runspaces.Command 'git reset --hard', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$ExecutionContext.InvokeCommand | % -MemberName:'InvokeScript' 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % InvokeScript 'git reset --hard' '-ArgumentList' 'x'",
    "$ExecutionContext.InvokeCommand | % -MemberName InvokeScript 'git reset --hard' --% x",
    // Review round 9 (runner rv10/truth*.out): a statement inside a group that
    // an operator follows, and PR #33's assignment shapes (t_279cc772).
    "($ExecutionContext.InvokeCommand | % InvokeScript 'git reset --hard') -join ','",
    "$c=New-Object System.Management.Automation.Runspaces.Command('git reset --hard', $true); $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "[System.Management.Automation.Runspaces.Command]$c = New-Object System.Management.Automation.Runspaces.Command 'git reset --hard', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$c, $d = New-Object System.Management.Automation.Runspaces.Command 'git reset --hard', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$c ??= New-Object System.Management.Automation.Runspaces.Command 'git reset --hard', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$c = $d = New-Object System.Management.Automation.Runspaces.Command 'git reset --hard', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$c=New-Object -TypeName System.Management.Automation.Runspaces.Command -ArgumentList 'git reset --hard', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$r=$ExecutionContext.InvokeCommand | % InvokeScript 'git reset --hard'",
    "[object]$r = $ExecutionContext.InvokeCommand | % -MemberName InvokeScript -ArgumentList 'git reset --hard'",
    "& { $ExecutionContext.InvokeCommand | % InvokeScript 'git reset --hard' }",
    "\"x $($ExecutionContext.InvokeCommand | % InvokeScript 'git reset --hard') y\"",
    "($ExecutionContext.InvokeCommand | % InvokeScript (\n'git reset --hard'\n)) -join ','",
    "if (($ExecutionContext.InvokeCommand | % InvokeScript 'git reset --hard') -eq $null) { 'n' }",
    "@($ExecutionContext.InvokeCommand | % -MemberName InvokeScript -ArgumentList 'git reset --hard') -match 'x'",
    "($c = New-Object System.Management.Automation.Runspaces.Command 'git reset --hard', $true) -ne $null; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    // `[scriptblock]::Create` by another spelling of the name (quoted,
    // computed, a script block's text, `.Invoke`, the method taken as a
    // value), of the type, or with the type held in a value (card
    // t_222650ea; runner p/t1.out, t2.out). `.{Name}` names other engine
    // methods too.
    "[scriptblock]::Create.Invoke('git reset --hard').Invoke()",
    "$f=[scriptblock]::Create; $f.Invoke('git reset --hard').Invoke()",
    "[scriptblock]::'Create'('git reset --hard').Invoke()",
    "[scriptblock]::(\"Cre\"+\"ate\")('git reset --hard').Invoke()",
    "$t=[scriptblock]; $t::Create('git reset --hard').Invoke()",
    "[scriptblock]::\"Create\"('git reset --hard').Invoke()",
    "$n='Create'; [scriptblock]::$n('git reset --hard').Invoke()",
    "[Management.Automation.ScriptBlock]::Create('git reset --hard').Invoke()",
    "using namespace System.Management.Automation\n[ScriptBlock]::Create('git reset --hard').Invoke()",
    "([type]'scriptblock')::Create('git reset --hard').Invoke()",
    "[scriptblock]::Create.Invoke(('git ' + 'reset --hard')).Invoke()",
    "[scriptblock]::'Create'.Invoke('git reset --hard').Invoke()",
    "$t=[scriptblock]; $t::'Create'('git reset --hard').Invoke()",
    "$sb=[scriptblock]::(\"Create\")('git reset --hard'); & $sb",
    "[scriptblock]::Create.Invoke('git reset --hard')|% Invoke",
    "[System.Management.Automation.ScriptBlock, System.Management.Automation]::Create('git reset --hard').Invoke()",
    "[scriptblock]::$('Create')('git reset --hard').Invoke()",
    "[scriptblock]::Create.Invoke(\"git reset --hard\").InvokeReturnAsIs()",
    "[scriptblock]::\n Create('git reset --hard').Invoke()",
    "[scriptblock]::`\nCreate('git reset --hard').Invoke()",
    "& ([scriptblock]::'Create'('git reset --hard'))",
    "$t=[type]'scriptblock'; $t::Create('git reset --hard').Invoke()",
    "$t='scriptblock' -as [type]; $t::Create('git reset --hard').Invoke()",
    "[scriptblock]::Create.Invoke.Invoke('git reset --hard').Invoke()",
    "$m=[scriptblock]::'Create'; & { $m.Invoke('git reset --hard').Invoke() }",
    "[ScriptBlock]::CREATE.invoke('git reset --hard').Invoke()",
    "[scriptblock]::{Create}('git reset --hard').Invoke()",
    "[System.Management.Automation.ScriptBlock]::'Create'('git reset --hard') | % Invoke",
    "$ExecutionContext.InvokeCommand.{InvokeScript}('git reset --hard')",
    "[scriptblock]::{Create}.Invoke('git reset --hard').Invoke()",
    "[powershell]::{Create}().AddScript('git reset --hard').Invoke()",
    "[scriptblock]:: 'Create'('git reset --hard').Invoke()",
    "[ScriptBlock]::('Create')('git reset --hard')|% Invoke",
    "[scriptblock]::Create('git reset --hard').Ast.GetScriptBlock().Invoke()",
    "[System.Management.Automation.ScriptBlock]::Create.Invoke('git reset --hard') | % Invoke",
    "$x=[scriptblock]; ($x)::Create('git reset --hard').Invoke()",
    "[scriptblock]::Create.Invoke(@('git reset --hard')).Invoke()",
    "([scriptblock]::Create).Invoke('git reset --hard').Invoke()",
    "[scriptblock]::'Create'.Invoke.Invoke('git reset --hard').Invoke()",
    "$t=[scriptblock]; $f=$t::Create; $f.Invoke('git reset --hard').Invoke()",
    "$n='Create'; $t=[scriptblock]; $t::$n('git reset --hard').Invoke()",
    // A here-string or array expression as the name, here and for the
    // engine methods; a type literal held only by groups; a type in an
    // index (review round 1; runner rv/truth.out, rv/truth2.out,
    // p2/n-truth.out).
    "[scriptblock]::@'\nCreate\n'@('git reset --hard').Invoke()",
    "[scriptblock]::@\"\nCreate\n\"@('git reset --hard').Invoke()",
    "[scriptblock]::@('Create')('git reset --hard').Invoke()",
    "[scriptblock]::@('Cre'+'ate')('git reset --hard').Invoke()",
    "$t=[scriptblock]; $t::@'\nCreate\n'@('git reset --hard').Invoke()",
    "[scriptblock]::@'\nCreate\n'@.Invoke('git reset --hard').Invoke()",
    "$f=[scriptblock]::@('Create'); $f.Invoke('git reset --hard').Invoke()",
    "$n='Create'; [scriptblock]::@\"\n$n\n\"@('git reset --hard').Invoke()",
    "$ExecutionContext.InvokeCommand.@'\nInvokeScript\n'@('git reset --hard')",
    "$ExecutionContext.InvokeCommand.@('InvokeScript')('git reset --hard')",
    "[powershell]::Create().@\"\nAddScript\n\"@('git reset --hard').Invoke()",
    "$a='git reset --hard'; ([scriptblock])::Create($a).Invoke()",
    "([scriptblock])::Create('git reset --hard').Invoke()",
    "$a='git reset --hard'; ( ( [scriptblock] ) )::Create($a).Invoke()",
    "$a='git reset --hard'; ([System.Management.Automation.ScriptBlock])::Create($a).Invoke()",
    "$a=@([scriptblock]); $a[0]::Create('git reset --hard').Invoke()",
    // A `@"…"@` name decodes its escapes, and a line continuation is blank
    // space in the group around a type (review round 2; runner
    // rv2/truth.out, rv2/truth2.out, rv2/truth3.out).
    "$a='git reset --hard'; $ExecutionContext.InvokeCommand.@\"\nInvoke`Script\n\"@($a)",
    "[scriptblock]::@\"\n`Create\n\"@('git reset --hard').Invoke()",
    "$a='git reset --hard'; [scriptblock]::@\"\n`Create\n\"@($a).Invoke()",
    "$t=[scriptblock]; $f=$t::@\"\n`Create\n\"@; $f.Invoke('git reset --hard').Invoke()",
    "$a='git reset --hard'; (`\n[scriptblock])::Create($a).Invoke()",
    // Review round 3 (runner rv3/truth.out, rv3/truth2.out, p4/k-truth.out):
    // a `$` in a `@"…"@` name is not static even beside a `"`; block
    // comments before `::`; an escaped `}` in a `${…}` name; and a `"` inside
    // the `$( … )` of a `"…"` name.
    "[scriptblock]::@\"\n$(\"Create\")\n\"@('git reset --hard').Invoke()",
    "$ExecutionContext.InvokeCommand.@\"\n$(\"InvokeScript\")\n\"@('git reset --hard')",
    "$t=[scriptblock]; $t::@\"\n$(\"Create\")\n\"@('git reset --hard').Invoke()",
    "$a='git reset --hard'; [scriptblock]<#c#>::Create($a).Invoke()",
    "$a='git reset --hard'; [scriptblock]<#c#>::'Create'($a).Invoke()",
    "$a='git reset --hard'; [System.Management.Automation.ScriptBlock]<#c#>::Create($a).Invoke()",
    "$a='git reset --hard'; $f=[scriptblock]<#c#>::Create; $f.Invoke($a).Invoke()",
    "$a='git reset --hard'; ([scriptblock])<#c#>::Create($a).Invoke()",
    "$a='git reset --hard'; [scriptblock]<#a#><#b#>::Create($a).Invoke()",
    "$a='git reset --hard'; [scriptblock]<# x <# y #>::Create($a).Invoke()",
    "$a='git reset --hard'; ([scriptblock]<#c#>)<#d#>::Create($a).Invoke()",
    "$a='git reset --hard'; (<#c#>[scriptblock]<#d#>)::Create($a).Invoke()",
    "${a`}b}='InvokeScript'; $ExecutionContext.InvokeCommand.${a`}b}('git reset --hard')",
    "$t=[scriptblock]; ${a`}b}='Create'; $t::${a`}b}('git reset --hard').Invoke()",
    "$ExecutionContext.InvokeCommand.\"$(\"InvokeScript\")\"('git reset --hard')",
    "$ExecutionContext.InvokeCommand.\"$(\"Invoke\"+\"Script\")\"('git reset --hard')",
    // Review round 4 (runner rv4/truth.out, rv4/truth2.out, p5/w-truth.out):
    // the method taken as a value on a member chain that starts at a group,
    // index, braced variable, hashtable or script block.
    "$t=[scriptblock]; $f=(gv t).Value::Create; $f.Invoke('git reset --hard').Invoke()",
    "$s=[scriptblock]; $f=(gv s).Value::Create; $f.Invoke('git reset --hard').Invoke()",
    "$f=(@{a=[scriptblock]}).a::Create; $f.Invoke('git reset --hard').Invoke()",
    "$f={}::Create; $f.Invoke('git reset --hard').Invoke()",
    "$m=(Get-Variable ExecutionContext).Value.InvokeCommand.InvokeScript; $m.Invoke('git reset --hard')",
    "$ic=$ExecutionContext.InvokeCommand; $m=(gv ic).Value.InvokeScript; $m.Invoke('git reset --hard')",
    "${i c}=$ExecutionContext.InvokeCommand; $m=${i c}.InvokeScript; $m.Invoke('git reset --hard')",
    "$h=@{a=@{b=[scriptblock]}}; $f=$h['a'].b::Create; $f.Invoke('git reset --hard').Invoke()",
    "$f=@{a=[scriptblock]}.a::Create; $f.Invoke('git reset --hard').Invoke()",
    "$a=@($ExecutionContext.InvokeCommand); $m=$a[0].InvokeScript; $m.Invoke('git reset --hard')",
    "$m=(gv ExecutionContext).Value.InvokeCommand.InvokeScript; & { $m.Invoke('git reset --hard') }",
    // Review round 5 (runner rv5/truth.out, rv5/truth2.out, p7/truth.out):
    // the method taken as a value on a chain that holds a quoted or
    // here-string member name, a name with letters outside ASCII, or a block
    // comment between its parts.
    "$m=$ExecutionContext.'InvokeCommand'.InvokeScript; $m.Invoke('git reset --hard')",
    "$m=$ExecutionContext.\"InvokeCommand\".InvokeScript; $m.Invoke('git reset --hard')",
    "$m=$ExecutionContext.@'\nInvokeCommand\n'@.InvokeScript; $m.Invoke('git reset --hard')",
    "$p='InvokeCommand'; $m=$ExecutionContext.\"$p\".InvokeScript; $m.Invoke('git reset --hard')",
    "$h=@{a=[scriptblock]}; $f=$h.'a'::Create; $f.Invoke('git reset --hard').Invoke()",
    "$m=$ExecutionContext.‘InvokeCommand’.InvokeScript; $m.Invoke('git reset --hard')",
    "$h=@{a=[scriptblock]}; $f=$h.“a”::Create; $f.Invoke('git reset --hard').Invoke()",
    "$ä=[scriptblock]; $f=$ä::Create; $f.Invoke('git reset --hard').Invoke()",
    "$ö=$ExecutionContext.InvokeCommand; $m=$ö.InvokeScript; $m.Invoke('git reset --hard')",
    "$h=@{ä=[scriptblock]}; $f=$h.ä::Create; $f.Invoke('git reset --hard').Invoke()",
    "$m=$ExecutionContext<#c#>.InvokeCommand.InvokeScript; $m.Invoke('git reset --hard')",
    "$h=@{a=[scriptblock]}; $f=$h<#c#>.a::Create; $f.Invoke('git reset --hard').Invoke()",
    "$m=$ExecutionContext.'InvokeCommand'<#c#>.InvokeScript; $m.Invoke('git reset --hard')",
    "$m=$ExecutionContext<#a#><#b#>.InvokeCommand.InvokeScript; $m.Invoke('git reset --hard')",
    "$h=@{a=[scriptblock]}; $f=$h.@\"\na\n\"@::Create; $f.Invoke('git reset --hard').Invoke()",
    "$h=@{'ä'=[scriptblock]}; $f=$h.'ä'<#c#>::Create; $f.Invoke('git reset --hard').Invoke()",
    "$ä=@{b=$ExecutionContext.InvokeCommand}; $m=$ä.b.InvokeScript; & { $m.Invoke('git reset --hard') }",
    // Review round 7 (runner rv7/truth2.out, rv7/truth3.out): a comment
    // glued to the chain after a `<#` that opens no comment, in a string,
    // here-string, bareword or braced name earlier in the statement.
    "$a = 'x y<#', $ExecutionContext<#c#>.InvokeCommand.InvokeScript; $a[1].Invoke('git reset --hard')",
    "$a = 'x y<#', $ExecutionContext.InvokeCommand<#c#>.InvokeScript; $a[1].Invoke('git reset --hard')",
    "$a = \"x y<#\", $ExecutionContext<#c#>.InvokeCommand.InvokeScript; $a[1].Invoke('git reset --hard')",
    "$a = @'\nx y<#\n'@, $ExecutionContext<#c#>.InvokeCommand.InvokeScript; $a[1].Invoke('git reset --hard')",
    "$m = 'x y<#' ? $ExecutionContext<#c#>.InvokeCommand.InvokeScript : 0; $m.Invoke('git reset --hard')",
    "$m = $(Write-Output 'x y<#' | Out-Null; $ExecutionContext<#c#>.InvokeCommand.InvokeScript); $m.Invoke('git reset --hard')",
    "$m = (Write-Output a<#) ? $ExecutionContext<#c#>.InvokeCommand.InvokeScript : 0; $m.Invoke('git reset --hard')",
    "$t=[scriptblock]; $f = 'x y<#', $t<#c#>::Create; $f[1].Invoke('git reset --hard').Invoke()",
    "$h=@{a=[scriptblock]}; $f = 'x y<#', $h<#c#>.a::Create; $f[1].Invoke('git reset --hard').Invoke()",
    "$t=[scriptblock]; $f = 'x y<#' ? $t<#c#>::Create : 0; $f.Invoke('git reset --hard').Invoke()",
    "$a = ${a <#}, $ExecutionContext<#c#>.InvokeCommand.InvokeScript; $a[1].Invoke('git reset --hard')",
    "$a = <#a#>'x y<#', $ExecutionContext<#c#>.InvokeCommand.InvokeScript; $a[1].Invoke('git reset --hard')",
];

/// Name spellings longer than dcg's first reading window (review round 2;
/// runner rv2/truth.out, rv2/truth3.out): the rows that ran `git reset
/// --hard` in sandboxed PowerShell 7.5, and their twins that ran `git
/// status`. `SP` is 300 blanks, `XS` 300 `x` and `CS` 300 `c`.
fn long_spelling_rows() -> (Vec<String>, Vec<String>) {
    let expand = |row: &str| {
        row.replace("SP", &" ".repeat(300))
            .replace("XS", &"x".repeat(300))
            .replace("CS", &"c".repeat(300))
    };
    let runs_it = [
        "[scriptblock]::(SP'Create')('git reset --hard').Invoke()",
        "[scriptblock]::@(SP'Create')('git reset --hard').Invoke()",
        "[scriptblock]::$(SP'Create')('git reset --hard').Invoke()",
        "[scriptblock]::@'SP\nCreate\n'@('git reset --hard').Invoke()",
        "${XS}='Create'; [scriptblock]::${XS}('git reset --hard').Invoke()",
        "[scriptblock]::(<#CS#>'Create')('git reset --hard').Invoke()",
        "$ExecutionContext.InvokeCommand.(SP'InvokeScript')('git reset --hard')",
        "[scriptblock]::('Cre'+SP'ate')('git reset --hard').Invoke()",
        "[scriptblock]::\"$(SP'Create')\"('git reset --hard').Invoke()",
        "[scriptblock]::@\"\n$(SP'Create')\n\"@('git reset --hard').Invoke()",
        // Review round 6 (runner rv6/truth.out, rv6/truth2.out): a block
        // comment glued to the chain whose opening lies before the window.
        "$m=$ExecutionContext<#XS#>.InvokeCommand.InvokeScript; $m.Invoke('git reset --hard')",
        "$m=$ExecutionContext.InvokeCommand<#XS#>.InvokeScript; $m.Invoke('git reset --hard')",
        "$t=[scriptblock]; $f=$t<#XS#>::Create; $f.Invoke('git reset --hard').Invoke()",
        "$h=@{a=[scriptblock]}; $f=$h<#XS#>.a::Create; $f.Invoke('git reset --hard').Invoke()",
        "$m=$ExecutionContext<#XS<#y#>.InvokeCommand.InvokeScript; $m.Invoke('git reset --hard')",
        "$m=$ExecutionContext.InvokeCommand<#XS<#y#>.InvokeScript; $m.Invoke('git reset --hard')",
        "$t=[scriptblock]; $f=$t<#XS<#y#>::Create; $f.Invoke('git reset --hard').Invoke()",
    ];
    let harmless = [
        "[scriptblock]::(SP'Create')('git status').Invoke()",
        "[scriptblock]::\"$(SP'Create')\"('git status').Invoke()",
    ];
    (
        runs_it.iter().map(|row| expand(row)).collect(),
        harmless.iter().map(|row| expand(row)).collect(),
    )
}

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
    // Grouped values that span lines are read to their close.
    "$c = New-Object -TypeName System.Management.Automation.Runspaces.Command -ArgumentList @(\n  'git status',\n  $true\n)\n$ps=[powershell]::Create()\n[void]$ps.Commands.AddCommand($c)\n[void]$ps.Invoke()",
    "$ExecutionContext.InvokeCommand | % -MemberName InvokeScript -ArgumentList (\n  'git status'\n)",
    "$l = New-Object -TypeName System.Collections.Generic.List[string] -ArgumentList @(\n  ,[string[]]@('a', 'b')\n)\n$l.Count",
    // Their harmless twins: the array still spans lines, and a group with
    // one element is the first of several arguments.
    "$c = New-Object System.Management.Automation.Runspaces.Command -ArgumentList 'git status',\n  $true\n$ps=[powershell]::Create()\n[void]$ps.Commands.AddCommand($c)\n[void]$ps.Invoke()",
    "$c = New-Object -ArgumentList 'git status',\n\n  $true -TypeName System.Management.Automation.Runspaces.Command\n$ps=[powershell]::Create()\n[void]$ps.Commands.AddCommand($c)\n[void]$ps.Invoke()",
    "$ExecutionContext.InvokeCommand | % -ArgumentList 'git status',\n  'x' -MemberName InvokeScript",
    "$c = New-Object -ArgumentList 'git status', # note\n  $true -TypeName System.Management.Automation.Runspaces.Command\n$ps=[powershell]::Create()\n[void]$ps.Commands.AddCommand($c)\n[void]$ps.Invoke()",
    "$c = New-Object System.Management.Automation.Runspaces.Command -ArgumentList ('git status'), $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    // A line that starts with `,` begins a new statement.
    "$c = New-Object System.Management.Automation.Runspaces.Command 'git reset --hard'\n,$true\n$ps=[powershell]::Create()\n[void]$ps.Commands.AddCommand($c)\n[void]$ps.Invoke()",
    // A parameter before the name, a call operator, a wildcard that matches
    // no engine method, and ordinary ForEach-Object and foreach forms.
    "$ExecutionContext.InvokeCommand | % -ErrorAction Stop InvokeScript 'git status'",
    "Get-ChildItem | % -ErrorAction Stop Name",
    "$ExecutionContext.InvokeCommand | & 'ForEach-Object' InvokeScript 'git status'",
    "$ExecutionContext.InvokeCommand | % InvokeScr* 'git status'",
    "Get-ChildItem | % Na* ",
    "$ExecutionContext.InvokeCommand | % 'I*Script' 'git status'",
    "$ExecutionContext.InvokeCommand | % 'Invoke`*' 'git reset --hard'",
    "Get-ChildItem | % -Verbose Name",
    "1..3 | ForEach-Object -Parallel { $_ } -ThrottleLimit 2",
    "foreach ($x in 1, 2) { Write-Output $x -NoEnumerate }",
    "$ExecutionContext.InvokeCommand | % InvokeScript 'git status' -ErrorAction Stop",
    "$ExecutionContext.InvokeCommand | % –MemberName InvokeScript 'git status'",
    "$ExecutionContext.InvokeCommand | . ForEach-Object InvokeScript 'git status'",
    "$c = New-Object -ErrorAction Stop System.Management.Automation.Runspaces.Command 'git status', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "1, 2 | ForEach-Object -Begin { $s = 0 } -Process { $s += $_ } -End { $s }",
    "$ExecutionContext.InvokeCommand | % -Verbose: $false InvokeScript 'git status'",
    "$ExecutionContext.InvokeCommand | % -MemberName InvokeScript -ErrorAction Stop 'git status'",
    // A positional word before the named name is the argument list.
    "$ExecutionContext.InvokeCommand | % 'git status' -MemberName InvokeScript",
    "$c = New-Object 'git status', $true -TypeName System.Management.Automation.Runspaces.Command; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$ExecutionContext.InvokeCommand | % -ArgumentList 'git status' InvokeScript",
    // Redirections, and a wildcard name with a non-ASCII letter (review
    // round 6).
    "$ExecutionContext.InvokeCommand | % Invo\u{212a}eScr* 'git status'",
    "Get-ChildItem | % Name 2>&1",
    "$null = New-Object System.Text.StringBuilder 2>&1",
    "$ExecutionContext.InvokeCommand | % InvokeScript 'git status' 2>&1",
    "$ExecutionContext.InvokeCommand | % 2>&1 InvokeScript 'git status'",
    "Get-ChildItem | % 2>&1 { $_.Name }",
    "$c = New-Object -TypeName System.Management.Automation.Runspaces.Command 2>&1 -ArgumentList 'git status', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()", // Their harmless twins (review round 7).
    "$ExecutionContext.InvokeCommand | % -ArgumentList 'x' 'git reset --hard' -MemberName InvokeScript",
    "$ExecutionContext.InvokeCommand | % -ArgumentList 'x' -MemberName InvokeScript 'git reset --hard'",
    "$ExecutionContext.InvokeCommand | % 'git status' 'x' -MemberName InvokeScript",
    "$ExecutionContext.InvokeCommand | % 2> ('x' + 'y') InvokeScript 'git status'",
    "Get-ChildItem | % 2> ('x' + 'y') Name",
    "$c = New-Object 2> ('x' + 'y') System.Management.Automation.Runspaces.Command 'git status', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$ExecutionContext.InvokeCommand | % InvokeScript ('git', 'reset --hard')",
    "$ExecutionContext.InvokeCommand | % InvokeScript ('git status') 'y'",
    "$ExecutionContext.InvokeCommand | % InvokeScript 'git', 'status'",
    "$ExecutionContext.InvokeCommand | % 'x' 'y' 'git reset --hard' -MemberName InvokeScript",
    "$ExecutionContext.InvokeCommand | % InvokeScript 'git status' 2> ('x' + 'y')",
    "$ExecutionContext.InvokeCommand | % 'git status' 'x' 'y' -MemberName InvokeScript",
    "$ExecutionContext.InvokeCommand | % InvokeScript ('git status') ('y')",
    "$ExecutionContext.InvokeCommand | % 2> <# c #> ('x' + 'y') InvokeScript 'git status'",
    "$ExecutionContext.InvokeCommand | % 2>&1 InvokeScript 'git status' 'x'",
    "Get-ChildItem | % -MemberName 2> ('x' + 'y') Name",
    "$c = New-Object -TypeName System.Management.Automation.Runspaces.Command 2> ('x' + 'y') -ArgumentList 'git status', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    // Their harmless twins, and dash strings passed to ordinary methods
    // (review round 8).
    "$ExecutionContext.InvokeCommand | % InvokeScript 'git status' '-MemberName' 'x'",
    "'a-old' | % Replace '-old' '-new'",
    "'a--b' | ForEach-Object Replace '--' '-'",
    "'x-y' | % -MemberName Split -ArgumentList '-y'",
    "'a-old' | % Replace '-old', '-new'",
    "'--x' | % TrimStart '--'",
    "$e = 'Stop'; $ExecutionContext.InvokeCommand | % -ErrorAction:$e InvokeScript 'git status'",
    "'a-old' | % -MemberName Replace -ArgumentList '-old', '-new'",
    "'a-b' | % Split \"-\"",
    "$ExecutionContext.InvokeCommand | % -MemberName:'InvokeScript' 'git status'",
    "'a.b' | % Split '.' -ErrorAction:$ErrorActionPreference",
    "$ExecutionContext.InvokeCommand | % InvokeScript 'git status' -‘MemberName’ x",
    // A ForEach-Object or New-Object statement inside a group ends at the
    // group's close; the operator after it is the outer expression's (review
    // round 9), and the git status twins of PR #33's assignment shapes.
    "(Get-ChildItem | ForEach-Object Name) -join ','",
    "(1..3 | % ToString) -join ','",
    "if ((Get-ChildItem | % Name) -contains 'README.md') { 'yes' }",
    "$ids = (Get-Process | % Id) -join ','",
    "@(Get-ChildItem | % Name) -match 'x'",
    "(New-Object System.Text.StringBuilder).Append('a').ToString() -eq 'a'",
    "(Get-ChildItem | % Name) -replace 'a', 'b'",
    "(New-Object System.Random).Next(1, 10) -gt 5",
    "if ((New-Object System.IO.FileInfo 'a.txt').Exists -eq $false) { 'missing' }",
    "Get-ChildItem | Where-Object { ($_ | % Name) -like 'a*' }",
    "if ((New-Object System.IO.DirectoryInfo '.').Exists -and $true) { 'ok' }",
    "Write-Output ((1..3 | % ToString) -join '+')",
    "(1..3 | ForEach-Object -MemberName ToString) -join ','",
    "[int](New-Object System.Random 42).Next(10) -lt 11",
    "foreach ($f in (Get-ChildItem | % FullName)) { Write-Output -InputObject $f }",
    "$names = (Get-ChildItem | % Name); $names -join ','",
    "(1..3 | % { $_ * 2 }) -join ','",
    "[System.Management.Automation.Runspaces.Command]$c = New-Object System.Management.Automation.Runspaces.Command 'git status', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$c ??= New-Object System.Management.Automation.Runspaces.Command 'git status', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$c = $d = New-Object System.Management.Automation.Runspaces.Command 'git status', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$c, $d = New-Object System.Management.Automation.Runspaces.Command 'git status', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$c=New-Object -TypeName System.Management.Automation.Runspaces.Command -ArgumentList 'git status', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$r=$ExecutionContext.InvokeCommand | % InvokeScript 'git status'",
    "& { $ExecutionContext.InvokeCommand | % InvokeScript 'git status' }",
    "Get-ChildItem | ForEach-Object { $_ | % Name }",
    "if (($ExecutionContext.InvokeCommand | % InvokeScript 'git status') -eq $null) { 'n' }",
    "$h = @{ n = (Get-ChildItem | % Name) -join ',' }; $h.n",
    // Their `git status` twins, other types' `Create`, a script block name
    // with blank space, and text naming the method (card t_222650ea).
    "[scriptblock]::Create.Invoke('git status').Invoke()",
    "[scriptblock]::'Create'('git status').Invoke()",
    "$t=[scriptblock]; $t::Create('git status').Invoke()",
    "[scriptblock]::(\"Cre\"+\"ate\")('git status').Invoke()",
    "$n='Create'; [scriptblock]::$n('git status').Invoke()",
    "[scriptblock]::Create.Invoke('Write-Output ok').Invoke()",
    "$x = [IO.File]::Create('a.txt'); $x.Dispose()",
    "Write-Output \"[scriptblock]::'Create'('git reset --hard')\"",
    "Write-Output '[scriptblock]::Create.Invoke(\"git reset --hard\")'",
    "[Management.Automation.ScriptBlock]::Create('git status').Invoke()",
    "[System.Management.Automation.ScriptBlock, System.Management.Automation]::Create('git status').Invoke()",
    "[scriptblock]::'Create'.Invoke('git status').Invoke()",
    "[scriptblock]::Create.Invoke(\"git status\").InvokeReturnAsIs()",
    "[System.IO.Directory]::CreateDirectory('x') | Out-Null",
    "[powershell]::Create().AddCommand('Get-Date').Invoke() | Out-Null",
    "[scriptblock]::{Create}('git status').Invoke()",
    "$ExecutionContext.InvokeCommand.{InvokeScript}('git status')",
    "$x=[IO.File]; $x::Create('a.txt').Dispose()",
    "[scriptblock]::Create('git status').Invoke()",
    // Twins of the round 1 review rows, and `new` taken as a value on a
    // type held in a value, which is an ordinary constructor.
    "[scriptblock]::@'\nCreate\n'@('git status').Invoke()",
    "[scriptblock]::@('Create')('git status').Invoke()",
    "([scriptblock])::Create('git status').Invoke()",
    "$a='git status'; ([IO.Path])::Combine($a, 'b') | Out-Null",
    "$a=@([IO.Path]); $a[0]::Combine('git status','b') | Out-Null",
    "$ExecutionContext.InvokeCommand.@'\nInvokeScript\n'@('git status')",
    "$ExecutionContext.InvokeCommand.@('InvokeScript')('git status')",
    "[powershell]::Create().@\"\nAddScript\n\"@('git status').Invoke()",
    "$t=[Text.StringBuilder]; $f = $t::new; $f.Invoke().Append('x') | Out-Null",
    "$t=[scriptblock]; $f = $t::new; $f.OverloadDefinitions | Out-Null",
    // Twins of the review round 3 rows; each ran `git status`.
    "[scriptblock]::@\"\n$(\"Create\")\n\"@('git status').Invoke()",
    "$ExecutionContext.InvokeCommand.@\"\n$(\"InvokeScript\")\n\"@('git status')",
    "[scriptblock]<#c#>::Create('git status').Invoke()",
    "$ExecutionContext.InvokeCommand.\"$(\"InvokeScript\")\"('git status')",
    // Bareword text that names an engine method is not a member taken as a
    // value (review round 4; runner p5/w-truth.out).
    "Write-Output InvokeCommand.InvokeScript",
    "Write-Output Widget::Create",
    "Write-Output a.b.InvokeScript; git status",
    // A quoted string is an expression even as an argument, and a word
    // after blank space, a redirection or a name outside ASCII is text
    // (review round 5; runner rv5/truth.out, p7/truth.out). A comment glued
    // to a bareword before an engine method name reads as an expression: a
    // listed cost (review round 7).
    "Write-Output 'abc'.Length; git status",
    "Write-Output x >out.InvokeScript; git status",
    "Write-Output ä.InvokeScript; git status",
];

/// Harmless in PowerShell 7.5 too. The Unknown dialect denies these on base
/// 9a712556, e94e3692 and 7c5f7a8c as well (its POSIX reading takes the quoted text as a command),
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
    "$c = New-Object -TypeName System.Management.Automation.Runspaces.Command `\n    -ArgumentList 'git status', $true\n$ps=[powershell]::Create()\n[void]$ps.Commands.AddCommand($c)\n[void]$ps.Invoke()",
    // Unknown denies these on base 7c5f7a8c as well.
    "$c = New-Object System.Management.Automation.Runspaces.Command ('git status') `\n, $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "$o = New-Object -TypeName PSObject -Property @{ a = 1; b = '-x' }; $o.b",
    // PowerShell wildcards have no `[!…]` negation, so this runs nothing. In
    // Unknown the windows.filesystem pack reads `!x` as unresolved syntax.
    "$ExecutionContext.InvokeCommand | % 'Invoke[!x]cript' 'git reset --hard'",
    // A redirection to a file: Unknown denies these on base 8bf24148 too
    // (core.filesystem:redirect-truncate-dynamic-path).
    "$ExecutionContext.InvokeCommand | % 2>$null InvokeScript 'git status'",
    "$ExecutionContext.InvokeCommand | % InvokeScript 'git status' 2>$null",
    "$c = New-Object System.Management.Automation.Runspaces.Command 2>$null 'git status', $true; $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    "Get-ChildItem | % 2>$null Name",
    "$ExecutionContext.InvokeCommand | % -MemberName 2>$null InvokeScript 'git status'",
    // An escaped dash word, a quoted dash string and `--%` inside a script
    // block (review round 8): Unknown denies these on base 5b316f61 too.
    "$ExecutionContext.InvokeCommand | % InvokeScript 'git status' `-MemberName 'x'",
    "$r = New-Object System.Text.RegularExpressions.Regex '-\\d+'; $r.Match('a-12').Value",
    "Get-ChildItem | % { cmd /c --% echo hi }",
    // A group in a string's subexpression, and PR #33's no-blank assignment
    // twin (review round 9): Unknown denies these on base 53c84977 too.
    "\"Files: $((Get-ChildItem | % Name) -join ', ')\"",
    "$c=New-Object System.Management.Automation.Runspaces.Command('git status', $true); $ps=[powershell]::Create(); [void]$ps.Commands.AddCommand($c); [void]$ps.Invoke()",
    // Another type's `Create`, `Create` that is not a static member, and
    // script block names that are not `Create` (card t_222650ea): Unknown
    // denies these on base 6740afcb too.
    "[IO.File]::Create('git reset --hard').Dispose()",
    "[Text.Encoding]::UTF8.GetBytes('git reset --hard').Length",
    "$t=[scriptblock]; $t.Create('git reset --hard').Invoke()",
    "[scriptblock]::{ Create }('git reset --hard').Invoke()",
    "$ExecutionContext.InvokeCommand.{ InvokeScript }('git reset --hard')",
    "[scriptblock]::{Cre`ate}('git reset --hard').Invoke()",
    "[scriptblock]::{$n}('git reset --hard').Invoke()",
    // Twin of the round 2 `@"…"@` escape rows: Unknown's POSIX reading
    // takes the backtick as command substitution.
    "[scriptblock]::@\"\n`Create\n\"@('git status').Invoke()",
    // Twins of the review round 3 `${a`}b}` rows; each ran `git status`.
    // Unknown's POSIX reading takes the `${…}` as a substitution it cannot
    // verify, on base f9b376a2 too.
    "${a`}b}='InvokeScript'; $ExecutionContext.InvokeCommand.${a`}b}('git status')",
    "$t=[scriptblock]; ${a`}b}='Create'; $t::${a`}b}('git status').Invoke()",
    "${a`}b}='Create'; [scriptblock]::${a`}b}('git status').Invoke()",
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
    let (long_runs_it, long_harmless) = long_spelling_rows();
    for protocol in [Protocol::Claude, Protocol::Codex] {
        for command in RUNS_IT
            .iter()
            .copied()
            .chain(long_runs_it.iter().map(String::as_str))
        {
            assert_eq!(
                hook_decision(protocol, "PowerShell", command),
                "deny",
                "{protocol:?}: {command:?}"
            );
        }
        for command in HARMLESS
            .iter()
            .chain(HARMLESS_IN_POWERSHELL)
            .copied()
            .chain(long_harmless.iter().map(String::as_str))
        {
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
    let (long_runs_it, _) = long_spelling_rows();
    for command in RUNS_IT
        .iter()
        .copied()
        .chain(long_runs_it.iter().map(String::as_str))
    {
        assert_eq!(
            hook_decision(Protocol::Codex, "Bash", command),
            "deny",
            "{command:?}"
        );
    }
}

#[test]
fn powershell_and_unknown_dialects_judge_engine_script_methods() {
    let (long_runs_it, long_harmless) = long_spelling_rows();
    for dialect in [ShellDialect::PowerShell, ShellDialect::Unknown] {
        for command in RUNS_IT
            .iter()
            .copied()
            .chain(long_runs_it.iter().map(String::as_str))
        {
            assert_eq!(
                decision_in(command, dialect),
                EvaluationDecision::Deny,
                "{dialect:?}: {command:?}"
            );
        }
        for command in HARMLESS
            .iter()
            .copied()
            .chain(long_harmless.iter().map(String::as_str))
        {
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
