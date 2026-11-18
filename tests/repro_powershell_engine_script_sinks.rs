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
