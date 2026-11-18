//! A PowerShell script block can run anywhere after it is built: from a
//! variable, a hashtable value, an array element, a splat, a property, the
//! pipeline, or any method, cmdlet or operator that takes a block. dcg judged
//! a `{ … }` or `[scriptblock]::Create(…)` only where it saw it run on the
//! spot, so `$p=@{ScriptBlock={git reset --hard}}; Invoke-Command @p` passed
//! in the PowerShell dialect. Now every block is judged where it is built.
//! Rows from cards t_a68ca4ed, t_22fada3a (cmdlets and operators) and
//! t_5f33fb31 (method arguments, its branch
//! fix/powershell-method-scriptblock-arguments).

use destructive_command_guard::evaluator::evaluate_command_with_pack_order_at_path_in_dialect;
use destructive_command_guard::normalize::ShellDialect;
use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::{Config, EvaluationDecision, LayeredAllowlist};
use std::io::Write;
use std::process::{Command, Stdio};

const HOOK_TEST_TIMEOUT_MS: &str = "30000";

/// Each ran `git reset --hard` in sandboxed PowerShell 7.5
/// (`scripts/shell-truth --json pwsh`, fake git), Nov 18 2026, or registers
/// a block that runs later (an engine event, a job, a Pester block).
const RUNS_IT: &[&str] = &[
    "$s={git reset --hard}; & $s",
    "$s={git reset --hard}; $s.Invoke()",
    "$s={git reset --hard}; Invoke-Command $s",
    "$x=[scriptblock]::Create('git reset --hard'); $y=$x; & $y",
    "$x=[scriptblock]::Create('git reset --hard'); $h=@{s=$x}; & $h.s",
    "$s={git reset --hard}; $y=$s; & $y",
    "$h=@{s={git reset --hard}}; & $h.s",
    "$h=@{s={git reset --hard}}; $h.s.Invoke()",
    "$l=@({git reset --hard}); & $l[0]",
    "$l={git reset --hard},{git status}; & $l[0]",
    "$p=@{ScriptBlock={git reset --hard}}; Invoke-Command @p",
    "$o=[pscustomobject]@{s={git reset --hard}}; & $o.s",
    "$o=New-Object psobject; $o | Add-Member ScriptMethod m {git reset --hard}; $o.m()",
    "function f($b){& $b}; f {git reset --hard}",
    "$a=@{}; $a.s={git reset --hard}; & $a.s",
    "$a=@{}; $a['s']={git reset --hard}; & $a['s']",
    "$x=[scriptblock]::Create('git reset --hard'); $a=@{}; $a.s=$x; & $a.s",
    "1 | Select-Object @{n='x';e={git reset --hard}}",
    "1 | Sort-Object {git reset --hard}",
    "'a' -replace 'a',{git reset --hard}",
    "$l=[System.Collections.Generic.List[scriptblock]]::new(); $l.Add({git reset --hard}); & $l[0]",
    "${function:f}={git reset --hard}; f",
    "Set-Item function:f {git reset --hard}; f",
    "$s={git reset --hard}; $s.GetNewClosure().Invoke()",
    "$h=@{s={git reset --hard}}; $h.Values | % {& $_}",
    ",{git reset --hard} | % {& $_}",
    "{git reset --hard} | % {& $_}",
    "Write-Output {git reset --hard} | % {& $_}",
    "$x=[scriptblock]::Create('git reset --hard'); ,$x | % {& $_}",
    "[scriptblock]::Create('git reset --hard') | % {& $_}",
    "$l=@([scriptblock]::Create('git reset --hard')); $l | % Invoke",
    "$x=[scriptblock]::Create('git reset --hard'); $p=@{ScriptBlock=$x}; Invoke-Command @p",
    "$p=@{ScriptBlock={git reset --hard}}; Start-Job @p | Receive-Job -Wait",
    "$h=@{s=[scriptblock]::Create('git reset --hard')}; $h.s.Invoke()",
    "$h=@{s=[scriptblock]::Create('git reset --hard')}; Invoke-Command $h.s",
    "$h=@{s=[scriptblock]::Create('git reset --hard')}; Invoke-Command -ScriptBlock $h.s",
    "$p=@{ScriptBlock=[scriptblock]::Create('git reset --hard')}; Invoke-Command @p",
    "$h=@{s=[scriptblock]::Create('git reset --hard')}; & $h.s",
    "$l=@([scriptblock]::Create('git reset --hard')); & $l[0]",
    "$l=,[scriptblock]::Create('git reset --hard'); & $l[0]",
    "$o=[pscustomobject]@{s=[scriptblock]::Create('git reset --hard')}; & $o.s",
    "[scriptblock]::Create( 'git reset --hard' ).InvokeReturnAsIs()",
    "[System.Management.Automation.ScriptBlock]::Create('git reset --hard')|% Invoke",
    "$h=@{}; $h.Add('s', {git reset --hard}); & $h.s",
    "$q=[System.Collections.Queue]::new(); $q.Enqueue({git reset --hard}); & $q.Dequeue()",
    "$s={git reset --hard}; Set-Variable t $s; & $t",
    "& @({git reset --hard})[0]",
    "&(@{s={git reset --hard}}).s",
    "$h=[ordered]@{s={git reset --hard}}; & $h.s",
    "$h=@{ 's' = { git reset --hard } }; & $h['s']",
    "Start-Job -ScriptBlock ([scriptblock]::Create('git reset --hard')) | Receive-Job -Wait",
    "$c=@{ScriptBlock={git reset --hard}}; Invoke-Command @c -NoNewScope",
    "$x = 1; $x.ForEach({ git reset --hard })",
    "(1).ForEach({ git reset --hard })",
    "(1,2).Where({ git reset --hard })",
    "@(1).ForEach{ git reset --hard }",
    "$b = { git reset --hard }; (1).ForEach($b)",
    "(1).Where({ git reset --hard }, 'First')",
    "[regex]::Replace('a', 'a', { git reset --hard })",
    "Measure-Command { git reset --hard }",
    "Trace-Command -Name x -Expression { git reset --hard }",
    "New-Module -ScriptBlock { git reset --hard } | Out-Null",
    "1 | Group-Object { git reset --hard }",
    "'a' -split { git reset --hard }",
    "1 | Measure-Command { git reset --hard }",
    "'a' -creplace 'a', { git reset --hard }",
    "Measure-Command -Expression { git reset --hard }",
    "Measure-Command { git reset --hard } | Out-Null",
    "$x = Measure-Command { git reset --hard }",
    "$null = Measure-Command { git reset --hard }",
    "[void](Measure-Command { git reset --hard })",
    "(Measure-Command { git reset --hard }).TotalSeconds",
    "Write-Host \"$(Measure-Command { git reset --hard })\"",
    "Trace-Command x { git reset --hard }",
    "New-Module -AsCustomObject { git reset --hard } | Out-Null",
    "1 | Sort-Object { git reset --hard }",
    "1 | Group-Object -Property { git reset --hard }",
    "1 | Select-Object -Property { git reset --hard }",
    "1 | Measure-Object -Property { git reset --hard } | Out-Null",
    "Compare-Object 1 2 -Property { git reset --hard }",
    "1 | Select-Object @{ n = 'x'; e = { git reset --hard } }",
    "Get-Date | Select-Object @{ Name = 'x'; Expression = { git reset --hard } }",
    "1 | Select-Object -Property @{ n = 'x'; e = 'y' }, { git reset --hard }",
    "1 | Sort-Object -Property @{ Expression = { git reset --hard }; Descending = $true }",
    "1 | ConvertTo-Html -Property @{ e = { git reset --hard } } | Out-Null",
    "$p = @{ ScriptBlock = { git reset --hard } }; Invoke-Command @p",
    "$p = @{ Expression = { git reset --hard } }; 1 | Select-Object -Property $p",
    "$h = @{ a = { git reset --hard } }; $h.a.Invoke()",
    "$o = New-Object psobject | Add-Member -MemberType ScriptMethod -Name m -Value { git reset --hard } -PassThru; $o.m()",
    "Set-Item function:f { git reset --hard }; f",
    "New-Item -Path function:f -Value { git reset --hard } | Out-Null; f",
    "[ValidateScript({ git reset --hard; $true })]$v = 1",
    "1 | % { $_ } { git reset --hard }",
    "'a' -replace 'a', { git reset --hard }",
    "'a' -ireplace 'a', { git reset --hard }",
    "'a', 'b' -replace 'a', { git reset --hard }",
    "$s = 'a' -replace 'a', { git reset --hard }",
    "'a' -replace 'a', ({ git reset --hard })",
    "'a' -csplit { git reset --hard }",
    "'a' -isplit { git reset --hard }, 2",
    "$x = if ($true) { git reset --hard }",
    "$x = foreach ($i in 1) { git reset --hard }",
    "$x = switch (1) { 1 { git reset --hard } }",
    "$x = try { git reset --hard } finally { }",
    "$a = { git reset --hard }, 1; & $a[0]",
    "$b = { git reset --hard }; Measure-Command $b | Out-Null",
    "$b = { git reset --hard }; 'a' -replace 'a', $b",
    "$b = { git reset --hard }; 'a' -split $b",
    "$b = { git reset --hard }; 1 | Sort-Object $b",
    "$b = { git reset --hard }; $p = @{ ScriptBlock = $b }; Invoke-Command @p",
    "$b = { git reset --hard }; $b.GetNewClosure().Invoke()",
    "$b = { git reset --hard }; \"x$($b.Invoke())\"",
    "$b = { git reset --hard }; if ($true) { Measure-Command $b }",
    "$b = { git reset --hard }\nMeasure-Command $b",
    "$b = { git reset --hard }; $c = $b; & $c",
    "Measure-Command ([scriptblock]::Create('git reset --hard')) | Out-Null",
    "'a' -replace 'a', [scriptblock]::Create('git reset --hard')",
    "$b = [scriptblock]::Create('git reset --hard'); Measure-Command $b | Out-Null",
    "Register-EngineEvent PowerShell.Exiting -Action { git reset --hard }",
    "$b = { git reset --hard }; Register-EngineEvent PowerShell.Exiting -Action $b",
    "$b = { git reset --hard }; Start-Job $b",
    "Describe 'x' { It 'y' { git reset --hard } }",
    "(1..2).ForEach({ git reset --hard })",
    "$a = @(1).ForEach({ git reset --hard })",
    "(1).ForEach{ git reset --hard }",
    "(1).Where{ git reset --hard }",
    "(1).ForEach{git reset --hard}",
    "(1).ForEach({ git reset --hard }, 'x')",
    "(1).Where({ git reset --hard }, 'Until', 1)",
    "(1). ForEach({ git reset --hard })",
    "(1).<# c #>ForEach({ git reset --hard })",
    "(1).ForEach(<# c #>{ git reset --hard })",
    "(1).ForEach(`\n{ git reset --hard })",
    "(1).ForEach(\n{ git reset --hard })",
    "(1).'ForEach'({ git reset --hard })",
    "(1).\"ForEach\"({ git reset --hard })",
    "(1).FOREACH({ git reset --hard })",
    "(1)?.ForEach({ git reset --hard })",
    "$m = 'ForEach'; (1).$m({ git reset --hard })",
    "(1).$('ForEach')({ git reset --hard })",
    "(1).ForEach(({ git reset --hard }))",
    "(1).ForEach([scriptblock]{ git reset --hard })",
    "(1).ForEach((Write-Output { git reset --hard }))",
    "[regex]::new('a').Replace('a', { git reset --hard })",
    "$l = [System.Collections.Generic.List[int]]::new(); $l.Add(2); $l.Add(1); $l.Sort({ git reset --hard; 0 })",
    "$l = [System.Collections.Generic.List[int]]::new(); $l.Add(2); $l.Add(1); $l.Sort{ git reset --hard; 0 }",
    "$x = (1).ForEach({ git reset --hard }).Count",
    "Write-Output (1).ForEach({ git reset --hard })",
    "$h = @{a=1}; $h.Keys.ForEach({ git reset --hard })",
    "(1).ForEach({ (2).Where({ git reset --hard }) })",
    "(1).ForEach({ & { git reset --hard } })",
    "(1).ForEach{ git reset --hard } | Out-Null",
    "Get-Item . | ForEach-Object { $_ }; (1).ForEach({ git reset --hard })",
    "$b = { git reset --hard }; (1).Where($b)",
    "$b = { git reset --hard }; (1).ForEach( $b )",
    "${b} = { git reset --hard }; (1).ForEach(${b})",
    "$script:b = { git reset --hard }; (1).ForEach($script:b)",
    "[scriptblock]$b = { git reset --hard }; (1).ForEach($b)",
    "$b = { git reset --hard }; [regex]::Replace('a', 'a', $b)",
    "$b = { git reset --hard }; $b.Invoke()",
    "$b = { git reset --hard }; $r = $b.Invoke()",
    "$b = [scriptblock]::Create('git reset --hard'); $r = $b.Invoke()",
    "$b = { git reset --hard }; $b.InvokeReturnAsIs()",
    "$b = { git reset --hard }; Invoke-Command $b",
    "$b = { git reset --hard }; Invoke-Command -ScriptBlock $b",
    "$b = { git reset --hard }; 1 | % $b",
    "$b = { git reset --hard }; . $b",
    "@(1).ForEach({ git reset --hard })",
    "@(1).Where({ git reset --hard })",
    // Nested blocks and hashtables, and a body that is only a block.
    "$b={ {git reset --hard} }; & (& $b)",
    "& { {git reset --hard} } | % { & $_ }",
    "$b={ if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { git reset --hard } } } } } } } } } } } } } } } } } } } } } } } } } } } } } } } } } } } } } } } } }; & $b",
    "& { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { if (1) { git reset --hard } } } } } } } } } } } } }",
    "$h=@{a=@{b=@{c={git reset --hard}}}}; & $h.a.b.c",
    "$b={ {git reset --hard} }; $b.Invoke().Invoke()",
    "$h=@{a={ { {git reset --hard} } }}; $h.a.Invoke().Invoke().Invoke()",
    // PowerShell decides what a `{` opens by where the token before it
    // starts: `$$` is a whole variable, a `@` or `$` inside a bareword or
    // after a here-string end is text, and an escaped `$` or `@` is text.
    // Each `{` below opens a block (rows from t_8fdd187f too).
    "$l = Write-Output $${git reset --hard}; & $l[1]",
    "$l = Write-Output a@{git reset --hard}; & $l[1]",
    "$l = Write-Output @'\nx\n'@{git reset --hard}; & $l[1]",
    "$l = Write-Output a$${git reset --hard}; & $l[1]",
    "$l = Write-Output 1@{git reset --hard}; & $l[1]",
    "$l = Write-Output a`@{git reset --hard}; & $l[1]",
    "$l = Write-Output `@{git reset --hard}; & $l[1]",
    "$l = Write-Output `${git reset --hard}; & $l[1]",
    "$null = 1; Write-Output $${git reset --hard} | Select-Object -Last 1 | ForEach-Object Invoke",
    "Write-Output a@{git reset --hard} | Select-Object -Last 1 | ForEach-Object Invoke",
    "$h = @{s = (Write-Output $${git reset --hard})[1]}; & $h.s",
    "$l = Write-Output $$$${git reset --hard}; & $l[-1]",
    "$l = Write-Output ``$${git reset --hard}; & $l[-1]",
    "$l = Write-Output a=@{git reset --hard}; & $l[-1]",
    "$l = Write-Output a[@{git reset --hard}; & $l[-1]",
    "$l = Write-Output a]@{git reset --hard}; & $l[-1]",
    "$l = Write-Output a!@{git reset --hard}; & $l[-1]",
    "$l = Write-Output a:@{git reset --hard}; & $l[-1]",
    "$l = Write-Output a.@{git reset --hard}; & $l[-1]",
    "$l = Write-Output aa@{git reset --hard}; & $l[-1]",
    "$l = Write-Output a1@{git reset --hard}; & $l[-1]",
    "$l = Write-Output a'x'@{git reset --hard}; & $l[-1]",
    "$l = Write-Output a\"x\"@{git reset --hard}; & $l[-1]",
    "$l = Write-Output a$@{git reset --hard}; & $l[-1]",
    "$l = Write-Output ax#@{git reset --hard}; & $l[-1]",
    "$l = Write-Output $x=@{git reset --hard}; & $l[-1]",
    "$l = Write-Output [x]@{git reset --hard}; & $l[-1]",
    "$l = Write-Output [ordered]@{git reset --hard}; & $l[-1]",
    "$l = Write-Output -x=@{git reset --hard}; & $l[-1]",
    "$l = Write-Output $a=$b=@{git reset --hard}; & $l[-1]",
    "$l = Write-Output a{git reset --hard}; & $l[1]",
    "$l = Write-Output a<x{git reset --hard}; & $l[1]",
    "$l = Write-Output a#{git reset --hard}; & $l[1]",
    // A glued `X@{` is a block wherever it stands, and an escaped blank or
    // mark is part of the bareword (review round 2).
    "$l = Write-Output a = $x=@{git reset --hard}; & $l[-1]",
    "$l = Write-Output a= $x=@{git reset --hard}; & $l[-1]",
    "$l = Write-Output {x} $x=@{git reset --hard}; & $l[-1]",
    "$l = Write-Output {x} [ordered]@{git reset --hard}; & $l[-1]",
    "$l = Write-Output a `\n$x=@{git reset --hard}; & $l[-1]",
    "$l = Write-Output a `\n[ordered]@{git reset --hard}; & $l[-1]",
    "$l = Write-Output {x}$x=@{git reset --hard}; & $l[-1]",
    "$l = Write-Output = 1@{git reset --hard}; & $l[-1]",
    "$l = Write-Output {x} 1@{git reset --hard}; & $l[-1]",
    "$l = Write-Output @{a=1} $x=@{git reset --hard}; & $l[-1]",
    "$l = Write-Output = .@{git reset --hard}; & $l[-1]",
    "Write-Output {x} $x=@{git reset --hard} | Select-Object -Last 1 | ForEach-Object Invoke",
    "$l = Write-Output a `\r\n$x=@{git reset --hard}; & $l[-1]",
    "$l = Write-Output a` @{git reset --hard}; & $l[-1]",
    "$l = Write-Output a`;@{git reset --hard}; & $l[-1]",
    "$l = Write-Output a`,@{git reset --hard}; & $l[-1]",
    "$l = Write-Output a`|@{git reset --hard}; & $l[-1]",
    "$l = Write-Output a`(@{git reset --hard}; & $l[-1]",
    "$l = Write-Output a`)@{git reset --hard}; & $l[-1]",
    "$l = Write-Output a`&@{git reset --hard}; & $l[-1]",
    "$l = Write-Output a`}@{git reset --hard}; & $l[-1]",
    "$l = Write-Output a`\t@{git reset --hard}; & $l[-1]",
    "$l = Write-Output a`{@{git reset --hard}; & $l[-1]",
    "$l = Write-Output a` -x:@{git reset --hard}; & $l[-1]",
    "$l = Write-Output a`\n@{git reset --hard}; & $l[-1]",
];

/// PowerShell 7.5 runs none of these: each builds a destructive block and
/// does not run it here (`List.Add` stores it, `String.Replace` turns it into
/// text, a function is defined and not called), or is a parse error
/// (`(1).ForEach ({ … })`). dcg judges a block where it is built, since it
/// cannot follow every later path to a runner; the Unknown dialect denied
/// them on base e94e3692 already.
const BUILT_NOT_RUN: &[&str] = &[
    "$s={git reset --hard}",
    "Write-Output {git reset --hard}",
    "$h=@{s={git reset --hard}}",
    "$h=@{s=[scriptblock]::Create('git reset --hard')}",
    "$x = [scriptblock]::Create('git reset --hard')",
    "Write-Output ([scriptblock]::Create('git reset --hard'))",
    "1 | Format-Table @{ e = { git reset --hard } } | Out-Null",
    "Write-Output { git reset --hard }",
    "Out-String -InputObject { git reset --hard }",
    "$h = @{ a = { git reset --hard } }",
    "param($x = { git reset --hard })",
    "-split { git reset --hard }",
    "$b = { git reset --hard }; Write-Output $b",
    "$b = { git reset --hard }; \"$b\"",
    "Register-ArgumentCompleter -CommandName x -ScriptBlock { git reset --hard }",
    "$b = { git reset --hard }",
    "$b = { git reset --hard }; $b = 'x'",
    "[scriptblock]$b = { git reset --hard }",
    "$b = ({ git reset --hard })",
    "$b = [scriptblock]{ git reset --hard }",
    "$b = { git reset --hard } # note",
    "if ($true) { $b = { git reset --hard } }",
    "$a = 1; $b = { git reset --hard }; Write-Output $a",
    "function f { git reset --hard }",
    "filter f { git reset --hard }",
    "$b = { git reset --hard }; $b = 'x'; (1).ForEach({ $_ })",
    "$h = @{}; $h.Add('k', @{ a = { git reset --hard } }); $h.Count",
    "(1).ForEach ({ git reset --hard })",
    "(1).ForEach { git reset --hard }",
    "(1) .ForEach({ git reset --hard })",
    "$l = [System.Collections.Generic.List[object]]::new(); $l.Add({ git reset --hard }); $l.Count",
    "$l = [System.Collections.Generic.List[object]]::new(); $l.Add{ git reset --hard }; $l.Count",
    "'x'.Replace('x', { git reset --hard })",
    // A block whose body is only a block builds that block.
    "$b={ {git reset --hard} }",
];

/// None of these ran `git reset --hard` in sandboxed PowerShell 7.5.
const HARMLESS: &[&str] = &[
    "$h=@{s={git status}}; & $h.s",
    "$h=@{s=[scriptblock]::Create('git status')}; & $h.s",
    "$p=@{ScriptBlock={git status}}; Invoke-Command @p",
    "Write-Output '$h=@{s={git reset --hard}}; & $h.s'",
    "$h=@{a=1;b='git reset --hard'}; $h.b",
    "$h=@{s={git status}; t=[scriptblock]::Create('git log')}; & $h.s; & $h.t",
    "Write-Output ${env:PATH}",
    "git rev-parse HEAD@{1}",
    "$x=@{a=1;b=@{c=2}}; $x.b.c",
    "1..3 | ForEach-Object { $_ * 2 }",
    "Get-ChildItem | Sort-Object { $_.Length }",
    "'a' -replace 'a',{ $_.Value.ToUpper() }",
    "function f { git status }; f",
    "[scriptblock]::Create('Write-Output ok').Invoke()",
    "Write-Output '{git reset --hard}'",
    "Write-Output \"{git reset --hard}\"",
    "Write-Output ok # {git reset --hard}",
    "<# {git reset --hard} #> Write-Output ok",
    "$x=${function:prompt}; Write-Output $x",
    "1 | Select-Object @{n='x';e={$_}}",
    "Get-Process | Where-Object { $_.CPU -gt 1 } | Format-Table @{e={$_.Name}}",
    "$p=@{Path='.'; Filter='*.txt'}; Get-ChildItem @p",
    "cp file{,.bak}",
    "echo ${HOME}",
    "awk '{print $1}' f",
    "find . -name '*.tmp' -exec ls {} \\;",
    "git log --pretty=format:'%h {%s}'",
    "[ -f x ] && { echo a; echo b; }",
    "f() { echo hi; }; f",
    "docker ps --format '{{.Names}}'",
    "git stash show stash@{0}",
    "for f in a b; do { echo $f; }; done",
    "jq '{a: .b}' x.json",
    "kubectl get pods -o jsonpath={.items[*].metadata.name}",
    "@(1, 2).ForEach({ $_ * 2 })",
    "(1..3).Where({ $_ -gt 1 })",
    "@('a').ForEach('ToUpper')",
    "$x = 1; $x.ForEach({ git status })",
    "Measure-Command { git status }",
    "1 | Sort-Object { $_ }",
    "'a' -replace 'a', 'b'",
    "1 | Select-Object @{ n = 'x'; e = { $_ } }",
    "Measure-Command { npm test }",
    "'a-b' -replace '-', { '_' }",
    "Get-Process | Select-Object Name, @{ n = 'MB'; e = { [math]::Round($_.WS / 1MB) } }",
    "Get-ChildItem | Where-Object { $_.Name -like '*.log' } | Sort-Object { $_.Length } | Select-Object -First 3",
    "1 | % { $_ } { git status }",
    "try { git status } catch { Write-Output $_ }",
    "$b = { git status }; Measure-Command $b",
    "$b = { git status }; 'a' -replace 'a', $b",
    "$h = @{ a = { git status } }; $h.a.Invoke()",
    "git show HEAD@{1}",
    "git log -g stash@{0}",
    "${b} = 1; ${b}",
    "enum E { A; B }",
    "Write-Output '{ git reset --hard }'",
    "Write-Output \"Measure-Command { git reset --hard }\"",
    "(1).ForEach('ToString')",
    "(1).ForEach({ git status })",
    "$b = { git status }; (1).ForEach($b)",
    "$b = { git status }; $b.Invoke()",
    "Write-Output '(1).ForEach({ git reset --hard })'",
    // A block whose body is only a harmless block.
    "{ {git status} }.Invoke().Invoke()",
    // Hashtables and braced variables, read as PowerShell does.
    "$h = [ordered]@{a=1}; $h.a",
    "[pscustomobject]@{Name='x'} | Format-List",
    "${x} = 1; ${x}",
    "Write-Output $$",
    "git rev-parse main@{upstream}",
    "Get-Process | Select-Object -Property @{n='x';e={$_.Name}}",
    "Write-Output -x:@{a=1}",
    "New-Object PSObject -Property ([ordered]@{a=1})",
    "$x = @{a='git reset --hard'}; $x.a",
    "$x = @{a=1},@{b=2}; $x.Count",
    "$p = @{Path='.'}; Get-ChildItem @p",
    "$h=@{}; $h['k']=@{a=1}; $h.k.a",
    "$h=@{}; $h.k=[ordered]@{a=1}; $h.k.a",
    "function f { return @{a=1} }; (f).a",
    // Twins of the round 2 rows, and glued hashtables whose bodies are
    // now judged as code.
    "$l = Write-Output a = $x=@{git status}; & $l[-1]",
    "$l = Write-Output a= $x=@{git status}; & $l[-1]",
    "$l = Write-Output {x} $x=@{git status}; & $l[-1]",
    "$l = Write-Output {x} [ordered]@{git status}; & $l[-1]",
    "$l = Write-Output {x}$x=@{git status}; & $l[-1]",
    "$l = Write-Output = 1@{git status}; & $l[-1]",
    "$l = Write-Output {x} 1@{git status}; & $l[-1]",
    "$l = Write-Output @{a=1} $x=@{git status}; & $l[-1]",
    "$l = Write-Output = .@{git status}; & $l[-1]",
    "Write-Output {x} $x=@{git status} | Select-Object -Last 1 | ForEach-Object Invoke",
    "$p=@{Path='.'; Recurse=$true}; Get-ChildItem @p | Out-Null",
    "$h=[ordered]@{a=1}; $h.a",
    "[pscustomobject]@{Name='x'; Size=1} | Format-List",
    "$h=@{n='x';e={$_.Name}}; Get-Item . | Select-Object $h",
    "$h=@{cmd='git'; args='reset --hard'}; $h.cmd",
    "$h=@{a=1}; $h['b']=@{c=2}; $h.b.c",
    "$o=[pscustomobject]@{Path='.'}; $o.Path",
];

/// Harmless in PowerShell 7.5 too. The Unknown dialect denies these on base
/// e94e3692 as well (its POSIX reading takes the quoted text or the bare
/// block as a command), so they are checked in the PowerShell dialect only.
/// A command that is only a block prints it.
const HARMLESS_IN_POWERSHELL: &[&str] = &[
    "{ git reset --hard }",
    "$x = @{ a = 1; b = 'git reset --hard' }",
    "$sw = Measure-Command { Get-ChildItem -Recurse | Out-Null }; $sw.TotalSeconds",
    "$p = @{ Path = '.'; Recurse = $true }; Get-ChildItem @p",
    // `$$$` is `$$` and then the braced variable `${…}`; `${…}` and an
    // escaped backtick before it are a variable too.
    "$l = Write-Output $$${git reset --hard}; & $l[1]",
    "$l = Write-Output ${git reset --hard}; & $l[-1]",
    "$l = Write-Output ``${git reset --hard}; & $l[-1]", // Backtick twins of the round 2 rows: the POSIX reading takes the
    // backtick as a command substitution.
    "$l = Write-Output a `\n$x=@{git status}; & $l[-1]",
    "$l = Write-Output a `\n[ordered]@{git status}; & $l[-1]",
    "$l = Write-Output a `\r\n$x=@{git status}; & $l[-1]",
    "$l = Write-Output a` @{git status}; & $l[-1]",
    "$l = Write-Output a`;@{git status}; & $l[-1]",
    "$l = Write-Output a`,@{git status}; & $l[-1]",
    "$l = Write-Output a`|@{git status}; & $l[-1]",
    "$l = Write-Output a`(@{git status}; & $l[-1]",
    "$l = Write-Output a`)@{git status}; & $l[-1]",
    "$l = Write-Output a`&@{git status}; & $l[-1]",
    "$l = Write-Output a`}@{git status}; & $l[-1]",
    "$l = Write-Output a`\t@{git status}; & $l[-1]",
    "$l = Write-Output a`{@{git status}; & $l[-1]",
    "$h = Write-Output a `\n@{a=1}; $h.Count",
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
            "session_id": "sess-ps-stored-blocks",
            "transcript_path": "/tmp/claude/transcript.jsonl",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "toolu_ps_stored_blocks",
        }),
        // `turn_id` selects Codex's protocol.
        Protocol::Codex => serde_json::json!({
            "session_id": "019dd11d-b795-7261-a9cb-9b85a5dadf15",
            "turn_id": "turn-ps-stored-blocks",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.5",
            "permission_mode": "default",
            "tool_name": tool_name,
            "tool_input": {"command": command},
            "tool_use_id": "call_ps_stored_blocks",
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
fn powershell_tool_judges_stored_script_blocks() {
    for protocol in [Protocol::Claude, Protocol::Codex] {
        for command in RUNS_IT.iter().chain(BUILT_NOT_RUN) {
            assert_eq!(
                hook_decision(protocol, "PowerShell", command),
                "deny",
                "{protocol:?}: {command:?}"
            );
        }
        // A label that names no shell is the Unknown dialect.
        for command in RUNS_IT {
            assert_eq!(
                hook_decision(protocol, "Shell", command),
                "deny",
                "{protocol:?} Shell: {command:?}"
            );
        }
        for command in HARMLESS {
            assert_eq!(
                hook_decision(protocol, "Shell", command),
                "allow",
                "{protocol:?} Shell: {command:?}"
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
fn codex_bash_label_on_windows_judges_stored_script_blocks() {
    for command in RUNS_IT {
        assert_eq!(
            hook_decision(Protocol::Codex, "Bash", command),
            "deny",
            "{command:?}"
        );
    }
}

#[test]
fn powershell_and_unknown_dialects_judge_stored_script_blocks() {
    for dialect in [ShellDialect::PowerShell, ShellDialect::Unknown] {
        for command in RUNS_IT.iter().chain(BUILT_NOT_RUN) {
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
