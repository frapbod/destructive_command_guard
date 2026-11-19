//! The string an interpreter program hands a shell, read the way the
//! program's language builds it (card t_c081b935, after
//! t_beee11cc / PR #48). Each string kind (Python's triple-quoted, raw and
//! f-strings, Perl's `q()`/`qq()`/`qw()`, Ruby's `%q()`/`%Q()`/`%()`/`%w()`,
//! a JavaScript template holding quotes), the language's own interpolation
//! (an unknown value where the shell reads it, including inside the shell's
//! single quotes), a name bound to a literal, and the sinks no reader saw
//! (Ruby backquotes, `%x()`, `IO.popen`, `Open3`, `open("|…")`; Perl's piped
//! `open`; PHP's backquotes; Python's `os.exec*`/`spawn*`/`posix_spawn*` and
//! aliased modules) were allowed while the plain `"…"` spelling of the same
//! command denied. A fixed argv word is a command line only for a shell
//! given `-c`: `subprocess.run(["echo", "git reset --hard"])` only prints.

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

fn payload(protocol: Protocol, command: &str, cwd: &std::path::Path) -> serde_json::Value {
    match protocol {
        Protocol::Claude => serde_json::json!({
            "session_id": "sess-interp-sink-strings",
            "transcript_path": "/tmp/claude/transcript.jsonl",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_use_id": "toolu_interp_sink_strings",
        }),
        // `turn_id` selects Codex's protocol.
        Protocol::Codex => serde_json::json!({
            "session_id": "019dd11d-b795-7261-a9cb-9b85a5dadf16",
            "turn_id": "turn-interp-sink-strings",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5.5",
            "permission_mode": "default",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_use_id": "call_interp_sink_strings",
        }),
    }
}

/// What the agent reads: "allow" for empty stdout, else the decision.
fn hook_decision(protocol: Protocol, command: &str) -> String {
    let temp = tempfile::tempdir().expect("temp dir");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let payload = payload(protocol, command, temp.path()).to_string();
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

/// Checks each command in `dialects` and in both hook formats, and reports
/// every miss at once.
fn misses(commands: &[&str], dialects: &[ShellDialect], want: EvaluationDecision) -> Vec<String> {
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
            let got = hook_decision(protocol, command);
            if got != hook_want {
                misses.push(format!("{protocol:?}: {command:?} -> {got}"));
            }
        }
    }
    misses
}

const POSIX: [ShellDialect; 2] = [ShellDialect::Posix, ShellDialect::Unknown];

fn assert_all(commands: &[&str], dialects: &[ShellDialect], want: EvaluationDecision) {
    let misses = misses(commands, dialects, want);
    assert!(misses.is_empty(), "misses:\n{}", misses.join("\n"));
}

/// `c = "git reset --hard"; os.system(c)` and its twins in each language.
#[test]
fn a_string_held_in_a_variable_is_judged() {
    assert_all(
        &[
            r#"python3 -c 'import os; c="git reset --hard"; os.system(c)'"#,
            r#"python3 <<'EOF'
import os; c="git reset --hard"; os.system(c)
EOF"#,
            r#"python3 -c 'import os; c="'"'"'git'"'"' reset --hard"; os.system(c)'"#,
            r#"python3 <<'EOF'
import os; c="'git' reset --hard"; os.system(c)
EOF"#,
            r#"python3 -c 'import subprocess; c="git reset --hard"; subprocess.run(c, shell=True)'"#,
            r#"python3 <<'EOF'
import subprocess; c="git reset --hard"; subprocess.run(c, shell=True)
EOF"#,
            r#"python3 -c 'import os; c="git checkout -- a.txt"; os.system(c)'"#,
            r#"python3 <<'EOF'
import os; c="git checkout -- a.txt"; os.system(c)
EOF"#,
            r#"node -e 'const c="git reset --hard"; require("child_process").execSync(c)'"#,
            r#"node <<'EOF'
const c="git reset --hard"; require("child_process").execSync(c)
EOF"#,
            r#"node -e 'const c="'"'"'git'"'"' reset --hard"; require("child_process").execSync(c)'"#,
            r#"node <<'EOF'
const c="'git' reset --hard"; require("child_process").execSync(c)
EOF"#,
            r#"node -e 'let c = '"'"'git push --force'"'"'; require('"'"'child_process'"'"').execSync(c)'"#,
            r"node <<'EOF'
let c = 'git push --force'; require('child_process').execSync(c)
EOF",
            r#"ruby -e 'c="git reset --hard"; system(c)'"#,
            r#"ruby <<'EOF'
c="git reset --hard"; system(c)
EOF"#,
            r#"perl -e 'my $c="git reset --hard"; system($c)'"#,
            r#"perl <<'EOF'
my $c="git reset --hard"; system($c)
EOF"#,
            r#"php -r '$c="git reset --hard"; system($c);'"#,
            r#"php <<'EOF'
$c="git reset --hard"; system($c);
EOF"#,
            r#"python3 -c 'import subprocess; c="git reset --hard"; subprocess.run(args=c, shell=True)'"#,
            r#"python3 <<'EOF'
import subprocess; c="git reset --hard"; subprocess.run(args=c, shell=True)
EOF"#,
        ],
        &POSIX,
        EvaluationDecision::Deny,
    );
}

/// The language's own interpolation is an unknown value where the shell
/// reads it: inside the shell's single quotes it can complete a command name
/// (`'gi${x}t'`), and it may be empty.
#[test]
fn the_languages_own_interpolation_is_unknown_shell_text() {
    assert_all(
        &[
            r#"perl -e 'my $x=""; system("'"'"'gi${x}t'"'"' reset --hard")'"#,
            r#"perl <<'EOF'
my $x=""; system("'gi${x}t' reset --hard")
EOF"#,
            r#"perl -e 'my $x=""; system("gi${x}t reset --hard")'"#,
            r#"perl <<'EOF'
my $x=""; system("gi${x}t reset --hard")
EOF"#,
            r#"php -r '$x=""; system("'"'"'gi{$x}t'"'"' reset --hard");'"#,
            r#"php <<'EOF'
$x=""; system("'gi{$x}t' reset --hard");
EOF"#,
            r#"php -r '$x=""; system("'"'"'gi${x}t'"'"' reset --hard");'"#,
            r#"php <<'EOF'
$x=""; system("'gi${x}t' reset --hard");
EOF"#,
            r#"ruby -e 'x=""; system("'"'"'gi#{x}t'"'"' reset --hard")'"#,
            r#"ruby <<'EOF'
x=""; system("'gi#{x}t' reset --hard")
EOF"#,
            r#"ruby -e 'x=""; system("gi#{x}t reset --hard")'"#,
            r#"ruby <<'EOF'
x=""; system("gi#{x}t reset --hard")
EOF"#,
            r#"python3 -c 'import os; x=""; os.system(f"'"'"'gi{x}t'"'"' reset --hard")'"#,
            r#"python3 <<'EOF'
import os; x=""; os.system(f"'gi{x}t' reset --hard")
EOF"#,
            r#"python3 -c 'import os; x=""; os.system(f"gi{x}t reset --hard")'"#,
            r#"python3 <<'EOF'
import os; x=""; os.system(f"gi{x}t reset --hard")
EOF"#,
            r#"node -e 'const x=""; require("child_process").execSync(`'"'"'gi${x}t'"'"' reset --hard`)'"#,
            r#"node <<'EOF'
const x=""; require("child_process").execSync(`'gi${x}t' reset --hard`)
EOF"#,
            r#"node -e 'const x=""; require("child_process").execSync(`gi${x}t reset --hard`)'"#,
            r#"node <<'EOF'
const x=""; require("child_process").execSync(`gi${x}t reset --hard`)
EOF"#,
        ],
        &POSIX,
        EvaluationDecision::Deny,
    );
}

/// Perl's and Ruby's quote operators are string literals (and word lists).
#[test]
fn quote_operators_are_string_literals() {
    assert_all(
        &[
            r#"perl -e 'system(q('"'"'git'"'"' reset --hard))'"#,
            r"perl <<'EOF'
system(q('git' reset --hard))
EOF",
            r"perl -e 'system(qq(git reset --hard))'",
            r"perl <<'EOF'
system(qq(git reset --hard))
EOF",
            r"perl -e 'system qq{git reset --hard}'",
            r"perl <<'EOF'
system qq{git reset --hard}
EOF",
            r"ruby -e 'system(%Q(git reset --hard))'",
            r"ruby <<'EOF'
system(%Q(git reset --hard))
EOF",
            r#"ruby -e 'system(%q('"'"'git'"'"' reset --hard))'"#,
            r"ruby <<'EOF'
system(%q('git' reset --hard))
EOF",
            r"ruby -e 'system(%(git reset --hard))'",
            r"ruby <<'EOF'
system(%(git reset --hard))
EOF",
            r"perl -e 'system(qw(git reset --hard))'",
            r"perl <<'EOF'
system(qw(git reset --hard))
EOF",
            r"ruby -e 'IO.popen(%w[git reset --hard])'",
            r"ruby <<'EOF'
IO.popen(%w[git reset --hard])
EOF",
        ],
        &POSIX,
        EvaluationDecision::Deny,
    );
}

/// Every other string kind and sink, with a shell-quoted command name.
#[test]
fn every_string_kind_and_sink_is_read() {
    assert_all(
        &[
            r#"python3 -c 'import os; os.system('"'"''"'"''"'"''"'"'git'"'"' reset --hard'"'"''"'"''"'"')'"#,
            r"python3 <<'EOF'
import os; os.system(''''git' reset --hard''')
EOF",
            r#"python3 -c 'import os; os.system("""'"'"'git'"'"' reset --hard""")'"#,
            r#"python3 <<'EOF'
import os; os.system("""'git' reset --hard""")
EOF"#,
            r#"python3 -c 'import os; os.system(r"'"'"'git'"'"' reset --hard")'"#,
            r#"python3 <<'EOF'
import os; os.system(r"'git' reset --hard")
EOF"#,
            r#"python3 -c 'import os; os.system(f"'"'"'git'"'"' reset --hard")'"#,
            r#"python3 <<'EOF'
import os; os.system(f"'git' reset --hard")
EOF"#,
            r#"python3 -c 'import subprocess as s; s.run("'"'"'git'"'"' reset --hard", shell=True)'"#,
            r#"python3 <<'EOF'
import subprocess as s; s.run("'git' reset --hard", shell=True)
EOF"#,
            r#"python3 -c 'import os as o; o.system("git checkout -- a.txt")'"#,
            r#"python3 <<'EOF'
import os as o; o.system("git checkout -- a.txt")
EOF"#,
            r#"python3 -c 'from subprocess import run as r; r("git reset --hard", shell=True)'"#,
            r#"python3 <<'EOF'
from subprocess import run as r; r("git reset --hard", shell=True)
EOF"#,
            r#"ruby -e '`'"'"'git'"'"' reset --hard`'"#,
            r"ruby <<'EOF'
`'git' reset --hard`
EOF",
            r#"ruby -e '%x('"'"'git'"'"' reset --hard)'"#,
            r"ruby <<'EOF'
%x('git' reset --hard)
EOF",
            r#"ruby -e 'IO.popen("'"'"'git'"'"' reset --hard")'"#,
            r#"ruby <<'EOF'
IO.popen("'git' reset --hard")
EOF"#,
            r#"ruby -e 'require "open3"; Open3.capture2("'"'"'git'"'"' reset --hard")'"#,
            r#"ruby <<'EOF'
require "open3"; Open3.capture2("'git' reset --hard")
EOF"#,
            r"ruby -e '`git checkout -- a.txt`'",
            r"ruby <<'EOF'
`git checkout -- a.txt`
EOF",
            r#"ruby -e 'open("|git reset --hard")'"#,
            r#"ruby <<'EOF'
open("|git reset --hard")
EOF"#,
            r#"node -e 'require("child_process").execSync(`'"'"'git'"'"' reset --hard`)'"#,
            r#"node <<'EOF'
require("child_process").execSync(`'git' reset --hard`)
EOF"#,
            r"php -r 'echo `git reset --hard`;'",
            r"php <<'EOF'
echo `git reset --hard`;
EOF",
            r#"php -r 'echo `'"'"'git'"'"' reset --hard`;'"#,
            r"php <<'EOF'
echo `'git' reset --hard`;
EOF",
            r#"python3 -c 'import os; os.execvp("git", ["git", "reset", "--hard"])'"#,
            r#"python3 <<'EOF'
import os; os.execvp("git", ["git", "reset", "--hard"])
EOF"#,
            r#"python3 -c 'import os; os.execlp("git", "git", "reset", "--hard")'"#,
            r#"python3 <<'EOF'
import os; os.execlp("git", "git", "reset", "--hard")
EOF"#,
            r#"python3 -c 'import os; os.spawnvp(os.P_WAIT, "git", ["git", "reset", "--hard"])'"#,
            r#"python3 <<'EOF'
import os; os.spawnvp(os.P_WAIT, "git", ["git", "reset", "--hard"])
EOF"#,
            r#"python3 -c 'import os; os.posix_spawnp("git", ["git", "reset", "--hard"], os.environ)'"#,
            r#"python3 <<'EOF'
import os; os.posix_spawnp("git", ["git", "reset", "--hard"], os.environ)
EOF"#,
            r#"python3 -c 'import os; os.system("git " + "reset --hard")'"#,
            r#"python3 <<'EOF'
import os; os.system("git " + "reset --hard")
EOF"#,
        ],
        &POSIX,
        EvaluationDecision::Deny,
    );
}

/// Commands only the packs know (`git checkout --`, `git branch -D`, `git
/// restore`, `git -C … reset --hard`, `git push --force`, `find -delete`)
/// through the sinks that only the rm/git reader saw.
#[test]
fn pack_commands_reach_the_packs_through_every_sink() {
    assert_all(
        &[
            r"ruby -e '`git checkout -- a.txt`'",
            r#"python3 -c 'import os; os.system('"'"''"'"''"'"'git checkout -- a.txt'"'"''"'"''"'"')'"#,
            r#"python3 -c 'import subprocess as s; s.run("git checkout -- a.txt", shell=True)'"#,
            r"ruby -e '`git checkout -- a.txt`'",
            r#"ruby -e 'IO.popen("git checkout -- a.txt")'"#,
            r#"python3 -c 'import os; os.system('"'"''"'"''"'"'git branch -D feat'"'"''"'"''"'"')'"#,
            r#"python3 -c 'import subprocess as s; s.run("git branch -D feat", shell=True)'"#,
            r"ruby -e '`git branch -D feat`'",
            r#"ruby -e 'IO.popen("git branch -D feat")'"#,
            r#"python3 -c 'import os; os.system('"'"''"'"''"'"'git restore a.txt'"'"''"'"''"'"')'"#,
            r#"python3 -c 'import subprocess as s; s.run("git restore a.txt", shell=True)'"#,
            r"ruby -e '`git restore a.txt`'",
            r#"ruby -e 'IO.popen("git restore a.txt")'"#,
            r#"python3 -c 'import os; os.system('"'"''"'"''"'"'git -C /x reset --hard'"'"''"'"''"'"')'"#,
            r#"python3 -c 'import subprocess as s; s.run("git -C /x reset --hard", shell=True)'"#,
            r"ruby -e '`git -C /x reset --hard`'",
            r#"ruby -e 'IO.popen("git -C /x reset --hard")'"#,
            r#"python3 -c 'import os; os.system('"'"''"'"''"'"'git push --force'"'"''"'"''"'"')'"#,
            r#"python3 -c 'import subprocess as s; s.run("git push --force", shell=True)'"#,
            r"ruby -e '`git push --force`'",
            r#"ruby -e 'IO.popen("git push --force")'"#,
            r#"python3 -c 'import os; os.system('"'"''"'"''"'"'find /x -name x -delete'"'"''"'"''"'"')'"#,
            r#"python3 -c 'import subprocess as s; s.run("find /x -name x -delete", shell=True)'"#,
            r"ruby -e '`find /x -name x -delete`'",
            r#"ruby -e 'IO.popen("find /x -name x -delete")'"#,
        ],
        &POSIX,
        EvaluationDecision::Deny,
    );
}

/// Perl's piped `open` runs a command; `system(LIST)` is an argv.
#[test]
fn piped_open_and_argv_lists_are_commands() {
    assert_all(
        &[
            r#"perl -e 'open(F, "git reset --hard |")'"#,
            r#"perl <<'EOF'
open(F, "git reset --hard |")
EOF"#,
            r#"perl -e 'open(F, "| git reset --hard")'"#,
            r#"perl <<'EOF'
open(F, "| git reset --hard")
EOF"#,
            r#"perl -e 'open(my $f, "-|", "git reset --hard")'"#,
            r#"perl <<'EOF'
open(my $f, "-|", "git reset --hard")
EOF"#,
            r#"perl -e 'open(my $f, "-|", "git", "reset", "--hard")'"#,
            r#"perl <<'EOF'
open(my $f, "-|", "git", "reset", "--hard")
EOF"#,
            r#"perl -e 'system("git","reset","--hard")'"#,
            r#"perl <<'EOF'
system("git","reset","--hard")
EOF"#,
            r#"ruby -e 'system("git","reset","--hard")'"#,
            r#"ruby <<'EOF'
system("git","reset","--hard")
EOF"#,
        ],
        &POSIX,
        EvaluationDecision::Deny,
    );
}

/// A value the parent shell substitutes, in the string kinds and sinks this
/// reader learned, is spelled where the child shell reads it (PR #48).
#[test]
#[allow(clippy::literal_string_with_formatting_args)]
fn parent_values_in_these_string_kinds_are_unknown_shell_text() {
    assert_all(
        &[
            r#"python3 -c "import os; os.system('''${g} reset --hard''')""#,
            r#"python3 -c "import subprocess as s; s.run(\"${g} reset --hard\", shell=True)""#,
            r#"ruby -e "\`${g} reset --hard\`""#,
            r#"ruby -e "IO.popen(\"git ${verb} --hard\")""#,
            r#"python3 -c "import os; os.system('''${GIT:-git} reset --hard''')""#,
            r#"python3 -c "import os; os.system('''${g} push --force''')""#,
            r#"perl -e "open(F, \"r${x}m -rf / |\")""#,
            r#"php -r "echo \`r${x}m -rf /\`;""#,
            r#"python3 -c "import os; os.system(f\"'gi${x}t' reset --hard\")""#,
        ],
        &POSIX,
        EvaluationDecision::Deny,
    );
}

/// A shell (or any runner) in a fixed argv still runs its command string.
#[test]
fn a_runner_in_a_fixed_argv_still_runs_its_command() {
    assert_all(
        &[
            r#"python3 -c 'import subprocess; subprocess.run(["sh", "-c", "git reset --hard"])'"#,
            r#"python3 <<'EOF'
import subprocess; subprocess.run(["sh", "-c", "git reset --hard"])
EOF"#,
            r#"python3 -c 'import subprocess; subprocess.run(["bash", "-lc", "git reset --hard"])'"#,
            r#"python3 <<'EOF'
import subprocess; subprocess.run(["bash", "-lc", "git reset --hard"])
EOF"#,
            r#"python3 -c 'import subprocess; subprocess.run(["sudo", "git", "reset", "--hard"])'"#,
            r#"python3 <<'EOF'
import subprocess; subprocess.run(["sudo", "git", "reset", "--hard"])
EOF"#,
            r#"python3 -c 'import subprocess; subprocess.run(["env", "sh", "-c", "rm -rf /"])'"#,
            r#"python3 <<'EOF'
import subprocess; subprocess.run(["env", "sh", "-c", "rm -rf /"])
EOF"#,
            r#"python3 -c 'import subprocess; subprocess.run(["ssh", "host", "git reset --hard"])'"#,
            r#"python3 <<'EOF'
import subprocess; subprocess.run(["ssh", "host", "git reset --hard"])
EOF"#,
        ],
        &POSIX,
        EvaluationDecision::Deny,
    );
}

/// The same shapes with harmless commands, text that runs nothing, and names
/// whose value is not a literal stay allowed.
#[test]
fn harmless_strings_and_sinks_stay_allowed() {
    assert_all(
        &[
            r#"python3 -c 'import os; c="git status"; os.system(c)'"#,
            r#"python3 <<'EOF'
import os; c="git status"; os.system(c)
EOF"#,
            r#"node -e 'const c="git status"; require("child_process").execSync(c)'"#,
            r#"node <<'EOF'
const c="git status"; require("child_process").execSync(c)
EOF"#,
            r#"ruby -e 'c="git status"; system(c)'"#,
            r#"ruby <<'EOF'
c="git status"; system(c)
EOF"#,
            r#"perl -e 'my $c="git status"; system($c)'"#,
            r#"perl <<'EOF'
my $c="git status"; system($c)
EOF"#,
            r#"php -r '$c="git status"; system($c);'"#,
            r#"php <<'EOF'
$c="git status"; system($c);
EOF"#,
            r#"python3 -c 'import os; x="a"; os.system(f"echo {x}")'"#,
            r#"python3 <<'EOF'
import os; x="a"; os.system(f"echo {x}")
EOF"#,
            r#"ruby -e 'x="a"; system("echo #{x}")'"#,
            r#"ruby <<'EOF'
x="a"; system("echo #{x}")
EOF"#,
            r#"perl -e 'my $x="a"; system("echo $x")'"#,
            r#"perl <<'EOF'
my $x="a"; system("echo $x")
EOF"#,
            r#"php -r '$x="a"; system("echo {$x}");'"#,
            r#"php <<'EOF'
$x="a"; system("echo {$x}");
EOF"#,
            r#"node -e 'const x="a"; require("child_process").execSync(`echo '"'"'${x}'"'"'`)'"#,
            r"perl -e 'system(q(git status))'",
            r"perl <<'EOF'
system(q(git status))
EOF",
            r"ruby -e 'system(%q(git status))'",
            r"ruby <<'EOF'
system(%q(git status))
EOF",
            r#"python3 -c 'import os; os.execvp("git", ["git", "status"])'"#,
            r#"python3 <<'EOF'
import os; os.execvp("git", ["git", "status"])
EOF"#,
            r"ruby -e 'puts `echo hi`'",
            r"ruby <<'EOF'
puts `echo hi`
EOF",
            r"php -r 'echo `ls`;'",
            r"php <<'EOF'
echo `ls`;
EOF",
            r#"ruby -e 'IO.popen("ls").read'"#,
            r#"ruby <<'EOF'
IO.popen("ls").read
EOF"#,
            r#"python3 -c 'import subprocess; subprocess.run(['"'"'printf'"'"', '"'"'%s'"'"', '"'"'rm -rf /'"'"'])'"#,
            r#"perl -e 'open(F, "< a.txt")'"#,
            r#"perl <<'EOF'
open(F, "< a.txt")
EOF"#,
            r#"perl -e 'open(my $f, "<", "a.txt")'"#,
            r#"perl <<'EOF'
open(my $f, "<", "a.txt")
EOF"#,
            r#"perl -e 'system("git","status")'"#,
            r#"perl <<'EOF'
system("git","status")
EOF"#,
            r#"ruby -e 'system("git","status")'"#,
            r#"ruby <<'EOF'
system("git","status")
EOF"#,
            r#"python3 <<'EOF'
x="a"; print(f"git reset --hard {x}")
EOF"#,
            r#"python3 <<'EOF'
x = "git reset --hard"; print(x)
EOF"#,
            r"python3 -c 'import os, sys; cmd = sys.argv[1]; os.system(cmd)'",
            r"python3 <<'EOF'
import os, sys; cmd = sys.argv[1]; os.system(cmd)
EOF",
            r"ruby -e 'x = 10 %(3)'",
            r"ruby <<'EOF'
x = 10 %(3)
EOF",
            r"perl <<'EOF'
print 1; # `git reset --hard`
EOF",
            r"node <<'EOF'
console.log(`git reset --hard`)
EOF",
        ],
        &POSIX,
        EvaluationDecision::Allow,
    );
}

/// A word of a fixed argv reaches its program as one argument. Under
/// `--dialect unknown` the raw text of an inline program is also read as
/// shell, so this holds for the POSIX reading the hooks use.
#[test]
fn a_fixed_argv_word_is_not_a_command_line() {
    assert_all(
        &[
            r#"python3 -c 'import subprocess; subprocess.run(["echo", "git reset --hard"])'"#,
            r#"python3 -c 'import subprocess; subprocess.run(['"'"'printf'"'"', '"'"'%s'"'"', '"'"'rm -rf /'"'"'])'"#,
            r#"python3 -c 'import subprocess; subprocess.run(["git", "commit", "-m", "git reset --hard"])'"#,
            r#"python3 -c 'import subprocess; subprocess.run(["sh", "-c", "echo hi", "git reset --hard"])'"#,
            r#"ruby -e 'system("echo", "git reset --hard")'"#,
            r#"perl -e 'system("echo", "git reset --hard")'"#,
            r#"node -e 'require("child_process").spawnSync("echo", ["git reset --hard"])'"#,
        ],
        &[ShellDialect::Posix],
        EvaluationDecision::Allow,
    );
}
